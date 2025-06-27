#!/usr/bin/env node
/**
 * JavaScript/TypeScript AST Parser for RSOLV RFC-031
 * Uses Babel to parse JS/TS code and returns AST in JSON format via stdin/stdout
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const t = require('@babel/types');

// Set up timeout handler
process.on('SIGALRM', () => {
    const errorResponse = {
        status: "error",
        error: {
            type: "TimeoutError",
            message: "Parser timeout after 30 seconds"
        }
    };
    console.log(JSON.stringify(errorResponse));
    process.exit(1);
});

function nodeToDict(node) {
    /**
     * Convert Babel AST node to dictionary format with circular reference handling
     */
    if (node === null || node === undefined) {
        return null;
    }
    
    if (typeof node !== 'object') {
        return node;
    }
    
    if (Array.isArray(node)) {
        return node.map(item => nodeToDict(item));
    }
    
    const result = {
        type: node.type
    };
    
    // Add location info if available
    if (node.loc) {
        result._loc = {
            start: {
                line: node.loc.start.line,
                column: node.loc.start.column
            },
            end: {
                line: node.loc.end.line,
                column: node.loc.end.column
            }
        };
    }
    
    if (node.start !== undefined) {
        result._start = node.start;
    }
    
    if (node.end !== undefined) {
        result._end = node.end;
    }
    
    // Process all properties except circular references
    for (const key in node) {
        if (key === 'parent' || key === 'scope' || key === 'hub' || key === '_parent') {
            // Skip circular references
            continue;
        }
        
        if (node.hasOwnProperty(key) && key !== 'type' && key !== 'loc' && key !== 'start' && key !== 'end') {
            result[key] = nodeToDict(node[key]);
        }
    }
    
    return result;
}

function findSecurityPatterns(ast) {
    /**
     * Extract security-relevant patterns from Babel AST
     */
    const patterns = [];
    
    traverse(ast, {
        // Dangerous function calls
        CallExpression(path) {
            const node = path.node;
            let funcName = '';
            
            if (t.isIdentifier(node.callee)) {
                funcName = node.callee.name;
            } else if (t.isMemberExpression(node.callee)) {
                if (t.isIdentifier(node.callee.object) && t.isIdentifier(node.callee.property)) {
                    funcName = `${node.callee.object.name}.${node.callee.property.name}`;
                } else if (t.isIdentifier(node.callee.property)) {
                    funcName = node.callee.property.name;
                }
            }
            
            // Common dangerous functions
            const dangerousFuncs = new Set([
                'eval', 'Function', 'setTimeout', 'setInterval', 
                'document.write', 'innerHTML', 'outerHTML',
                'exec', 'spawn', 'execSync'
            ]);
            
            if (dangerousFuncs.has(funcName) || funcName.includes('eval') || funcName.includes('innerHTML')) {
                patterns.push({
                    type: 'dangerous_function',
                    function: funcName,
                    line: node.loc ? node.loc.start.line : 0,
                    column: node.loc ? node.loc.start.column : 0
                });
            }
        },
        
        // Template literals that might build SQL/commands
        TemplateLiteral(path) {
            const node = path.node;
            patterns.push({
                type: 'template_literal',
                line: node.loc ? node.loc.start.line : 0,
                column: node.loc ? node.loc.start.column : 0
            });
        },
        
        // String concatenation that might build queries
        BinaryExpression(path) {
            const node = path.node;
            if (node.operator === '+') {
                patterns.push({
                    type: 'string_concat',
                    line: node.loc ? node.loc.start.line : 0,
                    column: node.loc ? node.loc.start.column : 0
                });
            }
        },
        
        // Assignment to innerHTML or similar dangerous properties
        AssignmentExpression(path) {
            const node = path.node;
            if (t.isMemberExpression(node.left) && t.isIdentifier(node.left.property)) {
                const propName = node.left.property.name;
                if (['innerHTML', 'outerHTML', 'document.write'].includes(propName)) {
                    patterns.push({
                        type: 'dangerous_assignment',
                        property: propName,
                        line: node.loc ? node.loc.start.line : 0,
                        column: node.loc ? node.loc.start.column : 0
                    });
                }
            }
        }
    });
    
    return patterns;
}

function main() {
    /**
     * Main parser loop - reads JSON requests from stdin, writes responses to stdout
     */
    
    // Ensure stdout is unbuffered
    process.stdout.setEncoding('utf8');
    
    const readline = require('readline');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        terminal: false
    });
    
    rl.on('line', (line) => {
        let timeout;
        try {
            // Set 30-second timeout for each request
            timeout = setTimeout(() => {
                const errorResponse = {
                    status: "error",
                    error: {
                        type: "TimeoutError",
                        message: "Parser timeout after 30 seconds"
                    }
                };
                console.log(JSON.stringify(errorResponse));
                process.exit(1);
            }, 30000);
            
            const request = JSON.parse(line.trim());
            const requestId = request.id || 'unknown';
            const command = request.command || '';
            const action = request.action || command; // Support both formats
            
            let response;
            
            if (action === 'HEALTH_CHECK') {
                response = {
                    id: requestId,
                    result: 'ok'
                };
            } else if (action !== 'parse' && command !== '') {
                // Handle command-based interface (for compatibility with PortWorker)
                const startTime = Date.now();
                const code = command; // Treat command as code to parse
                const options = request.options || {};
                const filename = request.filename || '<string>';
                
                // Determine if this is TypeScript based on filename or content
                const isTypeScript = filename.endsWith('.ts') || filename.endsWith('.tsx') || 
                                   code.includes('interface ') || code.includes('type ') || 
                                   code.includes(': string') || code.includes(': number');
                
                const language = isTypeScript ? 'typescript' : 'javascript';
                
                // Set up Babel parser options
                const parserOptions = {
                    sourceType: 'module',
                    allowImportExportEverywhere: true,
                    allowReturnOutsideFunction: true,
                    plugins: [
                        'jsx',
                        'asyncGenerators',
                        'decorators-legacy',
                        'doExpressions',
                        'exportDefaultFrom',
                        'exportNamespaceFrom',
                        'functionBind',
                        'objectRestSpread',
                        'dynamicImport'
                    ]
                };
                
                if (isTypeScript) {
                    parserOptions.plugins.push('typescript');
                }
                
                // Parse the code
                const ast = parser.parse(code, parserOptions);
                
                // Convert AST to dictionary
                const astDict = nodeToDict(ast);
                
                // Extract security patterns if requested
                let securityPatterns = [];
                if (options.include_security_patterns !== false) {
                    securityPatterns = findSecurityPatterns(ast);
                }
                
                const parseTimeMs = Date.now() - startTime;
                
                // Count nodes by traversing AST
                let nodeCount = 0;
                traverse(ast, {
                    enter() {
                        nodeCount++;
                    }
                });
                
                response = {
                    id: requestId,
                    status: 'success',
                    success: true,
                    ast: astDict,
                    security_patterns: securityPatterns,
                    metadata: {
                        parser_version: '1.0.0',
                        language: language,
                        language_version: process.version,
                        parse_time_ms: parseTimeMs,
                        ast_node_count: nodeCount
                    }
                };
            } else if (action !== 'parse' && !command) {
                response = {
                    id: requestId,
                    status: 'error',
                    error: {
                        type: 'InvalidAction',
                        message: `Unknown action: ${action}`
                    }
                };
            } else {
                const startTime = Date.now();
                const code = request.code || '';
                const options = request.options || {};
                const filename = request.filename || '<string>';
                
                // Determine if this is TypeScript
                const isTypeScript = filename.endsWith('.ts') || filename.endsWith('.tsx') || 
                                   code.includes('interface ') || code.includes('type ') || 
                                   code.includes(': string') || code.includes(': number');
                
                const language = isTypeScript ? 'typescript' : 'javascript';
                
                // Set up Babel parser options
                const parserOptions = {
                    sourceType: 'module',
                    allowImportExportEverywhere: true,
                    allowReturnOutsideFunction: true,
                    plugins: [
                        'jsx',
                        'asyncGenerators',
                        'decorators-legacy',
                        'doExpressions',
                        'exportDefaultFrom',
                        'exportNamespaceFrom',
                        'functionBind',
                        'objectRestSpread',
                        'dynamicImport'
                    ]
                };
                
                if (isTypeScript) {
                    parserOptions.plugins.push('typescript');
                }
                
                // Parse the code
                const ast = parser.parse(code, parserOptions);
                
                // Convert AST to dictionary
                const astDict = nodeToDict(ast);
                
                // Extract security patterns if requested
                let securityPatterns = [];
                if (options.include_security_patterns !== false) {
                    securityPatterns = findSecurityPatterns(ast);
                }
                
                const parseTimeMs = Date.now() - startTime;
                
                // Count nodes
                let nodeCount = 0;
                traverse(ast, {
                    enter() {
                        nodeCount++;
                    }
                });
                
                response = {
                    id: requestId,
                    status: 'success',
                    ast: astDict,
                    security_patterns: securityPatterns,
                    metadata: {
                        parser_version: '1.0.0',
                        language: language,
                        language_version: process.version,
                        parse_time_ms: parseTimeMs,
                        ast_node_count: nodeCount
                    }
                };
            }
            
            clearTimeout(timeout);
            console.log(JSON.stringify(response));
            
        } catch (error) {
            let requestId = 'unknown';
            try {
                const request = JSON.parse(line.trim());
                requestId = request.id || 'unknown';
            } catch (e) {
                // Could not parse request, use unknown ID
            }
            
            if (timeout) clearTimeout(timeout);
            
            let response;
            
            if (error.name === 'SyntaxError' || error.message.includes('Unexpected token')) {
                response = {
                    id: requestId,
                    status: 'error',
                    success: false,
                    error: {
                        type: 'SyntaxError',
                        message: error.message,
                        line: error.loc ? error.loc.line : undefined,
                        column: error.loc ? error.loc.column : undefined
                    }
                };
            } else {
                response = {
                    id: requestId,
                    status: 'error',
                    success: false,
                    error: {
                        type: error.constructor.name,
                        message: error.message
                    }
                };
            }
            
            console.log(JSON.stringify(response));
        }
    });
    
    rl.on('close', () => {
        process.exit(0);
    });
}

if (require.main === module) {
    main();
}