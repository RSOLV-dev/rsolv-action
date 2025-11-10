#!/usr/bin/env bun
/**
 * AST Pattern Interpreter for RSOLV-action
 *
 * Interprets AST-enhanced patterns from RSOLV-api to dramatically
 * reduce false positives without sending code to the server.
 */

import { parse, ParserOptions } from '@babel/parser';
import * as traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { Node, File } from '@babel/types';
import type { NodePath, Scope, Binding } from '@babel/traverse';

import { SecurityPattern } from './types.js';
import { SafeRegexMatcher } from './safe-regex-matcher.js';

// Type for AST rules structure
interface ASTRules {
  node_type?: string;
  operator?: string;
  context_analysis?: {
    contains_sql_keywords?: boolean;
    has_user_input_in_concatenation?: boolean;
    within_db_call?: boolean;
  };
  ancestor_requirements?: {
    has_db_method_call?: string;
    max_depth?: number;
  };
  name_matches?: string;
  body_excludes?: string;
  method_names?: string[];
  argument_contains?: {
    dangerous_keys?: string[];
  };
}

// Type for traversal handle
interface TraversalHandle {
  ast: File;
  active: boolean;
}

// Extend SecurityPattern type for internal use
interface ASTPattern extends SecurityPattern {
  // Map SecurityPattern fields to expected format
  regex?: string;
  ast_rules?: ASTRules;
  context_rules?: Record<string, unknown>;
  confidence_rules?: Record<string, unknown>;
  min_confidence?: number;
}

interface Finding {
  pattern: SecurityPattern;
  file: string;
  line: number;
  column: number;
  code: string;
  confidence: number;
}

// Constants for better maintainability
const SQL_KEYWORDS_REGEX = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i;
const USER_INPUT_SOURCES = ['req', 'request', 'params', 'query', 'body'] as const;
const DB_METHOD_NAMES = ['query', 'execute', 'exec', 'run', 'all', 'get'] as const;
const MAX_TRAVERSAL_DEPTH = 10;
const MAX_RECURSION_DEPTH = 5;
const DEFAULT_CONFIDENCE_THRESHOLD = 0.7;

// Type guards for cleaner code
const hasGC = (g: typeof globalThis): g is typeof globalThis & { gc: () => void } =>
  typeof (g as any).gc === 'function';

const isFunctionWithBody = (node: Node): node is t.FunctionDeclaration & { body: t.BlockStatement } =>
  t.isFunctionDeclaration(node) && node.body !== null && t.isBlockStatement(node.body);

export class ASTPatternInterpreter {
  private astCache: WeakMap<object, File> = new WeakMap();
  private activeTraversals: Set<TraversalHandle> = new Set();

  /**
   * Cleanup method to explicitly release resources
   */
  cleanup(): void {
    // Clear any active traversals
    this.activeTraversals.clear();

    // WeakMap will auto-GC but we can help by clearing references
    this.astCache = new WeakMap();

    // Force garbage collection if available (mainly for tests)
    if (typeof global !== 'undefined' && hasGC(global)) {
      global.gc();
    }
  }

  /**
   * Scan a file using both regex pre-filtering and AST analysis.
   */
  async scanFile(filePath: string, content: string, patterns: SecurityPattern[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    // Skip test files globally
    if (this.isTestFile(filePath)) {
      return [];
    }
    
    console.log(`[AST] Scanning file: ${filePath}`);
    console.log(`[AST] Total patterns: ${patterns.length}`);
    
    // Phase 1: Regex pre-filter (FAST!)
    const candidatePatterns = patterns.filter(pattern => {
      // Check if pattern has regex patterns to test
      if (pattern.patterns?.regex && pattern.patterns.regex.length > 0) {
        // Test each regex pattern
        const matched = pattern.patterns.regex.some(regex => regex.test(content));
        if (matched) {
          console.log(`[AST] Pattern ${pattern.id} matched via regex`);
        }
        return matched;
      }
      return false;
    });
    
    console.log(`[AST] Candidate patterns after regex filter: ${candidatePatterns.length}`);
    
    if (candidatePatterns.length === 0) {
      return findings;
    }
    
    // Check if this is a JavaScript/TypeScript file
    const isJavaScriptFile = this.isJavaScriptFile(filePath);
    
    // Phase 2: AST analysis for JavaScript/TypeScript files only
    if (isJavaScriptFile) {
      let ast: File | null = null;
      try {
        const parserOptions: ParserOptions = {
          sourceType: 'module',
          plugins: ['jsx', 'typescript'],
          errorRecovery: true
        };
        ast = parse(content, parserOptions);
      } catch (error) {
        // Fall back to regex-only for unparseable files
        return this.regexOnlyFallback(filePath, content, candidatePatterns);
      }

      try {
        // Apply each candidate pattern
        for (const pattern of candidatePatterns) {
          if (pattern.astRules) {
            console.log(`[AST] Applying AST rules for pattern ${pattern.id}`);
            const patternFindings = this.applyASTPattern(ast, pattern, filePath, content);
            console.log(`[AST] Found ${patternFindings.length} issues with AST rules`);
            findings.push(...patternFindings);
          } else {
            // Pattern doesn't have AST rules, use regex
            console.log(`[AST] Pattern ${pattern.id} has no AST rules, using regex`);
            const regexFindings = this.applyRegexPattern(content, pattern, filePath);
            findings.push(...regexFindings);
          }
        }
      } finally {
        // Explicit cleanup to help GC
        ast = null;
      }
    } else {
      // For non-JavaScript files, use regex-only approach
      return this.regexOnlyFallback(filePath, content, candidatePatterns);
    }
    
    // Filter by minimum confidence
    return findings.filter(f =>
      f.confidence >= (f.pattern.minConfidence ?? DEFAULT_CONFIDENCE_THRESHOLD)
    );
  }
  
  private applyASTPattern(ast: File, pattern: SecurityPattern, filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];
    const rules = pattern.astRules!;

    const self = this; // Capture this context

    // Track traversal for cleanup
    const traversalHandle: TraversalHandle = { ast, active: true };
    this.activeTraversals.add(traversalHandle);

    try {
      (traverse as any).default(ast, {
        enter(path: NodePath) {
          // Check node type if specified
          if (rules.node_type && path.node.type !== rules.node_type) {
            return;
          }

          // Apply pattern-specific logic
          let matches = false;
          let confidence = pattern.confidenceRules?.base || 0.8;

          // Convert VulnerabilityType enum to string for switch
          const patternType = pattern.type.toLowerCase().replace(/_/g, ' ');

          // Cache node data before checking to avoid keeping references
          const nodeLoc = path.node?.loc;
          const nodeStart = path.node?.start;
          const nodeEnd = path.node?.end;

          switch (patternType) {
          case 'sql injection':
            matches = self.checkSQLInjection(path, rules as ASTRules, pattern);
            break;
          case 'logging':
            matches = self.checkMissingLogging(path, rules as ASTRules, pattern);
            break;
          case 'nosql injection':
            matches = self.checkNoSQLInjection(path, rules as ASTRules, pattern);
            break;
          default:
            matches = self.checkGenericPattern(path, rules as ASTRules, pattern);
          }

          if (matches) {
            // Calculate confidence adjustments
            confidence = self.calculateConfidence(
              path,
              confidence,
              pattern.confidenceRules?.adjustments || {}
            );

            if (nodeLoc) {
              findings.push({
                pattern,
                file: filePath,
                line: nodeLoc.start.line,
                column: nodeLoc.start.column,
                code: content.substring(nodeStart || 0, nodeEnd || 0),
                confidence
              });
            }
          }
        }
      });
    } finally {
      // Clean up traversal
      traversalHandle.active = false;
      this.activeTraversals.delete(traversalHandle);
    }

    return findings;
  }
  
  private checkSQLInjection(path: NodePath, rules: ASTRules, pattern: SecurityPattern): boolean {
    const node = path.node;

    // Handle BinaryExpression (string concatenation with +)
    if (t.isBinaryExpression(node) && node.operator === '+') {
      const fullExpression = this.getFullConcatenatedString(path);
      const hasSQL = SQL_KEYWORDS_REGEX.test(fullExpression);

      console.log(`[AST] SQL check: BinaryExpression found, hasSQL=${hasSQL}, expression="${fullExpression}"`);

      if (hasSQL && this.hasConcatenatedUserInput(path)) {
        const inDbContext = this.isInDatabaseCall(path) || this.isAssignedToQueryVariable(path);

        if (inDbContext) {
          // Apply exclusion rules
          const exclusions = [
            pattern.contextRules?.exclude_if_parameterized && this.isParameterizedQuery(path),
            pattern.contextRules?.exclude_if_logging_only && this.isOnlyUsedForLogging(path)
          ];

          return !exclusions.some(Boolean);
        }
      }
    }

    // Also check template literals
    if (t.isTemplateLiteral(node)) {
      const hasSQL = node.quasis.some(q => SQL_KEYWORDS_REGEX.test(q.value.raw));
      const hasUserInput = node.expressions.some(expr => this.containsUserInput(expr, path));

      if (hasSQL && hasUserInput) {
        // Check if parameterized
        return !(pattern.contextRules?.exclude_if_parameterized && this.isParameterizedQuery(path));
      }
    }

    return false;
  }
  
  private checkMissingLogging(path: NodePath, rules: ASTRules, pattern: SecurityPattern): boolean {
    const node = path.node;
    
    // Must be a function declaration
    if (!t.isFunctionDeclaration(node)) return false;
    
    // Check function name
    if (rules.name_matches && node.id) {
      const nameRegex = new RegExp(rules.name_matches);
      if (!nameRegex.test(node.id.name)) return false;
      
      // Check if body contains logging
      const bodyString = this.getBodyString(node);
      const excludeRegex = new RegExp(rules.body_excludes || 'log|logger');
      
      if (excludeRegex.test(bodyString)) return false;
      
      // Check if it delegates
      if (pattern.contextRules?.exclude_if_delegates) {
        if (this.delegatesToOtherFunction(node)) return false;
      }
      
      return true;
    }
    
    return false;
  }
  
  private checkNoSQLInjection(path: NodePath, rules: ASTRules, pattern: SecurityPattern): boolean {
    const node = path.node;
    
    if (!t.isCallExpression(node)) return false;
    
    // Check method name
    if (t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.property)) {
      const methodName = node.callee.property.name;
      if (!rules.method_names?.includes(methodName)) return false;
      
      // Check arguments for user input
      const firstArg = node.arguments[0];
      if (t.isObjectExpression(firstArg)) {
        // Check for dangerous operators
        const hasDangerousOp = firstArg.properties.some(prop =>
          t.isObjectProperty(prop) && 
          t.isIdentifier(prop.key) &&
          rules.argument_contains?.dangerous_keys?.includes(prop.key.name)
        );
        
        if (hasDangerousOp) return true;

        // Check for user input
        const hasUserInput = firstArg.properties.some(prop =>
          t.isObjectProperty(prop) ? this.containsUserInput(prop.value, path) : false
        );
        
        return hasUserInput;
      }
    }
    
    return false;
  }
  
  private checkGenericPattern(path: NodePath, rules: ASTRules, pattern: SecurityPattern): boolean {
    // Generic pattern matching logic
    return false;
  }
  
  // Helper methods

  /**
   * Generic path traversal helper to DRY up ancestor checking
   */
  private traverseAncestors(
    path: NodePath,
    predicate: (node: Node) => boolean,
    maxDepth: number = MAX_TRAVERSAL_DEPTH
  ): boolean {
    let current: NodePath | null = path;
    let depth = 0;

    while (current && depth < maxDepth) {
      const parentPath: NodePath | null = current.parentPath;
      if (!parentPath) break;

      if (predicate(parentPath.node)) {
        return true;
      }

      current = parentPath;
      depth++;
    }

    return false;
  }

  private isTestFile(filePath: string): boolean {
    const testPatterns = [
      /\.test\.[jt]sx?$/,
      /\.spec\.[jt]sx?$/,
      /\/__tests__\//,
      /\/test\//,
      /\/spec\//
    ];
    return testPatterns.some(p => p.test(filePath));
  }

  private isJavaScriptFile(filePath: string): boolean {
    // Check if this is a JavaScript or TypeScript file
    const jsPatterns = [
      /\.[jt]sx?$/,  // .js, .jsx, .ts, .tsx
      /\.mjs$/,      // ES modules
      /\.cjs$/       // CommonJS modules
    ];
    return jsPatterns.some(p => p.test(filePath));
  }
  
  private isInDatabaseCall(path: NodePath): boolean {
    return this.traverseAncestors(path, (node) => {
      if (t.isCallExpression(node) && t.isMemberExpression(node.callee)) {
        const prop = node.callee.property;
        return t.isIdentifier(prop) && DB_METHOD_NAMES.includes(prop.name as any);
      }
      return false;
    });
  }
  
  private containsUserInput(node: Node | null | undefined, path: NodePath, depth: number = 0): boolean {
    if (!node || depth > MAX_RECURSION_DEPTH) return false;

    if (t.isMemberExpression(node)) {
      const objName = this.getObjectName(node);
      return USER_INPUT_SOURCES.includes(objName as any);
    }

    if (t.isIdentifier(node)) {
      // Avoid circular references by limiting scope lookups
      try {
        const binding = path.scope.getBinding(node.name);
        if (binding?.path.isVariableDeclarator()) {
          const init = binding.path.node.init;
          if (t.isMemberExpression(init)) {
            const objName = this.getObjectName(init);
            return USER_INPUT_SOURCES.includes(objName as any);
          }
        }
      } catch {
        // Ignore scope errors silently
      }
    }

    return false;
  }
  
  private getObjectName(node: Node): string {
    if (t.isMemberExpression(node) && t.isIdentifier(node.object)) {
      return node.object.name;
    }
    return '';
  }
  
  private isParameterizedQuery(path: NodePath): boolean {
    const parent = path.parent;
    if (t.isCallExpression(parent)) {
      // Check if using ? placeholders or array of params
      return parent.arguments.length > 1 ||
             (t.isTemplateLiteral(parent.arguments[0]) &&
              parent.arguments[0].quasis.some(q => q.value.raw.includes('?')));
    }
    return false;
  }
  
  private getBodyString(node: Node): string {
    return isFunctionWithBody(node)
      ? node.body.body.map(n => n.type).join(' ')
      : '';
  }

  private delegatesToOtherFunction(node: Node): boolean {
    return isFunctionWithBody(node) &&
      node.body.body.some(stmt =>
        t.isReturnStatement(stmt) &&
        t.isCallExpression(stmt.argument)
      );
  }
  
  private calculateConfidence(
    path: NodePath,
    baseConfidence: number,
    adjustments: Record<string, number>
  ): number {
    let confidence = baseConfidence;

    // Create adjustment conditions map
    const adjustmentChecks: Record<string, boolean> = {
      direct_req_param_concat: this.hasConcatenatedUserInput(path),
      within_db_query_call: this.isInDatabaseCall(path) || this.isAssignedToQueryVariable(path),
      has_sql_keywords: t.isBinaryExpression(path.node) &&
        SQL_KEYWORDS_REGEX.test(this.getFullConcatenatedString(path)),
      is_console_log: this.isInConsoleLog(path),
      direct_user_input: this.hasDirectUserInput(path),
      has_validation: this.hasValidation(path),
      is_test_code: this.isInTestCode(path),
      in_test_file: this.isTestFile('') // TODO: This should receive the actual filepath
    };

    // Apply all adjustments
    for (const [key, shouldApply] of Object.entries(adjustmentChecks)) {
      if (adjustments[key] && shouldApply) {
        confidence += adjustments[key];
      }
    }

    // Clamp between 0 and 1
    return Math.max(0, Math.min(1, confidence));
  }
  
  private hasDirectUserInput(path: NodePath): boolean {
    // Check if user input is used directly without any transformation
    return false; // Simplified for demo
  }

  private hasValidation(path: NodePath): boolean {
    // Check if input goes through validation
    return false; // Simplified for demo
  }

  private isInTestCode(path: NodePath): boolean {
    // Check if we're in test code
    return false; // Simplified for demo
  }

  private getFullConcatenatedString(path: NodePath): string {
    // Try to extract the full concatenated string for analysis
    const node = path.node;
    if (t.isBinaryExpression(node)) {
      const parts: string[] = [];
      
      // Get left side
      if (t.isStringLiteral(node.left)) {
        parts.push(node.left.value);
      }
      
      // Get right side (could be a variable)
      if (t.isStringLiteral(node.right)) {
        parts.push(node.right.value);
      } else if (t.isIdentifier(node.right)) {
        parts.push('USER_INPUT'); // Placeholder for analysis
      }
      
      return parts.join('');
    }
    return '';
  }
  
  private hasConcatenatedUserInput(path: NodePath): boolean {
    const node = path.node;
    if (!t.isBinaryExpression(node)) return false;

    const right = node.right;

    // Direct identifier that might be user input
    if (t.isIdentifier(right)) {
      return true; // Simplified - in production, should check binding source
    }

    // Member expression like req.params.id
    if (t.isMemberExpression(right) && t.isMemberExpression(right.object)) {
      const innerObj = right.object;
      const isReqObject = t.isIdentifier(innerObj.object) &&
        innerObj.object.name === 'req';

      if (isReqObject) {
        const prop = innerObj.property;
        return t.isIdentifier(prop) &&
          ['params', 'query', 'body'].includes(prop.name);
      }
    }

    return false;
  }
  
  private isAssignedToQueryVariable(path: NodePath): boolean {
    // Check if this expression is assigned to a variable with 'query' in the name
    const parent = path.parent;
    
    if (t.isVariableDeclarator(parent) && parent.init === path.node) {
      if (t.isIdentifier(parent.id)) {
        const varName = parent.id.name.toLowerCase();
        return varName.includes('query') || varName.includes('sql');
      }
    }
    
    return false;
  }
  
  private isInConsoleLog(path: NodePath): boolean {
    return this.traverseAncestors(path, (node) => {
      if (t.isCallExpression(node)) {
        const callee = node.callee;
        return t.isMemberExpression(callee) &&
          t.isIdentifier(callee.object) && callee.object.name === 'console' &&
          t.isIdentifier(callee.property) && callee.property.name === 'log';
      }
      return false;
    }, MAX_RECURSION_DEPTH);
  }
  
  private isOnlyUsedForLogging(path: NodePath): boolean {
    // Check if this SQL string is only used for logging, not execution
    const parent = path.parent;
    
    // If it's assigned to a variable, check all its uses
    if (t.isVariableDeclarator(parent) && parent.init === path.node && t.isIdentifier(parent.id)) {
      const varName = parent.id.name;
      
      // Find the scope and check all references to this variable
      const binding = path.scope.getBinding(varName);
      if (!binding) return false;
      
      // Check all references - if ALL are console.log, it's safe
      const allForLogging = binding.referencePaths.every((refPath: NodePath) => {
        return this.isInConsoleLog(refPath);
      });
      
      return allForLogging;
    }
    
    // If it's directly in console.log, it's only for logging
    return this.isInConsoleLog(path);
  }
  
  // Fallback methods
  
  private regexOnlyFallback(
    filePath: string, 
    content: string, 
    patterns: SecurityPattern[]
  ): Finding[] {
    // Use regex matching when AST parsing fails (e.g., for non-JavaScript languages)
    const findings: Finding[] = [];
    
    for (const pattern of patterns) {
      // Apply regex patterns regardless of whether pattern has AST rules
      // This ensures non-JavaScript code can still be analyzed
      const regexFindings = this.applyRegexPattern(content, pattern, filePath);
      findings.push(...regexFindings);
    }
    
    return findings;
  }
  
  private applyRegexPattern(
    content: string,
    pattern: SecurityPattern,
    filePath: string
  ): Finding[] {
    // Traditional regex matching for patterns without AST rules
    const findings: Finding[] = [];

    if (!pattern.patterns?.regex) {
      return findings;
    }

    // Use SafeRegexMatcher for all safety guarantees
    for (const regex of pattern.patterns.regex) {
      const result = SafeRegexMatcher.match(regex, content, {
        patternId: pattern.id,
        filePath
      });

      // Convert matches to findings
      for (const { match, lineNumber, column } of result.matches) {
        findings.push({
          pattern,
          file: filePath,
          line: lineNumber,
          column,
          code: match[0],
          confidence: pattern.confidenceRules?.base || 0.8
        });
      }
    }

    return findings;
  }
}

// Demo usage
// if (import.meta.main) {
//   console.log("AST Pattern Interpreter ready for integration!");
//   console.log("This dramatically reduces false positives by:");
//   console.log("1. Using AST to understand code structure");
//   console.log("2. Applying context rules (exclude test files, etc.)");
//   console.log("3. Dynamic confidence scoring");
//   console.log("4. Framework-aware detection");
// }