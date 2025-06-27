<?php
/**
 * PHP AST Parser for RSOLV RFC-031
 * Uses nikic/php-parser to parse PHP code and return AST in JSON format via stdin/stdout
 */

// Set error reporting
error_reporting(E_ALL & ~E_NOTICE);
ini_set('display_errors', 0);

// Change to parser directory to find composer autoload
chdir(__DIR__);

// Include composer autoload
if (file_exists('vendor/autoload.php')) {
    require_once 'vendor/autoload.php';
} else {
    // Fallback error response
    $error = [
        'id' => 'unknown',
        'status' => 'error',
        'success' => false,
        'error' => [
            'type' => 'ComposerError',
            'message' => 'Composer dependencies not installed. Run: composer install'
        ]
    ];
    echo json_encode($error) . "\n";
    exit(1);
}

use PhpParser\Error;
use PhpParser\NodeDumper;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter;
use PhpParser\Node;

class SecurityPatternFinder
{
    private $patterns = [];

    public function findPatterns($ast)
    {
        $this->patterns = [];
        $this->traverseNode($ast);
        return $this->patterns;
    }

    private function traverseNode($node)
    {
        if ($node instanceof Node) {
            $this->checkNodeForSecurityPatterns($node);
            
            // Traverse all child nodes
            foreach ($node->getSubNodeNames() as $name) {
                $child = $node->$name;
                if (is_array($child)) {
                    foreach ($child as $item) {
                        $this->traverseNode($item);
                    }
                } else {
                    $this->traverseNode($child);
                }
            }
        }
    }

    private function checkNodeForSecurityPatterns($node)
    {
        // Function/method calls
        if ($node instanceof Node\Expr\FuncCall) {
            $funcName = null;
            if ($node->name instanceof Node\Name) {
                $funcName = $node->name->toString();
            } elseif ($node->name instanceof Node\Expr\Variable && $node->name->name === 'this') {
                // Handle $this->method() calls
                return;
            }
            
            if ($funcName) {
                // Check for dangerous functions
                $dangerousFunctions = [
                    'eval', 'exec', 'system', 'shell_exec', 'passthru',
                    'popen', 'proc_open', 'file_get_contents', 'file_put_contents',
                    'fopen', 'fwrite', 'include', 'include_once', 'require', 'require_once',
                    'unserialize', 'preg_replace', 'create_function',
                    'call_user_func', 'call_user_func_array'
                ];
                
                if (in_array(strtolower($funcName), $dangerousFunctions)) {
                    $this->patterns[] = [
                        'type' => 'dangerous_function',
                        'function' => $funcName,
                        'line' => $node->getLine() ?? 0,
                        'column' => $node->getStartFilePos() ?? 0
                    ];
                }
                
                // Check for SQL-related functions
                $sqlFunctions = ['mysql_query', 'mysqli_query', 'pg_query', 'sqlite_query'];
                if (in_array(strtolower($funcName), $sqlFunctions)) {
                    $this->patterns[] = [
                        'type' => 'potential_sql_injection',
                        'function' => $funcName,
                        'line' => $node->getLine() ?? 0,
                        'column' => $node->getStartFilePos() ?? 0
                    ];
                }
            }
        }
        
        // Method calls
        if ($node instanceof Node\Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = $node->name->toString();
                
                // Check for dangerous methods
                $dangerousMethods = ['query', 'exec', 'prepare', 'execute'];
                if (in_array(strtolower($methodName), $dangerousMethods)) {
                    $this->patterns[] = [
                        'type' => 'potential_sql_injection',
                        'method' => $methodName,
                        'line' => $node->getLine() ?? 0,
                        'column' => $node->getStartFilePos() ?? 0
                    ];
                }
            }
        }
        
        // String concatenation that might lead to injection
        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            $this->patterns[] = [
                'type' => 'string_concatenation',
                'line' => $node->getLine() ?? 0,
                'column' => $node->getStartFilePos() ?? 0
            ];
        }
        
        // Variable variables ($$var)
        if ($node instanceof Node\Expr\Variable && $node->name instanceof Node\Expr) {
            $this->patterns[] = [
                'type' => 'variable_variable',
                'line' => $node->getLine() ?? 0,
                'column' => $node->getStartFilePos() ?? 0
            ];
        }
    }
}

function nodeToArray($node)
{
    if ($node === null) {
        return null;
    }
    
    if (is_array($node)) {
        $result = [];
        foreach ($node as $key => $value) {
            $result[$key] = nodeToArray($value);
        }
        return $result;
    }
    
    if (!($node instanceof Node)) {
        return $node;
    }
    
    $result = [
        'type' => $node->getType()
    ];
    
    // Add location information
    if ($node->getLine() !== -1) {
        $result['_loc'] = [
            'start' => [
                'line' => $node->getLine(),
                'column' => $node->getStartFilePos() ?? 0
            ],
            'end' => [
                'line' => $node->getEndLine() ?? $node->getLine(),
                'column' => $node->getEndFilePos() ?? ($node->getStartFilePos() ?? 0)
            ]
        ];
        
        $result['_start'] = $node->getStartFilePos() ?? 0;
        $result['_end'] = $node->getEndFilePos() ?? 0;
    }
    
    // Add children
    $children = [];
    foreach ($node->getSubNodeNames() as $name) {
        $child = $node->$name;
        $children[$name] = nodeToArray($child);
    }
    
    if (!empty($children)) {
        $result['children'] = $children;
    }
    
    return $result;
}

function processRequest($jsonInput)
{
    try {
        $request = json_decode($jsonInput, true);
        if (!$request) {
            throw new Exception('Invalid JSON input');
        }
        
        $requestId = $request['id'] ?? 'unknown';
        $command = $request['command'] ?? '';
        $action = $request['action'] ?? $command;
        
        if ($action === 'HEALTH_CHECK') {
            $response = [
                'id' => $requestId,
                'result' => 'ok'
            ];
            echo json_encode($response) . "\n";
            return;
        }
        
        $startTime = microtime(true);
        $code = '';
        $options = $request['options'] ?? [];
        $filename = $request['filename'] ?? '<string>';
        
        if ($action !== 'parse' && !empty($action)) {
            // Command-based interface
            $code = $command;
        } else {
            // Standard parse interface
            $code = $request['code'] ?? '';
        }
        
        // Parse PHP code
        $parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
        $ast = $parser->parse($code);
        
        // Convert AST to array
        $astArray = nodeToArray($ast);
        
        // Extract security patterns
        $securityPatterns = [];
        $includeSecurityPatterns = !isset($options['include_security_patterns']) || 
                                  $options['include_security_patterns'] !== false;
        
        if ($includeSecurityPatterns) {
            $finder = new SecurityPatternFinder();
            $securityPatterns = $finder->findPatterns($ast);
        }
        
        $parseTime = (microtime(true) - $startTime) * 1000;
        
        // Count nodes
        $nodeCount = countNodes($ast);
        
        $response = [
            'id' => $requestId,
            'status' => 'success',
            'success' => true,
            'ast' => $astArray,
            'security_patterns' => $securityPatterns,
            'metadata' => [
                'parser_version' => '1.0.0',
                'language' => 'php',
                'language_version' => phpversion(),
                'parse_time_ms' => (int)$parseTime,
                'ast_node_count' => $nodeCount
            ]
        ];
        
        echo json_encode($response) . "\n";
        
    } catch (Error $e) {
        $requestId = $request['id'] ?? 'unknown';
        $response = [
            'id' => $requestId,
            'status' => 'error',
            'success' => false,
            'error' => [
                'type' => 'SyntaxError',
                'message' => $e->getMessage(),
                'line' => method_exists($e, 'getStartLine') ? $e->getStartLine() : 0,
                'column' => 0
            ]
        ];
        echo json_encode($response) . "\n";
        
    } catch (Exception $e) {
        $requestId = isset($request) ? ($request['id'] ?? 'unknown') : 'unknown';
        $response = [
            'id' => $requestId,
            'status' => 'error',
            'success' => false,
            'error' => [
                'type' => get_class($e),
                'message' => $e->getMessage()
            ]
        ];
        echo json_encode($response) . "\n";
    }
}

function countNodes($node)
{
    if (!($node instanceof Node)) {
        return 0;
    }
    
    $count = 1; // Count current node
    
    foreach ($node->getSubNodeNames() as $name) {
        $child = $node->$name;
        if (is_array($child)) {
            foreach ($child as $item) {
                $count += countNodes($item);
            }
        } else {
            $count += countNodes($child);
        }
    }
    
    return $count;
}

// Main execution
function main()
{
    // Set timeout signal handler
    if (function_exists('pcntl_signal')) {
        pcntl_signal(SIGALRM, function() {
            $error = [
                'id' => 'unknown',
                'status' => 'error',
                'success' => false,
                'error' => [
                    'type' => 'TimeoutError',
                    'message' => 'Parser timeout after 30 seconds'
                ]
            ];
            echo json_encode($error) . "\n";
            exit(1);
        });
        pcntl_alarm(30); // 30 second timeout
    }
    
    // Read from stdin
    while (($line = fgets(STDIN)) !== false) {
        $line = trim($line);
        if (!empty($line)) {
            processRequest($line);
            flush();
        }
    }
}

if (php_sapi_name() === 'cli') {
    main();
}
?>