#!/usr/bin/env python3
"""
Python AST Parser for RSOLV RFC-031
Parses Python code and returns AST in JSON format via stdin/stdout
"""

import sys
import json
import ast
import time
import os
import signal

# Set up signal handler for timeout
def timeout_handler(signum, frame):
    error_response = {
        "status": "error",
        "error": {
            "type": "TimeoutError",
            "message": "Parser timeout after 30 seconds"
        }
    }
    print(json.dumps(error_response))
    sys.stdout.flush()
    sys.exit(1)

signal.signal(signal.SIGALRM, timeout_handler)

def node_to_dict(node):
    """Convert Python AST node to dictionary format"""
    if isinstance(node, ast.AST):
        fields = {}
        for field, value in ast.iter_fields(node):
            fields[field] = node_to_dict(value)
        
        result = {
            'type': node.__class__.__name__
        }
        
        # Add fields directly to result
        for field, value in fields.items():
            result[field] = value
        
        # Add location info if available
        if hasattr(node, 'lineno'):
            result['_lineno'] = node.lineno
        if hasattr(node, 'col_offset'):
            result['_col_offset'] = node.col_offset
        if hasattr(node, 'end_lineno'):
            result['_end_lineno'] = node.end_lineno
        if hasattr(node, 'end_col_offset'):
            result['_end_col_offset'] = node.end_col_offset
            
        return result
    elif isinstance(node, list):
        return [node_to_dict(item) for item in node]
    else:
        return node

def find_security_patterns(tree):
    """Extract security-relevant patterns from AST"""
    patterns = []
    
    class SecurityVisitor(ast.NodeVisitor):
        def visit_Call(self, node):
            # Look for dangerous function calls
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            
            # Common dangerous functions
            dangerous_funcs = {
                'eval', 'exec', 'compile', '__import__',
                'subprocess.call', 'subprocess.run', 'os.system',
                'open', 'file'
            }
            
            if func_name in dangerous_funcs:
                patterns.append({
                    'type': 'dangerous_function',
                    'function': func_name,
                    'line': node.lineno,
                    'column': node.col_offset
                })
            
            self.generic_visit(node)
        
        def visit_JoinedStr(self, node):
            # f-strings that might be building SQL/commands
            patterns.append({
                'type': 'f_string',
                'line': node.lineno,
                'column': node.col_offset
            })
            self.generic_visit(node)
        
        def visit_BinOp(self, node):
            # String concatenation that might build queries
            if isinstance(node.op, ast.Add):
                if (isinstance(node.left, ast.Str) or 
                    isinstance(node.right, ast.Str)):
                    patterns.append({
                        'type': 'string_concat',
                        'line': node.lineno,
                        'column': node.col_offset
                    })
            self.generic_visit(node)
    
    visitor = SecurityVisitor()
    visitor.visit(tree)
    
    return patterns

def main():
    """Main parser loop - reads JSON requests from stdin, writes responses to stdout"""
    
    # Ensure stdout is unbuffered
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 1)
    
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            
            # Set 30-second timeout for each request
            signal.alarm(30)
            
            request = json.loads(line.strip())
            request_id = request.get('id', 'unknown')
            command = request.get('command', '')
            action = request.get('action', command)  # Support both formats
            
            if action == 'HEALTH_CHECK':
                response = {
                    'id': request_id,
                    'result': 'ok'
                }
            elif action != 'parse' and command != '':
                # Handle command-based interface (for compatibility with PortWorker)
                start_time = time.time()
                code = command  # Treat command as code to parse
                options = request.get('options', {})
                filename = request.get('filename', '<string>')
                
                # Parse the code
                tree = ast.parse(code, filename=filename)
                
                # Convert AST to dictionary
                ast_dict = node_to_dict(tree)
                
                # Extract security patterns if requested
                security_patterns = []
                if options.get('include_security_patterns', True):
                    security_patterns = find_security_patterns(tree)
                
                parse_time_ms = int((time.time() - start_time) * 1000)
                
                response = {
                    'id': request_id,
                    'status': 'success',
                    'success': True,
                    'ast': ast_dict,
                    'security_patterns': security_patterns,
                    'metadata': {
                        'parser_version': '1.0.0',
                        'language': 'python',
                        'language_version': sys.version.split()[0],
                        'parse_time_ms': parse_time_ms,
                        'ast_node_count': len(list(ast.walk(tree)))
                    }
                }
            elif action != 'parse' and not command:
                response = {
                    'id': request_id,
                    'status': 'error',
                    'error': {
                        'type': 'InvalidAction',
                        'message': f"Unknown action: {action}"
                    }
                }
            else:
                start_time = time.time()
                code = request.get('code', '')
                options = request.get('options', {})
                filename = request.get('filename', '<string>')
                
                # Parse the code
                tree = ast.parse(code, filename=filename)
                
                # Convert AST to dictionary
                ast_dict = node_to_dict(tree)
                
                # Extract security patterns if requested
                security_patterns = []
                if options.get('include_security_patterns', True):
                    security_patterns = find_security_patterns(tree)
                
                parse_time_ms = int((time.time() - start_time) * 1000)
                
                response = {
                    'id': request_id,
                    'status': 'success',
                    'ast': ast_dict,
                    'security_patterns': security_patterns,
                    'metadata': {
                        'parser_version': '1.0.0',
                        'language': 'python',
                        'language_version': sys.version.split()[0],
                        'parse_time_ms': parse_time_ms,
                        'ast_node_count': len(list(ast.walk(tree)))
                    }
                }
                
        except SyntaxError as e:
            response = {
                'id': request_id,
                'status': 'error',
                'success': False,
                'error': {
                    'type': 'SyntaxError',
                    'message': str(e),
                    'line': e.lineno,
                    'offset': e.offset,
                    'text': e.text
                }
            }
        except json.JSONDecodeError as e:
            response = {
                'id': 'unknown',
                'status': 'error',
                'success': False,
                'error': {
                    'type': 'JSONDecodeError',
                    'message': f"Invalid JSON: {str(e)}"
                }
            }
        except Exception as e:
            response = {
                'id': request_id,
                'status': 'error',
                'success': False,
                'error': {
                    'type': type(e).__name__,
                    'message': str(e)
                }
            }
        finally:
            # Cancel timeout
            signal.alarm(0)
        
        # Send response
        print(json.dumps(response))
        sys.stdout.flush()

if __name__ == '__main__':
    main()