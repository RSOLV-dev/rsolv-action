#!/usr/bin/env python3
"""
Simple JavaScript parser for testing - handles JSON request format.
"""
import sys
import json

def handle_request(request):
    """Handle a JSON request and return JSON response."""
    try:
        request_data = json.loads(request)
        request_id = request_data.get("id", "unknown")
        command = request_data.get("command", "")
        
        if command == "HEALTH_CHECK":
            response = {
                "id": request_id,
                "result": "ok"
            }
        elif command == "FORCE_CRASH_SIGNAL":
            response = {
                "id": request_id,
                "success": False,
                "error": "Parser crashed during processing"
            }
            print(json.dumps(response))
            sys.exit(1)
        elif command == "FORCE_TIMEOUT_SIGNAL":
            import time
            time.sleep(35)  # Force timeout
        elif "invalid syntax" in command or "function broken(" in command:
            response = {
                "id": request_id,
                "success": False,
                "error": "SyntaxError: Unexpected token"
            }
        else:
            # Return a simple AST representation
            ast = {
                "type": "Program",
                "body": [{
                    "type": "FunctionDeclaration",
                    "id": {"type": "Identifier", "name": "test"},
                    "body": {"type": "BlockStatement", "body": []}
                }]
            }
            response = {
                "id": request_id,
                "success": True,
                "ast": ast
            }
            
        print(json.dumps(response))
        
    except json.JSONDecodeError:
        # Handle raw input for backward compatibility
        code = request.strip()
        if "invalid syntax" in code or "function broken(" in code:
            print(json.dumps({"success": False, "error": "SyntaxError: Unexpected token"}))
        else:
            ast = {
                "type": "Program",
                "body": [{
                    "type": "FunctionDeclaration",
                    "id": {"type": "Identifier", "name": "test"},
                    "body": {"type": "BlockStatement", "body": []}
                }]
            }
            print(json.dumps({"success": True, "ast": ast}))

def main():
    for line in sys.stdin:
        line = line.strip()
        if line:
            handle_request(line)

if __name__ == "__main__":
    main()