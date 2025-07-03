#!/usr/bin/env python3
"""Mock Python parser for testing Port supervision."""

import sys
import json
import time

def main():
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
                
            request = json.loads(line.strip())
            
            # Handle different test commands
            if request.get("command") == "CRASH_NOW":
                sys.exit(1)
            elif request.get("command") == "HEALTH_CHECK":
                response = {"status": "healthy", "id": request.get("id")}
            elif request.get("command") == "parse":
                # Simulate AST parsing
                response = {
                    "id": request.get("id"),
                    "result": {
                        "ast": {"type": "Program", "body": []},
                        "language": "python",
                        "parser_version": "1.0.0"
                    }
                }
            else:
                response = {
                    "id": request.get("id"),
                    "result": {"echo": request.get("command", "unknown")}
                }
            
            # Send response
            print(json.dumps(response))
            sys.stdout.flush()
            
        except Exception as e:
            error_response = {
                "id": request.get("id") if 'request' in locals() else None,
                "error": str(e)
            }
            print(json.dumps(error_response))
            sys.stdout.flush()

if __name__ == "__main__":
    main()