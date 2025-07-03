#!/usr/bin/env python3
"""Parser that crashes on specific input."""

import sys
import json

while True:
    line = sys.stdin.readline()
    if not line:
        break
    
    request = json.loads(line.strip())
    
    if request.get("command") == "CRASH_NOW":
        # Simulate crash
        raise RuntimeError("Intentional crash for testing")
    else:
        response = {"id": request.get("id"), "result": "ok"}
        print(json.dumps(response))
        sys.stdout.flush()