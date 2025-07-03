#!/usr/bin/env python3
"""Parser that consumes excessive CPU."""

import sys
import json

while True:
    line = sys.stdin.readline()
    if not line:
        break
        
    request = json.loads(line.strip())
    
    if request.get("command") == "INFINITE_LOOP":
        # Infinite CPU loop
        while True:
            pass
    else:
        response = {"id": request.get("id"), "result": "ok"}
        print(json.dumps(response))
        sys.stdout.flush()