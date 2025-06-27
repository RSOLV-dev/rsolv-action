#!/usr/bin/env python3
"""Parser that consumes excessive memory."""

import sys
import json

memory_hog = []

while True:
    line = sys.stdin.readline()
    if not line:
        break
        
    request = json.loads(line.strip())
    
    if request.get("command") == "ALLOCATE_100MB":
        # Allocate 100MB of memory
        memory_hog.append(bytearray(100 * 1024 * 1024))
        response = {"id": request.get("id"), "result": "allocated"}
    else:
        response = {"id": request.get("id"), "result": "ok"}
    
    print(json.dumps(response))
    sys.stdout.flush()