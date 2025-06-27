#!/usr/bin/env python3
"""Parser that fails health checks."""

import sys
import json

while True:
    line = sys.stdin.readline()
    if not line:
        break
        
    request = json.loads(line.strip())
    
    if request.get("command") == "HEALTH_CHECK":
        # Always report unhealthy
        response = {"id": request.get("id"), "status": "unhealthy", "error": "simulated failure"}
    else:
        response = {"id": request.get("id"), "result": "ok"}
    
    print(json.dumps(response))
    sys.stdout.flush()