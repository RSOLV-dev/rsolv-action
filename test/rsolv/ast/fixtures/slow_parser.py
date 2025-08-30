#!/usr/bin/env python3
"""Parser that simulates slow operations without infinite loops."""

import sys
import json
import time

while True:
    line = sys.stdin.readline()
    if not line:
        break
        
    request = json.loads(line.strip())
    
    if request.get("command") == "SLEEP_200":
        # Sleep for 200ms - will timeout if operation_timeout < 200ms
        time.sleep(0.2)
        response = {"id": request.get("id"), "result": "completed_after_200ms"}
    elif request.get("command") == "SLEEP_50":
        # Sleep for 50ms - should complete within most timeouts
        time.sleep(0.05)
        response = {"id": request.get("id"), "result": "completed_after_50ms"}
    else:
        response = {"id": request.get("id"), "result": "ok"}
    
    print(json.dumps(response))
    sys.stdout.flush()