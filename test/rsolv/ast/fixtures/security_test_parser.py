#!/usr/bin/env python3
"""Parser for testing security restrictions."""

import sys
import json
import os
import socket

# Check if security restrictions are enabled (simulated for testing)
read_only_fs = os.environ.get("SECURITY_READ_ONLY_FS") == "true"
no_network = os.environ.get("SECURITY_NO_NETWORK") == "true"

while True:
    line = sys.stdin.readline()
    if not line:
        break
        
    request = json.loads(line.strip())
    
    if request.get("command") == "WRITE_FILE":
        if read_only_fs:
            response = {"id": request.get("id"), "error": "permission_denied"}
        else:
            try:
                with open("/tmp/test.txt", "w") as f:
                    f.write("test")
                response = {"id": request.get("id"), "result": "success"}
            except Exception as e:
                response = {"id": request.get("id"), "error": "permission_denied"}
            
    elif request.get("command") == "NETWORK_REQUEST":
        if no_network:
            response = {"id": request.get("id"), "error": "network_disabled"}
        else:
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                response = {"id": request.get("id"), "result": "success"}
            except Exception as e:
                response = {"id": request.get("id"), "error": "network_disabled"}
    else:
        response = {"id": request.get("id"), "result": "ok"}
    
    print(json.dumps(response))
    sys.stdout.flush()