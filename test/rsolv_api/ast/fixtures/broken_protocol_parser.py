#!/usr/bin/env python3
"""Parser that sends malformed responses."""

import sys

while True:
    line = sys.stdin.readline()
    if not line:
        break
    
    # Send invalid JSON
    print("This is not valid JSON{{{")
    sys.stdout.flush()