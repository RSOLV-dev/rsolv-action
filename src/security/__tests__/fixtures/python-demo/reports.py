"""Line counts for report files. Deliberately vulnerable: shell=True with
interpolated input (CWE-78)."""
import subprocess


def line_count(filename):
    result = subprocess.run(f"wc -l < {filename}", shell=True, capture_output=True, text=True)
    return int(result.stdout.strip() or 0)
