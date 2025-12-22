#!/usr/bin/env python3
"""
Cross-runtime tracing test.

This script demonstrates tracing across Python, Node.js, and native code:
1. Python function is called and traced (py:traced_python_entry)
2. Python calls native open() which is traced
3. Python spawns Node.js subprocess
4. Node.js function is traced (js:traced_js_entry)
5. Node.js calls native fs.readFileSync which triggers native calls
"""

import subprocess
import sys
import os

def traced_python_entry(message):
    """A Python function that will be traced."""
    print(f"Python: {message}")
    return nested_python_call()

def nested_python_call():
    """Nested Python call to demonstrate call hierarchy."""
    # Make a native call via Python's open() - use /etc/passwd which exists on all Unix
    with open('/etc/passwd', 'r') as f:
        # Just read first line to keep output small
        content = f.readline().strip()
    print(f"Python: Read first line of /etc/passwd")
    return content

def spawn_nodejs_child(script_path, arg):
    """Spawn Node.js child process."""
    print(f"Python: Spawning Node.js with arg: {arg}")

    # Find node executable
    node_path = 'node'

    result = subprocess.run(
        [node_path, script_path, arg],
        capture_output=True,
        text=True
    )

    # Print child output
    if result.stdout:
        for line in result.stdout.strip().split('\n'):
            print(f"  [child] {line}")
    if result.stderr:
        for line in result.stderr.strip().split('\n'):
            print(f"  [child stderr] {line}")

    return result.returncode

def main():
    print("=== Cross-Runtime Tracing Test ===")

    # Step 1: Call Python function (traced)
    traced_python_entry("Starting cross-runtime test")

    # Step 2: Spawn Node.js child (child will be traced too)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    child_script = os.path.join(script_dir, 'test_cross_runtime_child.js')

    ret = spawn_nodejs_child(child_script, "from_python")

    # Step 3: Another Python call after child returns
    traced_python_entry("After Node.js child returned")

    print("=== Test Complete ===")
    return ret

if __name__ == '__main__':
    sys.exit(main())
