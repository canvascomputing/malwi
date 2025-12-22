#!/usr/bin/env python3
"""
trace_python.py - Example script for demonstrating Python function tracing

Trace specific functions:
    ../malwi x -c py:calculate -c py:process_data python3 trace_python.py

Trace with stack traces:
    ../malwi x -t -c py:calculate python3 trace_python.py

Trace all functions:
    ../malwi x -c 'py:*' python3 trace_python.py
"""

import marshal


def calculate(a: int, b: int) -> int:
    """Perform a calculation."""
    return a + b


def process_data(items: list) -> list:
    """Process a list of items by doubling each value."""
    return [calculate(x, x) for x in items]


def main():
    # Basic calculation
    result = calculate(5, 3)
    print(f"calculate(5, 3) = {result}")

    # Process some data
    data = [1, 2, 3, 4, 5]
    processed = process_data(data)
    print(f"process_data({data}) = {processed}")

    # Also test marshal (C extension) for stack trace testing
    encoded = marshal.dumps(data)
    decoded = marshal.loads(encoded)
    print(f"Marshal round-trip: {decoded}")


if __name__ == "__main__":
    main()
