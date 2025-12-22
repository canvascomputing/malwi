#!/usr/bin/env python3
"""Python test fixture for function tracing."""

import json
import sys


def calculate(x, y):
    """Simple arithmetic function."""
    return x + y


def process_data(data):
    """Parse JSON data."""
    return json.loads(data)


def nested_outer():
    """Outer function that calls inner."""
    return nested_inner()


def nested_inner():
    """Inner function called by outer."""
    return 42


def main():
    """Run test functions."""
    # Test single function
    result1 = calculate(10, 20)
    print(f"calculate: {result1}")

    # Test module function (json.loads)
    result2 = process_data('{"key": "value"}')
    print(f"process_data: {result2}")

    # Test nested calls
    result3 = nested_outer()
    print(f"nested: {result3}")


if __name__ == "__main__":
    main()
