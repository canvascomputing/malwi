#!/usr/bin/env python3
"""Recursive Python test fixture for stack depth testing."""


def recurse(n):
    """Recursively call self n times, then return."""
    if n <= 0:
        return 0
    return recurse(n - 1) + 1


if __name__ == "__main__":
    result = recurse(100)
    print(f"recurse: {result}")
