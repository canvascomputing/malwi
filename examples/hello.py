#!/usr/bin/env python3
"""
hello.py - Simple example for Python function tracing

Trace:   ../malwi x -c py:greet python3 hello.py
Stack:   ../malwi x -t -c py:greet python3 hello.py
All:     ../malwi x -c 'py:*' python3 hello.py
"""

import sys


def greet(name: str) -> str:
    """Generate a greeting message."""
    return format_message(name)


def format_message(name: str) -> str:
    """Format the greeting."""
    return f"Hello, {name}!"


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "World"
    message = greet(name)
    print(message)


if __name__ == "__main__":
    main()
