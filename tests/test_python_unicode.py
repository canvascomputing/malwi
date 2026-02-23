#!/usr/bin/env python3
"""Unicode function name test fixture for Python tracing."""


def grüße():
    """Function with non-ASCII name (German: greetings)."""
    return 42


def подсчёт():
    """Function with Cyrillic name (Russian: counting)."""
    return 99


if __name__ == "__main__":
    result1 = grüße()
    print(f"grüße: {result1}")
    result2 = подсчёт()
    print(f"подсчёт: {result2}")
