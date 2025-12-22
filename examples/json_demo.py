#!/usr/bin/env python3
"""
json_demo.py - Example showing JSON function tracing

Trace json:     ../malwi x -c 'py:json.*' python3 json_demo.py
With stack:     ../malwi x -t -c 'py:json.*' python3 json_demo.py
Trace marshal:  ../malwi x -t -c py:marshal.loads python3 json_demo.py
"""

import json
import marshal


def parse_config(config_str: str) -> dict:
    """Parse JSON configuration."""
    return json.loads(config_str)


def save_config(config: dict) -> str:
    """Save configuration to JSON string."""
    return json.dumps(config, indent=2)


def process_data(data: list) -> list:
    """Process a list of items."""
    return [item * 2 for item in data]


def main():
    # Parse JSON
    config = parse_config('{"name": "example", "version": 1}')
    print(f"Loaded config: {config}")

    # Modify and save
    config["processed"] = True
    output = save_config(config)
    print(f"Saved config:\n{output}")

    # Process data through JSON round-trip
    data = [1, 2, 3, 4, 5]
    json_data = json.dumps(data)
    loaded_data = json.loads(json_data)
    result = process_data(loaded_data)
    print(f"Processed data: {result}")

    # Marshal example (C extension)
    serialized = marshal.dumps(data)
    restored = marshal.loads(serialized)
    print(f"Marshal round-trip: {restored}")


if __name__ == "__main__":
    main()
