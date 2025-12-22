#!/usr/bin/env python3
"""
web_request.py - Example showing HTTP request tracing

Trace urllib:   ../malwi x -c 'py:urllib.*' python3 web_request.py
Trace socket:   ../malwi x -c 'py:socket.*' python3 web_request.py
Trace ssl:      ../malwi x -c 'py:ssl.*' python3 web_request.py
With stack:     ../malwi x -t -c 'py:urllib.request.*' python3 web_request.py
"""

import urllib.request
import json


def fetch_url(url: str) -> str:
    """Fetch content from a URL."""
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read().decode('utf-8')


def fetch_json(url: str) -> dict:
    """Fetch and parse JSON from a URL."""
    content = fetch_url(url)
    return json.loads(content)


def main():
    # Fetch a simple JSON endpoint
    url = "https://httpbin.org/json"
    print(f"Fetching: {url}")

    try:
        data = fetch_json(url)
        print(f"Response keys: {list(data.keys())}")
    except Exception as e:
        print(f"Error (expected if offline): {e}")

    # Also show local operations work
    print("\nLocal JSON operations:")
    local_data = json.dumps({"status": "ok", "offline": True})
    parsed = json.loads(local_data)
    print(f"Parsed: {parsed}")


if __name__ == "__main__":
    main()
