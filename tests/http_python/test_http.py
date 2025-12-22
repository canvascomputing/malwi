"""HTTP library test script for malwi integration tests.

Each function makes one HTTP request using a specific library.
The target URL is passed as the first argument (typically a local test server).

Usage: python test_http.py <url> <library>
  library: stdlib | requests | httpx | aiohttp | urllib3
"""
import sys


def test_stdlib(url):
    """Test http.client (standard library)."""
    import http.client
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(host, port)
    else:
        conn = http.client.HTTPConnection(host, port)

    conn.request("GET", parsed.path or "/")
    response = conn.getresponse()
    response.read()
    conn.close()
    print(f"stdlib: {response.status}")


def test_urllib(url):
    """Test urllib.request (standard library)."""
    import urllib.request
    resp = urllib.request.urlopen(url)
    resp.read()
    print(f"urllib: {resp.status}")


def test_requests(url):
    """Test requests library."""
    import requests
    resp = requests.get(url)
    print(f"requests: {resp.status_code}")


def test_requests_post(url):
    """Test requests.post with JSON body."""
    import requests
    resp = requests.post(url, json={"key": "value"})
    print(f"requests.post: {resp.status_code}")


def test_httpx(url):
    """Test httpx library."""
    import httpx
    resp = httpx.get(url)
    print(f"httpx: {resp.status_code}")


def test_aiohttp(url):
    """Test aiohttp library."""
    import aiohttp
    import asyncio

    async def fetch():
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                await resp.text()
                print(f"aiohttp: {resp.status}")

    asyncio.run(fetch())


def test_urllib3(url):
    """Test urllib3 library."""
    import urllib3
    pool = urllib3.PoolManager()
    resp = pool.request("GET", url)
    print(f"urllib3: {resp.status}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <library>")
        sys.exit(1)

    url = sys.argv[1]
    library = sys.argv[2]

    dispatch = {
        "stdlib": test_stdlib,
        "urllib": test_urllib,
        "requests": test_requests,
        "requests_post": test_requests_post,
        "httpx": test_httpx,
        "aiohttp": test_aiohttp,
        "urllib3": test_urllib3,
    }

    if library not in dispatch:
        print(f"Unknown library: {library}")
        sys.exit(1)

    dispatch[library](url)
