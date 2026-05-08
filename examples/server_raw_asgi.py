"""Publish a raw ASGI 3 callable — no framework at all.

Demonstrates the lower bound: any async (scope, receive, send) callable works.

    pip install tornion[server]
    python examples/server_raw_asgi.py
"""
import json

from tornion import server


async def app(scope, receive, send):
    if scope["type"] != "http":
        return

    body = json.dumps({
        "framework": "none",
        "path": scope["path"],
    }).encode("utf-8")

    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({
        "type": "http.response.body",
        "body": body,
    })


if __name__ == "__main__":
    server.serve(app, app_name="raw-asgi")
