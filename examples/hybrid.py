"""Hybrid example: a server that also makes outbound .onion calls.

Showcases both submodules in the same process. The same tor binary
is launched twice — once for the hidden service (server-side) and once
as a SOCKS client — but they're independent processes.

    pip install tornion[server] fastapi
    python examples/hybrid.py
"""
from fastapi import FastAPI

from tornion import client, server

app = FastAPI(docs_url=None, redoc_url=None)


@app.get("/")
def root():
    return {"role": "proxy"}


@app.get("/relay")
def relay(target: str):
    """Forwards a GET to another .onion and returns the JSON.

    Example: GET /relay?target=http://other.onion/ping
    """
    r = client.get(target, timeout=30)
    return {"upstream_status": r.status_code, "body": r.json()}


if __name__ == "__main__":
    server.serve(app, app_name="hybrid-relay")
