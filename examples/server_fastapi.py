"""Publish a FastAPI app on a Tor hidden service.

    pip install tornion[server] fastapi
    python examples/server_fastapi.py
"""
from fastapi import FastAPI

from tornion import server

app = FastAPI(title="my-onion-api", docs_url=None, redoc_url=None)


@app.get("/")
def root():
    return {"service": "fastapi-on-tor", "framework": "fastapi"}


@app.get("/ping")
def ping():
    return {"message": "pong"}


@app.post("/echo")
def echo(payload: dict):
    return {"received": payload}


if __name__ == "__main__":
    # Blocks until Ctrl+C; prints the .onion address on startup.
    server.serve(app)
