"""Publish a Flask (WSGI) app on a Tor hidden service.

Demonstrates that tornion is framework-agnostic — the WSGI app is
auto-wrapped to ASGI under the hood via asgiref.

    pip install tornion[server] flask
    python examples/server_flask.py
"""
from flask import Flask, jsonify

from tornion import server

app = Flask(__name__)


@app.route("/")
def root():
    return jsonify(service="flask-on-tor", framework="flask")


@app.route("/ping")
def ping():
    return jsonify(message="pong")


if __name__ == "__main__":
    server.serve(app)
