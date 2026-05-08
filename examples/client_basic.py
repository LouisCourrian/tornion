"""Basic client: call a .onion API.

    export ONION_URL=http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion
    python examples/client_basic.py
"""
import os

from tornion import client

URL = os.environ.get("ONION_URL", "http://CHANGE-ME.onion")
if "CHANGE-ME" in URL:
    raise SystemExit("Set ONION_URL first.")

r = client.get(f"{URL}/ping")
r.raise_for_status()
print("pong:", r.json())
