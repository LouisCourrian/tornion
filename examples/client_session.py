"""Reusable Session with multiple calls — circuit reuse demo.

    export ONION_URL=http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion
    python examples/client_session.py
"""
import os
import time

from tornion import client

URL = os.environ.get("ONION_URL", "http://CHANGE-ME.onion")
if "CHANGE-ME" in URL:
    raise SystemExit("Set ONION_URL first.")

with client.Session(timeout=30) as s:
    t0 = time.monotonic()
    r1 = s.get(f"{URL}/ping")
    print(f"1st call (bootstrap): {r1.status_code} in {time.monotonic() - t0:.2f}s")

    for i in range(5):
        t0 = time.monotonic()
        r = s.get(f"{URL}/ping")
        print(f"  call {i + 2}: {r.status_code} in {time.monotonic() - t0:.2f}s")

    # Mix of methods
    s.post(f"{URL}/items", json={"name": "demo"})

print("\n✅ done")
