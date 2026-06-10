"""Async client — many concurrent .onion calls over one Tor circuit.

Requires the async extra:

    pip install tornion[async]

Then:

    export ONION_URL=http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion
    python examples/client_async.py
"""
import asyncio
import os
import time

from tornion import client

URL = os.environ.get("ONION_URL", "http://CHANGE-ME.onion")
if "CHANGE-ME" in URL:
    raise SystemExit("Set ONION_URL first.")


async def main() -> None:
    # `.create()` runs the one-time tor bootstrap off the event loop.
    async with await client.AsyncSession.create(timeout=30) as s:
        t0 = time.monotonic()
        r1 = await s.get(f"{URL}/ping")
        print(f"1st call (bootstrap): {r1.status_code} in {time.monotonic() - t0:.2f}s")

        # Fire 10 requests concurrently over the shared circuit.
        t0 = time.monotonic()
        results = await asyncio.gather(
            *(s.get(f"{URL}/ping") for _ in range(10))
        )
        codes = [r.status_code for r in results]
        print(f"10 concurrent calls: {codes} in {time.monotonic() - t0:.2f}s")

    # Module-level helpers also work (they share one internal session):
    r = await client.aget(f"{URL}/ping")
    print(f"module-level aget: {r.status_code}")


if __name__ == "__main__":
    asyncio.run(main())

print("\n✅ done")
