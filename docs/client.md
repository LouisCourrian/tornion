# Client guide

[← back to README](../README.md)

`tornion.client` is a thin, opinionated wrapper around `requests` that
auto-routes traffic through Tor. Use it like you'd use `requests`.

## Table of contents

- [Module-level helpers](#module-level-helpers)
- [Reusable Session](#reusable-session)
- [Async client](#async-client)
- [Authentication, headers, cookies](#authentication-headers-cookies)
- [Smart tor reuse](#smart-tor-reuse)
- [Timeouts & retries](#timeouts--retries)
- [Drop-in into other libraries](#drop-in-into-other-libraries)
- [Error handling](#error-handling)
- [Performance tips](#performance-tips)

---

## Module-level helpers

The simplest case — fire-and-forget calls. tor is auto-started on first
call, killed at process exit.

```python
from tornion import client

r = client.get("http://xxx.onion/ping")
r.raise_for_status()
print(r.json())

client.post("http://xxx.onion/items", json={"name": "foo"})
client.put("http://xxx.onion/items/1", json={"name": "bar"})
client.delete("http://xxx.onion/items/1")
```

Available verbs: `get`, `post`, `put`, `delete`, `head`, `patch`, `options`,
plus the generic `client.request(method, url, **kwargs)`.

These all share a single internal `Session`, so the Tor circuit and TCP
connections are reused across calls.

## Reusable Session

When you need to bundle multiple requests as one logical unit (e.g. cookies
that should persist, custom headers everywhere, lifecycle control):

```python
from tornion import client

with client.Session() as s:
    s.headers["User-Agent"] = "my-app/1.0"
    s.get("http://xxx.onion/login")
    s.post("http://xxx.onion/items", json={...})
    s.get("http://xxx.onion/items")
```

`client.Session` is a real subclass of `requests.Session` — anything that
works with `requests.Session` works here.

## Async client

For high concurrency (100+ simultaneous `.onion` calls), use the async client.
It's the `httpx.AsyncClient`-style counterpart of the sync `requests`-style
API and routes through the **same** Tor process.

It's an opt-in extra so the base client stays lightweight:

```bash
pip install tornion[async]
```

```python
import asyncio
from tornion import client

async def main():
    async with client.AsyncSession() as s:
        r = await s.get("http://xxx.onion/ping")
        r.raise_for_status()
        print(r.json())

        # Fan out — all share one Tor circuit and connection pool.
        results = await asyncio.gather(
            *(s.get(f"http://xxx.onion/item/{i}") for i in range(100))
        )

asyncio.run(main())
```

`client.AsyncSession` is a real subclass of `httpx.AsyncClient` — anything that
works with `httpx.AsyncClient` works here (streaming, `auth`, `limits`, …). It
takes the same tornion options as the sync `Session`:

```python
client.AsyncSession(
    timeout=60,                  # default request timeout (s)
    auto_install=True,           # download tor if missing
    bootstrap_timeout=90,        # max wait for tor bootstrap (s)
    retries=3,                   # retries on 502/503/504
    use_existing=True,           # reuse running tor on :9050/:9150
)
```

The constructor starts (or reuses) the shared tor process — a **blocking**
operation the first time tor bootstraps. Inside an event loop, prefer the
`create()` async constructor, which does that startup in a worker thread so
the loop is never blocked:

```python
s = await client.AsyncSession.create(timeout=30)
try:
    r = await s.get("http://xxx.onion/ping")
finally:
    await s.aclose()
```

Module-level helpers mirror the sync ones, prefixed with `a`:

```python
from tornion import client

r = await client.aget("http://xxx.onion/ping")
await client.apost("http://xxx.onion/items", json={"name": "foo"})
```

Available: `aget`, `apost`, `aput`, `adelete`, `ahead`, `apatch`, `aoptions`,
plus the generic `client.arequest(method, url, **kwargs)`. They share one
internal `AsyncSession`. The bare module-level helpers don't close that session
for you — for deterministic cleanup, prefer `async with client.AsyncSession()`.

### Session options

```python
client.Session(
    timeout=60,                  # default request timeout (s)
    auto_install=True,           # download tor if missing
    bootstrap_timeout=90,        # max wait for tor bootstrap (s)
    retries=3,                   # retries on 502/503/504
    use_existing=True,           # reuse running tor on :9050/:9150
)
```

## Authentication, headers, cookies

Standard `requests` patterns:

```python
from tornion import client

# Bearer token
client.get("http://xxx.onion/me",
           headers={"Authorization": "Bearer eyJ..."})

# Basic auth
from requests.auth import HTTPBasicAuth
client.get("http://xxx.onion/admin",
           auth=HTTPBasicAuth("user", "pass"))

# Cookies persist across calls in a Session
with client.Session() as s:
    s.post("http://xxx.onion/login", json={"user": "x", "pw": "y"})
    s.get("http://xxx.onion/dashboard")  # cookie sent automatically
```

## Smart tor reuse

By default, `tornion.client` tries to **reuse an already-running tor** before
spawning a new one. It probes (in order):

1. `$TORNION_SOCKS_PORT` if set
2. `127.0.0.1:9050` (system tor service from `apt`/`brew install tor`)
3. `127.0.0.1:9150` (Tor Browser)

If any of these answers a real SOCKS5 handshake, that proxy is reused.
**No subprocess is spawned, no atexit cleanup is registered.**

To force isolation (always a fresh tor process):

```python
client.Session(use_existing=False)
```

To inspect what would happen without starting anything:

```python
import tornion

port = tornion.detect_running_tor()  # → 9050 / 9150 / None
```

## Timeouts & retries

Tor is slow. The first call in a process pays a 10–30s bootstrap cost.
Subsequent calls are ~500ms–2s in steady state.

```python
# Default timeout for every request from this Session
with client.Session(timeout=30) as s:
    r = s.get("http://xxx.onion/slow")     # 30s timeout
    r = s.get("http://xxx.onion/fast", timeout=5)  # override per-call
```

Retries on transient gateway errors (502/503/504) are enabled by default
(3 attempts, exponential backoff). Disable or tune:

```python
client.Session(retries=0)   # no retry
client.Session(retries=5)   # more aggressive
```

## Drop-in into other libraries

Anything that accepts a `requests.Session` accepts `client.Session`:

```python
from tornion import client
import some_lib

s = client.Session()
some_lib.do_stuff(session=s)   # works
```

Example with the `httpx-style` adapter pattern in any custom code:

```python
def fetch(url: str, *, session=None):
    s = session or client.Session()
    return s.get(url).json()

# Caller passes a tornion session, the function doesn't care.
fetch("http://xxx.onion/", session=client.Session())
```

## Error handling

```python
import tornion
from tornion import client

try:
    r = client.get("http://xxx.onion/")
except tornion.TorBootstrapError as e:
    # tor failed to bootstrap (timeout, port conflict, missing binary)
    ...
except tornion.TorBinaryNotFound as e:
    # No tor binary found and auto-install disabled
    ...
except requests.exceptions.ConnectionError as e:
    # The .onion was unreachable (or tor circuit failed)
    ...
except requests.exceptions.Timeout as e:
    # Request timed out
    ...
```

All `tornion` exceptions inherit from `tornion.OnionError`, so:

```python
try:
    client.get("...")
except tornion.OnionError:
    # any tornion-specific failure
    pass
```

## Performance tips

1. **Reuse a Session.** Each new `client.Session()` reuses the same global
   tor process, but creating one Session per call still wastes the connection
   pool. Bundle related calls.

2. **Run a system tor.** A persistent `apt install tor` + `systemctl start
   tor` saves the 20s bootstrap on every script invocation. `tornion`
   auto-detects it.

3. **For massive parallelism, use the async client.** For 100+ concurrent
   `.onion` calls, reach for [`client.AsyncSession`](#async-client) instead of
   the sync `Session` — it's `httpx.AsyncClient` over the same Tor proxy, with
   tor management handled for you:

   ```python
   import asyncio
   from tornion import client

   async with client.AsyncSession(timeout=30) as s:
       results = await asyncio.gather(
           *(s.get("http://xxx.onion/") for _ in range(100))
       )
   ```

   Install it with `pip install tornion[async]`.
