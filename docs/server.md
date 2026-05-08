# Server guide

[← back to README](../README.md)

`tornion.server` publishes any ASGI or WSGI app on a Tor hidden service
with a single function call. No `torrc`, no Docker, no manual key
management.

> Server features require the `[server]` extras: `pip install tornion[server]`

## Table of contents

- [Quick start](#quick-start)
- [Supported frameworks](#supported-frameworks)
- [Persistent .onion address](#persistent-onion-address)
- [Vanity addresses](#vanity-addresses)
- [Programmatic control: HiddenService](#programmatic-control-hiddenservice)
- [CLI: `tornion serve`](#cli-tornion-serve)
- [Production considerations](#production-considerations)
- [Hybrid: server + outbound calls](#hybrid-server--outbound-calls)
- [Error handling](#error-handling)

---

## Quick start

```python
from fastapi import FastAPI
from tornion import server

app = FastAPI()

@app.get("/")
def root():
    return {"hello": "from .onion"}

if __name__ == "__main__":
    server.serve(app)
```

Run it:

```bash
$ python myapp.py
🧅 starting tor...
   Bootstrapped 100% (done): Done

🚀 hidden service published:
   http://abc123def456ghi789jkl012mno345pqr678stu901vwxyz234abcdef.onion

   key persisted at: /home/user/.local/share/tornion/hs/FastAPI
   local port      : 47832

Press Ctrl+C to stop.
```

The `.onion` URL is yours. It's reachable from any Tor Browser or any
`tornion.client.get(...)`.

## Supported frameworks

`server.serve()` auto-detects ASGI and WSGI apps. WSGI is automatically
wrapped via `asgiref.wsgi.WsgiToAsgi`.

### ASGI (native)

```python
# FastAPI
from fastapi import FastAPI
app = FastAPI()
server.serve(app)

# Starlette
from starlette.applications import Starlette
app = Starlette(...)
server.serve(app)

# Quart (Flask async)
from quart import Quart
app = Quart(__name__)
server.serve(app)

# Litestar
from litestar import Litestar
app = Litestar(...)
server.serve(app)

# Plain ASGI 3 callable
async def app(scope, receive, send):
    if scope["type"] == "http":
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"hello"})

server.serve(app)
```

### WSGI (auto-wrapped)

```python
# Flask
from flask import Flask
app = Flask(__name__)
@app.route("/")
def hello(): return {"ok": True}
server.serve(app)

# Django
from django.core.wsgi import get_wsgi_application
app = get_wsgi_application()
server.serve(app)

# Bottle, Pyramid, web2py, CherryPy… same pattern
```

## Persistent `.onion` address

Tor hidden services v3 are identified by their **ed25519 public key**.
The address `xxxxxxx.onion` IS the encoded public key. So:

- **Same key on disk → same `.onion` address across restarts.**
- **Lose the key → new address.**

By default, `tornion` stores the key under:

| OS | Path |
|---|---|
| Linux | `~/.local/share/tornion/hs/<app_name>/` |
| macOS | `~/Library/Application Support/tornion/hs/<app_name>/` |
| Windows | `%APPDATA%\tornion\hs\<app_name>\` |

Override with `key_dir`:

```python
server.serve(app, key_dir="./my-onion-keys")
```

### Provide a fixed key (deterministic seed)

If you want to choose the key yourself — for example to keep the same
`.onion` across machines without copying files, or to derive it from a
secret you already control — drop a `hs_ed25519_secret_key` file into the
`key_dir` *before* the first run. Tor regenerates `hs_ed25519_public_key`
and `hostname` from it on startup, so those two files are optional.

The file format is strict: a 32-byte header followed by the ed25519
*expanded* secret key (SHA-512 of the seed, with the standard bit
clamping). Random bytes won't work — tor will reject the file.

```python
"""generate_key.py — run once to create a fixed onion identity."""
import hashlib
from pathlib import Path

# 32-byte seed. Replace with os.urandom(32) for real use, then store the
# result somewhere safe (password manager, vault, …). A literal seed like
# this one is fine for demos but provides zero secrecy.
seed = b"my-fake-seed-do-not-use-in-prod!"
assert len(seed) == 32

# ed25519 expansion: SHA-512(seed) → 64 bytes, then clamp per RFC 8032 §5.1.5
# so the result is a valid scalar on Curve25519.
h = bytearray(hashlib.sha512(seed).digest())
h[0]  &= 248   # clear the bottom 3 bits     (multiple of cofactor 8)
h[31] &= 127   # clear the top bit           (scalar < 2^254)
h[31] |= 64    # set the 2nd-top bit         (scalar ≥ 2^254)

# Tor hidden service v3 key file layout (rend-spec-v3.txt §6):
#   [ 32-byte ASCII header ] [ 64-byte expanded secret key ]
header   = b"== ed25519v1-secret: type0 ==\x00\x00\x00"  # 32 bytes
key_blob = header + bytes(h)                              # 96 bytes total

key_dir = Path("onion-key")
key_dir.mkdir(exist_ok=True)
(key_dir / "hs_ed25519_secret_key").write_bytes(key_blob)
print(f"key written to {key_dir.resolve()}")
```

Then point your app at it:

```python
from fastapi import FastAPI
from tornion import server

app = FastAPI(title="my-api", docs_url=None, redoc_url=None)

@app.get("/ping")
def ping():
    return {"pong": True}

if __name__ == "__main__":
    # Same seed → same key → same .onion, on any machine.
    server.serve(app, key_dir="./onion-key")
```

> ⚠️ The `.onion` is only as secret as the seed. A literal seed in source
> code means anyone with the code can impersonate your service. For real
> deployments, generate the seed once with `os.urandom(32)` and store it
> in a secrets manager or environment variable.

### Backup the key

The key dir contains:
- `hs_ed25519_secret_key` ← the identity. Treat like an SSH private key.
- `hs_ed25519_public_key`
- `hostname` (the .onion address itself, derivable from the public key)

Backup recommendation:

```bash
tar czf - -C ~/.local/share/tornion/hs/myapp . \
  | gpg --symmetric --cipher-algo AES256 \
  > backup-onion-$(date +%F).tar.gz.gpg
```

Restore:

```bash
mkdir -p ~/.local/share/tornion/hs/myapp
gpg -d backup-onion-2026-01-15.tar.gz.gpg \
  | tar xz -C ~/.local/share/tornion/hs/myapp
chmod 700 ~/.local/share/tornion/hs/myapp
chmod 600 ~/.local/share/tornion/hs/myapp/hs_ed25519_*
```

## Vanity addresses

To get an address starting with a chosen prefix (e.g. `myapi...`), use
[`mkp224o`](https://github.com/cathugger/mkp224o):

```bash
mkdir vanity
mkp224o -d vanity -n 1 myapi
# → vanity/myapixxx.../hostname
#   vanity/myapixxx.../hs_ed25519_secret_key
#   vanity/myapixxx.../hs_ed25519_public_key
```

Then point `key_dir` at the generated folder:

```python
server.serve(app, key_dir="./vanity/myapixxx...")
```

> ⚠️ Vanity computation is exponential in the prefix length. 6 chars takes
> minutes; 8 chars takes days; 10+ chars is impractical on commodity
> hardware. See `mkp224o`'s README.

## Programmatic control: HiddenService

If you want to manage the HTTP server yourself (custom uvicorn config,
gunicorn, hypercorn, your own loop), use `HiddenService` directly:

```python
from tornion import server

with server.HiddenService(target_port=8000, app_name="myapi") as hs:
    print(f"Available at: {hs.onion_url}")
    
    # Now run your HTTP server on :8000 however you want.
    # tor will forward .onion:80 → 127.0.0.1:8000 traffic.
    
    import uvicorn
    uvicorn.run(my_app, host="127.0.0.1", port=8000)
```

The context manager kills tor on exit. For long-running daemons, use
`hs.start()` / `hs.stop()` directly.

### HiddenService options

```python
server.HiddenService(
    target_port=8000,            # local port your HTTP server listens on
    target_host="127.0.0.1",     # local interface
    key_dir="./hs",              # where to store the .onion key
    app_name="default",          # used to derive default key_dir
    bootstrap_timeout=90,        # max wait for tor bootstrap (s)
    auto_install=True,           # download tor if missing
    verbose=False,               # stream tor's NOTICE-level logs
    onion_port=80,               # public port advertised on the .onion
)
```

## CLI: `tornion serve`

For when you'd use `uvicorn myapp:app`:

```bash
tornion serve myapp:app
tornion serve myapp:app --key-dir ./hs --log-level info
tornion serve myapp:app --name myapi --bootstrap-timeout 120
```

The app spec format is `module:attribute`, same as uvicorn/gunicorn.

## Production considerations

### 1. Disable framework introspection endpoints

By default FastAPI exposes `/docs`, `/redoc`, `/openapi.json`. On a public
`.onion`, this leaks your full API schema to anyone who finds the address.

```python
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
```

### 2. Don't add HTTPS

Tor already encrypts end-to-end between client and your hidden service.
Putting TLS on top buys you nothing and complicates the setup (cert
issuance for `.onion` is a niche thing).

### 3. IP addresses in logs are useless

Every request appears to come from `127.0.0.1` (the tor process). You
can't rate-limit by IP, geolocate users, or do any source-based logic.
Use authentication (cookies, tokens, client auth keys) instead.

### 4. Process supervision

`tornion.server.serve()` blocks. For production, run it under `systemd`,
`supervisor`, `pm2`, or in a Docker container with a restart policy. tor
and uvicorn both die together on exit.

Example systemd unit:

```ini
[Unit]
Description=My .onion API
After=network.target

[Service]
Type=simple
User=myapp
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/.venv/bin/python myapp.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 5. Resource limits

By default `tornion` configures tor with `MaxMemInQueues 256 MB`. If your
hidden service handles heavy traffic, you may want to override via custom
torrc — for now this requires using the lower-level
`tornion._tor.launch_tor_for_hidden_service()`.

## Hybrid: server + outbound calls

Both submodules in the same process:

```python
from fastapi import FastAPI
from tornion import client, server

app = FastAPI()

@app.get("/relay")
def relay(target: str):
    """Forwards a GET to another .onion."""
    r = client.get(target, timeout=30)
    return {"upstream_status": r.status_code, "body": r.json()}

server.serve(app)
```

Two independent tor processes are spawned: one as SOCKS client, one as
hidden service host. They share the same on-disk binary and cache.

## Error handling

```python
import tornion
from tornion import server

try:
    server.serve(app)
except tornion.UnsupportedAppError:
    # The app couldn't be classified as ASGI or WSGI
    ...
except tornion.HiddenServiceError:
    # Tor started but didn't publish a hostname in time
    ...
except tornion.TorBootstrapError:
    # Tor itself failed to start (port conflict, bad config, killed)
    ...
except tornion.TorBinaryNotFound:
    # No tor binary and auto-install disabled
    ...
except ImportError:
    # uvicorn or asgiref not installed → install tornion[server]
    ...
```
