<div align="center">

# 🧅 tornion

**Tor hidden service toolkit for Python — drop-in client + zero-config server.**

[![PyPI version](https://img.shields.io/pypi/v/tornion.svg)](https://pypi.org/project/tornion/)
[![Python versions](https://img.shields.io/pypi/pyversions/tornion.svg)](https://pypi.org/project/tornion/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-21%20passed-brightgreen.svg)](tests/)

*Consume any `.onion` API, or publish your own — in 3 lines of Python.*

</div>

---

```python
from tornion import client, server

# Consume a .onion API
r = client.get("http://xxxxxxxxxxxxxx.onion/ping")

# Publish your own
from fastapi import FastAPI
app = FastAPI()
server.serve(app)
```

That's it. No Docker, no `torrc`, no manual tor install — `tornion` handles
everything: discovers or downloads the `tor` binary, spawns it, manages the
SOCKS proxy or the hidden service, and tears it down on exit.

## ✨ Features

- 🔌 **Drop-in `requests`** — `client.Session` is a real `requests.Session` subclass
- 🚀 **Zero-config server** — `server.serve(app)` takes any ASGI **or** WSGI app
- 🧠 **Smart tor reuse** — auto-detects an already-running tor on `:9050`/`:9150`
- 📦 **Auto-install tor** — downloads the official Tor Expert Bundle on first use
- 🎯 **Framework-agnostic** — FastAPI, Flask, Starlette, Django, Quart, Litestar…
- 🔑 **Persistent `.onion`** — the address stays stable across restarts
- 🪶 **Lightweight client** — server features are opt-in via `pip install tornion[server]`

## 📦 Installation

```bash
# Client only
pip install tornion

# With server features
pip install tornion[server]
```

## 🚀 Quick start

### Client — call a `.onion` API

```python
from tornion import client

r = client.get("http://xxx.onion/ping")
print(r.json())

# Reusable session for multiple calls
with client.Session() as s:
    s.post("http://xxx.onion/items", json={"name": "foo"})
    s.get("http://xxx.onion/items/1")
```

📖 **[Full client guide →](docs/client.md)**

### Server — publish your app on a `.onion`

```python
from fastapi import FastAPI
from tornion import server

app = FastAPI()

@app.get("/")
def root():
    return {"hello": "from .onion"}

server.serve(app)
```

When you run this, `tornion` prints the `.onion` URL and blocks until Ctrl+C.
Same code works with Flask, Starlette, Django, etc. — auto-detected.

📖 **[Full server guide →](docs/server.md)**

### Hybrid — server that also makes outbound calls

```python
from fastapi import FastAPI
from tornion import client, server

app = FastAPI()

@app.get("/relay")
def relay(target: str):
    r = client.get(target, timeout=30)
    return {"upstream": r.status_code, "body": r.json()}

server.serve(app)
```

## 🛠️ CLI

```bash
tornion install-tor              # pre-download the tor binary
tornion serve myapp:app          # uvicorn-style: run an app on a .onion
tornion get http://xxx.onion/    # one-shot HTTP request
tornion info                     # diagnostic: where's tor, what's installed
```

📖 **[Configuration & CLI reference →](docs/configuration.md)**

## 🔍 How does it actually work?

`tornion` orchestrates a real `tor` binary as a subprocess. Python doesn't
implement Tor — it uses the C reference implementation (`tor`) under the
hood, talks to it via SOCKS5 (client side) or the hidden-service API
(server side), and shuts it down on exit.

📖 **[Architecture & internals →](docs/internals.md)**

## 📚 Documentation

| Topic | Doc |
|---|---|
| Calling `.onion` APIs from Python | [docs/client.md](docs/client.md) |
| Publishing your app on a hidden service | [docs/server.md](docs/server.md) |
| Env vars, CLI, paths, diagnostic | [docs/configuration.md](docs/configuration.md) |
| Architecture, design choices, pitfalls | [docs/internals.md](docs/internals.md) |
| Examples (client / server / hybrid) | [examples/](examples/) |

## 🧪 Try it

```bash
git clone https://github.com/LouisCourrian/tornion
cd tornion
pip install -e ".[dev]"
pytest
python examples/server_fastapi.py
```

## 🚧 Status

`tornion` is in **alpha**. The public API is settling but may still shift
slightly before `1.0.0`. Pin to a minor version (`tornion>=0.5,<0.6`) in
production-ish code.

## 🗺️ Roadmap to 1.0

Required before tagging `1.0.0`:

- [x] **Stable `.onion` by default.** ~~Stop deriving `app_name` from
      `app.title` (fragile).~~ `app_name` now defaults to the entry-script
      basename (`python myserver.py` → `myserver`); `serve()` prints the
      resolved `key_dir` and a fresh-vs-existing identity status before
      tor bootstrap so the first run is never silent.
- [x] **Verify Tor Expert Bundle downloads.** SHA-256 pinning. Hashes
      live in `KNOWN_TOR_HASHES`, populated from the Tor Project's signed
      `sha256sums-signed-build.txt`. Unknown versions are refused unless
      the caller passes an explicit `sha256=...`. Mismatched archives are
      deleted before extraction.
- [ ] **`CHANGELOG.md` + written SemVer policy.** What counts as a
      breaking change, deprecation window, etc.
- [ ] **Publish `1.0.0` to PyPI.** Reserve the `tornion` name, set up
      a trusted-publisher GitHub Actions workflow (no API token in
      secrets), and tag the first stable release.

Quick wins (small, high-value):

- [ ] `tornion keygen [--out DIR]` — generate a fresh
      `hs_ed25519_secret_key` without spinning up tor.
- [ ] `tornion onion <key_dir>` — print the `.onion` address derived
      from an existing key dir, offline.
- [ ] `TORNION_KEY_DIR` env var, symmetric to `TORNION_TOR_PATH`.

Deferred to 1.x:

- [ ] Tor v3 client authorization (restrict who can reach your HS).
- [ ] Async client (`httpx.AsyncClient`-style) alongside the sync one.

## 📄 License

MIT — see [LICENSE](LICENSE).

`tornion` is an independent project, not affiliated with the Tor Project.
The bundled `tor` binary comes from [torproject.org](https://torproject.org/)
under 3-clause BSD.
