# Architecture & internals

[← back to README](../README.md)

For users who want to understand what `tornion` is doing under the hood,
or contribute to the codebase.

## Table of contents

- [The big picture](#the-big-picture)
- [Why a real `tor` binary?](#why-a-real-tor-binary)
- [Client architecture](#client-architecture)
- [Server architecture](#server-architecture)
- [Auto-install mechanism](#auto-install-mechanism)
- [Code layout](#code-layout)
- [Known limitations & pitfalls](#known-limitations--pitfalls)
- [Future work](#future-work)

---

## The big picture

```
                    ┌─────────────────────────────────────┐
                    │      tornion (single process)       │
                    │                                     │
   client side:     │   client.get(...)                   │
                    │       │                             │
                    │       ▼                             │
                    │   requests + PySocks ──┐            │
                    │                        │ SOCKS5     │
                    │                        ▼            │
                    │                   ┌─────────┐       │
                    │                   │   tor   │       │
                    │                   │ client  │       │
                    │                   │ process │       │
                    │                   └────┬────┘       │
                    │                        │            │
                    │                        ▼            │
                    │                  réseau Tor         │
                    │                        ▲            │
                    │                        │            │
                    │                   ┌─────────┐       │
                    │                   │   tor   │       │
                    │                   │   HS    │       │
                    │                   │ process │       │
                    │                   └────┬────┘       │
                    │                        │ HS port    │
                    │                        ▼            │
   server side:     │   uvicorn(app) ◄───────┘            │
                    │       │                             │
                    │       ▼                             │
                    │   ton FastAPI / Flask / ASGI / ...  │
                    └─────────────────────────────────────┘
```

`tornion` doesn't implement Tor in Python. It **orchestrates** the C
reference implementation as a subprocess, communicating via:

- **SOCKS5** for the client side (Python opens TCP to the local SOCKS port)
- **The hidden service config + filesystem** for the server side (tor reads
  a `torrc` we generate, publishes the HS, writes the `.onion` to a file)

## Why a real `tor` binary?

A pure-Python implementation of Tor v3 is **not realistic** for a small
library:

- ~600 pages of protocol specs (cells, circuits, ntor handshake, HSDir hash
  ring, rendezvous protocol, ed25519, ...)
- Ongoing protocol changes by the Tor Project
- Subtle crypto operations that are hard to test
- Network-level debugging that's a nightmare without battle-tested code

The C `tor` is the canonical, secure, maintained implementation. Wrapping
it via subprocess is the [`stem`](https://stem.torproject.org/) approach,
which the Tor Project itself recommends for Python tooling.

The lib [`torpy`](https://github.com/torpyorg/torpy) attempts pure-Python
but only supports `.onion` v2 (deprecated since 2021).

## Client architecture

```
                       module-level helpers
                       (client.get, client.post, …)
                              │
                              ▼
                       _default_session
                       (a single OnionSession, lazily created)
                              │
                              │ inherits from
                              ▼
                   ┌─────────────────────┐
                   │  requests.Session   │
                   │  with SOCKS5 proxy  │
                   └──────────┬──────────┘
                              │ first instantiation triggers:
                              ▼
                   ┌─────────────────────┐
                   │     TorManager      │   ← process-wide singleton
                   │      (in _tor.py)   │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  detect_running_tor │   ← if found, REUSE
                   │   (probes 9050,     │     no spawn, no atexit
                   │    9150, env var)   │
                   └──────────┬──────────┘
                              │ if not found:
                              ▼
                   ┌─────────────────────┐
                   │ stem.process.launch │   ← spawn subprocess
                   │  _tor_with_config   │     atexit handler kills it
                   └─────────────────────┘
```

The `TorManager` is a `threading.Lock`-protected singleton. The first
`Session()` constructor in the process triggers either reuse or spawn,
all subsequent ones share the same proxy port.

Key properties:
- **One tor per Python process** (when spawned).
- **Reuse-by-default** to avoid stacking tor processes when the user
  already has one running.
- **`take_ownership=True`** in stem ensures the child tor dies if Python
  is `kill -9`'d.

## Server architecture

The server module spawns a **separate** tor process configured for hidden
service hosting (different config from the client tor).

```
   server.serve(app)
        │
        ├─ normalize_to_asgi(app)         ← auto-detect ASGI vs WSGI
        │   │                               wrap WSGI via asgiref if needed
        │   ▼
        │  ASGI 3 callable
        │
        ├─ HiddenService(...)             ← create the HS controller
        │   │
        │   └─ launch_tor_for_hidden_service:
        │      ├─ tor binary lookup (same logic as client)
        │      ├─ generate config: HiddenServiceDir, HiddenServicePort
        │      ├─ stem.process.launch_tor_with_config(...)
        │      ├─ wait for `<key_dir>/hostname` file to appear
        │      └─ return (proc, "http://xxx.onion")
        │
        └─ uvicorn.run(asgi_app, host="127.0.0.1", port=N)   ← blocks
                  │
                  └─ on Ctrl+C / exit: hs.stop() kills tor
```

Both processes (uvicorn + tor) share the same OS process group as the
Python parent. tor is configured to listen exclusively on `127.0.0.1`,
unreachable from the network.

### ASGI/WSGI auto-detection

In `server/_detection.py`:

- **ASGI**: async callable, signature `(scope, receive, send)`, or has
  framework markers (`router`, `middleware_stack`, `lifespan_context`)
- **WSGI**: sync callable with 2-arg signature, or has `wsgi_app` attribute
  (Flask convention)

WSGI apps are wrapped with `asgiref.wsgi.WsgiToAsgi`, which is the same
adapter Django itself uses for ASGI deployment. No custom wrapping logic.

## Auto-install mechanism

```
user has no tor
       │
       ▼
client.get(...) or server.serve(...)
       │
       ▼
find_tor_binary(auto_install=True)
       │
       ├─ check $TORNION_TOR_PATH  → miss
       ├─ check ~/.cache/tornion/tor/tor  → miss
       ├─ check $PATH for "tor"  → miss
       ├─ check Tor Browser locations  → miss
       │
       ▼
install_tor()
       │
       ├─ detect platform suffix (linux-x86_64, macos-aarch64, …)
       ├─ download tor-expert-bundle-<suffix>-<version>.tar.gz
       │   from archive.torproject.org via HTTPS
       ├─ extract into ~/.cache/tornion/tor/
       ├─ chmod +x the tor binary
       └─ return path to the binary
```

The Tor Project distributes the **Tor Expert Bundle** specifically for
this use case (developers embedding tor in their app). It contains the
`tor` binary, dynamic libs, pluggable transports, geoip files, etc.

Source: <https://www.torproject.org/download/tor/>

## Code layout

```
src/tornion/
├── __init__.py             Top-level: shared utilities, exceptions, version
├── _version.py             Single source of truth for the version string
├── _binary.py              tor binary discovery + download + paths
├── _tor.py                 TorManager (client side) + launch helper (server side)
├── exceptions.py           Public exception hierarchy
├── cli.py                  argparse-based CLI: install-tor, get, serve, info
├── client/
│   ├── __init__.py         Public client API: get, post, Session, …
│   └── session.py          OnionSession class + module helpers
└── server/
    ├── __init__.py         Public server API: serve, HiddenService
    ├── _detection.py       ASGI vs WSGI heuristics + normalize_to_asgi
    └── runner.py           HiddenService class + serve() function
```

Modules prefixed with `_` are internal — the public API is what's
re-exported in `__init__.py` files.

## Known limitations & pitfalls

### 1. Sync only

The client API is sync (built on `requests`). Async users can grab the
SOCKS port via `tornion.detect_running_tor()` and feed it to `httpx[socks]`
or `aiohttp` themselves.

### 2. One hidden service per process

Each `server.serve()` call (or `HiddenService(...)` instance) spawns its
own tor. Hosting multiple HS in one process would require sharing a tor
instance, which isn't currently supported.

### 3. Bootstrap latency on first call

10–30 seconds of tor circuit construction the first time, every time the
process restarts. Persistent tor (a system service) avoids this cost.

### 4. No GPG verification of downloaded tor

The auto-download trusts HTTPS for integrity. For high-security
environments, pre-install the binary with manual GPG verification and
point `$TORNION_TOR_PATH` at it.

### 5. PyInstaller bundling

If you bundle a `tornion`-using script with PyInstaller, the auto-downloaded
tor binary lives in `~/.cache/tornion/`, OUTSIDE the bundle. For a fully
self-contained executable, you need to bundle the tor binary yourself and
set `TORNION_TOR_PATH` at runtime.

### 6. v3 only

Hidden service v2 is dead since 2021 (rejected by the Tor network).
`tornion` only knows v3. There's no v2 fallback and won't be.

### 7. No control port

By default, tor's `ControlPort` is disabled (set to 0). This means you
can't dynamically change circuits, query tor status, etc. via stem's
control API. If you need that, drop down to using
`tornion._tor.launch_tor_for_hidden_service()` with a custom config.

## Future work

Roughly in order of likelihood:

- [ ] **Async client API** (`from tornion import asyncclient`) using
      `httpx[socks]` natively.
- [ ] **Multi-HS support** — one tor process serving multiple hidden
      services in the same Python process.
- [ ] **GPG verification** of the auto-downloaded tor.
- [ ] **GitHub Actions CI** with integration tests against a real tor.
- [ ] **Pluggable transports** (obfs4, snowflake) for users behind
      censoring firewalls.
- [ ] **Type stubs** (`py.typed` marker) for IDE autocomplete.
- [ ] **Onion auth v3** (client authentication keys) for restricting HS
      access to known clients.
