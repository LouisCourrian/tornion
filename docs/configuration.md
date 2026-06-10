# Configuration & CLI reference

[← back to README](../README.md)

## Table of contents

- [Environment variables](#environment-variables)
- [CLI commands](#cli-commands)
- [File system layout](#file-system-layout)
- [Tor binary discovery](#tor-binary-discovery)
- [Auto-updating the tor binary](#auto-updating-the-tor-binary)
- [Updating the pinned tor version](#updating-the-pinned-tor-version)

---

## Environment variables

| Variable | Effect |
|---|---|
| `TORNION_TOR_PATH` | Force a specific `tor` binary. Skips all discovery and auto-install. |
| `TORNION_SOCKS_PORT` | Tell the client to reuse a SOCKS5 proxy on this port (skips the spawn). |
| `TORNION_AUTO_UPDATE` | Set to `1` to keep the managed tor on the latest PGP-verified version (see [Auto-updating](#auto-updating-the-tor-binary)). Needs `pip install tornion[autoupdate]`. |
| `TORNION_KEY_DIR` | Default hidden service key directory (symmetric to `TORNION_TOR_PATH`). |
| `XDG_CACHE_HOME` | Override cache root on Linux. |
| `XDG_DATA_HOME` | Override persistent data root on Linux. |
| `LOCALAPPDATA` / `APPDATA` | Used as cache / data roots on Windows. |

## CLI commands

`tornion` ships a CLI: `pip install tornion` registers a `tornion`
executable.

### `tornion install-tor`

Pre-downloads the official Tor Expert Bundle into the user cache.
Idempotent — calling twice is a no-op unless `--force`.

```bash
tornion install-tor                  # latest pinned version
tornion install-tor --version 15.0.11
tornion install-tor --force          # re-download even if present
```

### `tornion update`

Update the cached tor to the **latest stable** Tor Expert Bundle, verified
against the Tor Project's PGP signature. Requires the `[autoupdate]` extra.
Idempotent — a no-op when already current unless `--force`.

```bash
pip install tornion[autoupdate]
tornion update            # check + update if a newer verified version exists
tornion update --force    # reinstall even if already on the latest
```

See [Auto-updating the tor binary](#auto-updating-the-tor-binary) for how the
verification works.

### `tornion get`

One-shot HTTP request to a `.onion`. Auto-spawns / auto-detects tor.

```bash
tornion get http://xxx.onion/ping
tornion get http://xxx.onion/data --json
tornion get http://xxx.onion/items \
    -X POST \
    -H 'Content-Type: application/json' \
    --data '{"name":"foo"}'
tornion get http://xxx.onion/slow --timeout 120
```

### `tornion serve`

Run an ASGI/WSGI app on a hidden service, à la `uvicorn`.

```bash
tornion serve myapp:app
tornion serve myapp:app --key-dir ./hs
tornion serve myapp:app --name myapi --log-level info
tornion serve myapp:app --bootstrap-timeout 120
tornion serve myapp:app --auto-update          # latest verified tor (needs [autoupdate])
```

App spec: `module:attribute` (same as uvicorn/gunicorn).

(`tornion get` also accepts `--auto-update`.)

### `tornion info`

Diagnostic. Prints what `tornion` would do without doing it.

```bash
$ tornion info
tornion 1.4.0
  cache dir         : /home/user/.cache/tornion
  data dir          : /home/user/.local/share/tornion
  bundled tor       : /home/user/.cache/tornion/tor/tor v15.0.15 (10.4 MB)
  resolved binary   : /home/user/.cache/tornion/tor/tor
  running tor       : ✓ SOCKS5 detected on :9050 (would be reused for client)
  server extras     : ✓ installed (uvicorn ready)
  auto-update       : ✓ available (PGPy ready), TORNION_AUTO_UPDATE=off
  pinned version    : 15.0.11
```

## File system layout

`tornion` follows the
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/)
on Linux, and OS conventions on macOS/Windows.

### Cache directory

Disposable. You can `rm -rf` it any time — `tornion` will re-download as
needed.

| OS | Path |
|---|---|
| Linux | `~/.cache/tornion/` |
| macOS | `~/Library/Caches/tornion/` |
| Windows | `%LOCALAPPDATA%\tornion\` |

Contents:

```
tornion/
├── tor/                    ← downloaded Tor Expert Bundle
│   ├── tor                 ← the binary
│   ├── pluggable_transports/
│   └── ...
└── tor-data/               ← per-tor-instance data (cached descriptors, …)
    ├── client-XXXX/        ← state for the client tor on port XXXX
    └── hs-XXXX/            ← state for hidden service tor instances
```

### Data directory

**Persistent.** Contains your hidden service ed25519 keys. **Back this up.**

| OS | Path |
|---|---|
| Linux | `~/.local/share/tornion/` |
| macOS | `~/Library/Application Support/tornion/` |
| Windows | `%APPDATA%\tornion\` |

Contents:

```
tornion/
└── hs/
    ├── myapi/              ← per-app key dir
    │   ├── hostname        ← the .onion address
    │   ├── hs_ed25519_secret_key   ← THE identity. NEVER share.
    │   └── hs_ed25519_public_key
    └── another-app/
        └── ...
```

Override paths via `XDG_DATA_HOME` (Linux) or pass `key_dir=...` to
`server.serve()`.

## Tor binary discovery

`tornion.find_tor_binary()` resolves a usable tor in this order:

1. **`$TORNION_TOR_PATH`** if set and pointing to an existing file.
2. **Auto-update** to the latest verified version — only when opted in via
   `auto_update=True` / `$TORNION_AUTO_UPDATE=1`. See
   [Auto-updating the tor binary](#auto-updating-the-tor-binary).
3. **`~/.cache/tornion/tor/tor`** if previously downloaded.
4. **`tor` in `$PATH`** (`apt install tor`, `brew install tor`).
5. **Tor Browser** at known locations:
   - macOS: `/Applications/Tor Browser.app/Contents/MacOS/Tor/tor`
   - Windows: `Desktop/Tor Browser/...` and `Program Files/Tor Browser/...`
6. **Auto-download** the pinned Tor Expert Bundle from
   `archive.torproject.org` (when `auto_install=True`, the default).

Disable auto-install:

```python
import tornion
tornion.find_tor_binary(auto_install=False)  # raises TorBinaryNotFound
```

Or use the CLI:

```bash
TORNION_TOR_PATH=/opt/tor/bin/tor tornion get http://xxx.onion/
```

## Auto-updating the tor binary

By default `tornion` installs a **pinned** Tor Expert Bundle whose SHA-256 is
hard-coded and verified before extraction. That's secure but frozen: you stay
on the pinned version until you upgrade `tornion` itself.

Opt into always running the latest stable tor instead:

```bash
pip install tornion[autoupdate]
export TORNION_AUTO_UPDATE=1
```

or per call:

```python
from tornion import client
client.Session(auto_update=True)          # sync
client.AsyncSession(auto_update=True)     # async
# server: server.serve(app, auto_update=True)
```

or one-shot from the CLI: `tornion update`.

### How it stays secure

The pinned hashes only cover versions tornion shipped — so for a version it has
never seen, it can't pre-pin a hash. Instead of trusting HTTPS alone, it
authenticates the new version against the Tor Project's own signature:

1. discover the latest **stable** version from `archive.torproject.org`
   (alphas like `16.0a7` are ignored);
2. download that version's `sha256sums-signed-build.txt` and its detached
   `.asc` signature;
3. **verify the PGP signature** against the Tor Browser build signing key
   embedded in the package
   (`tornion/assets/tor-signing-key.asc`, fingerprint
   `EF6E286D DA85EA2A 4BA7DE68 4E2C6E87 93298290`) — done in pure Python via
   [PGPy](https://pypi.org/project/PGPy/), no system `gpg` needed;
4. read the host platform's SHA-256 from the *signed* sums and hand it to
   `install_tor()`, which re-verifies it before extracting and replaces the
   old binary.

Every step is **failure-tolerant**: if you're offline, the listing can't be
parsed, or the signature doesn't verify, tornion logs a warning and falls back
to the cached/pinned binary. Auto-update can never break startup, and a
tampered sums file is rejected rather than installed.

A `.tornion-version` marker in the cache records the installed version, so a
launch where you're already current does a cheap signed-sums check (~6 KB) and
skips the multi-MB download.

## Updating the pinned tor version

Independently of auto-update, the always-available fallback version is pinned
at the top of `src/tornion/_binary.py`:

```python
DEFAULT_TOR_VERSION = "15.0.11"
```

To bump:

1. Pick a new version from
   [archive.torproject.org/tor-package-archive/torbrowser/](https://archive.torproject.org/tor-package-archive/torbrowser/)
2. Update `DEFAULT_TOR_VERSION`, add its pinned hashes to `KNOWN_TOR_HASHES`,
   and bump `tornion`'s own minor version
3. Run `tornion install-tor --force` locally to verify the URL exists
4. Commit & release

Users can install a non-default version on demand:

```python
import tornion
tornion.install_tor(version="14.5.6", force=True)
```
