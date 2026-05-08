# Configuration & CLI reference

[← back to README](../README.md)

## Table of contents

- [Environment variables](#environment-variables)
- [CLI commands](#cli-commands)
- [File system layout](#file-system-layout)
- [Tor binary discovery](#tor-binary-discovery)
- [Updating the bundled tor version](#updating-the-bundled-tor-version)

---

## Environment variables

| Variable | Effect |
|---|---|
| `TORNION_TOR_PATH` | Force a specific `tor` binary. Skips all discovery and auto-install. |
| `TORNION_SOCKS_PORT` | Tell the client to reuse a SOCKS5 proxy on this port (skips the spawn). |
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
```

App spec: `module:attribute` (same as uvicorn/gunicorn).

### `tornion info`

Diagnostic. Prints what `tornion` would do without doing it.

```bash
$ tornion info
tornion 0.5.0
  cache dir         : /home/user/.cache/tornion
  data dir          : /home/user/.local/share/tornion
  bundled tor       : /home/user/.cache/tornion/tor/tor (10.4 MB)
  resolved binary   : /home/user/.cache/tornion/tor/tor
  running tor       : ✓ SOCKS5 detected on :9050 (would be reused for client)
  server extras     : ✓ installed (uvicorn ready)
  default version   : 15.0.11
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
2. **`~/.cache/tornion/tor/tor`** if previously downloaded.
3. **`tor` in `$PATH`** (`apt install tor`, `brew install tor`).
4. **Tor Browser** at known locations:
   - macOS: `/Applications/Tor Browser.app/Contents/MacOS/Tor/tor`
   - Windows: `Desktop/Tor Browser/...` and `Program Files/Tor Browser/...`
5. **Auto-download** the Tor Expert Bundle from
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

## Updating the bundled tor version

The auto-downloaded version is pinned at the top of
`src/tornion/_binary.py`:

```python
DEFAULT_TOR_VERSION = "15.0.11"
```

To bump:

1. Pick a new version from
   [archive.torproject.org/tor-package-archive/torbrowser/](https://archive.torproject.org/tor-package-archive/torbrowser/)
2. Update `DEFAULT_TOR_VERSION` and bump `tornion`'s own minor version
3. Run `tornion install-tor --force` locally to verify the URL exists
4. Commit & release

Users can install a non-default version on demand:

```python
import tornion
tornion.install_tor(version="14.5.6", force=True)
```
