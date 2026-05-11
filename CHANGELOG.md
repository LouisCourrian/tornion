# Changelog

All notable changes to **tornion** are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## Versioning policy

`tornion` commits to SemVer for everything reachable from the
top-level packages `tornion`, `tornion.client`, and `tornion.server`.
Anything in a module prefixed with `_` (e.g. `tornion._tor`,
`tornion._binary`, `tornion._console`) is **internal** and may change
in any release.

### MAJOR bump (breaking change)

We bump the major version for any of these:

- Removing or renaming a public function, class, method, attribute,
  or keyword argument.
- Changing the type or documented semantics of an existing public
  argument or return value.
- Changing the exception class hierarchy in a way users would catch
  (e.g. moving an exception out of `OnionError`).
- Changing the on-disk format or location of `key_dir` in a way that
  invalidates a user's existing `.onion` identity, without an
  automatic migration.
- Raising the minimum supported Python version.
- Removing support for a Tor Expert Bundle version still in
  `KNOWN_TOR_HASHES` of the previous release.

### MINOR bump (new feature, backwards-compatible)

- New public functions, classes, methods, keyword arguments (with
  defaults that preserve previous behavior).
- New CLI subcommands or flags.
- New environment variables (default behavior unchanged when unset).
- Bumping `DEFAULT_TOR_VERSION` and adding pinned hashes for the new
  release.
- Widening the set of supported Python versions, OS, or app
  frameworks.

### PATCH bump (fixes, no behavior change)

- Bug fixes that don't change documented behavior.
- Performance improvements.
- Documentation, examples, type hints, internal refactoring.
- New tests.
- Adding pinned hashes for an existing-version Tor Expert Bundle that
  was rebuilt by the Tor Project.

### Deprecation window

Before removing or renaming anything public, we keep the old name
working for **at least one MINOR release** while emitting a
`DeprecationWarning` that points at the replacement. The actual
removal happens at the next MAJOR.

### Pre-1.0 caveat

While `tornion` is below `1.0.0`, MINOR releases (`0.X.0`) may
contain breaking changes when justified — but we call them out
loudly in this changelog and provide migration notes. Pin to a
minor version in production-ish code:

```toml
# pyproject.toml
dependencies = ["tornion>=0.6,<0.7"]
```

---

## [Unreleased]

_No changes yet._

---

## [1.2.0] — 2026-05-08

**Tor v3 client authorization.** Hidden services can now restrict who
is allowed to connect — knowing the `.onion` address alone is no
longer enough. Authorized clients hold an x25519 private key that
matches a public key registered with the server; everyone else times
out trying to connect.

### Added

- **New module `tornion._client_auth`** implementing the v3 client
  authorization protocol per rend-spec-v3.txt §G. Includes a pure-Python
  x25519 (RFC 7748 §5) — no `cryptography` or PyNaCl dependency. The
  implementation is verified against RFC 7748 §6.1 test vectors in the
  unit tests.

- **Server-side API**, re-exported from `tornion.server`:
  - `add_authorized_client(key_dir, nickname, public_key=None)` —
    if `public_key` is omitted, generates a fresh x25519 keypair and
    returns both halves; the private key must be conveyed to the client.
    Writes `<key_dir>/authorized_clients/<nickname>.auth` in the
    `descriptor:x25519:<BASE32>` format tor expects.
  - `revoke_authorized_client(key_dir, nickname)`
  - `list_authorized_clients(key_dir)` → `[(nickname, pubkey_b32), ...]`
  - `generate_client_keypair()` — exposed as a building block.

- **Client-side API**, re-exported from `tornion.client`:
  - `add_client_auth(onion, private_key)` — registers a `.auth_private`
    file in the default `ClientOnionAuthDir`
    (`<data_dir>/client-auth/`).
  - `remove_client_auth(onion)`, `list_client_auth()`
  - `default_client_auth_dir()` — exposed for inspection.

- **CLI commands**:
  - `tornion authorize <key_dir> <nickname>` — generate + add, prints
    the private key for the operator to give to the client.
  - `tornion authorize <key_dir> <nickname> --public-key KEY` — add an
    existing public key the client gave you.
  - `tornion authorize --list <key_dir>`
  - `tornion authorize --revoke <nickname> <key_dir>`
  - `tornion client-auth <onion> <private-key>` — add.
  - `tornion client-auth --list`
  - `tornion client-auth --remove <onion>`

- **TorManager** now passes `ClientOnionAuthDir` to the tor subprocess
  on startup so any registered `.auth_private` files take effect.

### Fixed

- `tornion.shutdown()` now also invalidates the module-level
  `client._default_session`, which previously kept pointing at the
  dead tor's SOCKS port and caused subsequent `tornion.client.get(...)`
  calls to fail with "connection refused".

### Tests

- 19 new unit tests covering: RFC 7748 §6.1 vectors (Alice/Bob keypair
  derivation + ECDH shared secret), base32 roundtrip, keypair
  generation, server-side add/list/revoke including duplicate and
  malformed input cases, onion-URL normalization, client-side
  add/list/remove, and the module re-export surface.
- 1 new e2e integration test: an authorized client successfully
  reaches an HS with `authorized_clients/` populated.

Test count: 64 unit + 2 e2e (was 45 unit + 1 e2e).

---

## [1.1.0] — 2026-05-08

Ergonomics release: two new CLI subcommands for offline identity
management, a symmetric environment variable, and an auto-release
workflow.

### Added
- **`tornion keygen [--out DIR] [--force]`** — generate a fresh
  `hs_ed25519_secret_key` without spinning up tor. Default `--out`
  is `./onion-key/`. Useful for provisioning a fixed onion identity
  before deploying a server, or for scripted setups.
- **`tornion onion <key_dir>`** — print the `.onion` address derived
  from an existing key directory, fully offline. Reads `hostname` if
  present; otherwise derives from `hs_ed25519_public_key` via
  SHA3-256 + base32 (stdlib only).
- **`TORNION_KEY_DIR`** environment variable, symmetric to
  `TORNION_TOR_PATH`. Picked up by `_resolve_key_dir()` when no
  explicit `key_dir` argument is passed to `serve()` /
  `HiddenService`. Lets ops swap identities without touching app code.
- New module **`tornion._onion`** exposing the v3 identity helpers:
  `generate_secret_key_blob()`, `write_secret_key(key_dir)`,
  `onion_from_public_key(pubkey)`, `onion_for_key_dir(key_dir)`.
  Stdlib-only — no `cryptography` / PyNaCl dependency.
- New GitHub Actions workflow
  ([`.github/workflows/release.yml`](.github/workflows/release.yml)):
  on tag push (`v*.*.*`), extracts the matching CHANGELOG section,
  creates the GitHub Release with those notes as the body, then
  publishes to PyPI via OIDC trusted publisher. Replaces the previous
  PyPI-only `publish.yml`.

### Changed
- `tornion info` now reports the value of `$TORNION_KEY_DIR` when
  it is set.

### Tests
- 11 new unit tests: key blob format and clamping, randomness across
  generations, `.onion` derivation from a known public key, error
  messages for malformed / missing key directories, and three tests
  for the `TORNION_KEY_DIR` resolution precedence. 45 unit tests
  total, plus the e2e integration test.

---

## [1.0.1] — 2026-05-08

Security and hygiene patch following a static-review pass.

### Security
- **`detect_running_tor()` now actually verifies the SOCKS5 server is Tor.**
  The previous probe accepted any SOCKS5-speaking endpoint, which would
  have let tornion silently route privacy-sensitive traffic through a
  non-Tor proxy (e.g. proxychains, dante, `ssh -D`) running on the
  default Tor ports. The probe now performs Tor's RESOLVE protocol
  extension (SOCKS5 command byte `0xF0`); plain SOCKS5 servers reply
  with REP=0x07 ("Command not supported") and are rejected.
- **Hardened tar extraction for Python 3.9–3.11.** `install_tor()`
  previously fell back to bare `tarfile.extractall()` when the
  `filter="data"` argument (3.12+) wasn't available, leaving a path
  traversal window open if a malicious archive ever defeated the
  SHA-256 pin. New `_safe_extract_tar()` validates every member —
  rejects symlinks, hardlinks, devices, FIFOs, absolute paths, and
  any path that resolves outside the target directory — before
  calling `extractall`.

### Changed
- Reusing an externally-managed tor (`use_existing=True`, default)
  now logs a `WARNING` instead of `INFO`, telling the user explicitly
  that `tornion` did not start tor itself and pointing at
  `use_existing=False` for full management.
- Per-HS `tor-data` cache subdirectory name is now `hs-<sha256(key_dir)[:16]>`
  instead of `hs-<builtin hash()>`. The builtin `hash()` is salted by
  `PYTHONHASHSEED` and produced a different name on every Python
  process, accumulating orphan cache directories. The on-disk `.onion`
  identity itself was never affected.

### Fixed
- `tornion.server.runner.serve()` docstring example showed
  `import tornion; tornion.serve(app)`, contradicting the documented
  `from tornion import server; server.serve(app)` usage that the test
  suite enforces.
- README: removed the static "tests 21 passed" badge (misleading —
  the count had drifted and there is no continuous CI signal behind it).
- README: section title `Roadmap to 1.0` renamed to `Roadmap` now
  that 1.0 has shipped.

### Tests
- 4 new unit tests: probe rejects plain SOCKS5 (security regression
  guard), probe accepts Tor's RESOLVE response, safe extract refuses
  absolute paths, safe extract refuses path traversal. 34 unit tests
  total, plus the e2e integration test.

---

## [1.0.0] — 2026-05-08

First stable release. From this point on, the public API of `tornion`,
`tornion.client`, and `tornion.server` is under the SemVer guarantee
documented in the *Versioning policy* section above.

### Added
- GitHub Actions workflow ([`.github/workflows/publish.yml`](.github/workflows/publish.yml))
  that publishes to PyPI via OIDC trusted publisher whenever a `v*`
  tag is pushed. No API tokens stored in repo secrets.
- `Changelog` and `Documentation` URLs in `[project.urls]`, exposed in
  PyPI's project sidebar.
- `CHANGELOG.md` and `docs/` are now packaged inside the sdist
  uploaded to PyPI.

### Changed
- Trove classifier flipped from `Development Status :: 3 - Alpha` to
  `5 - Production/Stable`.
- README "Status" section now states the SemVer commitment and
  recommends `tornion>=1.0,<2.0` for pinning.

### No functional changes since 0.6.0
This release codifies the API contract for all the work that landed
during the 0.x series — there are no behavior changes between 0.6.0
and 1.0.0.

---

## [0.6.0] — 2026-05-08

### Added
- `tornion.server.serve()` now picks `app_name` from the entry-script
  basename (`python myserver.py` → `myserver`) and falls back to the
  `__main__` module name (`python -m mypackage` → `mypackage`).
  See `_resolve_app_name()` in `tornion.server.runner`.
- `serve()` prints a clear status block before tor bootstrap:
  resolved `app_name` and where it came from, the absolute `key_dir`,
  and whether this run will publish a **fresh** `.onion` or **reuse**
  the existing identity.
- SHA-256 pinning for Tor Expert Bundle downloads. Hashes for known
  versions and platforms live in `tornion._binary.KNOWN_TOR_HASHES`,
  populated from the Tor Project's signed `sha256sums-signed-build.txt`.
- `install_tor(sha256=...)` keyword to override the pinned hash for
  versions not in `KNOWN_TOR_HASHES` (after manual verification).
- `tornion install-tor --sha256 <hex>` CLI flag mirroring the API.
- `TORNION_INSECURE_SKIP_HASH_CHECK=1` environment escape hatch
  (HTTPS-only authentication; not recommended).
- `tornion._console.setup_console_encoding()` helper that switches
  `stdout`/`stderr` to UTF-8 with `errors="replace"`. Called at every
  user-facing entry point.
- `tests/integration/test_e2e.py`: spawns a real `tor` process,
  publishes a real `.onion`, performs a full round-trip HTTP call
  through the `tornion` client.
- Pytest marker `integration` (registered in `pyproject.toml`),
  excluded from the default run; opt-in via `pytest -m integration`.
- `docs/server.md`: new section *"Provide a fixed key (deterministic
  seed)"* showing how to construct a valid `hs_ed25519_secret_key`
  from a chosen seed.
- Roadmap section in `README.md` enumerating what's left before 1.0.

### Changed
- **`app_name` default heuristic.** Previously derived from
  `app.title or type(app).__name__`, which silently shifted between
  runs (default FastAPI title, refactored class name) and changed the
  `.onion` address. **Existing apps relying on the old default will
  see a new `.onion` on first run with 0.6.0** — pass
  `app_name="<previous-value>"` explicitly to keep the old identity.
- `serve()` log output is richer and now emits *before* tor bootstrap
  starts, so users see where their identity lives without waiting
  30–90s.

### Fixed
- Windows `cp1252` console crash (`UnicodeEncodeError`) on every
  emoji-bearing `print()` in `_binary.py`, `server/runner.py`, and
  `cli.py`. Affected every Windows user who tried `tornion install-tor`
  or `serve()`.
- `stem.process.launch_tor_with_config(timeout=...)` is rejected on
  Windows because the timeout uses POSIX-only `signal.alarm`. The
  argument is now silently dropped on Windows for both the client
  SOCKS launcher and the hidden service launcher.

### Security
- Tor Expert Bundle downloads are now verified against a pinned
  SHA-256 before extraction. Previously the binary was authenticated
  only by HTTPS — a CA mis-issuance, state-level MITM, or compromise
  of `archive.torproject.org` could have led `tornion` to install and
  execute an attacker-controlled binary.

---

## [0.5.0] — 2026-05-08 — initial public release

### Added
- `tornion.client`: `OnionSession` (a `requests.Session` subclass)
  that auto-routes traffic through Tor's SOCKS5; module-level
  `get/post/put/delete/head/patch/options/request` helpers mirroring
  `requests`.
- `tornion.server`: `HiddenService` wrapper class managing a tor
  subprocess that publishes a v3 `.onion`; `serve(app)` convenience
  function that hosts any ASGI or WSGI app.
- Auto-detection of ASGI vs WSGI (FastAPI, Starlette, Quart,
  Litestar, Flask, Django, Bottle, plain callables, …) via
  `tornion.server._detection`. WSGI is auto-wrapped through
  `asgiref.wsgi.WsgiToAsgi`.
- Tor binary auto-discovery: `$TORNION_TOR_PATH`, user cache,
  system `PATH`, well-known Tor Browser locations.
- Tor Expert Bundle auto-installer: `tornion install-tor` /
  `_binary.install_tor()`.
- Smart reuse of an externally running tor on `:9050` / `:9150` /
  `$TORNION_SOCKS_PORT` for the client side.
- CLI: `tornion install-tor`, `tornion get`, `tornion serve`,
  `tornion info`.
- Exception hierarchy rooted at `OnionError`:
  `TorBinaryNotFound`, `TorBootstrapError`, `TorAlreadyRunning`,
  `HiddenServiceError`, `UnsupportedAppError`.
- 21 unit tests (smoke level — no network, no real tor).
- Documentation: `README.md`, `docs/client.md`, `docs/server.md`,
  `docs/configuration.md`, `docs/internals.md`, runnable examples
  under `examples/`.
