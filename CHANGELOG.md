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
