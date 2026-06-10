"""Auto-update unit tests — no network.

PGP verification is exercised for real against the embedded Tor signing key
using captured fixtures (a genuine signed sha256sums file + detached
signature), so the security-critical path is tested offline. Everything else
mocks the network.
"""
import sys
from pathlib import Path

import pytest

from tornion import _binary, _update

FIXTURES = Path(__file__).parent / "fixtures"
SUMS = (FIXTURES / "sha256sums-15.0.15.txt").read_bytes()
SIG = (FIXTURES / "sha256sums-15.0.15.txt.asc").read_bytes()


# ---------------------------------------------------------------------------
# version_tuple
# ---------------------------------------------------------------------------

def test_version_tuple_stable():
    assert _update.version_tuple("15.0.15") == (15, 0, 15)
    assert _update.version_tuple("15") == (15, 0, 0)
    assert _update.version_tuple("15.1") == (15, 1, 0)


def test_version_tuple_rejects_alpha():
    assert _update.version_tuple("16.0a7") is None
    assert _update.version_tuple("nope") is None
    assert _update.version_tuple("") is None


def test_version_ordering():
    assert _update.version_tuple("15.0.15") > _update.version_tuple("15.0.11")
    assert _update.version_tuple("16.0.0") > _update.version_tuple("15.9.9")


# ---------------------------------------------------------------------------
# discover_latest
# ---------------------------------------------------------------------------

_INDEX_HTML = """
<html><body>
  <a href="../">../</a>
  <a href="13.5.9/">13.5.9/</a>
  <a href="15.0.11/">15.0.11/</a>
  <a href="15.0.15/">15.0.15/</a>
  <a href="16.0a7/">16.0a7/</a>
  <a href="sha256sums-signed-build.txt">sha256sums…</a>
</body></html>
"""


def test_discover_latest_picks_highest_stable(monkeypatch):
    monkeypatch.setattr(_update, "_fetch", lambda url: _INDEX_HTML.encode())
    assert _update.discover_latest("https://example/torbrowser") == "15.0.15"


def test_discover_latest_ignores_alpha(monkeypatch):
    html = '<a href="16.0a7/">x</a><a href="14.5.6/">x</a>'
    monkeypatch.setattr(_update, "_fetch", lambda url: html.encode())
    assert _update.discover_latest("https://example") == "14.5.6"


def test_discover_latest_none_on_fetch_error(monkeypatch):
    def _boom(url):
        raise OSError("offline")
    monkeypatch.setattr(_update, "_fetch", _boom)
    assert _update.discover_latest("https://example") is None


# ---------------------------------------------------------------------------
# hash_for
# ---------------------------------------------------------------------------

def test_hash_for_extracts_known_archive():
    h = _update.hash_for(SUMS, "tor-expert-bundle-windows-x86_64-15.0.15.tar.gz")
    assert h == "8d3daf579192f3f128c0f42553dd994c640501b4b98682216d807c88004f7a96"


def test_hash_for_missing_returns_none():
    assert _update.hash_for(SUMS, "tor-expert-bundle-nope-99.tar.gz") is None


# ---------------------------------------------------------------------------
# verify_sums — REAL PGP verification against the embedded Tor key
# ---------------------------------------------------------------------------

def test_verify_sums_real_signature_passes():
    assert _update.verify_sums(SUMS, SIG) is True


def test_verify_sums_tampered_fails():
    tampered = bytearray(SUMS)
    tampered[100] ^= 0x01
    assert _update.verify_sums(bytes(tampered), SIG) is False


def test_verify_sums_garbage_signature_fails():
    assert _update.verify_sums(SUMS, b"not a real signature") is False


def test_imghdr_shim_for_py313(monkeypatch):
    """On Python 3.13 (no stdlib imghdr), the shim must let pgpy import.

    Simulated by poisoning the import so `import imghdr` raises the way it
    does on 3.13, then asserting the shim installs a usable stub.
    """
    monkeypatch.delitem(sys.modules, "imghdr", raising=False)
    monkeypatch.setitem(sys.modules, "imghdr", None)  # → ModuleNotFoundError

    _update._ensure_pgp_importable()

    import imghdr  # now resolves to the stub
    assert callable(imghdr.what)
    assert imghdr.what("anything") is None


# ---------------------------------------------------------------------------
# resolve_latest
# ---------------------------------------------------------------------------

def _fixture_fetch(url: str) -> bytes:
    if url.endswith(".asc"):
        return SIG
    if url.endswith("sha256sums-signed-build.txt"):
        return SUMS
    raise AssertionError(f"unexpected fetch: {url}")


def test_resolve_latest_happy_path(monkeypatch):
    monkeypatch.setattr(_update, "discover_latest", lambda base: "15.0.15")
    monkeypatch.setattr(_update, "_fetch", _fixture_fetch)
    out = _update.resolve_latest("https://example/torbrowser", "windows-x86_64")
    assert out == (
        "15.0.15",
        "8d3daf579192f3f128c0f42553dd994c640501b4b98682216d807c88004f7a96",
    )


def test_resolve_latest_none_when_discovery_fails(monkeypatch):
    monkeypatch.setattr(_update, "discover_latest", lambda base: None)
    assert _update.resolve_latest("https://example", "windows-x86_64") is None


def test_resolve_latest_none_when_signature_bad(monkeypatch):
    monkeypatch.setattr(_update, "discover_latest", lambda base: "15.0.15")

    def _tampered_fetch(url):
        if url.endswith(".asc"):
            return SIG
        t = bytearray(SUMS)
        t[100] ^= 0x01
        return bytes(t)
    monkeypatch.setattr(_update, "_fetch", _tampered_fetch)
    assert _update.resolve_latest("https://example", "windows-x86_64") is None


def test_resolve_latest_none_when_suffix_absent(monkeypatch):
    monkeypatch.setattr(_update, "discover_latest", lambda base: "15.0.15")
    monkeypatch.setattr(_update, "_fetch", _fixture_fetch)
    # A platform the signed sums don't cover → no hash → None.
    assert _update.resolve_latest("https://example", "fictional-arch") is None


# ---------------------------------------------------------------------------
# _binary auto-update plumbing
# ---------------------------------------------------------------------------

def test_resolve_auto_update_precedence(monkeypatch):
    monkeypatch.delenv("TORNION_AUTO_UPDATE", raising=False)
    assert _binary._resolve_auto_update(None) is False
    assert _binary._resolve_auto_update(True) is True
    assert _binary._resolve_auto_update(False) is False
    monkeypatch.setenv("TORNION_AUTO_UPDATE", "1")
    assert _binary._resolve_auto_update(None) is True
    assert _binary._resolve_auto_update(False) is False  # explicit arg wins


def test_try_auto_update_missing_extra(monkeypatch):
    """No [autoupdate] extra → fall back to cached path, never raise."""
    import tornion
    # Make `from . import _update` raise ImportError the way a missing PGPy
    # would: drop the cached submodule AND the attribute already set on the
    # parent package, then poison the import so it can't be re-resolved.
    monkeypatch.delattr(tornion, "_update", raising=False)
    monkeypatch.delitem(sys.modules, "tornion._update", raising=False)
    monkeypatch.setitem(sys.modules, "tornion._update", None)
    # Guard: if the ImportError sim ever fails, this makes the test fail loudly
    # instead of falling through to a real network call.
    monkeypatch.setattr(
        _binary, "_detect_platform_suffix",
        lambda: (_ for _ in ()).throw(AssertionError("should not reach resolve")),
    )
    monkeypatch.setattr(_binary, "installed_tor_path", lambda: Path("/cached/tor"))
    assert _binary._try_auto_update() == Path("/cached/tor")


def test_try_auto_update_resolve_none_keeps_cache(monkeypatch):
    monkeypatch.setattr(_binary, "_detect_platform_suffix", lambda: "windows-x86_64")
    monkeypatch.setattr(_update, "resolve_latest", lambda base, suffix: None)
    monkeypatch.setattr(_binary, "installed_tor_path", lambda: Path("/cached/tor"))
    assert _binary._try_auto_update() == Path("/cached/tor")


def test_try_auto_update_skips_when_cache_current(monkeypatch):
    monkeypatch.setattr(_binary, "_detect_platform_suffix", lambda: "windows-x86_64")
    monkeypatch.setattr(_update, "resolve_latest", lambda base, suffix: ("15.0.15", "deadbeef"))
    monkeypatch.setattr(_binary, "installed_tor_version", lambda: "16.0.0")
    monkeypatch.setattr(_binary, "installed_tor_path", lambda: Path("/cached/tor"))

    def _must_not_install(*a, **k):
        raise AssertionError("install_tor must not run when cache is current")
    monkeypatch.setattr(_binary, "install_tor", _must_not_install)
    assert _binary._try_auto_update() == Path("/cached/tor")


def test_try_auto_update_installs_when_newer(monkeypatch):
    monkeypatch.setattr(_binary, "_detect_platform_suffix", lambda: "windows-x86_64")
    monkeypatch.setattr(_update, "resolve_latest", lambda base, suffix: ("15.0.15", "abc123"))
    monkeypatch.setattr(_binary, "installed_tor_version", lambda: "15.0.11")

    captured = {}

    def _fake_install(*, version, sha256, force, progress):
        captured.update(version=version, sha256=sha256, force=force)
        return Path("/cached/tor-new")
    monkeypatch.setattr(_binary, "install_tor", _fake_install)

    out = _binary._try_auto_update()
    assert out == Path("/cached/tor-new")
    assert captured == {"version": "15.0.15", "sha256": "abc123", "force": True}


def test_try_auto_update_installs_when_no_cache(monkeypatch):
    monkeypatch.setattr(_binary, "_detect_platform_suffix", lambda: "windows-x86_64")
    monkeypatch.setattr(_update, "resolve_latest", lambda base, suffix: ("15.0.15", "abc123"))
    monkeypatch.setattr(_binary, "installed_tor_version", lambda: None)
    monkeypatch.setattr(_binary, "install_tor",
                        lambda **k: Path("/cached/tor-fresh"))
    assert _binary._try_auto_update() == Path("/cached/tor-fresh")


def test_find_tor_binary_triggers_auto_update(monkeypatch):
    """auto_update=True routes through _try_auto_update and returns its path."""
    monkeypatch.delenv("TORNION_TOR_PATH", raising=False)
    monkeypatch.setattr(_binary, "_try_auto_update", lambda: Path("/updated/tor"))
    assert _binary.find_tor_binary(auto_update=True) == str(Path("/updated/tor"))


def test_find_tor_binary_auto_update_falls_through_when_none(monkeypatch):
    """If auto-update yields nothing, normal resolution continues."""
    monkeypatch.delenv("TORNION_TOR_PATH", raising=False)
    monkeypatch.setattr(_binary, "_try_auto_update", lambda: None)
    monkeypatch.setattr(_binary, "installed_tor_path", lambda: Path("/cached/tor"))
    assert _binary.find_tor_binary(auto_update=True) == str(Path("/cached/tor"))
