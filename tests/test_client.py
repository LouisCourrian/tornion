"""Client-side smoke tests — no network, no real tor."""
import requests

import tornion
from tornion import client


def test_client_submodule_exposes_api():
    """`from tornion import client` exposes the requests-style API."""
    assert hasattr(client, "get")
    assert hasattr(client, "post")
    assert hasattr(client, "put")
    assert hasattr(client, "delete")
    assert hasattr(client, "Session")
    assert hasattr(client, "OnionSession")


def test_client_not_re_exported_at_top_level():
    """Top-level `tornion` should NOT pollute namespace with client symbols."""
    assert hasattr(tornion, "install_tor")
    assert hasattr(tornion, "cache_dir")
    assert not hasattr(tornion, "get")
    assert not hasattr(tornion, "Session")


def test_session_subclasses_requests_session():
    assert issubclass(client.OnionSession, requests.Session)
    assert client.Session is client.OnionSession


def test_exceptions_at_top_level():
    assert issubclass(tornion.TorBinaryNotFound, tornion.OnionError)
    assert issubclass(tornion.TorBootstrapError, tornion.OnionError)
    assert issubclass(tornion.HiddenServiceError, tornion.OnionError)
    assert issubclass(tornion.UnsupportedAppError, tornion.OnionError)


def test_dirs_creates():
    assert tornion.cache_dir().exists()
    assert tornion.data_dir().exists()


def test_version_string():
    assert isinstance(tornion.__version__, str)
    assert tornion.__version__.count(".") >= 1


def test_default_tor_version():
    assert isinstance(tornion.DEFAULT_TOR_VERSION, str)


def test_find_tor_binary_no_install_raises(monkeypatch):
    import tornion._binary as _binary

    monkeypatch.delenv("TORNION_TOR_PATH", raising=False)
    monkeypatch.setattr(_binary, "installed_tor_path", lambda: None)
    monkeypatch.setattr(_binary.shutil, "which", lambda _: None)
    monkeypatch.setattr(_binary, "_tor_browser_locations", lambda: [])

    try:
        _binary.find_tor_binary(auto_install=False)
    except tornion.TorBinaryNotFound as e:
        assert "tor" in str(e).lower()
    else:
        raise AssertionError("Expected TorBinaryNotFound")


def test_detect_running_tor_returns_none(monkeypatch):
    import tornion._tor as _tor
    monkeypatch.delenv("TORNION_SOCKS_PORT", raising=False)
    monkeypatch.setattr(_tor, "_probe_socks5", lambda host, port, timeout=0.3: False)
    assert _tor.detect_running_tor() is None


def test_detect_running_tor_via_env(monkeypatch):
    import tornion._tor as _tor
    monkeypatch.setenv("TORNION_SOCKS_PORT", "9999")
    monkeypatch.setattr(_tor, "_probe_socks5",
                        lambda host, port, timeout=0.3: port == 9999)
    assert _tor.detect_running_tor() == 9999


# ---------- Tor binary download verification (SHA-256 pinning) ----------

def test_known_tor_hashes_well_formed():
    """Every pinned hash must be a 64-char lowercase hex string."""
    import tornion._binary as _binary
    import re

    assert _binary.KNOWN_TOR_HASHES, "no pinned hashes — security check disabled"
    hex_re = re.compile(r"^[0-9a-f]{64}$")
    for version, by_platform in _binary.KNOWN_TOR_HASHES.items():
        assert by_platform, f"version {version} has no platforms"
        for suffix, h in by_platform.items():
            assert hex_re.match(h), f"{version}/{suffix}: {h!r} is not a sha256"


def test_default_version_has_pinned_hashes():
    """The version we ship by default MUST have hashes for the desktop platforms."""
    import tornion._binary as _binary

    by_platform = _binary.KNOWN_TOR_HASHES.get(_binary.DEFAULT_TOR_VERSION)
    assert by_platform is not None, \
        f"DEFAULT_TOR_VERSION={_binary.DEFAULT_TOR_VERSION} not in KNOWN_TOR_HASHES"
    for suffix in ("linux-x86_64", "macos-aarch64", "macos-x86_64",
                   "windows-x86_64", "windows-i686"):
        assert suffix in by_platform, f"missing pinned hash for {suffix}"


def test_expected_hash_unknown_returns_none():
    import tornion._binary as _binary
    assert _binary._expected_hash("999.0.0", "linux-x86_64") is None
    assert _binary._expected_hash(_binary.DEFAULT_TOR_VERSION, "fictional-arch") is None


def test_hash_file_matches_known_value(tmp_path):
    """`_hash_file` must match the well-known SHA-256 of a tiny file."""
    import tornion._binary as _binary

    p = tmp_path / "blob"
    p.write_bytes(b"hello")
    # SHA-256 of "hello" — well-known, no way to fake it
    assert _binary._hash_file(p) == \
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_install_tor_unknown_version_fails_fast(monkeypatch, tmp_path):
    """Unknown version → TorBinaryNotFound BEFORE any download is attempted."""
    import tornion._binary as _binary

    monkeypatch.setattr(_binary, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(_binary, "_detect_platform_suffix", lambda: "linux-x86_64")
    monkeypatch.delenv("TORNION_INSECURE_SKIP_HASH_CHECK", raising=False)

    # Refuse to be silent if the test ever leaks into a real network call.
    def _no_download(*a, **kw):
        raise AssertionError("install_tor must not download for unknown versions")

    monkeypatch.setattr(_binary, "_download_with_progress", _no_download)

    try:
        _binary.install_tor(version="999.99.99", progress=False)
    except tornion.TorBinaryNotFound as e:
        msg = str(e)
        assert "No SHA-256 hash on file" in msg
        assert "999.99.99" in msg
    else:
        raise AssertionError("Expected TorBinaryNotFound for unknown version")


def test_probe_rejects_plain_socks5(monkeypatch):
    """A SOCKS5 proxy that doesn't speak Tor's RESOLVE must NOT be reused.

    This is the security fix from 1.0.1: previously `_probe_socks5` only
    checked that something speaks SOCKS5, which would happily match
    proxychains / dante / `ssh -D` and route privacy-sensitive traffic
    through a non-Tor proxy.
    """
    import socket as _socket
    import tornion._tor as _tor

    class _FakeSocket:
        """Minimal SOCKS5 server that supports greeting but rejects RESOLVE."""
        def __init__(self):
            self._sent = b""
            self._step = 0

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, _t):
            pass

        def sendall(self, data):
            self._sent += data

        def recv(self, n):
            # First recv = greeting reply. NO_AUTH accepted.
            if self._step == 0:
                self._step = 1
                return b"\x05\x00"
            # Second recv = response to RESOLVE. Standard SOCKS5 says
            # "Command not supported" (REP=0x07).
            return b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"

    monkeypatch.setattr(_socket, "create_connection",
                        lambda addr, timeout=None: _FakeSocket())

    assert _tor._probe_socks5("127.0.0.1", 9050) is False


def test_probe_accepts_tor_socks5(monkeypatch):
    """Tor's SOCKS5 implements RESOLVE; the probe must match it."""
    import socket as _socket
    import tornion._tor as _tor

    class _TorSocket:
        def __init__(self):
            self._step = 0

        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, _t): pass
        def sendall(self, _data): pass

        def recv(self, n):
            if self._step == 0:
                self._step = 1
                return b"\x05\x00"
            # Tor accepted RESOLVE and returned a (fake) resolved address.
            return b"\x05\x00\x00\x01\x5d\xb8\xd8\x22\x00\x50"

    monkeypatch.setattr(_socket, "create_connection",
                        lambda addr, timeout=None: _TorSocket())

    assert _tor._probe_socks5("127.0.0.1", 9050) is True


def test_safe_extract_rejects_absolute_paths(tmp_path):
    """A tarball with an absolute path must be refused.

    On Python 3.12+ this is enforced by ``filter="data"``; on 3.9-3.11 by
    our manual validation. Either way ``_safe_extract_tar`` must raise
    rather than write outside ``target_dir``.
    """
    import tarfile
    import io
    import tornion._binary as _binary

    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="/etc/passwd")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"hello"))

    out = tmp_path / "out"
    out.mkdir()

    raised = False
    with tarfile.open(archive, "r:gz") as tar:
        try:
            _binary._safe_extract_tar(tar, out)
        except Exception:
            raised = True

    assert raised, "absolute-path member was extracted — security regression"
    assert not (out / "etc" / "passwd").exists()


def test_safe_extract_rejects_path_traversal(tmp_path):
    """A tarball with ``..`` that escapes target_dir must be refused."""
    import tarfile
    import io
    import tornion._binary as _binary

    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="../../escape.txt")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"pwn!"))

    out = tmp_path / "out"
    out.mkdir()

    raised = False
    with tarfile.open(archive, "r:gz") as tar:
        try:
            _binary._safe_extract_tar(tar, out)
        except Exception:
            raised = True

    assert raised, "path-traversal member was extracted — security regression"
    # Make sure nothing landed two directories up from out/
    assert not (tmp_path.parent / "escape.txt").exists()


def test_install_tor_hash_mismatch_raises(monkeypatch, tmp_path):
    """A successful download with the wrong bytes → TorBinaryNotFound."""
    import tornion._binary as _binary

    monkeypatch.setattr(_binary, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(_binary, "_detect_platform_suffix", lambda: "linux-x86_64")
    monkeypatch.delenv("TORNION_INSECURE_SKIP_HASH_CHECK", raising=False)

    # Simulate the download: write deterministic junk that won't match the
    # pinned hash for the default version.
    from pathlib import Path as _Path
    def _fake_download(url, dest):
        _Path(dest).write_bytes(b"this is definitely not the real tor archive")

    monkeypatch.setattr(_binary, "_download_with_progress", _fake_download)
    monkeypatch.setattr("urllib.request.urlretrieve",
                        lambda url, dest: _fake_download(url, dest))

    try:
        _binary.install_tor(progress=False)
    except tornion.TorBinaryNotFound as e:
        msg = str(e)
        assert "SHA-256 mismatch" in msg
        # Both the expected pinned hash and our junk hash must appear.
        assert "expected:" in msg and "actual:" in msg
    else:
        raise AssertionError("Expected TorBinaryNotFound on hash mismatch")
