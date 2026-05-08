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
