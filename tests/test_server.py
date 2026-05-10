"""Server-side smoke tests — no tor, no network."""
import pytest

import tornion
from tornion import server


def test_server_submodule_exposes_api():
    """`from tornion import server` exposes the public API."""
    assert callable(server.serve)
    assert server.HiddenService is not None
    assert callable(server.is_asgi_app)
    assert callable(server.is_wsgi_app)
    assert callable(server.normalize_to_asgi)


def test_server_not_re_exported_at_top_level():
    """Top-level should NOT have serve/HiddenService."""
    assert not hasattr(tornion, "serve")
    assert not hasattr(tornion, "HiddenService")


# ---------- ASGI detection ----------

def test_detect_async_function_with_3_params():
    async def app(scope, receive, send):
        ...

    assert server.is_asgi_app(app)


def test_detect_class_with_async_call():
    class App:
        async def __call__(self, scope, receive, send):
            ...

    assert server.is_asgi_app(App())


def test_detect_starlette_like_marker():
    class FakeStarlette:
        router = object()

    assert server.is_asgi_app(FakeStarlette())


# ---------- WSGI detection ----------

def test_detect_flask_like():
    class FakeFlask:
        wsgi_app = object()

        def __call__(self, environ, start_response):
            ...

    assert server.is_wsgi_app(FakeFlask())


def test_detect_plain_wsgi_function():
    def app(environ, start_response):
        ...

    assert server.is_wsgi_app(app)


def test_async_function_is_not_wsgi():
    async def app(scope, receive, send):
        ...

    assert not server.is_wsgi_app(app)


# ---------- Normalization ----------

def test_normalize_asgi_passes_through():
    async def app(scope, receive, send):
        ...

    assert server.normalize_to_asgi(app) is app


def test_normalize_unsupported_raises():
    with pytest.raises(tornion.UnsupportedAppError):
        server.normalize_to_asgi(42)


def test_normalize_wsgi_wraps_via_asgiref():
    def wsgi_app(environ, start_response):
        ...

    wrapped = server.normalize_to_asgi(wsgi_app)
    assert wrapped is not wsgi_app
    assert callable(wrapped)


# ---------- app_name resolution (stable .onion identity) ----------

def test_resolve_app_name_uses_entry_script(monkeypatch):
    """`python myserver.py` → app_name "myserver" (stable across reruns)."""
    from tornion.server.runner import _resolve_app_name

    monkeypatch.setattr("sys.argv", ["/some/path/myserver.py"])
    name, source = _resolve_app_name(object())
    assert name == "myserver"
    assert "entry script" in source


def test_resolve_app_name_ignores_app_title(monkeypatch):
    """The new resolver MUST NOT consult app.title (was the fragile path)."""
    from tornion.server.runner import _resolve_app_name

    class FakeFastAPI:
        title = "should-be-ignored"

    monkeypatch.setattr("sys.argv", ["/some/path/myserver.py"])
    name, _ = _resolve_app_name(FakeFastAPI())
    assert name == "myserver"
    assert "should-be-ignored" not in name


def test_resolve_app_name_falls_back_to_default(monkeypatch):
    """Empty/REPL argv → "default" with a clear source label."""
    from tornion.server.runner import _resolve_app_name

    monkeypatch.setattr("sys.argv", [""])
    monkeypatch.delitem(__import__("sys").modules, "__main__", raising=False)
    name, source = _resolve_app_name(object())
    assert name == "default"
    assert "fallback" in source.lower() or "no entry point" in source.lower()


# ---------- TORNION_KEY_DIR env var ----------

def test_resolve_key_dir_explicit_wins_over_env(monkeypatch, tmp_path):
    """An explicit `key_dir` argument must beat $TORNION_KEY_DIR."""
    from tornion.server.runner import _resolve_key_dir

    monkeypatch.setenv("TORNION_KEY_DIR", str(tmp_path / "from-env"))
    explicit = tmp_path / "from-arg"
    resolved = _resolve_key_dir(explicit, app_name="ignored")
    assert resolved == explicit.resolve()


def test_resolve_key_dir_picks_up_env(monkeypatch, tmp_path):
    """When key_dir is None, $TORNION_KEY_DIR is used."""
    from tornion.server.runner import _resolve_key_dir

    env_dir = tmp_path / "from-env"
    monkeypatch.setenv("TORNION_KEY_DIR", str(env_dir))
    resolved = _resolve_key_dir(None, app_name="ignored-because-env-wins")
    assert resolved == env_dir.resolve()
    assert resolved.exists()


def test_resolve_key_dir_falls_back_to_data_dir(monkeypatch, tmp_path):
    """When neither argument nor env var is set, fall back to <data>/hs/<slug>/."""
    import tornion.server.runner as _runner
    monkeypatch.delenv("TORNION_KEY_DIR", raising=False)
    monkeypatch.setattr(_runner._binary, "data_dir", lambda: tmp_path)

    resolved = _runner._resolve_key_dir(None, app_name="myapp")
    assert resolved == (tmp_path / "hs" / "myapp").resolve()
