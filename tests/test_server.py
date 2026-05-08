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
