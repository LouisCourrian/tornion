"""Auto-detection of ASGI vs WSGI apps.

ASGI 3 apps are async callables with signature (scope, receive, send).
WSGI apps are sync callables with signature (environ, start_response).

This module provides best-effort heuristics to distinguish them so users
can pass any framework's app object without manual flagging.
"""
from __future__ import annotations

import inspect
from typing import Any

from ..exceptions import UnsupportedAppError


def _signature_param_count(callable_obj: Any) -> int:
    """Return the number of params of a callable's signature, or -1 on failure."""
    try:
        sig = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return -1
    # Filter out 'self' / 'cls' for bound methods
    params = [
        p for p in sig.parameters.values()
        if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
    ]
    return len(params)


def is_asgi_app(app: Any) -> bool:
    """Best-effort detection: True if `app` looks like an ASGI app."""
    # 1. Plain async function with 3 params
    if inspect.iscoroutinefunction(app):
        return _signature_param_count(app) == 3

    # 2. Class instance with async __call__
    call = getattr(app, "__call__", None)
    if call is not None and inspect.iscoroutinefunction(call):
        return True

    # 3. Inspect typical attributes that uniquely identify ASGI frameworks
    #    (FastAPI, Starlette, Quart, Litestar all expose router/routes etc.)
    asgi_markers = {"router", "middleware_stack", "lifespan_context"}
    if any(hasattr(app, attr) for attr in asgi_markers):
        return True

    return False


def is_wsgi_app(app: Any) -> bool:
    """Best-effort detection: True if `app` looks like a WSGI app."""
    # Flask app: has wsgi_app attribute
    if hasattr(app, "wsgi_app"):
        return True

    if not callable(app):
        return False

    # For plain functions / methods, inspect the callable itself.
    # For class instances, look at the __call__ method.
    if inspect.isfunction(app) or inspect.ismethod(app) or inspect.isbuiltin(app):
        target = app
    else:
        target = getattr(app, "__call__", app)

    if inspect.iscoroutinefunction(target):
        return False

    n = _signature_param_count(target)
    return n == 2


def normalize_to_asgi(app: Any) -> Any:
    """Return an ASGI app, wrapping WSGI if needed.

    Raises:
        UnsupportedAppError: if the app cannot be classified as ASGI or WSGI.
        ImportError: if WSGI->ASGI conversion is needed but asgiref is missing.
    """
    if is_asgi_app(app):
        return app
    if is_wsgi_app(app):
        try:
            from asgiref.wsgi import WsgiToAsgi
        except ImportError as e:
            raise ImportError(
                "WSGI app detected but `asgiref` is not installed. "
                "Install tornion server extras: `pip install tornion[server]`"
            ) from e
        return WsgiToAsgi(app)

    raise UnsupportedAppError(
        f"Could not detect {app!r} as ASGI or WSGI. "
        f"Make sure your app object exposes a standard interface "
        f"(FastAPI, Starlette, Quart, Flask, Django…) or pass an ASGI "
        f"3-callable directly."
    )
