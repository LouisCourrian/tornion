"""HTTP server side: publish any ASGI/WSGI app on a Tor hidden service."""
from ._detection import is_asgi_app, is_wsgi_app, normalize_to_asgi
from .runner import HiddenService, serve

__all__ = [
    "serve",
    "HiddenService",
    "is_asgi_app",
    "is_wsgi_app",
    "normalize_to_asgi",
]
