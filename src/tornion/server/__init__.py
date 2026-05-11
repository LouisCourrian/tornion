"""HTTP server side: publish any ASGI/WSGI app on a Tor hidden service."""
from .._client_auth import (
    add_authorized_client,
    list_authorized_clients,
    revoke_authorized_client,
    generate_keypair as generate_client_keypair,
)
from ._detection import is_asgi_app, is_wsgi_app, normalize_to_asgi
from .runner import HiddenService, serve

__all__ = [
    "serve",
    "HiddenService",
    "is_asgi_app",
    "is_wsgi_app",
    "normalize_to_asgi",
    # Client authorization (restrict who can reach your HS)
    "add_authorized_client",
    "list_authorized_clients",
    "revoke_authorized_client",
    "generate_client_keypair",
]
