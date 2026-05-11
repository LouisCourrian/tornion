"""HTTP client side: requests-style API that routes through Tor."""
from .._client_auth import (
    add_client_auth,
    default_client_auth_dir,
    list_client_auth,
    remove_client_auth,
)
from .session import (
    DEFAULT_TIMEOUT,
    OnionSession,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
)

# Friendly alias — `client.Session()` reads more naturally than OnionSession
Session = OnionSession

__all__ = [
    "Session",
    "OnionSession",
    "request",
    "get",
    "post",
    "put",
    "delete",
    "head",
    "patch",
    "options",
    "DEFAULT_TIMEOUT",
    # Client authorization (auth keys to reach restricted hidden services)
    "add_client_auth",
    "list_client_auth",
    "remove_client_auth",
    "default_client_auth_dir",
]
