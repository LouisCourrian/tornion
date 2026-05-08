"""HTTP client side: requests-style API that routes through Tor."""
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
]
