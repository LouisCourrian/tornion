"""HTTP client side: requests-style API that routes through Tor.

The sync client (``requests``-based) is always available. The async client
(``httpx.AsyncClient``-based) is opt-in via ``pip install tornion[async]`` and
is imported lazily — accessing ``AsyncSession``/``aget``/… below triggers the
``httpx`` import on first use, so the base client stays lightweight.
"""
from typing import Any

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

# Async client symbols, resolved lazily so `httpx` is only required when the
# async API is actually used. Deliberately NOT added to ``__all__`` — keeping
# them out means ``from tornion.client import *`` never drags in httpx for
# users who only need the sync client.
_ASYNC_EXPORTS = frozenset({
    "AsyncSession",
    "AsyncOnionSession",
    "arequest",
    "aget",
    "apost",
    "aput",
    "adelete",
    "ahead",
    "apatch",
    "aoptions",
})


def __getattr__(name: str) -> Any:
    # PEP 562 module-level __getattr__: only consulted for names not already
    # defined above, so the sync API has zero overhead.
    if name in _ASYNC_EXPORTS:
        try:
            from . import async_session
        except ImportError as e:
            raise ImportError(
                f"tornion.client.{name} requires the async extra. "
                "Install it with:  pip install tornion[async]"
            ) from e
        return getattr(async_session, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
