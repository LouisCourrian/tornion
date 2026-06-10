"""Async HTTP layer: httpx.AsyncClient subclass + module-level aget/apost/… helpers.

This mirrors :mod:`tornion.client.session` but for asyncio. It is the
``httpx.AsyncClient``-style counterpart of the sync ``requests``-style client.

``httpx`` is an **optional** dependency — the sync client stays lightweight.
Install it with::

    pip install tornion[async]

Both clients share the same process-wide tor instance (the singleton
:class:`tornion._tor.TorManager`), so spinning up an :class:`AsyncOnionSession`
does not start a second tor when a sync session already runs, and vice versa.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

import httpx

from .. import _tor
from .session import DEFAULT_TIMEOUT

# Transient gateway errors worth retrying — same set as the sync client.
_RETRY_STATUSES = frozenset({502, 503, 504})
_DEFAULT_BACKOFF_FACTOR = 2  # seconds; exponential, mirrors the sync Retry


class AsyncOnionSession(httpx.AsyncClient):
    """An :class:`httpx.AsyncClient` that auto-routes traffic through Tor.

    Drop-in async counterpart of :class:`tornion.client.OnionSession`. Use it
    exactly like ``httpx.AsyncClient``::

        async with tornion.client.AsyncSession() as s:
            r = await s.get("http://xxx.onion/ping")
            await s.post("http://xxx.onion/items", json={...})

    Args:
        timeout: Default timeout for every request (in seconds).
        auto_install: Auto-download a tor binary into the user cache if no
            system tor is found. Default True.
        bootstrap_timeout: Max seconds to wait for tor bootstrap.
        retries: Number of retries on transient gateway errors (502/503/504).
        use_existing: If True (default), reuse an already-running tor SOCKS
            proxy detected on 9050/9150/$TORNION_SOCKS_PORT instead of
            spawning a new one.
        **httpx_kwargs: Any other keyword argument forwarded to
            ``httpx.AsyncClient`` (``headers``, ``auth``, ``limits``, …).

    Note:
        The constructor starts (or reuses) the shared tor process, which is a
        **blocking** operation the first time tor bootstraps. Inside an event
        loop, prefer :meth:`create` — it performs that startup in a worker
        thread so the loop is never blocked.
    """

    def __init__(
        self,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        auto_install: bool = True,
        bootstrap_timeout: int = 90,
        retries: int = 3,
        use_existing: bool = True,
        **httpx_kwargs: Any,
    ) -> None:
        tor = _tor.get_tor(
            auto_install=auto_install,
            bootstrap_timeout=bootstrap_timeout,
            use_existing=use_existing,
        )

        proxy = f"socks5h://127.0.0.1:{tor.socks_port}"

        # tornion owns the proxy + a Tor-appropriate default timeout. A caller
        # passing their own would silently bypass Tor, so we take precedence.
        httpx_kwargs.pop("proxy", None)
        httpx_kwargs.setdefault("timeout", timeout)

        super().__init__(proxy=proxy, **httpx_kwargs)

        self._retries = retries
        self._backoff_factor = _DEFAULT_BACKOFF_FACTOR

    @classmethod
    async def create(cls, **kwargs: Any) -> "AsyncOnionSession":
        """Async constructor that never blocks the event loop.

        Identical to ``AsyncOnionSession(**kwargs)`` but runs the (potentially
        slow) tor bootstrap in a worker thread::

            s = await tornion.client.AsyncSession.create()
            try:
                r = await s.get("http://xxx.onion/ping")
            finally:
                await s.aclose()

        The plain constructor is fine when tor is already running (instant) or
        when you don't mind blocking briefly during the one-time bootstrap.
        """
        return await asyncio.to_thread(lambda: cls(**kwargs))

    async def request(  # type: ignore[override]
        self, method: str, url: Any, **kwargs: Any
    ) -> httpx.Response:
        """Issue a request, retrying transient 502/503/504 with backoff.

        ``httpx`` only retries connection failures, not HTTP status codes, so
        we add status-based retries here to match the sync client's behavior.
        """
        attempt = 0
        while True:
            response = await super().request(method, url, **kwargs)
            if response.status_code not in _RETRY_STATUSES or attempt >= self._retries:
                return response
            # 0s on the first retry, then 2s, 6s, … (backoff_factor * (2**n - 1)).
            delay = self._backoff_factor * (2 ** attempt - 1)
            attempt += 1
            if delay:
                await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Module-level convenience helpers (mirroring httpx.get / httpx.post / …)
#
# A single shared AsyncOnionSession is reused so Tor circuits and connections
# are pooled across calls. httpx's connection pool binds to the event loop it
# first runs on, so we rebuild the default session if the running loop changes
# (e.g. a second asyncio.run() in the same process).
# ---------------------------------------------------------------------------

_default_async_session: Optional[AsyncOnionSession] = None
_default_async_loop: Optional[asyncio.AbstractEventLoop] = None


async def _get_default_async_session() -> AsyncOnionSession:
    global _default_async_session, _default_async_loop
    loop = asyncio.get_running_loop()
    if _default_async_session is None or _default_async_loop is not loop:
        # Off-loop construction: tor bootstrap must not block the event loop.
        _default_async_session = await AsyncOnionSession.create()
        _default_async_loop = loop
    return _default_async_session


async def arequest(method: str, url: Any, **kwargs: Any) -> httpx.Response:
    session = await _get_default_async_session()
    return await session.request(method, url, **kwargs)


async def aget(url: Any, **kwargs: Any) -> httpx.Response:
    return await arequest("GET", url, **kwargs)


async def apost(url: Any, **kwargs: Any) -> httpx.Response:
    return await arequest("POST", url, **kwargs)


async def aput(url: Any, **kwargs: Any) -> httpx.Response:
    return await arequest("PUT", url, **kwargs)


async def adelete(url: Any, **kwargs: Any) -> httpx.Response:
    return await arequest("DELETE", url, **kwargs)


async def ahead(url: Any, **kwargs: Any) -> httpx.Response:
    return await arequest("HEAD", url, **kwargs)


async def apatch(url: Any, **kwargs: Any) -> httpx.Response:
    return await arequest("PATCH", url, **kwargs)


async def aoptions(url: Any, **kwargs: Any) -> httpx.Response:
    return await arequest("OPTIONS", url, **kwargs)


# Friendly alias — `client.AsyncSession()` reads more naturally.
AsyncSession = AsyncOnionSession
