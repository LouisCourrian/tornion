"""HTTP layer: requests.Session subclass + module-level get/post/... helpers."""
from __future__ import annotations

from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .. import _tor

DEFAULT_TIMEOUT = 60  # seconds — Tor circuits warrant generous timeouts


class OnionSession(requests.Session):
    """A :class:`requests.Session` that auto-routes traffic through Tor.

    Drop-in replacement for ``requests.Session``. Use exactly like requests::

        with tornion.Session() as s:
            r = s.get("http://xxx.onion/ping")
            s.post("http://xxx.onion/items", json={...})

    Args:
        timeout: Default timeout for every request (in seconds).
        auto_install: Auto-download a tor binary into the user cache if no
            system tor is found. Default True.
        bootstrap_timeout: Max seconds to wait for tor bootstrap.
        retries: Number of retries on transient gateway errors (502/503/504).
        use_existing: If True (default), reuse an already-running tor SOCKS
            proxy detected on 9050/9150/$TORNION_SOCKS_PORT instead of
            spawning a new one.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        auto_install: bool = True,
        bootstrap_timeout: int = 90,
        retries: int = 3,
        use_existing: bool = True,
    ) -> None:
        super().__init__()

        tor = _tor.get_tor(
            auto_install=auto_install,
            bootstrap_timeout=bootstrap_timeout,
            use_existing=use_existing,
        )

        proxy_url = f"socks5h://127.0.0.1:{tor.socks_port}"
        self.proxies.update({"http": proxy_url, "https": proxy_url})

        retry_strategy = Retry(
            total=retries,
            backoff_factor=2,
            status_forcelist=[502, 503, 504],
            allowed_methods=frozenset(["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"]),
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

        self._default_timeout = timeout

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self._default_timeout)
        return super().request(method, url, **kwargs)


# ---------------------------------------------------------------------------
# Module-level convenience helpers (mirroring requests.get / requests.post / …)
# ---------------------------------------------------------------------------

_default_session: Optional[OnionSession] = None


def _get_default_session() -> OnionSession:
    global _default_session
    if _default_session is None:
        _default_session = OnionSession()
    return _default_session


def request(method: str, url: str, **kwargs: Any) -> requests.Response:
    return _get_default_session().request(method, url, **kwargs)


def get(url: str, **kwargs: Any) -> requests.Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    return request("POST", url, **kwargs)


def put(url: str, **kwargs: Any) -> requests.Response:
    return request("PUT", url, **kwargs)


def delete(url: str, **kwargs: Any) -> requests.Response:
    return request("DELETE", url, **kwargs)


def head(url: str, **kwargs: Any) -> requests.Response:
    return request("HEAD", url, **kwargs)


def patch(url: str, **kwargs: Any) -> requests.Response:
    return request("PATCH", url, **kwargs)


def options(url: str, **kwargs: Any) -> requests.Response:
    return request("OPTIONS", url, **kwargs)
