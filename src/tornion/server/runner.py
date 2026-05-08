"""HiddenService class + serve() convenience function.

The server side mirrors the client side: same tor binary management,
same auto-download, same env vars. The difference is the tor config
(HiddenService* directives instead of SocksPort).
"""
from __future__ import annotations

import logging
import re
import signal
import threading
from pathlib import Path
from typing import Any, Optional

from .. import _binary, _tor
from ..exceptions import HiddenServiceError
from ._detection import normalize_to_asgi

log = logging.getLogger("tornion")


def _slugify(text: str) -> str:
    """Filesystem-safe slug, used to derive default key_dir name."""
    text = re.sub(r"[^a-zA-Z0-9._-]", "_", text)
    return text.strip("_") or "default"


def _resolve_key_dir(key_dir: Optional[str | Path], app_name: str) -> Path:
    """Pick where to store the hidden service ed25519 key.

    Default: <user data dir>/tornion/hs/<app_name>/
    """
    if key_dir is not None:
        p = Path(key_dir).expanduser().resolve()
    else:
        p = _binary.data_dir() / "hs" / _slugify(app_name)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class HiddenService:
    """Tor hidden service wrapper.

    Manages the tor subprocess that publishes a `.onion` address pointing
    to a local HTTP port. Does NOT run the HTTP server itself — pair this
    with :func:`serve` for the all-in-one experience, or run your own
    uvicorn / gunicorn / whatever and just point this at its port.

    Use as a context manager::

        with HiddenService(target_port=8000, key_dir="./mykeys") as hs:
            print(hs.onion_url)
            # Run your HTTP server on :8000 here
    """

    def __init__(
        self,
        *,
        target_port: int,
        target_host: str = "127.0.0.1",
        key_dir: Optional[str | Path] = None,
        app_name: str = "default",
        bootstrap_timeout: int = 90,
        auto_install: bool = True,
        verbose: bool = False,
        onion_port: int = 80,
    ) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.key_dir = _resolve_key_dir(key_dir, app_name)
        self.bootstrap_timeout = bootstrap_timeout
        self.auto_install = auto_install
        self.verbose = verbose
        self.onion_port = onion_port

        self._proc = None
        self._onion_url: Optional[str] = None

    # ---------- Properties ----------

    @property
    def onion_url(self) -> str:
        if self._onion_url is None:
            raise RuntimeError("HiddenService not started yet")
        return self._onion_url

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ---------- Lifecycle ----------

    def start(self) -> str:
        """Spawn tor, wait for HS publication, return the .onion URL."""
        if self.is_running:
            return self._onion_url  # type: ignore[return-value]

        proc, url = _tor.launch_tor_for_hidden_service(
            target_host=self.target_host,
            target_port=self.target_port,
            key_dir=self.key_dir,
            bootstrap_timeout=self.bootstrap_timeout,
            auto_install=self.auto_install,
            verbose=self.verbose,
            onion_port=self.onion_port,
        )
        self._proc = proc
        self._onion_url = url
        return url

    def stop(self) -> None:
        """Kill tor (idempotent)."""
        if self._proc is not None:
            try:
                self._proc.kill()
            except Exception:
                pass
            self._proc = None
        self._onion_url = None

    def __enter__(self) -> "HiddenService":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def serve(
    app: Any,
    *,
    host: str = "127.0.0.1",
    port: Optional[int] = None,
    key_dir: Optional[str | Path] = None,
    app_name: Optional[str] = None,
    bootstrap_timeout: int = 90,
    auto_install: bool = True,
    log_level: str = "warning",
    server_kwargs: Optional[dict] = None,
) -> None:
    """Run an ASGI/WSGI app behind a Tor hidden service.

    Blocks until SIGINT (Ctrl+C). On exit, both uvicorn and tor are stopped.

    Works with any ASGI framework (FastAPI, Starlette, Quart, Litestar, …)
    or any WSGI framework (Flask, Django, Bottle, …) — the latter is
    auto-wrapped via ``asgiref.wsgi.WsgiToAsgi``.

    Args:
        app: ASGI 3 callable, or WSGI app, or framework instance.
        host: Local interface uvicorn binds to. Default 127.0.0.1.
        port: Local port for uvicorn. None → free port (recommended;
            nothing on the host is exposed externally anyway).
        key_dir: Directory storing the .onion ed25519 key. Default:
            user data dir, slot named after `app_name`. Reuse the same
            directory across runs to keep a stable .onion address.
        app_name: Slug used to derive the default key_dir. Default:
            inferred from the app object.
        bootstrap_timeout: Max seconds to wait for tor bootstrap.
        auto_install: Auto-download tor if missing.
        log_level: uvicorn log level.
        server_kwargs: Extra kwargs forwarded to ``uvicorn.run``.

    Example:
        >>> from fastapi import FastAPI
        >>> import tornion
        >>> app = FastAPI()
        >>> tornion.serve(app)
    """
    try:
        import uvicorn
    except ImportError as e:
        raise ImportError(
            "tornion.serve() requires uvicorn. Install server extras:\n"
            "    pip install tornion[server]"
        ) from e

    # Make sure the emoji status lines below don't crash on cp1252 (Windows).
    from .._console import setup_console_encoding
    setup_console_encoding()

    asgi_app = normalize_to_asgi(app)

    if port is None:
        port = _free_port()

    if app_name is None:
        app_name = getattr(app, "title", None) or type(app).__name__ or "default"

    hs = HiddenService(
        target_host=host,
        target_port=port,
        key_dir=key_dir,
        app_name=app_name,
        bootstrap_timeout=bootstrap_timeout,
        auto_install=auto_install,
    )

    print("🧅 starting tor...")
    hs.start()
    print(f"\n🚀 hidden service published:\n   {hs.onion_url}")
    print(f"\n   key persisted at: {hs.key_dir}")
    print(f"   local port      : {port}")
    print("\nPress Ctrl+C to stop.\n")

    # Make sure tor is killed even if uvicorn crashes
    try:
        kwargs = {"host": host, "port": port, "log_level": log_level}
        if server_kwargs:
            kwargs.update(server_kwargs)
        uvicorn.run(asgi_app, **kwargs)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n→ shutting down tor...")
        hs.stop()
