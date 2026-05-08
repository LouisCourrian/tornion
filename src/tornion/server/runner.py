"""HiddenService class + serve() convenience function.

The server side mirrors the client side: same tor binary management,
same auto-download, same env vars. The difference is the tor config
(HiddenService* directives instead of SocksPort).
"""
from __future__ import annotations

import logging
import re
import signal
import sys
import threading
from pathlib import Path
from typing import Any, Optional, Tuple

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


def _resolve_app_name(app: Any) -> Tuple[str, str]:
    """Pick a stable slug for the .onion identity, plus a human source label.

    Returned as ``(app_name, source)`` where ``source`` describes — in plain
    English — why this slug was chosen, so the user can see it on stdout.

    Resolution order, most-to-least preferred:
        1. Entry-script basename — ``python myserver.py`` → "myserver".
           Stable across reruns as long as the file name doesn't change.
        2. ``__main__`` module name — ``python -m mypackage`` → "mypackage".
        3. Hard fallback "default" (e.g. when called from a REPL).

    We deliberately do NOT consult ``app.title`` or ``type(app).__name__``:
    both shift between runs (default FastAPI title, refactored class name)
    and would silently invalidate the user's .onion identity.
    """
    argv0 = sys.argv[0] if sys.argv else ""
    if argv0 and not argv0.startswith("-"):
        stem = Path(argv0).stem
        if stem and stem not in ("__main__", "-c"):
            return stem, f"from entry script ({argv0})"

    main_mod = sys.modules.get("__main__")
    if main_mod is not None:
        spec = getattr(main_mod, "__spec__", None)
        if spec is not None and spec.name and spec.name != "__main__":
            return spec.name.replace(".", "_"), f"from __main__ module ({spec.name})"

    return "default", "no entry point detected — using fallback slug"


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
            the entry-script basename (`python myserver.py` → "myserver"),
            or the `__main__` module name when launched via `python -m`,
            falling back to "default" otherwise. Pass an explicit value
            for full control of where your identity lives.
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
        app_name, name_source = _resolve_app_name(app)
    else:
        name_source = "explicit app_name argument"

    # Resolve key_dir up front so we can tell the user, *before* tor bootstrap,
    # whether this run will publish a brand-new .onion or reuse an existing
    # one. Hidden in the past behind the HiddenService constructor — too late
    # for the user to notice that today's run has a different identity than
    # yesterday's.
    resolved_key_dir = _resolve_key_dir(key_dir, app_name)
    secret_key_file = resolved_key_dir / "hs_ed25519_secret_key"
    is_fresh_identity = not secret_key_file.exists()

    print("🧅 tornion — Tor hidden service")
    print(f"   app_name   : {app_name}  ({name_source})")
    print(f"   key_dir    : {resolved_key_dir}")
    if is_fresh_identity:
        print( "   identity   : NEW — a fresh .onion will be generated")
        print(f"                back up `{secret_key_file.name}` to keep this address")
    else:
        print( "   identity   : reusing existing key — same .onion as last run")
    print(f"   local port : {port}")
    print()
    print("🧅 starting tor...")

    hs = HiddenService(
        target_host=host,
        target_port=port,
        key_dir=resolved_key_dir,
        app_name=app_name,
        bootstrap_timeout=bootstrap_timeout,
        auto_install=auto_install,
    )

    hs.start()
    print(f"\n🚀 hidden service published:\n   {hs.onion_url}")
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
