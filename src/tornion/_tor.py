"""Tor lifecycle management.

Exposes:
    - TorManager: process-wide singleton that runs tor as a SOCKS client.
      Used by the `tornion.client` module. Lazily started, atexit-cleaned.
    - launch_tor_for_hidden_service(): low-level helper that spawns a tor
      subprocess configured to host a hidden service. Returns the proc
      handle plus the resolved .onion address. Used by `tornion.server`.
    - detect_running_tor(): probes 9050 / 9150 / $TORNION_SOCKS_PORT for an
      existing SOCKS5 server.
"""
from __future__ import annotations

import atexit
import hashlib
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Iterable, Optional, Tuple

import stem.process

from . import _binary
from .exceptions import TorBootstrapError, HiddenServiceError


def _stem_timeout(value: int) -> Optional[int]:
    """Return ``value`` everywhere except Windows, where stem rejects timeouts.

    ``stem.process.launch_tor_with_config(timeout=...)`` uses ``signal.alarm``
    under the hood, which is POSIX-only. On Windows passing any non-None
    timeout raises immediately ("You cannot launch tor with a timeout on
    Windows"). We swallow the timeout there; tor still streams its progress
    via ``init_msg_handler`` and exits when its parent dies thanks to
    ``take_ownership=True``.
    """
    return None if sys.platform == "win32" else value

log = logging.getLogger("tornion")

DEFAULT_BOOTSTRAP_TIMEOUT = 90  # seconds
DEFAULT_SOCKS_PROBE_PORTS = (9050, 9150)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _probe_socks5(host: str, port: int, timeout: float = 0.5) -> bool:
    """Return True iff host:port is a **Tor** SOCKS5 server.

    A plain SOCKS5 probe (greeting only) cannot distinguish Tor from any
    other SOCKS5 proxy — proxychains, dante, ``ssh -D``, etc. would all
    pass and tornion would happily route privacy-sensitive traffic
    through them. Two-step check instead:

        1. SOCKS5 greeting / auth-method negotiation
           (filters out non-SOCKS5 services).
        2. SOCKS5 RESOLVE request (command byte ``\\xf0``) — a Tor
           protocol extension. Plain SOCKS5 servers reply with
           REP=0x07 ("Command not supported") or close the connection;
           Tor parses and dispatches the command and returns any other
           REP code.

    Both must pass. A false positive would mean Tor's RESOLVE protocol
    is implemented by something that isn't Tor — unlikely in practice.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)

            # 1. SOCKS5 greeting: VER=5, 1 method, NO_AUTH (0x00).
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
                return False

            # 2. Tor-specific RESOLVE request.
            # Format: VER=5 CMD=0xF0 RSV=0 ATYP=3(domain) LEN DOMAIN PORT
            hostname = b"example.com"
            req = (
                b"\x05\xf0\x00\x03"
                + bytes([len(hostname)]) + hostname
                + b"\x00\x00"  # port=0, ignored by RESOLVE
            )
            s.sendall(req)
            resp = s.recv(10)
            if len(resp) < 2 or resp[0] != 0x05:
                return False
            # REP=0x07 means "Command not supported" → vanilla SOCKS5.
            # Any other REP code (success, network error, etc.) means
            # the server understood the command → Tor.
            return resp[1] != 0x07
    except (OSError, socket.timeout):
        return False


def detect_running_tor(
    ports: Iterable[int] = DEFAULT_SOCKS_PROBE_PORTS,
    host: str = "127.0.0.1",
) -> Optional[int]:
    """Return the SOCKS5 port of an existing running tor, or None.

    Resolution order:
        1. ``$TORNION_SOCKS_PORT`` if set and responsive.
        2. Each port in ``ports`` (default: 9050, 9150).
    """
    env = os.environ.get("TORNION_SOCKS_PORT")
    if env:
        try:
            p = int(env)
        except ValueError:
            log.warning("TORNION_SOCKS_PORT=%r is not a valid int, ignoring", env)
        else:
            if _probe_socks5(host, p):
                return p
            log.warning(
                "TORNION_SOCKS_PORT=%d set but no SOCKS5 server responding "
                "on that port — falling back to default probes",
                p,
            )

    for p in ports:
        if _probe_socks5(host, p):
            return p
    return None


# ---------------------------------------------------------------------------
# Client tor: process-wide singleton
# ---------------------------------------------------------------------------

class TorManager:
    """Lazily-started, process-wide tor client manager (singleton)."""

    _instance: Optional["TorManager"] = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._proc = None
        self._socks_port: Optional[int] = None
        self._tor_binary: Optional[str] = None
        self._external: bool = False

    @property
    def socks_port(self) -> int:
        if self._socks_port is None:
            raise RuntimeError("Tor not started — call start() first")
        return self._socks_port

    @property
    def tor_binary(self) -> Optional[str]:
        return self._tor_binary

    @property
    def is_external(self) -> bool:
        return self._external

    @property
    def is_running(self) -> bool:
        if self._external:
            return self._socks_port is not None
        return self._proc is not None and self._proc.poll() is None

    def start(
        self,
        socks_port: Optional[int] = None,
        bootstrap_timeout: int = DEFAULT_BOOTSTRAP_TIMEOUT,
        auto_install: bool = True,
        verbose: bool = False,
        extra_config: Optional[dict] = None,
        use_existing: bool = True,
    ) -> None:
        if self.is_running:
            return

        if use_existing and socks_port is None:
            existing = detect_running_tor()
            if existing is not None:
                self._socks_port = existing
                self._external = True
                # Surface this loudly: the user expects tornion to manage
                # tor; reusing an outside instance is a side effect they
                # should be aware of (and can disable via use_existing=False).
                log.warning(
                    "tornion reusing an externally-managed tor on SOCKS5 :%d "
                    "(detected via Tor RESOLVE protocol). Pass use_existing=False "
                    "to start a managed tor instead.", existing,
                )
                return

        port = socks_port if socks_port is not None else _free_port()
        binary = _binary.find_tor_binary(auto_install=auto_install)
        self._tor_binary = binary

        data_dir = _binary.cache_dir() / "tor-data" / f"client-{port}"
        data_dir.mkdir(parents=True, exist_ok=True)

        log.info("starting tor client (SOCKS=%d)", port)

        def _on_log(line: str) -> None:
            if verbose or "Bootstrapped 100%" in line:
                msg = line.split("] ", 1)[-1].strip() if "] " in line else line.strip()
                log.info("  tor: %s", msg)

        config = {
            "SocksPort": str(port),
            "ControlPort": "0",
            "Log": "NOTICE stdout",
            "DataDirectory": str(data_dir),
            "MaxMemInQueues": "256 MB",
        }

        # Wire up tornion's default client-auth directory so any
        # `tornion.client.add_client_auth(...)` registered before this
        # tor process started takes effect. Tor reads the dir on
        # startup; new files added later require a tor restart
        # (call tornion.shutdown() to force one).
        from . import _client_auth
        client_auth_dir = _client_auth.default_client_auth_dir()
        config["ClientOnionAuthDir"] = str(client_auth_dir)

        if extra_config:
            config.update(extra_config)

        try:
            self._proc = stem.process.launch_tor_with_config(
                tor_cmd=binary,
                config=config,
                init_msg_handler=_on_log,
                timeout=_stem_timeout(bootstrap_timeout),
                take_ownership=True,
            )
        except Exception as e:
            self._proc = None
            self._socks_port = None
            raise TorBootstrapError(f"tor bootstrap failed: {e}") from e

        self._socks_port = port
        self._external = False
        log.info("tor ready on SOCKS5 :%d", port)

    def stop(self) -> None:
        if self._external:
            self._socks_port = None
            self._external = False
            return

        if self._proc is not None:
            try:
                self._proc.kill()
            except Exception:
                pass
            self._proc = None
        self._socks_port = None

    @classmethod
    def get_or_start(cls, **kwargs) -> "TorManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
                atexit.register(cls._instance.stop)
            if not cls._instance.is_running:
                cls._instance.start(**kwargs)
        return cls._instance


def get_tor(**kwargs) -> TorManager:
    """Get (and start if needed) the process-wide TorManager singleton."""
    return TorManager.get_or_start(**kwargs)


def shutdown() -> None:
    """Manually shut down the managed client tor instance.

    Also invalidates the module-level default ``client.Session`` so that
    subsequent ``tornion.client.get(...)`` calls build a fresh session
    against the *next* tor's SOCKS port. Without this, a session
    captured the dead tor's port and every request would hang on a
    connection refused.
    """
    if TorManager._instance is not None:
        TorManager._instance.stop()
    # Late import to avoid the tornion._tor ↔ tornion.client.session cycle.
    try:
        from .client import session as _sess
        _sess._default_session = None
    except ImportError:
        pass
    # Same for the async default session, if the async client was ever used.
    # It may be bound to an already-closed event loop, so we just drop the
    # reference (mirroring the sync path) rather than awaiting aclose().
    try:
        from .client import async_session as _async_sess
        _async_sess._default_async_session = None
        _async_sess._default_async_loop = None
    except ImportError:
        # httpx not installed → async client was never used. Nothing to clear.
        pass


# ---------------------------------------------------------------------------
# Server-side helper: launch tor configured for a hidden service
# ---------------------------------------------------------------------------

def launch_tor_for_hidden_service(
    *,
    target_host: str,
    target_port: int,
    key_dir: Path,
    bootstrap_timeout: int = DEFAULT_BOOTSTRAP_TIMEOUT,
    auto_install: bool = True,
    verbose: bool = False,
    onion_port: int = 80,
) -> Tuple[object, str]:
    """Spawn a tor subprocess configured to host a hidden service.

    Args:
        target_host: Local host where the user's HTTP server listens.
        target_port: Local port the HTTP server listens on.
        key_dir: Directory holding (or where to create) the v3 ed25519 key.
            Must be 0700 on POSIX. Kept persistent so the .onion is stable.
        bootstrap_timeout: Max seconds to wait for tor bootstrap.
        auto_install: Auto-download the tor binary if missing.
        verbose: Stream tor's NOTICE-level logs.
        onion_port: Public port advertised on the .onion (default 80).

    Returns:
        (proc, onion_url) where proc is the stem-managed subprocess and
        onion_url is the full http URL ('http://xxx.onion').
    """
    key_dir = Path(key_dir).expanduser().resolve()
    key_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(key_dir, 0o700)

    binary = _binary.find_tor_binary(auto_install=auto_install)

    # Per-HS DataDirectory based on a *stable* hash of the key_dir path.
    # Using builtin hash() here would pick up Python's per-process
    # PYTHONHASHSEED randomization, creating a new tor-data subdir on
    # every run and accumulating cruft. SHA-256 of the normalized path
    # is deterministic across processes and Python versions.
    key_dir_digest = hashlib.sha256(str(key_dir).encode("utf-8")).hexdigest()[:16]
    data_dir = _binary.cache_dir() / "tor-data" / f"hs-{key_dir_digest}"
    data_dir.mkdir(parents=True, exist_ok=True)

    def _on_log(line: str) -> None:
        if verbose or "Bootstrapped 100%" in line:
            msg = line.split("] ", 1)[-1].strip() if "] " in line else line.strip()
            log.info("  tor: %s", msg)

    config = {
        "SocksPort": "0",                # no client mode
        "ControlPort": "0",
        "Log": "NOTICE stdout",
        "DataDirectory": str(data_dir),
        "HiddenServiceDir": str(key_dir),
        "HiddenServiceVersion": "3",
        "HiddenServicePort": f"{onion_port} {target_host}:{target_port}",
        "MaxMemInQueues": "256 MB",
    }

    log.info("starting tor for hidden service (target=%s:%d)", target_host, target_port)

    try:
        proc = stem.process.launch_tor_with_config(
            tor_cmd=binary,
            config=config,
            init_msg_handler=_on_log,
            timeout=_stem_timeout(bootstrap_timeout),
            take_ownership=True,
        )
    except Exception as e:
        raise TorBootstrapError(f"tor bootstrap failed: {e}") from e

    # Read the .onion hostname (tor writes it as soon as the HS dir is loaded)
    hostname_file = key_dir / "hostname"
    deadline = time.time() + 30
    while time.time() < deadline:
        if hostname_file.exists():
            onion = hostname_file.read_text().strip()
            log.info("hidden service published: %s", onion)
            return proc, f"http://{onion}"
        time.sleep(0.1)

    try:
        proc.kill()
    except Exception:
        pass
    raise HiddenServiceError(
        f"tor did not publish a hostname file within 30s (key_dir={key_dir})"
    )
