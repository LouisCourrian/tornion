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


def _probe_socks5(host: str, port: int, timeout: float = 0.3) -> bool:
    """Return True if host:port speaks SOCKS5 (no-auth method offered)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")  # SOCKS5 client greeting
            resp = s.recv(2)
            return len(resp) == 2 and resp[0] == 0x05
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
                log.info("reusing existing tor on SOCKS5 :%d", existing)
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
    """Manually shut down the managed client tor instance."""
    if TorManager._instance is not None:
        TorManager._instance.stop()


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

    # Per-HS DataDirectory based on key_dir hash to avoid collisions
    data_dir = _binary.cache_dir() / "tor-data" / f"hs-{abs(hash(str(key_dir))):x}"
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
