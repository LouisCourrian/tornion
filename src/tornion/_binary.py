"""tor binary discovery, download, and installation.

Resolution priority when looking for a usable tor binary:
    1. $TORNION_TOR_PATH env var
    2. tornion cache (~/.cache/tornion/tor/)
    3. tor in PATH (`apt install tor` / `brew install tor`)
    4. Tor Browser known locations (Win/macOS)
    5. Auto-install (Tor Expert Bundle download) — opt-in via auto_install=True
"""
from __future__ import annotations

import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

from .exceptions import TorBinaryNotFound

#: Default Tor Expert Bundle version downloaded by ``install_tor()``.
#: Bumped when a new stable line is published.
#: List of versions: https://archive.torproject.org/tor-package-archive/torbrowser/
DEFAULT_TOR_VERSION = "15.0.11"

TOR_DOWNLOAD_BASE = "https://archive.torproject.org/tor-package-archive/torbrowser"


def cache_dir() -> Path:
    """Return the tornion per-user cache directory, creating it if needed."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    p = base / "tornion"
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir() -> Path:
    """Return the tornion per-user persistent data directory.

    Used to store hidden service keys (so the .onion address is stable across
    restarts of the same app).
    """
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    p = base / "tornion"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _bin_name() -> str:
    return "tor.exe" if sys.platform == "win32" else "tor"


def _detect_platform_suffix() -> str:
    """Map current platform to a Tor Expert Bundle filename suffix."""
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Linux":
        if machine in ("x86_64", "amd64"):
            return "linux-x86_64"
        if machine in ("aarch64", "arm64"):
            return "linux-aarch64"
    elif system == "Darwin":
        if machine in ("arm64", "aarch64"):
            return "macos-aarch64"
        if machine in ("x86_64", "amd64"):
            return "macos-x86_64"
    elif system == "Windows":
        if machine in ("amd64", "x86_64"):
            return "windows-x86_64"
        if machine in ("i386", "i686", "x86"):
            return "windows-i686"

    raise TorBinaryNotFound(
        f"No Tor Expert Bundle available for {system}/{machine}. "
        f"Build tor from source and set TORNION_TOR_PATH."
    )


def installed_tor_path() -> Optional[Path]:
    """Return the path of tor in tornion's cache, or None if not installed."""
    p = cache_dir() / "tor" / _bin_name()
    return p if p.exists() else None


def _tor_browser_locations() -> list[Path]:
    """Return possible Tor Browser tor binary paths for the current OS."""
    paths: list[Path] = []
    if sys.platform == "win32":
        userprofile = Path(os.environ.get("USERPROFILE", ""))
        paths += [
            userprofile / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            Path("C:/Program Files/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
            Path("C:/Program Files (x86)/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
        ]
    elif sys.platform == "darwin":
        paths += [
            Path("/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"),
        ]
    return paths


def find_tor_binary(
    auto_install: bool = True,
    version: str = DEFAULT_TOR_VERSION,
) -> str:
    """Locate a usable tor binary, optionally auto-installing one.

    Args:
        auto_install: If True (default), download the Tor Expert Bundle into
            the user cache when no system tor is found.
        version: Tor Expert Bundle version to fetch when auto-installing.

    Returns:
        Absolute filesystem path to a tor binary.

    Raises:
        TorBinaryNotFound: when no binary could be found and auto_install=False
            (or auto-install itself failed).
    """
    if env_path := os.environ.get("TORNION_TOR_PATH"):
        if Path(env_path).exists():
            return env_path

    if p := installed_tor_path():
        return str(p)

    if path := shutil.which("tor"):
        return path

    for cand in _tor_browser_locations():
        if cand.exists():
            return str(cand)

    if auto_install:
        return str(install_tor(version=version))

    raise TorBinaryNotFound(
        "No tor binary found. Install one with one of:\n"
        "  - `tornion install-tor` (downloads to user cache)\n"
        "  - `apt install tor` / `brew install tor`\n"
        "  - Set TORNION_TOR_PATH=/path/to/tor"
    )


def install_tor(
    version: str = DEFAULT_TOR_VERSION,
    force: bool = False,
    progress: bool = True,
) -> Path:
    """Download and extract the Tor Expert Bundle into the user cache."""
    if progress:
        # Make sure emoji-bearing prints below don't crash on cp1252 (Windows).
        from ._console import setup_console_encoding
        setup_console_encoding()

    target_dir = cache_dir() / "tor"
    target_bin = target_dir / _bin_name()

    if target_bin.exists() and not force:
        return target_bin

    suffix = _detect_platform_suffix()
    archive_name = f"tor-expert-bundle-{suffix}-{version}.tar.gz"
    url = f"{TOR_DOWNLOAD_BASE}/{version}/{archive_name}"

    if progress:
        print(f"⬇  tornion: downloading Tor Expert Bundle {version} ({suffix})")

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".tar.gz")
    os.close(tmp_fd)
    tmp_path = Path(tmp_path)
    try:
        try:
            if progress:
                _download_with_progress(url, tmp_path)
            else:
                urllib.request.urlretrieve(url, tmp_path)
        except Exception as e:
            raise TorBinaryNotFound(
                f"Failed to download {url}: {e}\n"
                f"Verify version {version} exists at "
                f"https://www.torproject.org/download/tor/"
            ) from e

        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True)

        with tarfile.open(tmp_path, "r:gz") as tar:
            try:
                tar.extractall(target_dir, filter="data")
            except TypeError:
                tar.extractall(target_dir)
    finally:
        tmp_path.unlink(missing_ok=True)

    if not target_bin.exists():
        candidates = list(target_dir.rglob(_bin_name()))
        if not candidates:
            raise TorBinaryNotFound(
                f"tor binary not found inside the extracted bundle"
            )
        src_bin = candidates[0]
        if src_bin.parent != target_bin.parent:
            for sibling in src_bin.parent.iterdir():
                shutil.move(str(sibling), str(target_bin.parent / sibling.name))

    if sys.platform != "win32":
        os.chmod(target_bin, 0o755)

    if progress:
        size_mb = target_bin.stat().st_size / (1024 * 1024)
        print(f"✅ tor ready at {target_bin} ({size_mb:.1f} MB)")

    return target_bin


def _download_with_progress(url: str, dest: Path) -> None:
    def _hook(blocks: int, bsize: int, total: int) -> None:
        downloaded = blocks * bsize
        if total > 0:
            pct = min(100, int(100 * downloaded / total))
            bar_w = 30
            filled = pct * bar_w // 100
            bar = "█" * filled + "░" * (bar_w - filled)
            kb = downloaded // 1024
            print(f"\r   [{bar}] {pct:3d}%  {kb:>7d} KB", end="", flush=True)
        else:
            kb = downloaded // 1024
            print(f"\r   {kb} KB", end="", flush=True)

    urllib.request.urlretrieve(url, dest, reporthook=_hook)
    print()
