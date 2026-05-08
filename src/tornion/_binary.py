"""tor binary discovery, download, and installation.

Resolution priority when looking for a usable tor binary:
    1. $TORNION_TOR_PATH env var
    2. tornion cache (~/.cache/tornion/tor/)
    3. tor in PATH (`apt install tor` / `brew install tor`)
    4. Tor Browser known locations (Win/macOS)
    5. Auto-install (Tor Expert Bundle download) — opt-in via auto_install=True
"""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, Optional

from .exceptions import TorBinaryNotFound

#: Default Tor Expert Bundle version downloaded by ``install_tor()``.
#: Bumped when a new stable line is published.
#: List of versions: https://archive.torproject.org/tor-package-archive/torbrowser/
DEFAULT_TOR_VERSION = "15.0.11"

TOR_DOWNLOAD_BASE = "https://archive.torproject.org/tor-package-archive/torbrowser"

#: Pinned SHA-256 hashes for ``tor-expert-bundle-{suffix}-{version}.tar.gz``.
#: Hashes are verified against the Tor Project's signed checksums file
#: (``sha256sums-signed-build.txt``) at the time a version is added here.
#: Once frozen in source, they protect against HTTPS compromise: even if the
#: archive at torproject.org is replaced, the bytes won't match what's pinned.
#:
#: Bumping ``DEFAULT_TOR_VERSION`` requires adding the corresponding entry.
KNOWN_TOR_HASHES: Dict[str, Dict[str, str]] = {
    "15.0.11": {
        "linux-i686":     "983c02597becc14aed304d001099496a4c5812ac02f8322194fce7a8013a5eb0",
        "linux-x86_64":   "ff2992e410181aa1e21339a226bfb67fc37f919ff30a63075fa69a691b05a339",
        "macos-aarch64":  "21abf38f0e0d6803c5171db61ba92de3ebd0cb40621e43a128de3c5a49eb0d9b",
        "macos-x86_64":   "85b26ddd5a2e4e7b04e33c7551076c64710c90c78499d973cf2fc3b4f339ba4d",
        "windows-i686":   "c4bc9345655913fed71e05d4a9f7d599cfab65bb6adfd6df55dde9f3e887153b",
        "windows-x86_64": "65e7b0916d75faefc5e385fe894aea49d1b7f961759df0c8aaf211c905bbb42b",
    },
}


def _expected_hash(version: str, suffix: str) -> Optional[str]:
    """Return the pinned SHA-256 for a (version, platform), or None if unknown."""
    return KNOWN_TOR_HASHES.get(version, {}).get(suffix)


def _hash_file(path: Path, *, chunk_size: int = 1 << 20) -> str:
    """Stream a file through SHA-256 and return the hex digest."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


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
    sha256: Optional[str] = None,
) -> Path:
    """Download, verify, and extract the Tor Expert Bundle into the user cache.

    The downloaded archive is checked against a pinned SHA-256 before
    extraction. Hashes for known versions live in ``KNOWN_TOR_HASHES``.

    Args:
        version: Bundle version, e.g. "15.0.11".
        force: Re-download even if a tor binary is already cached.
        progress: Print a progress bar and status lines to stdout.
        sha256: Override the pinned hash (use when installing a version not
            yet known to this tornion release, after manually verifying it
            against the Tor Project's signed sha256sums file).

    Raises:
        TorBinaryNotFound: if the version is not pinned and no explicit
            ``sha256`` is provided, if the download fails, or if the
            archive's actual hash does not match the expected value.
    """
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

    # Resolve expected hash up front so we fail fast on unknown versions
    # without spending bandwidth on a download we'd refuse to extract.
    expected_hash = sha256 if sha256 is not None else _expected_hash(version, suffix)
    skip_check = os.environ.get("TORNION_INSECURE_SKIP_HASH_CHECK") == "1"

    if expected_hash is None and not skip_check:
        raise TorBinaryNotFound(
            f"No SHA-256 hash on file for {archive_name}.\n"
            f"This is a security check — tornion only installs Tor Expert\n"
            f"Bundle versions whose contents have been verified at release\n"
            f"time. To proceed:\n"
            f"  - Use a supported version: {sorted(KNOWN_TOR_HASHES)}\n"
            f"  - OR pass `sha256='...'` to install_tor() (verify it yourself\n"
            f"    against {TOR_DOWNLOAD_BASE}/{version}/sha256sums-signed-build.txt)\n"
            f"  - OR set TORNION_INSECURE_SKIP_HASH_CHECK=1 (NOT recommended;\n"
            f"    the binary will only be authenticated by HTTPS)"
        )

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

        if expected_hash is not None:
            actual = _hash_file(tmp_path)
            if actual != expected_hash:
                tmp_path.unlink(missing_ok=True)
                raise TorBinaryNotFound(
                    f"SHA-256 mismatch for {url}\n"
                    f"  expected: {expected_hash}\n"
                    f"  actual:   {actual}\n"
                    f"\n"
                    f"This usually means: HTTPS interception, a corrupted or\n"
                    f"partial download, or tornion shipping a stale hash for\n"
                    f"a re-released version. The downloaded archive has been\n"
                    f"deleted; re-run to retry."
                )
            if progress:
                print(f"   sha256 ok ({actual[:16]}…)")
        elif progress:
            print(f"   ⚠ sha256 NOT verified (TORNION_INSECURE_SKIP_HASH_CHECK=1)")

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
