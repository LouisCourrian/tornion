"""Optional, secure auto-update of the Tor Expert Bundle.

A Python port of the approach used in OnionRooter's ``tor_update.rs``.

A single hard-pinned version (``_binary.DEFAULT_TOR_VERSION``) is always the
guaranteed fallback. When auto-update is enabled, this module instead:

    1. discovers the latest **stable** Tor Browser version from the package
       archive (alphas like ``16.0a7`` are ignored),
    2. downloads ``sha256sums-signed-build.txt`` and its detached ``.asc``,
    3. **verifies the PGP signature** against the Tor Browser build signing
       key embedded in the package (``assets/tor-signing-key.asc``,
       fingerprint ``EF6E286D…93298290``),
    4. extracts the SHA-256 for the host platform's expert bundle from the
       *signed* sums.

That hash is then handed to :func:`tornion._binary.install_tor`, which
re-verifies it before extraction. The net effect: tornion can install a
version whose hash it never shipped, yet the bytes are still authenticated —
not by HTTPS alone, but by the Tor Project's own signature.

This module requires the ``[autoupdate]`` extra (PGPy) and is imported lazily,
so the base install never pulls a PGP stack. Every public entry point here is
**failure-tolerant**: any network, parse, or signature error returns ``None``
so the caller falls back to the pinned/cached binary instead of breaking.
"""
from __future__ import annotations

import logging
import ssl
import sys
import types
import urllib.request
from importlib import resources
from typing import Optional, Tuple

log = logging.getLogger("tornion")


def _ensure_pgp_importable() -> None:
    """Make ``import pgpy`` work on Python 3.13+, which removed ``imghdr``.

    PGPy imports the stdlib ``imghdr`` module at load time (only to sniff
    image types in OpenPGP user-attribute packets — irrelevant to signature
    verification). ``imghdr`` was removed in Python 3.13 (PEP 594), so
    ``import pgpy`` raises ``ModuleNotFoundError`` there. We install a tiny
    no-op stub before importing pgpy so the [autoupdate] extra keeps working
    on 3.13. On older Pythons the real module imports and this is a no-op.
    """
    try:
        import imghdr  # noqa: F401
    except ImportError:
        stub = types.ModuleType("imghdr")
        stub.what = lambda *args, **kwargs: None  # type: ignore[attr-defined]
        sys.modules["imghdr"] = stub

#: Expected fingerprint of the embedded Tor Browser build signing key. Checked
#: at load time so a swapped-out asset can't silently weaken verification.
TOR_KEY_FINGERPRINT = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"

_HTTP_TIMEOUT = 30  # seconds


def _signing_key_text() -> str:
    """Return the embedded Tor signing key (ASCII-armored)."""
    return (
        resources.files("tornion")
        .joinpath("assets/tor-signing-key.asc")
        .read_text(encoding="ascii")
    )


def _fetch(url: str) -> bytes:
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(url, context=ctx, timeout=_HTTP_TIMEOUT) as resp:
        return resp.read()


def version_tuple(s: str) -> Optional[Tuple[int, int, int]]:
    """Parse ``"X.Y.Z"`` into a comparable tuple, or None if not all-numeric.

    Anything with a non-digit component (e.g. an alpha ``16.0a7``) returns
    None, which keeps pre-releases out of the "latest stable" selection.
    """
    parts = s.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    nums = [int(p) for p in parts]
    nums += [0] * (3 - len(nums))  # pad 15 / 15.0 → 15.0.0
    return (nums[0], nums[1], nums[2])


def discover_latest(base_url: str) -> Optional[str]:
    """Return the highest **stable** version directory under ``base_url``.

    Parses the server's HTML directory index. Alphas/betas and any non
    ``digits-and-dots`` href are skipped. Returns None on any failure.
    """
    try:
        html = _fetch(base_url if base_url.endswith("/") else base_url + "/").decode(
            "utf-8", "replace"
        )
    except Exception as e:  # noqa: BLE001 — best-effort, never fatal
        log.warning("auto-update: could not list %s (%s)", base_url, e)
        return None

    best: Optional[Tuple[Tuple[int, int, int], str]] = None
    for piece in html.split('href="')[1:]:
        end = piece.find('"')
        if end == -1:
            continue
        href = piece[:end].rstrip("/")
        if not href or not all(c.isdigit() or c == "." for c in href):
            continue
        v = version_tuple(href)
        if v is not None and (best is None or v > best[0]):
            best = (v, href)
    return best[1] if best else None


def verify_sums(sums: bytes, sig: bytes) -> bool:
    """True iff ``sig`` is a valid Tor signature over ``sums``.

    Verifies against the embedded signing key (PGPy tries the primary key and
    its subkeys; Tor signs the sums with a subkey). Returns False on any error
    rather than raising, so callers can treat it as a plain gate.
    """
    try:
        import warnings

        _ensure_pgp_importable()
        import pgpy

        with warnings.catch_warnings():
            # PGPy emits noisy TODO warnings about self-sig/revocation parsing
            # that are irrelevant to detached-signature verification.
            warnings.simplefilter("ignore")
            key, _ = pgpy.PGPKey.from_blob(_signing_key_text())
            if key.fingerprint.replace(" ", "") != TOR_KEY_FINGERPRINT:
                log.error(
                    "auto-update: embedded signing key fingerprint mismatch "
                    "(got %s); refusing to verify", key.fingerprint
                )
                return False
            signature = pgpy.PGPSignature.from_blob(sig)
            return bool(key.verify(sums, signature))
    except Exception as e:  # noqa: BLE001
        log.warning("auto-update: PGP verification error (%s)", e)
        return False


def hash_for(sums: bytes, archive_name: str) -> Optional[str]:
    """Return the lowercase hex SHA-256 for ``archive_name`` in a sums file."""
    for raw in sums.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if line.endswith(archive_name):
            head = line.split()[0] if line.split() else ""
            if len(head) == 64 and all(c in "0123456789abcdefABCDEF" for c in head):
                return head.lower()
    return None


def resolve_latest(base_url: str, suffix: str) -> Optional[Tuple[str, str]]:
    """Resolve the latest stable, PGP-verified ``(version, sha256)``.

    Args:
        base_url: Tor package archive root (the same base tornion downloads
            bundles from, so the version, sums, and bundle share one origin).
        suffix: Platform suffix, e.g. ``"windows-x86_64"``.

    Returns:
        ``(version, sha256)`` for the host platform's expert bundle, or None
        if discovery, download, signature verification, or hash lookup failed.
        Never raises.
    """
    base_url = base_url.rstrip("/")
    latest = discover_latest(base_url)
    if latest is None:
        return None

    base = f"{base_url}/{latest}"
    try:
        sums = _fetch(f"{base}/sha256sums-signed-build.txt")
        sig = _fetch(f"{base}/sha256sums-signed-build.txt.asc")
    except Exception as e:  # noqa: BLE001
        log.warning("auto-update: could not fetch signed sums for %s (%s)", latest, e)
        return None

    if not verify_sums(sums, sig):
        log.warning(
            "auto-update: signature verification FAILED for %s — refusing", latest
        )
        return None

    archive = f"tor-expert-bundle-{suffix}-{latest}.tar.gz"
    digest = hash_for(sums, archive)
    if digest is None:
        log.warning("auto-update: no %s entry in verified sums", archive)
        return None

    return latest, digest
