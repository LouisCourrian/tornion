"""v3 hidden service identity helpers — key generation and address derivation.

Everything in this module is **offline and stdlib-only**: no tor process,
no network, no third-party crypto library. Used by the ``tornion keygen``
and ``tornion onion <key_dir>`` CLI subcommands so users can:

  - bootstrap a fixed onion identity before deploying a server
  - look up the .onion address of an existing key directory without
    spinning up tor

Key file formats follow rend-spec-v3.txt §6:

    hs_ed25519_secret_key  = 32-byte ASCII header || 64-byte expanded secret
    hs_ed25519_public_key  = 32-byte ASCII header || 32-byte public key
    hostname               = 56-char base32 of (pubkey || checksum || \\x03) + ".onion\\n"
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

# Header bytes that tor expects at the top of each key file
# (rend-spec-v3.txt §6). 32 bytes each, ASCII + null padding.
SECRET_KEY_HEADER = b"== ed25519v1-secret: type0 ==\x00\x00\x00"
PUBLIC_KEY_HEADER = b"== ed25519v1-public: type0 ==\x00\x00\x00"

# v3 .onion address derivation constants (rend-spec-v3.txt §6).
ONION_CHECKSUM_PREFIX = b".onion checksum"
ONION_V3_VERSION = b"\x03"

# Standard filenames inside a key directory.
SECRET_KEY_FILE = "hs_ed25519_secret_key"
PUBLIC_KEY_FILE = "hs_ed25519_public_key"
HOSTNAME_FILE = "hostname"


def generate_secret_key_blob() -> bytes:
    """Generate a fresh v3 ``hs_ed25519_secret_key`` blob (96 bytes).

    Layout: 32-byte header || 64-byte expanded ed25519 secret.

    The expanded form is ``SHA-512(seed)`` with the standard ed25519 bit
    clamping from RFC 8032 §5.1.5. The seed is 32 bytes of ``os.urandom``,
    so the resulting onion identity is unpredictable.
    """
    seed = os.urandom(32)
    h = bytearray(hashlib.sha512(seed).digest())
    h[0]  &= 248   # clear the bottom 3 bits     (multiple of cofactor 8)
    h[31] &= 127   # clear the top bit           (scalar < 2^254)
    h[31] |= 64    # set the 2nd-top bit         (scalar ≥ 2^254)
    return SECRET_KEY_HEADER + bytes(h)


def write_secret_key(key_dir: Path) -> Path:
    """Generate a key and write ``hs_ed25519_secret_key`` into ``key_dir``.

    Creates ``key_dir`` if needed. On POSIX, tightens permissions to
    0700 on the directory and 0600 on the file (tor refuses to load a
    HS dir that's group/world-readable). Returns the written path.
    """
    key_dir = key_dir.expanduser().resolve()
    key_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(key_dir, 0o700)

    target = key_dir / SECRET_KEY_FILE
    target.write_bytes(generate_secret_key_blob())
    if os.name == "posix":
        os.chmod(target, 0o600)
    return target


def read_public_key(public_key_path: Path) -> bytes:
    """Parse an ``hs_ed25519_public_key`` file → 32-byte raw public key."""
    data = public_key_path.read_bytes()
    if len(data) != 64 or not data.startswith(PUBLIC_KEY_HEADER):
        raise ValueError(
            f"{public_key_path} is not a valid hs_ed25519_public_key file "
            f"(expected 32-byte header + 32-byte key = 64 bytes, got {len(data)})"
        )
    return data[32:]


def onion_from_public_key(pubkey: bytes) -> str:
    """Derive a v3 ``.onion`` address from a 32-byte ed25519 public key.

    Per rend-spec-v3.txt §6::

        onion_address = base32(PUBKEY || CHECKSUM || VERSION).lower() + ".onion"
        CHECKSUM      = SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2]
        VERSION       = 0x03
    """
    if len(pubkey) != 32:
        raise ValueError(f"public key must be 32 bytes, got {len(pubkey)}")
    checksum = hashlib.sha3_256(
        ONION_CHECKSUM_PREFIX + pubkey + ONION_V3_VERSION
    ).digest()[:2]
    blob = pubkey + checksum + ONION_V3_VERSION
    return base64.b32encode(blob).decode("ascii").lower() + ".onion"


def onion_for_key_dir(key_dir: Path) -> str:
    """Return the ``.onion`` address for a HS key directory, fully offline.

    Lookup order:
        1. ``<key_dir>/hostname`` — tor writes this on first boot. Trivial.
        2. ``<key_dir>/hs_ed25519_public_key`` — derive via stdlib hashes.
        3. Only the secret key present → raise with a clear message.

    We deliberately don't derive the address from the secret key alone:
    that requires ed25519 scalar multiplication, which is not in the
    stdlib. The 30-second workaround is ``tornion serve`` once on the
    key_dir; tor writes the public key and hostname files on startup.
    """
    key_dir = key_dir.expanduser().resolve()
    if not key_dir.exists():
        raise ValueError(f"{key_dir} does not exist")

    hostname = key_dir / HOSTNAME_FILE
    if hostname.exists():
        return hostname.read_text().strip()

    public_key = key_dir / PUBLIC_KEY_FILE
    if public_key.exists():
        return onion_from_public_key(read_public_key(public_key))

    secret_key = key_dir / SECRET_KEY_FILE
    if secret_key.exists():
        raise ValueError(
            f"{key_dir} has only the secret key — to compute the .onion "
            f"address, run `tornion serve` once on this key_dir and tor "
            f"will derive the public key and hostname files."
        )

    raise ValueError(
        f"{key_dir} contains no v3 hidden service files "
        f"(expected one of: {HOSTNAME_FILE}, {PUBLIC_KEY_FILE}, {SECRET_KEY_FILE})"
    )
