"""Tor v3 hidden service client authorization helpers.

What this enables: an operator of a `.onion` service can restrict who
can connect to it. Without client auth, anyone who knows the .onion
address can reach the service. With it, the client must also possess
an x25519 private key that matches a public key the operator placed
on the server. Knowing the URL is no longer enough.

How it works under tor (rend-spec-v3.txt §G):

  - Each authorized client has an x25519 key pair.
  - The operator places the PUBLIC key on the server in
    `<key_dir>/authorized_clients/<nickname>.auth` with format:
        descriptor:x25519:<BASE32_PUBLIC_KEY>
  - When the HS publishes its descriptor, the introduction-point info
    is encrypted with all authorized clients' public keys (one envelope
    each). A client without the matching private key downloads the
    descriptor but cannot decrypt the IP info, and times out trying to
    connect.
  - The PRIVATE key lives on the client side in a file under
    `<ClientOnionAuthDir>/<name>.auth_private` with format:
        <onion-address-without-.onion>:descriptor:x25519:<BASE32_PRIVATE_KEY>
    Tor reads this directory on startup.

Crypto: x25519 (Curve25519, RFC 7748). We implement it in pure Python
rather than depending on `cryptography` — the operation is fast enough
for key generation (which is rare), and avoiding the dep keeps tornion
installable everywhere with no C-extension build step. RFC 7748 §6.1
test vectors are checked in the unit tests.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Iterator, List, NamedTuple, Optional, Tuple

# ---------------------------------------------------------------------------
# x25519 — RFC 7748, in pure Python.
#
# We need exactly two operations:
#   - scalar_mult_base(secret) → public key  (private → public derivation)
#   - the encoding/decoding wrappers handle the bit-clamping per RFC 7748 §5.
# ---------------------------------------------------------------------------

_P = 2**255 - 19  # the Curve25519 field prime
_A24 = 121665     # (A - 2) / 4, with A = 486662, the curve's Montgomery a


def _decode_u(u_bytes: bytes) -> int:
    """Decode a 32-byte u-coordinate, masking the high bit per RFC 7748."""
    if len(u_bytes) != 32:
        raise ValueError(f"u-coordinate must be 32 bytes, got {len(u_bytes)}")
    arr = bytearray(u_bytes)
    arr[31] &= 0x7F  # clear bit 255 (RFC 7748 §5)
    return int.from_bytes(arr, "little")


def _decode_scalar(scalar_bytes: bytes) -> int:
    """Decode a 32-byte scalar with the ed25519/x25519 clamping applied."""
    if len(scalar_bytes) != 32:
        raise ValueError(f"scalar must be 32 bytes, got {len(scalar_bytes)}")
    arr = bytearray(scalar_bytes)
    arr[0]  &= 248   # clear bottom 3 bits (cofactor 8)
    arr[31] &= 127   # clear top bit
    arr[31] |= 64    # set second-top bit
    return int.from_bytes(arr, "little")


def _encode_u(x: int) -> bytes:
    """Encode a field element back to its 32-byte little-endian form."""
    return (x % _P).to_bytes(32, "little")


def _x25519(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    """Compute the x25519 scalar multiplication: scalar * (u, ...).

    Algorithm: Montgomery ladder per RFC 7748 §5. Constant-time over the
    scalar bits — though Python's bigints leak timing through allocation,
    so this is NOT a hardened implementation; it's only used for key
    derivation, where the input scalar is freshly generated and never
    reused, making timing observations meaningless in practice.
    """
    k = _decode_scalar(scalar_bytes)
    u = _decode_u(u_bytes)

    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0

    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        A  = (x_2 + z_2) % _P
        AA = (A * A) % _P
        B  = (x_2 - z_2) % _P
        BB = (B * B) % _P
        E  = (AA - BB) % _P
        C  = (x_3 + z_3) % _P
        D  = (x_3 - z_3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P

        x_3 = pow((DA + CB), 2, _P)
        z_3 = (x_1 * pow((DA - CB), 2, _P)) % _P
        x_2 = (AA * BB) % _P
        z_2 = (E * (AA + _A24 * E)) % _P

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    # x_2 / z_2 mod _P  (Fermat's little theorem for the inverse)
    return _encode_u(x_2 * pow(z_2, _P - 2, _P))


# The x25519 base point u-coordinate is 9.
_BASE_POINT = b"\x09" + b"\x00" * 31


def _public_from_private(private_bytes: bytes) -> bytes:
    """Derive the x25519 public key from a 32-byte private key."""
    return _x25519(private_bytes, _BASE_POINT)


# ---------------------------------------------------------------------------
# Base32 encoding — tor's `.auth` and `.auth_private` files want uppercase
# base32 without the trailing '=' padding.
# ---------------------------------------------------------------------------

def _b32encode(b: bytes) -> str:
    """Uppercase base32, no padding (tor's convention for auth keys)."""
    return base64.b32encode(b).decode("ascii").rstrip("=")


def _b32decode(s: str) -> bytes:
    """Inverse of ``_b32encode``: accept either-case, re-add padding."""
    s = s.strip().upper()
    pad = "=" * ((-len(s)) % 8)
    return base64.b32decode(s + pad)


# ---------------------------------------------------------------------------
# Public API: key pair generation
# ---------------------------------------------------------------------------

class ClientKeyPair(NamedTuple):
    """A v3 hidden-service client authorization key pair (base32 form).

    Both ``public`` and ``private`` are 52-character uppercase base32
    strings of the corresponding 32-byte raw keys, suitable for
    interpolation into tor's ``descriptor:x25519:<key>`` format.
    """
    public: str
    private: str


def generate_keypair() -> ClientKeyPair:
    """Generate a fresh x25519 keypair for tor v3 client authorization.

    The private key is 32 bytes from ``os.urandom``; the public key is
    derived by scalar multiplication against the curve's base point.
    """
    private_raw = os.urandom(32)
    public_raw = _public_from_private(private_raw)
    return ClientKeyPair(
        public=_b32encode(public_raw),
        private=_b32encode(private_raw),
    )


# ---------------------------------------------------------------------------
# Server side: <key_dir>/authorized_clients/<nickname>.auth
# ---------------------------------------------------------------------------

_AUTH_DIR_NAME = "authorized_clients"
_AUTH_FILE_SUFFIX = ".auth"
_AUTH_LINE_FORMAT = "descriptor:x25519:{pubkey}"


def _validate_nickname(nickname: str) -> str:
    """Reject nicknames that wouldn't be valid filenames or contain path bits."""
    nickname = nickname.strip()
    if not nickname:
        raise ValueError("nickname must be non-empty")
    if "/" in nickname or "\\" in nickname or nickname.startswith(".") or "\x00" in nickname:
        raise ValueError(f"invalid nickname {nickname!r}: must be a plain filename")
    return nickname


def add_authorized_client(
    key_dir: Path | str,
    nickname: str,
    public_key: Optional[str] = None,
) -> ClientKeyPair:
    """Authorize a client to reach the hidden service hosted at ``key_dir``.

    Args:
        key_dir: Directory holding the HS identity (``hs_ed25519_secret_key``).
        nickname: Arbitrary label for this client (e.g. "alice", "phone").
            Becomes the filename ``authorized_clients/<nickname>.auth``.
        public_key: If provided, the client's x25519 public key in base32
            form (52 chars). Use this when the client has already generated
            their key pair and given you the public half. If None, tornion
            generates a fresh keypair and returns both halves — give the
            ``.private`` field to the client.

    Returns:
        :class:`ClientKeyPair`. When ``public_key`` was provided, the
        ``private`` field is the empty string (we don't have it).

    Raises:
        ValueError: nickname or public_key is malformed, or an entry with
            that nickname already exists.
        FileNotFoundError: ``key_dir`` doesn't exist.
    """
    key_dir = Path(key_dir).expanduser().resolve()
    if not key_dir.exists():
        raise FileNotFoundError(f"{key_dir} does not exist")

    nickname = _validate_nickname(nickname)

    if public_key is None:
        keypair = generate_keypair()
    else:
        # Validate the supplied key parses correctly and is the right size.
        try:
            raw = _b32decode(public_key)
        except Exception as e:
            raise ValueError(f"public_key is not valid base32: {e}") from e
        if len(raw) != 32:
            raise ValueError(
                f"public_key must decode to 32 bytes, got {len(raw)}"
            )
        keypair = ClientKeyPair(public=public_key.strip().upper(), private="")

    auth_dir = key_dir / _AUTH_DIR_NAME
    auth_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(auth_dir, 0o700)

    auth_file = auth_dir / (nickname + _AUTH_FILE_SUFFIX)
    if auth_file.exists():
        raise ValueError(
            f"client {nickname!r} is already authorized for {key_dir} "
            f"(remove {auth_file} first to re-authorize)"
        )

    auth_file.write_text(_AUTH_LINE_FORMAT.format(pubkey=keypair.public) + "\n")
    if os.name == "posix":
        os.chmod(auth_file, 0o600)

    return keypair


def revoke_authorized_client(key_dir: Path | str, nickname: str) -> bool:
    """Remove a client's authorization. Returns True iff the file existed.

    Tor picks up the change on the next descriptor republication, which
    happens roughly every hour by default — so revocation isn't instant.
    Restart the HS via ``tornion serve`` for an immediate effect.
    """
    key_dir = Path(key_dir).expanduser().resolve()
    nickname = _validate_nickname(nickname)
    auth_file = key_dir / _AUTH_DIR_NAME / (nickname + _AUTH_FILE_SUFFIX)
    if not auth_file.exists():
        return False
    auth_file.unlink()
    return True


def list_authorized_clients(key_dir: Path | str) -> List[Tuple[str, str]]:
    """Return ``[(nickname, public_key_b32), ...]`` for the given HS key_dir."""
    key_dir = Path(key_dir).expanduser().resolve()
    auth_dir = key_dir / _AUTH_DIR_NAME
    if not auth_dir.exists():
        return []

    result: List[Tuple[str, str]] = []
    for entry in sorted(auth_dir.iterdir()):
        if not entry.name.endswith(_AUTH_FILE_SUFFIX):
            continue
        nickname = entry.name[: -len(_AUTH_FILE_SUFFIX)]
        try:
            line = entry.read_text().strip()
        except OSError:
            continue
        # Expected: "descriptor:x25519:<KEY>"
        parts = line.split(":")
        pubkey = parts[2] if len(parts) >= 3 else "<malformed>"
        result.append((nickname, pubkey))
    return result


# ---------------------------------------------------------------------------
# Client side: <ClientOnionAuthDir>/<onion-stem>.auth_private
# ---------------------------------------------------------------------------

_AUTH_PRIVATE_SUFFIX = ".auth_private"
_AUTH_PRIVATE_FORMAT = "{onion_stem}:descriptor:x25519:{privkey}"


def _strip_onion(onion: str) -> str:
    """Normalize 'http://xxx.onion/' / 'xxx.onion' → 'xxx' (the address stem)."""
    o = onion.strip().lower()
    # Strip protocol if present
    for prefix in ("http://", "https://"):
        if o.startswith(prefix):
            o = o[len(prefix):]
    # Strip trailing path / port
    o = o.split("/", 1)[0].split(":", 1)[0]
    if o.endswith(".onion"):
        o = o[: -len(".onion")]
    if not o:
        raise ValueError(f"could not extract onion stem from {onion!r}")
    return o


def default_client_auth_dir() -> Path:
    """Return tornion's default ``ClientOnionAuthDir``.

    Lives under the user data dir alongside hidden-service keys so it
    survives reboots. Created with mode 0700 on POSIX.
    """
    from . import _binary
    p = _binary.data_dir() / "client-auth"
    p.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(p, 0o700)
    return p


def add_client_auth(
    onion: str,
    private_key: str,
    auth_dir: Optional[Path | str] = None,
) -> Path:
    """Register a client-auth private key for ``onion``.

    Writes ``<auth_dir>/<onion-stem>.auth_private`` with the tor-expected
    format. ``auth_dir`` defaults to :func:`default_client_auth_dir`.

    Returns the path of the written file.

    NOTE: tor reads the auth directory on startup. If tornion's client
    tor is already running when you call this, the new authorization
    will only take effect on the next tor restart — call
    :func:`tornion.shutdown` to force one.
    """
    onion_stem = _strip_onion(onion)
    # Validate the private key parses and has the right size.
    raw = _b32decode(private_key)
    if len(raw) != 32:
        raise ValueError(
            f"private_key must decode to 32 bytes, got {len(raw)}"
        )

    target_dir = Path(auth_dir).expanduser().resolve() if auth_dir else default_client_auth_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(target_dir, 0o700)

    target = target_dir / (onion_stem + _AUTH_PRIVATE_SUFFIX)
    line = _AUTH_PRIVATE_FORMAT.format(
        onion_stem=onion_stem,
        privkey=private_key.strip().upper(),
    )
    target.write_text(line + "\n")
    if os.name == "posix":
        os.chmod(target, 0o600)
    return target


def remove_client_auth(
    onion: str,
    auth_dir: Optional[Path | str] = None,
) -> bool:
    """Forget a previously-added client auth. Returns True iff a file was removed."""
    onion_stem = _strip_onion(onion)
    target_dir = Path(auth_dir).expanduser().resolve() if auth_dir else default_client_auth_dir()
    target = target_dir / (onion_stem + _AUTH_PRIVATE_SUFFIX)
    if not target.exists():
        return False
    target.unlink()
    return True


def list_client_auth(auth_dir: Optional[Path | str] = None) -> List[str]:
    """Return the list of onion stems for which we have a registered private key."""
    target_dir = Path(auth_dir).expanduser().resolve() if auth_dir else default_client_auth_dir()
    if not target_dir.exists():
        return []
    return sorted(
        f.name[: -len(_AUTH_PRIVATE_SUFFIX)]
        for f in target_dir.iterdir()
        if f.name.endswith(_AUTH_PRIVATE_SUFFIX)
    )
