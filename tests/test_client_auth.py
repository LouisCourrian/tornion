"""Unit tests for v3 hidden service client authorization helpers."""
from __future__ import annotations

from pathlib import Path

import pytest

from tornion import _client_auth


# ---------------------------------------------------------------------------
# x25519 — verify the pure-Python implementation against RFC 7748 §6.1
# vectors. If any of these fail, the crypto is broken and the rest of the
# module is unsafe.
# ---------------------------------------------------------------------------

# Alice's private key from RFC 7748 §6.1
_ALICE_PRIV_HEX = (
    "77076d0a7318a57d3c16c17251b26645"
    "df4c2f87ebc0992ab177fba51db92c2a"
)
_ALICE_PUB_HEX = (
    "8520f0098930a754748b7ddcb43ef75a"
    "0dbf3a0d26381af4eba4a98eaa9b4e6a"
)

# Bob's pair from the same RFC
_BOB_PRIV_HEX = (
    "5dab087e624a8a4b79e17f8b83800ee6"
    "6f3bb1292618b6fd1c2f8b27ff88e0eb"
)
_BOB_PUB_HEX = (
    "de9edb7d7b7dc1b4d35b61c2ece43537"
    "3f8343c85b78674dadfc7e146f882b4f"
)


def test_x25519_alice_public_matches_rfc_vector():
    priv = bytes.fromhex(_ALICE_PRIV_HEX)
    expected_pub = bytes.fromhex(_ALICE_PUB_HEX)
    assert _client_auth._public_from_private(priv) == expected_pub


def test_x25519_bob_public_matches_rfc_vector():
    priv = bytes.fromhex(_BOB_PRIV_HEX)
    expected_pub = bytes.fromhex(_BOB_PUB_HEX)
    assert _client_auth._public_from_private(priv) == expected_pub


def test_x25519_ecdh_shared_secret_matches_rfc_vector():
    """RFC 7748 §6.1: Alice and Bob derive the same shared K."""
    alice_priv = bytes.fromhex(_ALICE_PRIV_HEX)
    bob_pub = bytes.fromhex(_BOB_PUB_HEX)
    bob_priv = bytes.fromhex(_BOB_PRIV_HEX)
    alice_pub = bytes.fromhex(_ALICE_PUB_HEX)
    expected_k = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25"
        "e07e21c947d19e3376f09b3c1e161742"
    )
    assert _client_auth._x25519(alice_priv, bob_pub) == expected_k
    assert _client_auth._x25519(bob_priv, alice_pub) == expected_k


# ---------------------------------------------------------------------------
# Base32 encoding (tor's no-padding uppercase convention)
# ---------------------------------------------------------------------------

def test_b32_roundtrip():
    data = b"\x00\x01\x02\xff" * 8  # 32 bytes
    encoded = _client_auth._b32encode(data)
    assert "=" not in encoded
    assert encoded == encoded.upper()
    assert _client_auth._b32decode(encoded) == data


def test_b32_decode_accepts_lowercase():
    data = b"\x10" * 32
    encoded = _client_auth._b32encode(data).lower()
    assert _client_auth._b32decode(encoded) == data


# ---------------------------------------------------------------------------
# Keypair generation
# ---------------------------------------------------------------------------

def test_generate_keypair_format():
    kp = _client_auth.generate_keypair()
    # 32 bytes → 52 base32 chars after stripping padding
    assert len(kp.public) == 52
    assert len(kp.private) == 52
    # The public key must derive from the private key
    raw_priv = _client_auth._b32decode(kp.private)
    raw_pub = _client_auth._b32decode(kp.public)
    assert _client_auth._public_from_private(raw_priv) == raw_pub


def test_generate_keypair_is_random():
    a = _client_auth.generate_keypair()
    b = _client_auth.generate_keypair()
    assert a != b


# ---------------------------------------------------------------------------
# Server-side: add / list / revoke authorized clients
# ---------------------------------------------------------------------------

def test_add_authorized_client_generates_keypair(tmp_path):
    kp = _client_auth.add_authorized_client(tmp_path, "alice")
    assert kp.public and kp.private
    auth_file = tmp_path / "authorized_clients" / "alice.auth"
    assert auth_file.exists()
    content = auth_file.read_text().strip()
    assert content == f"descriptor:x25519:{kp.public}"


def test_add_authorized_client_with_explicit_public_key(tmp_path):
    kp = _client_auth.generate_keypair()
    result = _client_auth.add_authorized_client(
        tmp_path, "bob", public_key=kp.public,
    )
    assert result.public == kp.public
    assert result.private == ""  # we didn't generate it
    content = (tmp_path / "authorized_clients" / "bob.auth").read_text()
    assert kp.public in content


def test_add_authorized_client_rejects_duplicate(tmp_path):
    _client_auth.add_authorized_client(tmp_path, "alice")
    try:
        _client_auth.add_authorized_client(tmp_path, "alice")
    except ValueError as e:
        assert "already authorized" in str(e)
    else:
        raise AssertionError("duplicate add should have raised")


def test_add_authorized_client_rejects_bad_nickname(tmp_path):
    for bad in ["", "..", "alice/bob", "alice\\bob", ".hidden"]:
        try:
            _client_auth.add_authorized_client(tmp_path, bad)
        except ValueError:
            continue
        raise AssertionError(f"bad nickname {bad!r} was accepted")


def test_add_authorized_client_rejects_bad_pubkey(tmp_path):
    try:
        _client_auth.add_authorized_client(tmp_path, "alice", public_key="not-base32!")
    except ValueError as e:
        assert "base32" in str(e).lower()
    else:
        raise AssertionError("bad pubkey was accepted")


def test_list_and_revoke_authorized_clients(tmp_path):
    assert _client_auth.list_authorized_clients(tmp_path) == []

    kp_a = _client_auth.add_authorized_client(tmp_path, "alice")
    kp_b = _client_auth.add_authorized_client(tmp_path, "bob")
    listing = _client_auth.list_authorized_clients(tmp_path)
    assert {nickname for nickname, _ in listing} == {"alice", "bob"}
    pubs = {nickname: pub for nickname, pub in listing}
    assert pubs["alice"] == kp_a.public
    assert pubs["bob"] == kp_b.public

    assert _client_auth.revoke_authorized_client(tmp_path, "alice") is True
    # second revoke is a no-op
    assert _client_auth.revoke_authorized_client(tmp_path, "alice") is False
    listing = _client_auth.list_authorized_clients(tmp_path)
    assert [nickname for nickname, _ in listing] == ["bob"]


# ---------------------------------------------------------------------------
# Client-side: add / list / remove client auth
# ---------------------------------------------------------------------------

def test_strip_onion_normalizes_inputs():
    expected = "xxxxxx"
    for raw in [
        "xxxxxx.onion",
        "XXXXXX.onion",
        "http://xxxxxx.onion",
        "http://xxxxxx.onion/",
        "https://xxxxxx.onion/ping",
        "xxxxxx.onion:80",
        "xxxxxx",
    ]:
        assert _client_auth._strip_onion(raw) == expected


def test_add_client_auth_writes_correct_format(tmp_path):
    kp = _client_auth.generate_keypair()
    written = _client_auth.add_client_auth(
        "abcde.onion", kp.private, auth_dir=tmp_path,
    )
    assert written == tmp_path / "abcde.auth_private"
    line = written.read_text().strip()
    assert line == f"abcde:descriptor:x25519:{kp.private}"


def test_add_client_auth_rejects_bad_key(tmp_path):
    try:
        _client_auth.add_client_auth("abc.onion", "not-base32!", auth_dir=tmp_path)
    except Exception:
        return
    raise AssertionError("bad private key was accepted")


def test_list_and_remove_client_auth(tmp_path):
    kp = _client_auth.generate_keypair()
    assert _client_auth.list_client_auth(tmp_path) == []

    _client_auth.add_client_auth("aaa.onion", kp.private, auth_dir=tmp_path)
    _client_auth.add_client_auth("bbb.onion", kp.private, auth_dir=tmp_path)
    assert _client_auth.list_client_auth(tmp_path) == ["aaa", "bbb"]

    assert _client_auth.remove_client_auth("aaa.onion", auth_dir=tmp_path) is True
    assert _client_auth.remove_client_auth("aaa.onion", auth_dir=tmp_path) is False
    assert _client_auth.list_client_auth(tmp_path) == ["bbb"]


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------

def test_re_exports_from_server_module():
    from tornion import server
    assert callable(server.add_authorized_client)
    assert callable(server.list_authorized_clients)
    assert callable(server.revoke_authorized_client)
    assert callable(server.generate_client_keypair)


def test_re_exports_from_client_module():
    from tornion import client
    assert callable(client.add_client_auth)
    assert callable(client.list_client_auth)
    assert callable(client.remove_client_auth)
    assert callable(client.default_client_auth_dir)
