"""Command-line interface: ``tornion install-tor | get | serve | info | keygen | onion``."""
from __future__ import annotations

import argparse
import importlib
import json as _json
import logging
import sys
from pathlib import Path

from . import _binary, _version
from .client import session as _session
from .exceptions import OnionError


def _cmd_install_tor(args: argparse.Namespace) -> int:
    try:
        path = _binary.install_tor(
            version=args.version,
            force=args.force,
            sha256=args.sha256,
        )
        print(f"\n✅ tor installed at: {path}")
        return 0
    except OnionError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1


def _cmd_update(args: argparse.Namespace) -> int:
    """Update the cached tor to the latest PGP-verified Tor Expert Bundle."""
    try:
        from . import _update
    except ImportError:
        print(
            "❌ auto-update requires the [autoupdate] extra:\n"
            "    pip install tornion[autoupdate]",
            file=sys.stderr,
        )
        return 1

    try:
        suffix = _binary._detect_platform_suffix()
    except OnionError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1

    print("🔎 checking torproject.org for the latest verified Tor Expert Bundle...")
    resolved = _update.resolve_latest(_binary.TOR_DOWNLOAD_BASE, suffix)
    if resolved is None:
        print(
            "❌ could not resolve a verified latest version "
            "(offline, or PGP signature check failed).",
            file=sys.stderr,
        )
        return 1

    version, sha = resolved
    cached = _binary.installed_tor_version()
    cached_v = _update.version_tuple(cached) if cached else None
    latest_v = _update.version_tuple(version) or (0, 0, 0)
    if not args.force and cached_v is not None and latest_v <= cached_v:
        print(f"✅ already up to date: cached tor {cached} (latest stable {version})")
        return 0

    try:
        path = _binary.install_tor(version=version, sha256=sha, force=True)
    except OnionError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1
    print(f"\n✅ updated to PGP-verified Tor {version}\n   {path}")
    return 0


def _cmd_get(args: argparse.Namespace) -> int:
    try:
        with _session.OnionSession(
            timeout=args.timeout, auto_update=args.auto_update
        ) as s:
            kwargs = {}
            if args.data is not None:
                kwargs["data"] = args.data
            if args.header:
                headers = {}
                for h in args.header:
                    if ":" not in h:
                        print(f"❌ Invalid header: {h!r}", file=sys.stderr)
                        return 2
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
                kwargs["headers"] = headers

            r = s.request(args.method, args.url, **kwargs)
            print(f"\n→ {args.method} {args.url}  [{r.status_code} {r.reason}]")
            if args.json:
                print(_json.dumps(r.json(), indent=2, ensure_ascii=False))
            else:
                print(r.text)
            return 0 if r.ok else 1
    except OnionError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1


def _cmd_serve(args: argparse.Namespace) -> int:
    """Launch a user app on a hidden service. Style: `uvicorn myapp:app`."""
    try:
        from . import server  # lazy
    except ImportError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1

    if ":" not in args.app:
        print(f"❌ App spec must be 'module:attribute' (e.g. myapp:app)",
              file=sys.stderr)
        return 2

    module_name, attr = args.app.rsplit(":", 1)
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        print(f"❌ Could not import {module_name!r}: {e}", file=sys.stderr)
        return 1

    if not hasattr(module, attr):
        print(f"❌ Module {module_name!r} has no attribute {attr!r}",
              file=sys.stderr)
        return 1

    app = getattr(module, attr)

    try:
        server.serve(
            app,
            key_dir=args.key_dir,
            app_name=args.name or attr,
            bootstrap_timeout=args.bootstrap_timeout,
            auto_update=args.auto_update,
            log_level=args.log_level,
        )
        return 0
    except OnionError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a fresh v3 hs_ed25519_secret_key (no tor needed)."""
    from . import _onion

    out_dir = Path(args.out).expanduser().resolve()
    secret_path = out_dir / _onion.SECRET_KEY_FILE

    if secret_path.exists() and not args.force:
        print(
            f"❌ {secret_path} already exists. Use --force to overwrite "
            f"(this destroys the existing .onion identity).",
            file=sys.stderr,
        )
        return 1

    written = _onion.write_secret_key(out_dir)
    print(f"✅ wrote {written}")
    print()
    print(f"Next steps:")
    print(f"  - to learn the .onion address derived from this key, run:")
    print(f"        tornion onion {out_dir}")
    print(f"    (tor populates the hostname file the first time the key is loaded)")
    print(f"  - to serve an app on this identity:")
    print(f"        TORNION_KEY_DIR={out_dir} tornion serve module:app")
    print(f"  - keep `{_onion.SECRET_KEY_FILE}` safe — it IS your .onion identity.")
    return 0


def _cmd_onion(args: argparse.Namespace) -> int:
    """Print the .onion address derived from a key directory."""
    from . import _onion

    try:
        url = _onion.onion_for_key_dir(Path(args.key_dir))
    except (ValueError, OSError) as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1
    print(url)
    return 0


def _cmd_authorize(args: argparse.Namespace) -> int:
    """Manage server-side client authorizations (who can reach this HS)."""
    from . import _client_auth

    key_dir = Path(args.key_dir)

    if args.list:
        try:
            clients = _client_auth.list_authorized_clients(key_dir)
        except OSError as e:
            print(f"❌ {e}", file=sys.stderr)
            return 1
        if not clients:
            print(f"(no authorized clients for {key_dir})")
            return 0
        print(f"Authorized clients for {key_dir}:")
        for nickname, pubkey in clients:
            print(f"  - {nickname:<20s} {pubkey}")
        return 0

    if args.revoke:
        try:
            removed = _client_auth.revoke_authorized_client(key_dir, args.revoke)
        except (ValueError, OSError) as e:
            print(f"❌ {e}", file=sys.stderr)
            return 1
        if removed:
            print(f"✅ revoked {args.revoke!r} from {key_dir}")
        else:
            print(f"(no client {args.revoke!r} was authorized for {key_dir})")
        return 0

    # Default action: add a new authorization.
    if not args.nickname:
        print(
            "❌ Specify a nickname to authorize, or use --list / --revoke",
            file=sys.stderr,
        )
        return 2

    try:
        keypair = _client_auth.add_authorized_client(
            key_dir, args.nickname, public_key=args.public_key,
        )
    except (ValueError, FileNotFoundError, OSError) as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1

    print(f"✅ authorized {args.nickname!r} on {key_dir}")
    if keypair.private:
        # We generated the pair. The private key MUST reach the client; we
        # only print it here, never to disk.
        print()
        print(f"   Give this PRIVATE key to {args.nickname} (one-time display):")
        print(f"       {keypair.private}")
        print()
        print(f"   On the client, register it with:")
        print(f"       tornion client-auth add <this-onion-url> {keypair.private}")
    else:
        print(f"   (you supplied the public key; the client already has the private)")
    return 0


def _cmd_client_auth(args: argparse.Namespace) -> int:
    """Manage client-side auth keys (private keys for restricted hidden services)."""
    from . import _client_auth

    if args.list:
        items = _client_auth.list_client_auth()
        if not items:
            print(f"(no registered client-auth keys in "
                  f"{_client_auth.default_client_auth_dir()})")
            return 0
        print(f"Registered client-auth keys "
              f"({_client_auth.default_client_auth_dir()}):")
        for stem in items:
            print(f"  - {stem}.onion")
        return 0

    if args.remove:
        try:
            removed = _client_auth.remove_client_auth(args.remove)
        except ValueError as e:
            print(f"❌ {e}", file=sys.stderr)
            return 1
        if removed:
            print(f"✅ removed client-auth for {args.remove}")
            print(f"   (restart tor for the change to take effect: `tornion info`")
            print(f"    will start a fresh tor on next use)")
        else:
            print(f"(no client-auth registered for {args.remove})")
        return 0

    # Default action: add.
    if not args.onion or not args.private_key:
        print(
            "❌ Specify <onion> <private_key> to add, or use --list / --remove",
            file=sys.stderr,
        )
        return 2

    try:
        path = _client_auth.add_client_auth(args.onion, args.private_key)
    except ValueError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1
    print(f"✅ wrote {path}")
    print(f"   tor reads this on startup. If a managed tor is already running,")
    print(f"   it will pick up the new auth only after a restart.")
    return 0


def _cmd_info(args: argparse.Namespace) -> int:
    import os
    from . import _tor

    print(f"tornion {_version.__version__}")
    print(f"  cache dir         : {_binary.cache_dir()}")
    print(f"  data dir          : {_binary.data_dir()}")
    env_key_dir = os.environ.get("TORNION_KEY_DIR")
    if env_key_dir:
        print(f"  TORNION_KEY_DIR   : {env_key_dir}")

    p = _binary.installed_tor_path()
    if p:
        size_mb = p.stat().st_size / (1024 * 1024)
        cached_ver = _binary.installed_tor_version()
        ver_str = f" v{cached_ver}" if cached_ver else " (version unknown)"
        print(f"  bundled tor       : {p}{ver_str} ({size_mb:.1f} MB)")
    else:
        print("  bundled tor       : (not installed)")

    try:
        resolved = _binary.find_tor_binary(auto_install=False)
        print(f"  resolved binary   : {resolved}")
    except OnionError:
        print(f"  resolved binary   : (none — would auto-install)")

    running = _tor.detect_running_tor()
    if running is not None:
        print(f"  running tor       : ✓ SOCKS5 detected on :{running} "
              f"(would be reused for client)")
    else:
        print(f"  running tor       : (no SOCKS5 on standard ports)")

    # server extras
    try:
        import uvicorn  # noqa: F401
        print(f"  server extras     : ✓ installed (uvicorn ready)")
    except ImportError:
        print(f"  server extras     : (not installed — run `pip install tornion[server]`)")

    # auto-update extras
    auto_on = os.environ.get("TORNION_AUTO_UPDATE") == "1"
    try:
        import pgpy  # noqa: F401
        state = "on" if auto_on else "off"
        print(f"  auto-update       : ✓ available (PGPy ready), TORNION_AUTO_UPDATE={state}")
    except ImportError:
        print(f"  auto-update       : (not installed — run `pip install tornion[autoupdate]`)")

    print(f"  pinned version    : {_binary.DEFAULT_TOR_VERSION}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Switch stdout/stderr to UTF-8 so emoji status lines work on Windows.
    from ._console import setup_console_encoding
    setup_console_encoding()

    parser = argparse.ArgumentParser(
        prog="tornion",
        description="Tor hidden service client + server toolkit",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_install = sub.add_parser("install-tor", help="Download tor into the user cache")
    p_install.add_argument("--version", default=_binary.DEFAULT_TOR_VERSION)
    p_install.add_argument("--force", action="store_true")
    p_install.add_argument(
        "--sha256",
        help="Override the pinned SHA-256. Use only if you've verified the "
             "value against torproject.org's signed sha256sums-signed-build.txt.",
    )
    p_install.set_defaults(func=_cmd_install_tor)

    p_update = sub.add_parser(
        "update",
        help="Update the cached tor to the latest PGP-verified version "
             "(needs the [autoupdate] extra)",
    )
    p_update.add_argument(
        "--force", action="store_true",
        help="Reinstall even if the cache is already on the latest version",
    )
    p_update.set_defaults(func=_cmd_update)

    p_get = sub.add_parser("get", help="Make a single HTTP request to a .onion URL")
    p_get.add_argument("url")
    p_get.add_argument("-X", "--method", default="GET")
    p_get.add_argument("-H", "--header", action="append", default=[])
    p_get.add_argument("--data")
    p_get.add_argument("--json", action="store_true")
    p_get.add_argument("--timeout", type=int, default=_session.DEFAULT_TIMEOUT)
    p_get.add_argument(
        "--auto-update", action="store_true", default=None,
        help="Keep tor on the latest PGP-verified version before the request",
    )
    p_get.set_defaults(func=_cmd_get)

    p_serve = sub.add_parser(
        "serve",
        help="Run an ASGI/WSGI app on a Tor hidden service (à la uvicorn)",
    )
    p_serve.add_argument("app", help="App spec: 'module:attribute' (e.g. myapp:app)")
    p_serve.add_argument("--key-dir", help="Directory to store the .onion key")
    p_serve.add_argument("--name", help="Slug used to derive default key dir")
    p_serve.add_argument("--bootstrap-timeout", type=int, default=90)
    p_serve.add_argument(
        "--auto-update", action="store_true", default=None,
        help="Keep tor on the latest PGP-verified version (needs [autoupdate])",
    )
    p_serve.add_argument("--log-level", default="warning",
                         choices=["critical", "error", "warning", "info", "debug"])
    p_serve.set_defaults(func=_cmd_serve)

    p_info = sub.add_parser("info", help="Print diagnostic info")
    p_info.set_defaults(func=_cmd_info)

    p_keygen = sub.add_parser(
        "keygen",
        help="Generate a fresh v3 hidden service secret key (no tor needed)",
    )
    p_keygen.add_argument(
        "--out",
        default="./onion-key",
        help="Directory to write hs_ed25519_secret_key into "
             "(created if missing; default: ./onion-key)",
    )
    p_keygen.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing key file (destroys the existing .onion identity)",
    )
    p_keygen.set_defaults(func=_cmd_keygen)

    p_onion = sub.add_parser(
        "onion",
        help="Print the .onion address derived from an existing key directory",
    )
    p_onion.add_argument(
        "key_dir",
        help="Directory containing hostname / hs_ed25519_public_key / hs_ed25519_secret_key",
    )
    p_onion.set_defaults(func=_cmd_onion)

    p_auth = sub.add_parser(
        "authorize",
        help="Manage server-side authorized clients (who can reach this HS)",
    )
    p_auth.add_argument(
        "key_dir",
        help="Directory holding the HS identity (with hs_ed25519_secret_key)",
    )
    p_auth.add_argument(
        "nickname",
        nargs="?",
        help="Arbitrary label for the new client (e.g. 'alice', 'phone')",
    )
    p_auth.add_argument(
        "--public-key",
        help="Client's x25519 public key (base32, 52 chars). "
             "If omitted, tornion generates a fresh keypair and prints the private.",
    )
    p_auth.add_argument(
        "--list", action="store_true",
        help="List currently authorized clients for this key_dir",
    )
    p_auth.add_argument(
        "--revoke", metavar="NICKNAME",
        help="Revoke the given client's authorization",
    )
    p_auth.set_defaults(func=_cmd_authorize)

    p_cauth = sub.add_parser(
        "client-auth",
        help="Manage client-side auth keys for restricted hidden services",
    )
    p_cauth.add_argument(
        "onion",
        nargs="?",
        help="The .onion address (with or without 'http://' / '.onion' / path)",
    )
    p_cauth.add_argument(
        "private_key",
        nargs="?",
        help="Client's x25519 private key in base32 (52 chars)",
    )
    p_cauth.add_argument(
        "--list", action="store_true",
        help="List all .onion addresses with a registered client-auth key",
    )
    p_cauth.add_argument(
        "--remove", metavar="ONION",
        help="Forget the registered client-auth key for the given .onion",
    )
    p_cauth.set_defaults(func=_cmd_client_auth)

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
