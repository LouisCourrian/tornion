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


def _cmd_get(args: argparse.Namespace) -> int:
    try:
        with _session.OnionSession(timeout=args.timeout) as s:
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
        print(f"  bundled tor       : {p} ({size_mb:.1f} MB)")
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

    print(f"  default version   : {_binary.DEFAULT_TOR_VERSION}")
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

    p_get = sub.add_parser("get", help="Make a single HTTP request to a .onion URL")
    p_get.add_argument("url")
    p_get.add_argument("-X", "--method", default="GET")
    p_get.add_argument("-H", "--header", action="append", default=[])
    p_get.add_argument("--data")
    p_get.add_argument("--json", action="store_true")
    p_get.add_argument("--timeout", type=int, default=_session.DEFAULT_TIMEOUT)
    p_get.set_defaults(func=_cmd_get)

    p_serve = sub.add_parser(
        "serve",
        help="Run an ASGI/WSGI app on a Tor hidden service (à la uvicorn)",
    )
    p_serve.add_argument("app", help="App spec: 'module:attribute' (e.g. myapp:app)")
    p_serve.add_argument("--key-dir", help="Directory to store the .onion key")
    p_serve.add_argument("--name", help="Slug used to derive default key dir")
    p_serve.add_argument("--bootstrap-timeout", type=int, default=90)
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

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
