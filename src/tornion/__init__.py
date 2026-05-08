"""tornion — Tor hidden service toolkit.

Use the submodules explicitly to keep client / server concerns separate::

    from tornion import client, server

    # Consume a .onion API
    r = client.get("http://xxx.onion/ping")

    with client.Session() as s:
        s.post("http://xxx.onion/items", json={"foo": "bar"})

    # Publish your app on a .onion
    from fastapi import FastAPI
    app = FastAPI()
    server.serve(app)        # blocks; prints the .onion URL

The top-level ``tornion`` namespace exposes only what's shared between
client and server: tor-binary management, cache/data dirs, exceptions,
and version info.

Server features require the ``[server]`` extras::

    pip install tornion[server]

Both submodules share the same tor binary discovery, auto-download, and
cache directory. See ``tornion info`` from the CLI for diagnostic output.
"""
# --- Tor binary management (shared) ---
from ._binary import (
    DEFAULT_TOR_VERSION,
    cache_dir,
    data_dir,
    find_tor_binary,
    install_tor,
    installed_tor_path,
)

# --- Tor process detection (shared) ---
from ._tor import detect_running_tor, shutdown

# --- Version ---
from ._version import __version__

# --- Public exceptions (shared, not client- or server-specific) ---
from .exceptions import (
    HiddenServiceError,
    OnionError,
    TorAlreadyRunning,
    TorBinaryNotFound,
    TorBootstrapError,
    UnsupportedAppError,
)

# Submodules `client` and `server` are NOT re-exported here on purpose.
# Users import them explicitly:
#     from tornion import client, server
#
# This keeps the namespaces separated and makes WHO is doing WHAT
# obvious at every call site.

__all__ = [
    "__version__",
    # Tor binary management
    "install_tor",
    "find_tor_binary",
    "installed_tor_path",
    "cache_dir",
    "data_dir",
    "detect_running_tor",
    "shutdown",
    "DEFAULT_TOR_VERSION",
    # Exceptions
    "OnionError",
    "TorBinaryNotFound",
    "TorBootstrapError",
    "TorAlreadyRunning",
    "HiddenServiceError",
    "UnsupportedAppError",
]
