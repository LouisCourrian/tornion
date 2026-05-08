"""Best-effort terminal encoding reconfiguration.

Tornion's user-facing output uses emojis (⬇, ✅, 🧅, 🚀, …) and arrows (→).
On legacy Windows consoles the active code page is cp1252, which cannot
encode any of these characters — every ``print()`` containing one would
raise ``UnicodeEncodeError`` and abort the program.

This module exposes a single helper that switches stdout/stderr to UTF-8
with ``errors="replace"`` so undecodable codepoints fall back to ``?``
instead of crashing. It is a no-op on terminals already using UTF-8
(Linux, macOS, modern Windows Terminal with PYTHONIOENCODING=utf-8).
"""
from __future__ import annotations

import sys


def setup_console_encoding() -> None:
    """Reconfigure stdout/stderr to UTF-8 with replacement on undecodable chars.

    Safe to call multiple times. Silently ignored when the streams don't
    support ``reconfigure()`` (e.g. captured by some test runners).
    """
    for stream in (sys.stdout, sys.stderr):
        # ``reconfigure`` only exists on TextIOWrapper (Python 3.7+). Some
        # test harnesses replace these streams with objects that lack it.
        if not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            # Stream may already be detached, closed, or unable to switch
            # codecs — degrade silently rather than mask the real error
            # the caller is about to print.
            pass
