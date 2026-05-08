"""Custom exceptions raised across tornion."""


class OnionError(Exception):
    """Base exception for all tornion errors."""


class TorBinaryNotFound(OnionError):
    """No usable tor binary could be located, and auto-install failed/disabled."""


class TorBootstrapError(OnionError):
    """The tor subprocess failed to bootstrap (timeout, port conflict, crash…)."""


class TorAlreadyRunning(OnionError):
    """A managed tor instance is already running in this process."""


class HiddenServiceError(OnionError):
    """Hidden service setup or runtime failure."""


class UnsupportedAppError(OnionError):
    """The provided app could not be detected as ASGI or WSGI."""
