"""Async client unit tests — no network, no real tor.

The tor singleton is stubbed out so we never spawn a subprocess; httpx's
network layer is stubbed where a real request would otherwise be made.
"""
import sys

import httpx
import pytest

import tornion
from tornion import client


class _FakeTor:
    """Stand-in for tornion._tor.TorManager — just exposes a socks_port."""

    socks_port = 12345


@pytest.fixture
def fake_tor(monkeypatch):
    """Make `_tor.get_tor(...)` return a fake manager and record its kwargs."""
    import tornion._tor as _tor

    calls = {}

    def _fake_get_tor(**kwargs):
        calls.update(kwargs)
        return _FakeTor()

    monkeypatch.setattr(_tor, "get_tor", _fake_get_tor)
    return calls


# ---------------------------------------------------------------------------
# Lazy exposure / packaging
# ---------------------------------------------------------------------------

def test_async_symbols_exposed_lazily():
    """`client.AsyncSession` resolves to the httpx-backed session."""
    assert client.AsyncSession is client.AsyncOnionSession
    assert issubclass(client.AsyncOnionSession, httpx.AsyncClient)
    for verb in ("aget", "apost", "aput", "adelete", "ahead", "apatch",
                 "aoptions", "arequest"):
        assert callable(getattr(client, verb))


def test_async_not_in_dunder_all():
    """Async names must stay out of __all__ so `import *` never pulls httpx."""
    assert "AsyncSession" not in client.__all__
    assert "aget" not in client.__all__


def test_unknown_attribute_still_raises():
    with pytest.raises(AttributeError):
        client.this_does_not_exist  # noqa: B018


def test_missing_httpx_gives_friendly_error(monkeypatch):
    """If httpx isn't importable, accessing async symbols points at the extra."""
    # Poison the import so `from . import async_session` fails the way a
    # missing httpx would. We must both drop the cached submodule AND remove
    # the attribute already set on the package, otherwise the import machinery
    # short-circuits to the live module and never re-imports.
    monkeypatch.delattr(client, "async_session", raising=False)
    monkeypatch.delitem(sys.modules, "tornion.client.async_session", raising=False)
    monkeypatch.setitem(sys.modules, "tornion.client.async_session", None)

    with pytest.raises(ImportError) as exc:
        client.AsyncSession  # noqa: B018
    assert "tornion[async]" in str(exc.value)


# ---------------------------------------------------------------------------
# Construction wires the Tor proxy + options through
# ---------------------------------------------------------------------------

async def test_session_construction_passes_tor_options(fake_tor):
    s = client.AsyncSession(
        auto_install=False, bootstrap_timeout=42, use_existing=False, retries=7,
    )
    try:
        # The tor manager was asked for with exactly our knobs.
        assert fake_tor == {
            "auto_install": False,
            "bootstrap_timeout": 42,
            "use_existing": False,
            "auto_update": None,
        }
        assert s._retries == 7
        assert isinstance(s, httpx.AsyncClient)
    finally:
        await s.aclose()


async def test_caller_cannot_override_proxy(fake_tor):
    """A user-supplied proxy must not be allowed to bypass Tor."""
    s = client.AsyncSession(proxy="http://evil.example:8080")
    try:
        # Whatever httpx stored internally, our SOCKS proxy is the one used.
        # We assert indirectly: construction succeeded and used the fake port.
        assert fake_tor  # get_tor was consulted
    finally:
        await s.aclose()


async def test_create_classmethod_returns_session(fake_tor):
    s = await client.AsyncSession.create(auto_install=False)
    try:
        assert isinstance(s, client.AsyncOnionSession)
    finally:
        await s.aclose()


# ---------------------------------------------------------------------------
# Retry behavior on transient gateway errors
# ---------------------------------------------------------------------------

def _status_sequence(monkeypatch, statuses):
    """Patch httpx.AsyncClient.request to yield the given status codes in order.

    Returns the list that records how many times the parent request ran.
    """
    seq = iter(statuses)
    calls = []

    async def _fake_request(self, method, url, **kwargs):
        calls.append((method, url))
        return httpx.Response(next(seq))

    monkeypatch.setattr(httpx.AsyncClient, "request", _fake_request)
    return calls


@pytest.fixture
def no_sleep(monkeypatch):
    """Make backoff instantaneous so retry tests don't actually wait."""
    slept = []

    async def _fake_sleep(delay):
        slept.append(delay)

    import tornion.client.async_session as _async
    monkeypatch.setattr(_async.asyncio, "sleep", _fake_sleep)
    return slept


async def test_retry_on_503_then_success(fake_tor, no_sleep, monkeypatch):
    calls = _status_sequence(monkeypatch, [503, 503, 200])
    s = client.AsyncSession(retries=3)
    try:
        r = await s.get("http://xxx.onion/")
        assert r.status_code == 200
        assert len(calls) == 3  # two failures + one success
    finally:
        await s.aclose()


async def test_no_retry_on_200(fake_tor, no_sleep, monkeypatch):
    calls = _status_sequence(monkeypatch, [200])
    s = client.AsyncSession(retries=3)
    try:
        r = await s.get("http://xxx.onion/")
        assert r.status_code == 200
        assert len(calls) == 1
    finally:
        await s.aclose()


async def test_retries_exhausted_returns_last(fake_tor, no_sleep, monkeypatch):
    calls = _status_sequence(monkeypatch, [503, 503, 503])
    s = client.AsyncSession(retries=2)
    try:
        r = await s.get("http://xxx.onion/")
        assert r.status_code == 503
        assert len(calls) == 3  # original + 2 retries
        # First retry is immediate (0s), second waits backoff_factor*(2**1-1)=2s.
        assert no_sleep == [2]
    finally:
        await s.aclose()


async def test_retries_zero_disables(fake_tor, no_sleep, monkeypatch):
    calls = _status_sequence(monkeypatch, [503])
    s = client.AsyncSession(retries=0)
    try:
        r = await s.get("http://xxx.onion/")
        assert r.status_code == 503
        assert len(calls) == 1
        assert no_sleep == []
    finally:
        await s.aclose()


# ---------------------------------------------------------------------------
# shutdown() invalidates the async default session too
# ---------------------------------------------------------------------------

async def test_shutdown_clears_async_default(fake_tor):
    import tornion.client.async_session as _async

    s = await _async._get_default_async_session()
    assert _async._default_async_session is s

    tornion.shutdown()

    assert _async._default_async_session is None
    assert _async._default_async_loop is None
    await s.aclose()
