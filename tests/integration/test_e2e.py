"""End-to-end integration test — spawns real tor, uses the network.

These tests are excluded from the default run because tor bootstrap
takes 30-90 seconds and the first execution may also download a
~25 MB Tor Expert Bundle. Run them explicitly:

    pytest -m integration

If tor cannot bootstrap (no network, restricted environment), the test
will fail with a TorBootstrapError after `bootstrap_timeout` seconds.
"""
import json
import socket
import threading
import time

import pytest
import uvicorn

from tornion import client, server


# Plain ASGI 3 callable — avoids depending on FastAPI/Flask in the test deps.
async def _ping_app(scope, receive, send):
    if scope["type"] != "http":
        return

    if scope["path"] == "/ping":
        body = json.dumps({"message": "pong"}).encode()
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
        return

    body = b"not found"
    await send({
        "type": "http.response.start",
        "status": 404,
        "headers": [(b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body})


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ThreadedServer(uvicorn.Server):
    """uvicorn.Server safe to run in a non-main thread.

    The default Server.install_signal_handlers() calls signal.signal(),
    which only works from the main thread. Override to a no-op so we can
    run uvicorn alongside the test main thread.
    """

    def install_signal_handlers(self) -> None:
        return


def _wait_for_port(host: str, port: int, deadline_s: float) -> bool:
    """Block until the local TCP port accepts connections, or until deadline."""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.mark.integration
def test_publish_and_consume_round_trip(tmp_path):
    """Full loop: serve an ASGI app on a .onion and reach it via the client.

    Steps:
        1. Run a uvicorn-hosted ASGI app on a local free port.
        2. Spin up a tornion HiddenService pointing at that port.
        3. Use tornion.client to GET the resulting .onion URL.
        4. Assert the JSON body round-trips intact.
    """
    port = _free_port()
    config = uvicorn.Config(
        _ping_app, host="127.0.0.1", port=port, log_level="error",
    )
    uv = _ThreadedServer(config)
    uv_thread = threading.Thread(target=uv.run, daemon=True)
    uv_thread.start()

    if not _wait_for_port("127.0.0.1", port, deadline_s=10):
        uv.should_exit = True
        pytest.fail("uvicorn did not start within 10s")

    hs = server.HiddenService(
        target_port=port,
        key_dir=tmp_path / "hs",
        bootstrap_timeout=180,  # be lenient: first run may auto-install tor
    )

    try:
        onion_url = hs.start()
        assert onion_url.startswith("http://")
        assert onion_url.endswith(".onion")

        # Tor circuits can be slow on first contact — generous client timeout.
        r = client.get(f"{onion_url}/ping", timeout=180)
        assert r.status_code == 200
        assert r.json() == {"message": "pong"}
    finally:
        hs.stop()
        uv.should_exit = True
        uv_thread.join(timeout=5)


@pytest.mark.integration
async def test_publish_and_consume_round_trip_async(tmp_path):
    """Same round-trip as above, but via the async client.

    Publishes an ASGI app on a .onion, then reaches it with
    `client.AsyncSession`, exercising the httpx-based path end to end.
    """
    port = _free_port()
    config = uvicorn.Config(
        _ping_app, host="127.0.0.1", port=port, log_level="error",
    )
    uv = _ThreadedServer(config)
    uv_thread = threading.Thread(target=uv.run, daemon=True)
    uv_thread.start()

    if not _wait_for_port("127.0.0.1", port, deadline_s=10):
        uv.should_exit = True
        pytest.fail("uvicorn did not start within 10s")

    hs = server.HiddenService(
        target_port=port,
        key_dir=tmp_path / "hs-async",
        bootstrap_timeout=180,
    )

    try:
        onion_url = hs.start()
        assert onion_url.endswith(".onion")

        async with await client.AsyncSession.create(timeout=180) as s:
            r = await s.get(f"{onion_url}/ping")
            assert r.status_code == 200
            assert r.json() == {"message": "pong"}
    finally:
        hs.stop()
        uv.should_exit = True
        uv_thread.join(timeout=5)


@pytest.mark.integration
def test_authorized_client_can_reach_restricted_hs(tmp_path):
    """End-to-end client-auth: only the holder of the matching private key
    can reach a hidden service that has authorized_clients configured.

    Steps:
        1. Start uvicorn on a free local port.
        2. Generate an x25519 client keypair via tornion's helper.
        3. Authorize the client on a fresh HS key_dir.
        4. Register the matching private key on the client side.
        5. Restart the client tor so the new auth dir is read.
        6. Publish the HS and assert that the tornion client can reach it.
    """
    import tornion
    from tornion._client_auth import (
        add_authorized_client, add_client_auth, default_client_auth_dir,
        remove_client_auth,
    )

    port = _free_port()
    config = uvicorn.Config(
        _ping_app, host="127.0.0.1", port=port, log_level="error",
    )
    uv = _ThreadedServer(config)
    uv_thread = threading.Thread(target=uv.run, daemon=True)
    uv_thread.start()

    if not _wait_for_port("127.0.0.1", port, deadline_s=10):
        uv.should_exit = True
        pytest.fail("uvicorn did not start within 10s")

    key_dir = tmp_path / "restricted-hs"
    key_dir.mkdir()

    # Generate the keypair + authorize the client.
    keypair = add_authorized_client(key_dir, "tester")
    assert keypair.public and keypair.private

    hs = server.HiddenService(
        target_port=port, key_dir=key_dir, bootstrap_timeout=180,
    )

    # Make sure we tidy our client-auth dir on exit (it's persistent
    # under the user data dir).
    onion_url_holder = {}

    try:
        onion_url = hs.start()
        onion_url_holder["url"] = onion_url

        # Register the matching private key on the client side, then
        # force-restart any existing tornion-managed client tor so it
        # rereads the auth dir on next request.
        add_client_auth(onion_url, keypair.private)
        tornion.shutdown()

        r = client.get(f"{onion_url}/ping", timeout=180)
        assert r.status_code == 200
        assert r.json() == {"message": "pong"}
    finally:
        # Clean up persistent state so subsequent runs of this test
        # (or the simple round-trip test) are not affected.
        url = onion_url_holder.get("url")
        if url:
            remove_client_auth(url)
        tornion.shutdown()
        hs.stop()
        uv.should_exit = True
        uv_thread.join(timeout=5)
