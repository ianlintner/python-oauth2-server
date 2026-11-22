"""The mTLS trusted-proxy check must see the real socket peer under uvicorn."""

from __future__ import annotations

import socket
import threading
import time

import httpx
import pytest
import uvicorn
from starlette.requests import Request
from starlette.responses import JSONResponse

from oauth2_server.config import Config
from oauth2_server.services.mtls import mtls_headers

_CONFIG = Config(
    jwt_secret="x" * 40,
    trust_proxy_headers=True,
    trusted_proxy_cidrs=["127.0.0.0/8"],
)


async def _app(scope, receive, send):
    request = Request(scope, receive)
    thumbprint, subject_dn = mtls_headers(request, _CONFIG)
    await JSONResponse({"thumbprint": thumbprint, "dn": subject_dn})(scope, receive, send)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _fetch(proxy_headers: bool) -> dict:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            _app,
            host="127.0.0.1",
            port=port,
            proxy_headers=proxy_headers,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not server.started:
            if time.time() > deadline:
                pytest.fail("uvicorn did not start")
            time.sleep(0.05)
        response = httpx.get(
            f"http://127.0.0.1:{port}/",
            headers={
                "X-Forwarded-For": "203.0.113.9",
                "X-Client-Cert-Thumbprint": "abc",
                "X-SSL-Client-S-DN": "CN=client1",
            },
        )
        return response.json()
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_headers_honoured_from_loopback_peer_with_proxy_headers_disabled():
    # The configuration `__main__` uses: the peer stays the socket address.
    assert _fetch(proxy_headers=False) == {"thumbprint": "abc", "dn": "CN=client1"}


def test_uvicorn_forwarded_rewrite_hides_the_socket_peer():
    # Control: with uvicorn's rewriting on, the app sees the forwarded address
    # instead of the peer, which is why `__main__` turns it off.
    assert _fetch(proxy_headers=True) == {"thumbprint": None, "dn": None}
