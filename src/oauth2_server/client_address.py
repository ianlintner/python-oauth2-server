"""Single derivation of the client network address.

Every component that needs to know "which address is this request from"
(`RateLimitMiddleware`, the login limiter, `DenylistGuard`) calls
`client_address` so they all agree.

Trust rule:

* `trust_proxy_headers` off — the raw ASGI peer address; forwarding headers
  are ignored entirely.
* `trust_proxy_headers` on — the **right-most** `X-Forwarded-For` entry, i.e.
  the address appended by the trusted reverse proxy closest to this server.
  Entries to its left are supplied by earlier hops (including the client) and
  can be set to anything. If the header is absent or empty the peer address
  is used.

When there is no peer at all the literal `"unknown"` is returned, so callers
degrade to one shared bucket instead of losing the key.

Deliberate divergence from the Rust server, which takes the left-most entry.
"""

from __future__ import annotations

from starlette.requests import Request

UNKNOWN_CLIENT = "unknown"


def client_address(request: Request, trust_proxy_headers: bool) -> str:
    if trust_proxy_headers:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            last = forwarded_for.rsplit(",", 1)[-1].strip()
            if last:
                return last
    client = request.client
    return client.host if client is not None else UNKNOWN_CLIENT
