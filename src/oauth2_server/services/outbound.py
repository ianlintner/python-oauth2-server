"""Connect-time target checks for server-initiated outbound requests.

A client-supplied URL that the server later POSTs to (the OIDC Back-Channel
Logout endpoint) is validated twice: shape at registration time
(`services/clients.py`), and — here — the *resolved* address immediately before
connecting. Resolving first and then connecting to the pinned address means a
name that only resolves to an internal address at dispatch time is refused, and
that the address checked is the address connected to.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

import httpx

_DEFAULT_PORTS = {"https": 443, "http": 80}


class OutboundTargetError(Exception):
    """The target URL is not acceptable for an outbound request."""


def is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether `address` is a globally routable unicast address."""
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return address.is_global and not address.is_multicast


async def resolve_host(host: str, port: int) -> list[str]:
    """Resolve `host` to its IP address strings (module-level so tests can
    substitute it without real DNS)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]).split("%", 1)[0] for info in infos))


_DEFAULT_RESOLVE_TIMEOUT = 10.0


def _resolve_timeout(http_client: httpx.AsyncClient) -> float:
    """The caller's connect timeout, used to bound DNS resolution too."""
    connect = http_client.timeout.connect
    return connect if connect is not None else _DEFAULT_RESOLVE_TIMEOUT


async def post_to_public_https_target(
    http_client: httpx.AsyncClient,
    url: str,
    *,
    content: str,
    headers: dict[str, str],
) -> httpx.Response:
    """POST to an `https` URL whose every resolved address is public.

    The request is sent to the first resolved address (with the original
    `Host` header and TLS server name), redirects are not followed, and the
    caller's client timeout applies. Raises `OutboundTargetError` when the URL
    is not https, has no host, or any resolved address is non-public.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        explicit_port = parsed.port
    except ValueError as exc:
        raise OutboundTargetError("malformed target authority") from exc
    if parsed.scheme != "https" or not host:
        raise OutboundTargetError("target must be an https URL")
    port = explicit_port or _DEFAULT_PORTS["https"]

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        # Name resolution happens before httpx is involved, so the client's
        # connect timeout does not cover it; bound it explicitly so a stalled
        # lookup releases its dispatch slot without anything being sent.
        try:
            async with asyncio.timeout(_resolve_timeout(http_client)):
                addresses = await resolve_host(host, port)
        except TimeoutError as exc:
            raise OutboundTargetError("target resolution timed out") from exc
        except OSError as exc:
            raise OutboundTargetError("target did not resolve") from exc
    else:
        addresses = [str(literal)]

    parsed_addresses = []
    for text in addresses:
        try:
            parsed_addresses.append(ipaddress.ip_address(text))
        except ValueError as exc:
            raise OutboundTargetError("unparseable address") from exc
    if not parsed_addresses or not all(is_public_address(a) for a in parsed_addresses):
        raise OutboundTargetError("target resolves to a non-public address")

    pinned = parsed_addresses[0]
    ip_text = f"[{pinned}]" if pinned.version == 6 else str(pinned)
    netloc = f"{ip_text}:{port}" if parsed.port else ip_text
    pinned_url = parsed._replace(netloc=netloc).geturl()
    host_header = parsed.netloc.rsplit("@", 1)[-1]

    # The pinned IP is the URL host, so httpx's pool keys connections by
    # (scheme, IP, port) alone: a kept-alive connection whose TLS session was
    # authenticated for one hostname could be reused for another hostname
    # that resolves to the same address. `Connection: close` makes every
    # request use (and then discard) its own connection, authenticated for
    # exactly this `sni_hostname`.
    return await http_client.post(
        pinned_url,
        content=content,
        headers={**headers, "Host": host_header, "Connection": "close"},
        extensions={"sni_hostname": host},
        follow_redirects=False,
    )
