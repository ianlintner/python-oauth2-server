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
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise OutboundTargetError("target must be an https URL")
    host = parsed.hostname
    try:
        port = parsed.port or _DEFAULT_PORTS["https"]
    except ValueError as exc:
        raise OutboundTargetError("invalid port") from exc

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            addresses = await resolve_host(host, port)
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

    return await http_client.post(
        pinned_url,
        content=content,
        headers={**headers, "Host": host_header},
        extensions={"sni_hostname": host},
        follow_redirects=False,
    )
