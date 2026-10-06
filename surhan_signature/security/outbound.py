"""Safe outbound HTTP primitives for callbacks and webhooks."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

class UnsafeOutboundURL(ValueError):
    pass


def _public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return bool(ip.is_global and not ip.is_multicast and not ip.is_unspecified)


def validate_outbound_url(url: str) -> str:
    value = str(url or "").strip()
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"}:
        raise UnsafeOutboundURL("Only HTTP/HTTPS callback URLs are allowed.")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise UnsafeOutboundURL("Malformed callback URL.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)}
    except (OSError, ValueError) as exc:
        raise UnsafeOutboundURL("Callback host cannot be resolved safely.") from exc
    if not addresses or any(not _public_ip(address) for address in addresses):
        raise UnsafeOutboundURL("Private, loopback, link-local and reserved callback hosts are blocked.")
    return value


def safe_post(url: str, *, data: bytes, headers: dict, timeout: int = 10):
    import requests

    target = validate_outbound_url(url)
    timeout = max(1, min(int(timeout or 10), 30))
    response = requests.post(
        target,
        data=data,
        headers=headers,
        timeout=(5, timeout),
        allow_redirects=False,
        stream=True,
    )
    if 300 <= response.status_code < 400:
        response.close()
        raise UnsafeOutboundURL("Outbound redirects are blocked.")
    connection = getattr(response.raw, "_connection", None)
    sock = getattr(connection, "sock", None)
    try:
        peer_ip = sock.getpeername()[0]
    except Exception as exc:
        response.close()
        raise UnsafeOutboundURL("Unable to verify the outbound peer address.") from exc
    if not _public_ip(peer_ip):
        response.close()
        raise UnsafeOutboundURL("The connected peer address is not public.")
    response.raw.decode_content = True
    content = response.raw.read(65_537)
    response.close()
    if len(content) > 65_536:
        raise UnsafeOutboundURL("Outbound response exceeds the 64KB limit.")
    response._content = content
    response._content_consumed = True
    return response
