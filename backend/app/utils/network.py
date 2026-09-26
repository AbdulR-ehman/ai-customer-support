"""Client-IP resolution that distrusts forwarding headers by default.

``X-Forwarded-For`` is attacker-controlled unless a trusted reverse proxy sets it.
The header is therefore ignored unless the immediate peer matches
``TRUSTED_PROXIES`` (a comma-separated list of IPs/CIDRs), in which case the
last hop that the proxy itself appended is used.
"""

from __future__ import annotations

import ipaddress
import logging

from starlette.requests import Request

from app.config import Settings

logger = logging.getLogger("app.network")


def _parse_networks(entries: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("ignoring invalid TRUSTED_PROXIES entry")
    return networks


def peer_ip(request: Request) -> str | None:
    """The immediate network peer, as ASGI reports it."""
    return request.client.host if request.client else None


def client_ip(request: Request, settings: Settings) -> str | None:
    """Resolve the client IP for rate limiting and audit records."""
    peer = peer_ip(request)
    trusted = _parse_networks(settings.trusted_proxies_list)
    if not trusted or not peer:
        return peer
    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:  # pragma: no cover - defensive
        return peer

    if not any(peer_address in network for network in trusted):
        # Someone is sending forwarding headers without being our proxy.
        if request.headers.get("x-forwarded-for"):
            logger.warning("ignoring untrusted X-Forwarded-For header")
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
    for candidate in reversed(candidates):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return peer


def is_local_address(host: str | None) -> bool:
    """True for loopback/unspecified addresses (used by dev-only checks)."""
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified
