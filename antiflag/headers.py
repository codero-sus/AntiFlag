"""Inspect HTTP headers for signs that a request passed through an intermediary.

Forwarding headers such as ``Via`` and ``X-Forwarded-For`` are written by the
software in the middle, and clients can forge them. Treat them as hints. The
address that actually opened the connection is the authoritative signal, and
the classifier uses it that way.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass

# Headers that show a chain of intermediaries (one entry per hop).
_CHAIN_HEADERS = ("via", "x-forwarded-for", "forwarded")

# Weaker or legacy markers. They suggest a proxy but show no chain.
_WEAK_HEADERS = ("x-real-ip", "client-ip", "proxy-connection", "x-proxy-id")

# Pulls the node from a RFC 7239 ``Forwarded`` element, e.g. ``for="[2001:db8::1]:4711"``.
_FORWARDED_FOR_RE = re.compile(r'for=\s*"?\[?([^;,"\]]+)', re.IGNORECASE)


@dataclass(frozen=True)
class HeaderFindings:
    """What the forwarding headers reveal about the request path."""

    hops: int = 0
    weak_markers: tuple[str, ...] = ()
    forwarded_addresses: tuple[str, ...] = ()

    @property
    def has_intermediary(self) -> bool:
        """True if any header suggests the request was relayed."""
        return self.hops > 0 or bool(self.weak_markers)

    @property
    def has_private_hop(self) -> bool:
        """True if a forwarded address is private, which usually means a LAN proxy."""
        return any(_is_private(addr) for addr in self.forwarded_addresses)


def analyze_headers(headers: Mapping[str, str]) -> HeaderFindings:
    """Count proxy hops and collect forwarding markers from request headers.

    Header names are matched case-insensitively. ``hops`` is the longest chain
    seen across ``Via``, ``X-Forwarded-For`` and ``Forwarded``.
    """
    normalised = {name.lower(): value for name, value in headers.items()}

    hop_counts: list[int] = []
    addresses: list[str] = []

    if "via" in normalised:
        hop_counts.append(len(_split_list(normalised["via"])))

    if "x-forwarded-for" in normalised:
        nodes = [_strip_port(token) for token in _split_list(normalised["x-forwarded-for"])]
        hop_counts.append(len(nodes))
        addresses.extend(nodes)

    if "forwarded" in normalised:
        nodes = [
            _strip_port(match.group(1))
            for match in _FORWARDED_FOR_RE.finditer(normalised["forwarded"])
        ]
        hop_counts.append(len(nodes))
        addresses.extend(nodes)

    weak = tuple(name for name in _WEAK_HEADERS if name in normalised)
    valid_addresses = tuple(addr for addr in addresses if _is_ip(addr))

    return HeaderFindings(
        hops=max(hop_counts, default=0),
        weak_markers=weak,
        forwarded_addresses=valid_addresses,
    )


def headers_from_wsgi(environ: Mapping[str, object]) -> dict[str, str]:
    """Extract HTTP request headers from a WSGI ``environ`` mapping.

    ``HTTP_X_FORWARDED_FOR`` becomes ``x-forwarded-for``. Useful for Flask,
    Django, Bottle and other WSGI frameworks.
    """
    headers: dict[str, str] = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            name = key[len("HTTP_") :].replace("_", "-").lower()
            headers[name] = str(value)
    return headers


def _split_list(value: str) -> list[str]:
    """Split a comma-separated header value and drop empty items."""
    return [part.strip() for part in value.split(",") if part.strip()]


def _strip_port(token: str) -> str:
    """Remove a port or brackets from an address token where that is unambiguous."""
    token = token.strip().strip('"')
    if token.startswith("["):
        end = token.find("]")
        return token[1:end] if end != -1 else token[1:]
    # "192.0.2.1:8080" has exactly one colon. A bare IPv6 address has several.
    if token.count(":") == 1:
        return token.split(":", 1)[0]
    return token


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False
