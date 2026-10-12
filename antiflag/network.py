"""Work out what kind of network an IP address belongs to.

Two sources are combined:

* A ``NetworkDB`` of CIDR ranges, loaded from a JSON file you maintain or
  generate from your own IP intelligence source. Longest prefix wins.
* Keyword rules on the organisation name (for example "Mullvad" or "University"),
  used when no database entry exists.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol, runtime_checkable

from .models import NetworkInfo, NetworkKind

# Order matters: a VPN brand that also says "cloud" should still count as a VPN.
_KEYWORD_RULES: tuple[tuple[NetworkKind, re.Pattern[str]], ...] = (
    (
        NetworkKind.VPN,
        re.compile(
            r"vpn|proxy|tunnel|mullvad|surfshark|windscribe|cyberghost|ipvanish|"
            r"torguard|private internet access|hide\.me",
            re.IGNORECASE,
        ),
    ),
    (
        NetworkKind.HOSTING,
        re.compile(
            r"\b(hosting|hosted|cloud|datacenter|data center|colocation|colo|servers?|"
            r"digital ocean|digitalocean|ovh|hetzner|linode|vultr|akamai|amazon|aws|azure)\b",
            re.IGNORECASE,
        ),
    ),
    (
        NetworkKind.INSTITUTION,
        re.compile(
            r"\b(universi\w*|college|school|institute|academy|government|ministry|"
            r"hospital|library|municipal)\b",
            re.IGNORECASE,
        ),
    ),
    (
        NetworkKind.RESIDENTIAL,
        re.compile(
            r"\b(telecom\w*|broadband|cable|dsl|fib(?:re|er)|mobile|wireless|isp|"
            r"internet services?|communications?)\b",
            re.IGNORECASE,
        ),
    ),
)


def classify_org(org: str | None) -> NetworkKind:
    """Guess a network kind from an organisation or ISP name."""
    if not org:
        return NetworkKind.UNKNOWN
    for kind, pattern in _KEYWORD_RULES:
        if pattern.search(org):
            return kind
    return NetworkKind.UNKNOWN


@runtime_checkable
class NetworkLookup(Protocol):
    """Anything that can map an IP address to network facts."""

    def lookup(self, ip: str) -> NetworkInfo | None:
        """Return facts about ``ip``, or ``None`` if it is unknown."""
        ...


class NetworkDB:
    """An in-memory table of CIDR ranges with longest-prefix matching."""

    def __init__(self, entries: Iterable[tuple[str, NetworkInfo]] = ()) -> None:
        self._entries: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, NetworkInfo]] = []
        for cidr, info in entries:
            self.add(cidr, info)

    def __len__(self) -> int:
        return len(self._entries)

    def add(self, cidr: str, info: NetworkInfo) -> None:
        """Add a range. Host bits are ignored, so ``10.1.2.3/8`` means ``10.0.0.0/8``."""
        network = ipaddress.ip_network(cidr, strict=False)
        self._entries.append((network, info))

    def lookup(self, ip: str) -> NetworkInfo | None:
        """Return the most specific range containing ``ip``, if any."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped

        best: tuple[int, NetworkInfo] | None = None
        for network, info in self._entries:
            if network.version != address.version or address not in network:
                continue
            if best is None or network.prefixlen > best[0]:
                best = (network.prefixlen, info)
        return best[1] if best else None

    @classmethod
    def from_file(cls, path: str | Path) -> NetworkDB:
        """Load a database from a JSON file.

        Expected format::

            {"networks": [
                {"cidr": "198.51.100.0/24", "org": "Example VPN", "asn": 64500,
                 "kind": "vpn"}
            ]}

        ``kind`` must be one of: residential, institution, hosting, vpn, unknown.
        If it is omitted, the kind is inferred from ``org``.
        """
        path = Path(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read network database {path}: {exc}") from exc

        db = cls()
        for index, item in enumerate(raw.get("networks", [])):
            try:
                kind_value = item.get("kind")
                kind = (
                    NetworkKind(kind_value)
                    if kind_value is not None
                    else classify_org(item.get("org"))
                )
                info = NetworkInfo(kind=kind, org=item.get("org"), asn=item.get("asn"))
                db.add(item["cidr"], info)
            except (KeyError, ValueError, TypeError) as exc:
                raise ValueError(f"invalid entry #{index} in {path}: {exc}") from exc
        return db
