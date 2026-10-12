"""Core data types shared across AntiFlag."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class NetworkKind(str, Enum):
    """The kind of network an IP address belongs to."""

    UNKNOWN = "unknown"
    RESIDENTIAL = "residential"  # consumer ISP or mobile carrier
    INSTITUTION = "institution"  # school, university, employer, government
    HOSTING = "hosting"  # cloud provider or datacenter
    VPN = "vpn"  # commercial VPN provider


class Verdict(str, Enum):
    """What a connection most likely is."""

    DIRECT = "direct"  # no intermediary detected
    PROXY = "proxy"  # local or transparent proxy (Wi-Fi, school, corporate); not a VPN
    VPN = "vpn"  # the exit address belongs to a VPN provider
    HOSTING = "hosting"  # datacenter exit: could be a VPN, a cloud proxy, or a bot


@dataclass(frozen=True)
class NetworkInfo:
    """Facts about the network that owns a client IP address."""

    kind: NetworkKind = NetworkKind.UNKNOWN
    org: str | None = None
    asn: int | None = None


@dataclass(frozen=True)
class Assessment:
    """The result of assessing a connection.

    ``confidence`` is a rough heuristic score between 0 and 1, not a probability.
    """

    verdict: Verdict
    confidence: float
    network: NetworkInfo
    proxy_hops: int = 0
    reasons: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        data = asdict(self)
        data["verdict"] = self.verdict.value
        data["network"]["kind"] = self.network.kind.value
        data["reasons"] = list(self.reasons)
        return data
