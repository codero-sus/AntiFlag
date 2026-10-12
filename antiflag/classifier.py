"""Combine header and network evidence into a verdict.

The decision order is deliberate:

1. A VPN exit address is a VPN, whatever the headers say.
2. A datacenter exit is ``HOSTING``. It is not labelled a VPN, because it could
   be a VPN, a cloud proxy, or a bot.
3. Forwarding headers from a residential or institutional network are a
   ``PROXY``. This is the common Wi-Fi, school or corporate case, which many
   sites wrongly treat as a VPN.
4. Anything else is ``DIRECT``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from .headers import HeaderFindings, analyze_headers
from .models import Assessment, NetworkInfo, NetworkKind, Verdict
from .network import NetworkLookup, classify_org

_TRUSTED_ACCESS_KINDS = (NetworkKind.RESIDENTIAL, NetworkKind.INSTITUTION)


def assess(
    client_ip: str | None,
    headers: Mapping[str, str] | None = None,
    *,
    network: NetworkInfo | None = None,
    lookup: NetworkLookup | None = None,
) -> Assessment:
    """Assess how a connection looks to a website.

    Args:
        client_ip: The address that opened the TCP connection. This is the
            authoritative address, not one taken from forwarding headers.
        headers: Request headers. Used to detect proxy hops.
        network: Known facts about the client network. Takes priority over
            ``lookup``.
        lookup: A source such as ``NetworkDB`` used when ``network`` is not given.

    Returns:
        An ``Assessment`` with the verdict, a heuristic confidence, and reasons.
    """
    findings = analyze_headers(headers or {})
    info, from_database = _resolve_network(client_ip, network, lookup)
    reasons: list[str] = []

    if info.kind is NetworkKind.VPN:
        return _vpn(info, findings, from_database, reasons)

    if info.kind is NetworkKind.HOSTING:
        return _hosting(info, findings, reasons)

    if findings.has_intermediary:
        return _proxy(info, findings, reasons)

    return _direct(info, reasons)


def _vpn(
    info: NetworkInfo, findings: HeaderFindings, from_database: bool, reasons: list[str]
) -> Assessment:
    # A curated range is stronger evidence than a name that merely contains "vpn".
    confidence = 0.9 if from_database else 0.7
    reasons.append(f"exit address belongs to a VPN provider ({_org_label(info)})")
    if findings.has_intermediary:
        reasons.append(
            "forwarding headers are also present, but the exit network decides this case"
        )
    return _build(Verdict.VPN, confidence, info, findings, reasons)


def _hosting(info: NetworkInfo, findings: HeaderFindings, reasons: list[str]) -> Assessment:
    reasons.append(f"exit address is in a hosting or datacenter network ({_org_label(info)})")
    if findings.has_intermediary:
        reasons.append("forwarding headers indicate a relay running on a datacenter host")
        confidence = 0.8
    else:
        reasons.append(
            "hosting ranges are often VPNs, cloud proxies or bots, so this is not conclusive"
        )
        confidence = 0.6
    return _build(Verdict.HOSTING, confidence, info, findings, reasons)


def _proxy(info: NetworkInfo, findings: HeaderFindings, reasons: list[str]) -> Assessment:
    if findings.hops:
        reasons.append(f"forwarding headers show {findings.hops} proxy hop(s)")
    else:
        reasons.append("weak proxy markers present: " + ", ".join(findings.weak_markers))

    if findings.has_private_hop:
        reasons.append("a forwarded address is private, which points to a local network proxy")

    trusted_access = info.kind in _TRUSTED_ACCESS_KINDS
    if trusted_access:
        reasons.append(
            f"exit network is {info.kind.value} ({_org_label(info)}), so this is most likely "
            "a Wi-Fi, school or corporate proxy rather than a VPN"
        )
        confidence = 0.85 if findings.hops else 0.65
    else:
        reasons.append("exit network type is unknown, so this could be a proxy or a VPN")
        confidence = 0.6 if findings.hops else 0.5

    return _build(Verdict.PROXY, confidence, info, findings, reasons)


def _direct(info: NetworkInfo, reasons: list[str]) -> Assessment:
    reasons.append("no proxy headers and no VPN or hosting network detected")
    confidence = 0.9 if info.kind in _TRUSTED_ACCESS_KINDS else 0.6
    return _build(Verdict.DIRECT, confidence, info, HeaderFindings(), reasons)


def _resolve_network(
    client_ip: str | None,
    network: NetworkInfo | None,
    lookup: NetworkLookup | None,
) -> tuple[NetworkInfo, bool]:
    """Return the network facts and whether they are curated.

    Curated means a source (``network`` or ``lookup``) supplied an explicit
    kind. A kind inferred only from the org name is not curated.
    """
    info = network
    if info is None and lookup is not None and client_ip:
        info = lookup.lookup(client_ip)
    if info is None:
        return NetworkInfo(), False
    curated = info.kind is not NetworkKind.UNKNOWN
    if not curated and info.org:
        info = replace(info, kind=classify_org(info.org))
    return info, curated


def _org_label(info: NetworkInfo) -> str:
    parts = []
    if info.org:
        parts.append(info.org)
    if info.asn is not None:
        parts.append(f"AS{info.asn}")
    return ", ".join(parts) if parts else "unnamed network"


def _build(
    verdict: Verdict,
    confidence: float,
    info: NetworkInfo,
    findings: HeaderFindings,
    reasons: list[str],
) -> Assessment:
    return Assessment(
        verdict=verdict,
        confidence=round(confidence, 2),
        network=info,
        proxy_hops=findings.hops,
        reasons=tuple(reasons),
    )
