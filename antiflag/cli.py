"""Command-line interface: ``antiflag check``."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .classifier import assess
from .models import Assessment, NetworkInfo
from .network import NetworkDB


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antiflag",
        description="Assess whether a connection looks like a VPN, a proxy, or direct.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="assess a connection from its IP and headers")
    check.add_argument("--ip", help="the address that opened the connection")
    check.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'NAME: VALUE'",
        help="a request header; repeat for several headers",
    )
    check.add_argument("--org", help="ISP or organisation name for the client address")
    check.add_argument(
        "--db",
        metavar="FILE",
        help="JSON network database (see examples/networks.example.json)",
    )
    check.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    headers = {}
    for raw in args.header:
        name, sep, value = raw.partition(":")
        if not sep or not name.strip():
            parser.error(f"header must look like 'Name: value', got {raw!r}")
        headers[name.strip()] = value.strip()

    try:
        db = NetworkDB.from_file(args.db) if args.db else None
    except ValueError as exc:
        parser.error(str(exc))

    # Only the name is given, so the classifier infers the kind and marks it as
    # less certain than a curated database entry.
    network = NetworkInfo(org=args.org) if args.org else None

    result = assess(args.ip, headers, network=network, lookup=db)

    if args.json:
        json.dump(result.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_text(result, args.ip)
    return 0


def _print_text(result: Assessment, ip: str | None) -> None:
    net = result.network
    describe = net.org or "unknown"
    if net.asn is not None:
        describe += f" (AS{net.asn})"
    print(f"Client IP:   {ip or 'not given'}")
    print(f"Network:     {describe} [{net.kind.value}]")
    print(f"Verdict:     {result.verdict.value.upper()} (confidence {result.confidence:.2f})")
    print(f"Proxy hops:  {result.proxy_hops}")
    print("Reasons:")
    for reason in result.reasons:
        print(f"  - {reason}")
