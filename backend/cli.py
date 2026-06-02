"""CLI entrypoint for SOCINTEL backend."""
from __future__ import annotations

import argparse

from .orchestrator import analyze_many
from .report import render_human, render_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SOCINTEL v2 - OSINT para SOC N1")
    parser.add_argument("--ip")
    parser.add_argument("--domain")
    parser.add_argument("--email")
    parser.add_argument("--url")
    parser.add_argument("--web")
    parser.add_argument("--hash")
    parser.add_argument("--mac", help="Endereço MAC para identificar fabricante (MACVendors)")
    parser.add_argument("--json", action="store_true", help="Saída em JSON (para GUI)")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    ioc_handlers = [
        ("ip", args.ip),
        ("web", args.web),
        ("web", args.domain),
        ("email", args.email),
        ("web", args.url),
        ("hash", args.hash),
        ("mac", args.mac),
    ]

    result = analyze_many(ioc_handlers)
    if args.json:
        print(render_json(result))
    else:
        print(render_human(result))


if __name__ == "__main__":
    main()
