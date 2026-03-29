from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

from src.domain_discovery import DomainDiscovery
from src.schemas import AnalyzeRequest
from src.service import DetectionService
from src.utils import generate_report, save_results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phishing Detection System CLI")
    parser.add_argument("--url", help="Single URL to analyze")
    parser.add_argument("--file", help="File containing URLs to analyze")
    parser.add_argument("--output", default="phishing_results.json", help="Output JSON file")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--basic", action="store_true", help="Skip comprehensive crawl and HTML comparison")
    parser.add_argument("--discover", action="store_true", help="Run quick discovery and export CSV results")
    parser.add_argument("--discover-banks", nargs="+", help="Optional bank short names to target during discovery")
    parser.add_argument("--discover-threshold", type=int, default=30, help="Risk threshold for discovery reporting")
    return parser


def load_urls(url: str | None, file_path: str | None) -> list[str]:
    if url:
        return [url]
    if file_path:
        return [line.strip() for line in Path(file_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    raise ValueError("Provide --url or --file.")


def render_summary(results: Iterable[dict]) -> None:
    items = list(results)
    phishing_count = sum(1 for item in items if item.get("is_phishing", False))
    suspicious_count = sum(1 for item in items if not item.get("is_phishing", False) and item.get("confidence", 0) >= 0.4)
    legitimate_count = len(items) - phishing_count - suspicious_count
    print(f"Analyzed {len(items)} URL(s)")
    print(f"Phishing: {phishing_count}")
    print(f"Suspicious: {suspicious_count}")
    print(f"Legitimate: {legitimate_count}")


def run_analysis(args: argparse.Namespace) -> int:
    service = DetectionService(config_path=args.config)
    try:
        urls = load_urls(args.url, args.file)
        results = service.analyze(AnalyzeRequest(urls=urls, comprehensive=not args.basic))
        save_results(results, args.output)
        generate_report(results, "phishing_report.html")
        render_summary(results)
    finally:
        service.close()
    return 0


def run_discovery(args: argparse.Namespace) -> int:
    service = DetectionService(config_path=args.config)
    try:
        targets = args.discover_banks or [bank.short_name for bank in service.settings.known_banks]
    finally:
        service.close()

    discovery = DomainDiscovery(args.config)
    results = discovery.quick_discover(target_banks=targets)
    high_risk = discovery.get_high_risk_domains(results, threshold=args.discover_threshold)
    output_path = discovery.save_discovery_results(results)
    print(f"Discovered {len(results)} candidates and {len(high_risk)} high-risk domains.")
    print(f"Saved discovery output to {output_path}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.discover:
        return run_discovery(args)
    return run_analysis(args)


if __name__ == "__main__":
    raise SystemExit(main())
