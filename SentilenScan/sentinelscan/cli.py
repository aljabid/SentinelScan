"""CLI entry point for SentinelScan."""

import argparse
import sys
import time
from typing import List, Optional

from sentinelscan import __version__
from sentinelscan.scanner import Scanner
from sentinelscan.reporters.text_reporter import TextReporter
from sentinelscan.reporters.json_reporter import JsonReporter
from sentinelscan.reporters.html_reporter import HtmlReporter
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
  ____  _____ _   _ _____ ___ _   _ _____ _     ____   ____    _    _   _ 
 / ___|| ____| \ | |_   _|_ _| \ | | ____| |   / ___| / ___|  / \  | \ | |
 \___ \|  _| |  \| | | |  | ||  \| |  _| | |   \___ \| |     / _ \ |  \| |
  ___) | |___| |\  | | |  | || |\  | |___| |___ ___) | |___ / ___ \| |\  |
 |____/|_____|_| \_| |_| |___|_| \_|_____|_____|____/ \____/_/   \_\_| \_|

  v{version}  |  Industrial-Grade Web Security Scanner
  ─────────────────────────────────────────────────────
""".format(version=__version__)

REPORTERS = {
    "text": TextReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
}

ALL_MODULES = ["headers", "ssl_tls", "owasp", "cookies", "ports", "dns", "cors"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelscan",
        description="SentinelScan – Modular web security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinelscan example.com
  sentinelscan example.com -m headers ssl_tls
  sentinelscan example.com -m all -f json -o results.json
  sentinelscan example.com -m all -f html -o report.html
  sentinelscan example.com --timeout 15 --retries 3
  sentinelscan example.com -m all --severity high medium
        """,
    )

    # target is now optional (*) so --version works without it
    parser.add_argument("target", nargs="*", help="Target host(s) to scan (e.g. example.com)")

    parser.add_argument(
        "-m", "--modules",
        nargs="+",
        default=["all"],
        choices=ALL_MODULES + ["all"],
        metavar="MODULE",
        help=f"Modules to run. Choices: {', '.join(ALL_MODULES)}, all (default: all)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Number of retries on connection failure (default: 2)",
    )
    parser.add_argument(
        "--severity",
        nargs="+",
        choices=["critical", "high", "medium", "low", "info"],
        default=["critical", "high", "medium", "low", "info"],
        help="Filter findings by severity level",
    )
    parser.add_argument(
        "--user-agent",
        default="SentinelScan/2.0 (Security Scanner)",
        help="Custom User-Agent string",
    )
    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        default=True,
        help="Follow HTTP redirects (default: True)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (show debug info)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"SentinelScan {__version__}",
    )
    parser.add_argument(
        "--exit-on-critical",
        action="store_true",
        help="Exit with code 2 if any critical findings are found (for CI/CD pipelines)",
    )
    parser.add_argument(
        "--score-threshold",
        type=int,
        default=0,
        metavar="SCORE",
        help="Exit with code 2 if risk score exceeds this value (CI/CD gate)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # If no target provided (e.g. just --version), exit cleanly
    if not args.target:
        return 0

    # Resolve modules
    modules = ALL_MODULES if "all" in args.modules else args.modules

    if not args.no_color:
        print(BANNER)

    start = time.monotonic()

    scanner = Scanner(
        timeout=args.timeout,
        retries=args.retries,
        user_agent=args.user_agent,
        follow_redirects=args.follow_redirects,
        verbose=args.verbose,
    )

    all_results = {}
    for target in args.target:
        print(f"  → Scanning {target} ...")
        results = scanner.scan(target, modules=modules)
        all_results[target] = results

    elapsed = time.monotonic() - start
    print(f"\n  ✓ Scan completed in {elapsed:.2f}s\n")

    # Build report
    reporter_cls = REPORTERS[args.format]
    reporter = reporter_cls(severity_filter=args.severity, no_color=args.no_color)
    output = reporter.render(all_results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"  Report written → {args.output}")
    else:
        print(output)

    # CI/CD exit codes
    has_critical = any(
        finding.get("severity") == "critical"
        for res in all_results.values()
        for mod_findings in res.values()
        for finding in mod_findings.get("findings", [])
    )

    total_score = sum(
        res.get("__meta__", {}).get("risk_score", 0)
        for res in all_results.values()
    )

    if args.exit_on_critical and has_critical:
        return 2
    if args.score_threshold and total_score > args.score_threshold:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
