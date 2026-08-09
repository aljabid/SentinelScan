"""CLI entry point for SentinelScan."""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

from sentinelscan import __version__
from sentinelscan.config_file import load_profile
from sentinelscan.plugins import DEFAULT_PLUGIN_DIR, load_plugins
from sentinelscan.reporters.html_reporter import HtmlReporter
from sentinelscan.reporters.json_reporter import JsonReporter
from sentinelscan.reporters.sarif_reporter import SarifReporter
from sentinelscan.reporters.text_reporter import TextReporter
from sentinelscan.scanner import MODULE_MAP, Scanner
from sentinelscan.updater import DEFAULT_SIGNATURES_URL, USER_SIGNATURES_PATH, update_signatures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = rf"""
  ____  _____ _   _ _____ ___ _   _ _____ _     ____   ____    _    _   _
 / ___|| ____| \ | |_   _|_ _| \ | | ____| |   / ___| / ___|  / \  | \ | |
 \___ \|  _| |  \| | | |  | ||  \| |  _| | |   \___ \| |     / _ \ |  \| |
  ___) | |___| |\  | | |  | || |\  | |___| |___ ___) | |___ / ___ \| |\  |
 |____/|_____|_| \_| |_| |___|_| \_|_____|_____|____/ \____/_/   \_\_| \_|

  Web Security Scanner
  ─────────────────────────────────────────────────────
"""

REPORTERS: dict[str, type[Any]] = {
    "text": TextReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
    "sarif": SarifReporter,
}

ALL_MODULES = [
    "headers",
    "ssl_tls",
    "owasp",
    "cookies",
    "ports",
    "dns",
    "cors",
    "subdomains",
    "crawler",
    "cve_fingerprint",
]

# Safety cap on CIDR expansion so a typo like "10.0.0.0/8" can't silently queue millions of scans.
MAX_CIDR_HOSTS = 1024

# nmap-style timing templates: each step trades stealth/politeness for speed by
# adjusting the default per-request timeout and how much scanning runs in parallel.
TIMING_PROFILES: dict[int, dict[str, Any]] = {
    0: {"name": "paranoid", "timeout": 30, "target_workers": 1, "module_workers": 1, "port_workers": 5},
    1: {"name": "sneaky", "timeout": 20, "target_workers": 1, "module_workers": 2, "port_workers": 10},
    2: {"name": "polite", "timeout": 15, "target_workers": 2, "module_workers": 3, "port_workers": 15},
    3: {"name": "normal", "timeout": 10, "target_workers": 3, "module_workers": 4, "port_workers": 20},
    4: {"name": "aggressive", "timeout": 7, "target_workers": 5, "module_workers": 6, "port_workers": 40},
    5: {"name": "insane", "timeout": 5, "target_workers": 10, "module_workers": 7, "port_workers": 60},
}

# Built-in fallback for every profile-settable field (see sentinelscan/config_file.py).
# Precedence at runtime is: explicit CLI flag > --profile value > this dict.
BUILTIN_DEFAULTS: dict[str, Any] = {
    "modules": ["all"],
    "format": "text",
    "severity": ["critical", "high", "medium", "low", "info"],
    "timing": 3,
    "retries": 2,
    "user_agent": "SentinelScan/2.0 (Security Scanner)",
    "plugin_dir": None,
    "crawl_max_pages": 15,
    "score_threshold": 0,
}

# Exit code contract (documented in USAGE.md and the man page):
#   0 = scan completed, no CI/CD gate tripped
#   1 = usage/runtime error (bad target, bad flag, network/plugin failure) -- scan did not complete
#   2 = scan completed successfully but a CI/CD gate (--exit-on-critical / --score-threshold) tripped
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_GATE_TRIPPED = 2

DISCLAIMER = (
    "SentinelScan performs active security probes (port scans, path enumeration,\n"
    "CORS/header probing) against the target(s) you specify. Only scan systems you\n"
    "own or have explicit written authorization to test -- unauthorized scanning may\n"
    "violate computer-crime laws and the target's terms of service.\n"
    "(Shown once. Set SENTINELSCAN_SKIP_DISCLAIMER=1 to suppress in CI.)\n"
)

DISCLAIMER_MARKER = (
    Path(os.environ.get("SENTINELSCAN_CONFIG_DIR", str(Path.home() / ".config" / "sentinelscan"))) / ".disclaimer_shown"
)

logger = logging.getLogger("sentinelscan.cli")


def maybe_show_disclaimer() -> None:
    """Show the authorized-use disclaimer once (never blocks; CI/automation-friendly)."""
    if os.environ.get("SENTINELSCAN_SKIP_DISCLAIMER") == "1":
        return
    if DISCLAIMER_MARKER.exists():
        return
    logger.warning(DISCLAIMER)
    try:
        DISCLAIMER_MARKER.parent.mkdir(parents=True, exist_ok=True)
        DISCLAIMER_MARKER.touch()
    except OSError:
        pass


def run_doctor() -> int:
    """Self-diagnosis: report Python version, optional deps, and key paths."""
    checks: list[tuple[str, bool, str]] = []

    checks.append(("Python >= 3.9", sys.version_info >= (3, 9), sys.version.split()[0]))

    try:
        import dns.resolver  # noqa: F401

        checks.append(("dnspython (enhanced DNS checks)", True, "installed"))
    except ImportError:
        checks.append(("dnspython (enhanced DNS checks)", False, "not installed -- pip install 'sentinelscan[dns]'"))

    plugin_dir_status = "present" if DEFAULT_PLUGIN_DIR.is_dir() else "not present (fine -- plugins are optional)"
    checks.append((f"Plugin directory ({DEFAULT_PLUGIN_DIR})", True, plugin_dir_status))

    sig_path = USER_SIGNATURES_PATH
    sig_status = "user override present" if sig_path.is_file() else "using bundled default (fine)"
    checks.append((f"CVE signature override ({sig_path})", True, sig_status))

    all_ok = all(ok for _, ok, _ in checks)
    for name, ok, detail in checks:
        symbol = "OK  " if ok else "FAIL"
        logger.info("  [%s] %-40s %s", symbol, name, detail)

    return EXIT_OK if all_ok else EXIT_ERROR


def configure_logging(verbose: bool) -> None:
    """Send status/progress output to stderr so stdout stays clean for piping reports."""
    handler = logging.StreamHandler(sys.stderr)
    fmt = "%(levelname)s %(name)s: %(message)s" if verbose else "%(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    root = logging.getLogger("sentinelscan")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.propagate = False


def _expand_target(raw: str) -> list[str]:
    candidate = raw.strip()
    if not candidate:
        return []
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return [candidate]
    if network.num_addresses == 1:
        return [str(network.network_address)]
    host_count = network.num_addresses - 2
    if host_count > MAX_CIDR_HOSTS:
        raise ValueError(
            f"{candidate} expands to {host_count} hosts, exceeding the safety limit of "
            f"{MAX_CIDR_HOSTS}. Narrow the range or use -iL with a curated host list."
        )
    return [str(ip) for ip in network.hosts()]


def resolve_targets(raw_targets: list[str], input_list: str | None) -> list[str]:
    """Expand CLI targets (hostnames, CIDR ranges, '-' for stdin) and an optional -iL file."""
    targets: list[str] = []
    for raw in raw_targets:
        if raw == "-":
            targets.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            targets.extend(_expand_target(raw))
    if input_list:
        with open(input_list, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    targets.extend(_expand_target(stripped))

    seen: set[str] = set()
    ordered: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def parse_headers(raw_headers: list[str]) -> dict[str, str]:
    """Parse repeated -H 'Name: Value' flags into a header dict."""
    headers: dict[str, str] = {}
    for raw in raw_headers:
        if ":" not in raw:
            raise ValueError(f"invalid header '{raw}', expected 'Name: Value' format")
        name, _, value = raw.partition(":")
        name = name.strip()
        if not name:
            raise ValueError(f"invalid header '{raw}', expected 'Name: Value' format")
        headers[name] = value.strip()
    return headers


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
  sentinelscan 10.0.0.0/28 -m ports --timing 4
  sentinelscan -iL targets.txt -m all -f json -o results.json
  cat targets.txt | sentinelscan - -m headers
  sentinelscan example.com --timeout 15 --retries 3
  sentinelscan example.com -m all --severity high medium
        """,
    )

    # target is now optional (*) so --version works without it
    parser.add_argument(
        "target",
        nargs="*",
        help="Target host(s) to scan: hostname, URL, CIDR range, or '-' to read from stdin",
    )

    parser.add_argument(
        "-iL",
        "--input-list",
        metavar="FILE",
        help="Read targets from FILE, one per line ('#' comments allowed; CIDR ranges accepted)",
    )
    parser.add_argument(
        "-m",
        "--modules",
        nargs="+",
        default=None,
        metavar="MODULE",
        help=(
            f"Modules to run. Built-in: {', '.join(ALL_MODULES)}, all (default: all). "
            "Plugin modules (see --plugin-dir) are also selectable by name."
        ),
    )
    parser.add_argument(
        "--plugin-dir",
        metavar="DIR",
        help="Directory to load custom analyzer plugins from (default: ~/.config/sentinelscan/plugins)",
    )
    parser.add_argument(
        "--no-plugins",
        action="store_true",
        help="Disable loading plugins from the plugin directory",
    )
    parser.add_argument(
        "--profile",
        metavar="NAME",
        help="Load defaults from ~/.config/sentinelscan/profiles/NAME.toml (CLI flags still override it)",
    )
    parser.add_argument(
        "--profile-file",
        metavar="PATH",
        help="Load defaults from an explicit TOML file (CLI flags still override it)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "html", "sarif"],
        default=None,
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "-T",
        "--timing",
        type=int,
        choices=[0, 1, 2, 3, 4, 5],
        default=None,
        metavar="0-5",
        help=(
            "Timing template, nmap-style: 0=paranoid .. 3=normal (default) .. 5=insane. "
            "Controls default timeout and scan concurrency."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Request timeout in seconds (default: derived from --timing, normally 10)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=None,
        help="Number of retries on connection failure (default: 2)",
    )
    parser.add_argument(
        "--crawl-max-pages",
        type=int,
        default=None,
        metavar="N",
        help="Max pages the 'crawler' module visits when checking header consistency (default: 15)",
    )
    parser.add_argument(
        "--severity",
        nargs="+",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Filter findings by severity level",
    )
    parser.add_argument(
        "--user-agent",
        default=None,
        help="Custom User-Agent string",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Name: Value'",
        help="Add a custom HTTP header (repeatable). E.g. -H 'Authorization: Bearer TOKEN'",
    )
    parser.add_argument(
        "--cookie",
        metavar="'name=value; name2=value2'",
        help="Set a raw Cookie header, e.g. for scanning behind an authenticated session",
    )
    parser.add_argument(
        "--follow-redirects",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Follow HTTP redirects (default: True). Use --no-follow-redirects to disable.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--verbose",
        "-v",
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
        default=None,
        metavar="SCORE",
        help="Exit with code 2 if risk score exceeds this value (CI/CD gate)",
    )
    parser.add_argument(
        "--update-db",
        action="store_true",
        help="Download the latest CVE signature database and exit (see --update-url)",
    )
    parser.add_argument(
        "--update-url",
        metavar="URL",
        default=DEFAULT_SIGNATURES_URL,
        help="URL to fetch the CVE signature database from (advanced)",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Run self-diagnosis (Python version, optional deps, config paths) and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.doctor:
        configure_logging(args.verbose)
        return run_doctor()

    if args.update_db:
        configure_logging(args.verbose)
        success, message = update_signatures(requests.Session(), url=args.update_url)
        if success:
            logger.info(message)
            return EXIT_OK
        logger.error("Error: %s", message)
        return EXIT_ERROR

    # If no target/-iL provided (e.g. just --version), exit cleanly
    if not args.target and not args.input_list:
        return EXIT_OK

    configure_logging(args.verbose)
    maybe_show_disclaimer()

    try:
        profile_data = load_profile(name=args.profile, path=args.profile_file)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Error: %s", exc)
        return EXIT_ERROR

    def resolved(field: str) -> Any:
        """Precedence: explicit CLI flag > --profile value > built-in default."""
        cli_value = getattr(args, field)
        if cli_value is not None:
            return cli_value
        if field in profile_data:
            return profile_data[field]
        return BUILTIN_DEFAULTS[field]

    try:
        targets = resolve_targets(args.target, args.input_list)
    except ValueError as exc:
        logger.error("Error: %s", exc)
        return EXIT_ERROR

    if not targets:
        return EXIT_OK

    try:
        extra_headers = parse_headers(args.header)
    except ValueError as exc:
        logger.error("Error: %s", exc)
        return EXIT_ERROR
    if args.cookie:
        extra_headers["Cookie"] = args.cookie

    modules_arg = resolved("modules")
    fmt = resolved("format")
    severity = resolved("severity")
    timing = resolved("timing")
    retries = resolved("retries")
    user_agent = resolved("user_agent")
    plugin_dir = resolved("plugin_dir")
    crawl_max_pages = resolved("crawl_max_pages")
    score_threshold = resolved("score_threshold")

    if fmt not in REPORTERS:
        logger.error("Error: invalid format '%s'. Valid: %s", fmt, ", ".join(REPORTERS))
        return EXIT_ERROR
    if timing not in TIMING_PROFILES:
        logger.error("Error: invalid timing '%s'. Valid: 0-5", timing)
        return EXIT_ERROR
    invalid_severity = set(severity) - {"critical", "high", "medium", "low", "info"}
    if invalid_severity:
        logger.error("Error: invalid severity value(s): %s", ", ".join(sorted(invalid_severity)))
        return EXIT_ERROR

    plugin_modules = {} if args.no_plugins else load_plugins(plugin_dir)
    module_map: dict[str, type[Any]] = {**MODULE_MAP, **plugin_modules}
    if plugin_modules:
        logger.info("  Loaded %d plugin module(s): %s", len(plugin_modules), ", ".join(sorted(plugin_modules)))

    # Resolve modules
    unknown = set(modules_arg) - set(module_map) - {"all"}
    if unknown:
        logger.error(
            "Error: unknown module(s): %s. Available: %s",
            ", ".join(sorted(unknown)),
            ", ".join(sorted(module_map)),
        )
        return EXIT_ERROR

    modules = list(module_map) if "all" in modules_arg else modules_arg
    timing_profile = TIMING_PROFILES[timing]

    if args.timeout is not None:
        timeout = args.timeout
    elif profile_data.get("timeout") is not None:
        timeout = profile_data["timeout"]
    else:
        timeout = timing_profile["timeout"]

    if not args.no_color:
        logger.info(BANNER)

    start = time.monotonic()

    scanner = Scanner(
        timeout=timeout,
        retries=retries,
        user_agent=user_agent,
        follow_redirects=args.follow_redirects,
        verbose=args.verbose,
        module_workers=timing_profile["module_workers"],
        port_workers=timing_profile["port_workers"],
        extra_headers=extra_headers,
        module_map=module_map,
        crawl_max_pages=crawl_max_pages,
    )

    logger.info(
        "  → Scanning %d target(s) [-T%d %s, %d parallel] ...",
        len(targets),
        timing,
        timing_profile["name"],
        timing_profile["target_workers"],
    )

    all_results: dict[str, Any] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=timing_profile["target_workers"]) as executor:
        future_to_target = {executor.submit(scanner.scan, target, modules): target for target in targets}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            logger.debug("Finished %s", target)
            all_results[target] = future.result()

    # Report targets in the order the user specified, regardless of completion order.
    all_results = {t: all_results[t] for t in targets}

    elapsed = time.monotonic() - start
    logger.info("\n  ✓ Scan completed in %.2fs\n", elapsed)

    # Build report
    reporter_cls = REPORTERS[fmt]
    reporter = reporter_cls(severity_filter=severity, no_color=args.no_color)
    output = reporter.render(all_results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        logger.info("  Report written → %s", args.output)
    else:
        print(output)

    # CI/CD exit codes
    has_critical = any(
        finding.get("severity") == "critical"
        for res in all_results.values()
        for key, mod_findings in res.items()
        if key != "__error__"
        for finding in mod_findings.get("findings", [])
    )

    total_score = sum(res.get("__meta__", {}).get("risk_score", 0) for res in all_results.values())

    if args.exit_on_critical and has_critical:
        return EXIT_GATE_TRIPPED
    if score_threshold and total_score > score_threshold:
        return EXIT_GATE_TRIPPED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
