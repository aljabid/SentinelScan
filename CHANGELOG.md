# Changelog

All notable changes to SentinelScan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Security
- **Fixed: terminal escape-sequence injection via scanned-target content.** A malicious/compromised target could send ANSI escape sequences in a port banner (`ports` module, newly added this cycle) or a crafted crawled URL (`crawler` module) that, when printed unsanitized by the default text reporter, could manipulate the user's terminal — most concerningly, hiding other findings in the same report. Fixed centrally in `Finding.__init__` (`sentinelscan/analyzers/base.py`), which now strips non-printable/control characters from every finding field, protecting all current and future analyzers. `ports.py`'s raw `open_ports` metadata is sanitized separately since it doesn't go through `Finding`. Verified against a real local socket server sending an actual malicious banner, not just mocked tests. Found via a self-directed security review of this cycle's changes; see `SECURITY.md`.

### Added
- **Distribution packaging** — `debian/` (control, rules, changelog, copyright), `packaging/rpm/sentinelscan.spec`, `packaging/aur/PKGBUILD`, `packaging/homebrew/sentinelscan.rb`, `packaging/snap/snapcraft.yaml`; release automation (`.github/workflows/release.yml`) and a maintainer runbook (`RELEASING.md`). The `debian/` package was actually built (`dpkg-buildpackage`) and verified `lintian --pedantic`-clean (zero errors/warnings) with the real installed binary exercised end-to-end.

### Fixed
- `setup.py`'s `find_packages()` was installing the `tests/` directory as an importable top-level `tests` package (an overly generic name risking collision with other packages). Fixed with `find_packages(exclude=["tests", "tests.*"])`.
- `setup.py`'s `data_files` (man page/completions) produced duplicate, inconsistently-named installs when combined with distro packaging's own explicit installs. Removed `data_files`; each packaging format now installs these assets itself.
- **Open-source project docs** — `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `SECURITY.md` (responsible disclosure policy, scoped explicitly to vulnerabilities in the tool itself vs. findings it reports), GitHub issue templates (bug/feature) and a PR template
- **Explicit Responsible Use section in README.md** and a new man page `LEGAL` section — states the no-telemetry policy plainly (and how to verify it yourself), the authorized-use-only requirement, and that default timing (`-T3`) is deliberately moderate rather than the fastest available
- **Concurrent scanning engine** – analyzer modules for a target now run in parallel via a thread pool instead of sequentially; multiple targets also scan in parallel
- **Timing templates (`-T0`–`-T5`)** – nmap-style presets trading stealth/politeness for speed, controlling default timeout, target concurrency, module concurrency, and port-scan concurrency
- **CIDR range scanning** – `sentinelscan 10.0.0.0/28` expands to individual hosts (capped at 1024 hosts as a safety limit)
- **Host-list input (`-iL FILE`)** – read targets from a file, one per line, `#` comments supported
- **Stdin input** – `cat targets.txt | sentinelscan -` reads targets from stdin
- Structured logging – progress/status messages now go to stderr, so stdout stays clean for piping (`sentinelscan example.com -f json | jq .` no longer breaks)
- Debug-level logging (`-v`) for previously-silent swallowed exceptions in `owasp`, `cors`, and `dns` analyzers
- **Port banner-grabbing** – open ports now report a service banner where one is available, not just open/closed
- **Authenticated scanning** – `-H/--header` (repeatable) and `--cookie` for scanning behind login (bearer tokens, session cookies)
- **SARIF 2.1.0 output** (`-f sarif`) – for GitHub Code Scanning and other CI security dashboards
- **Plugin system** (`sentinelscan/plugins.py`) – drop a `.py` file exposing an `ANALYZER` attribute into `--plugin-dir` (default `~/.config/sentinelscan/plugins/`) to add a custom check with zero source changes; `--no-plugins` to disable
- **Subdomain enumeration** (`subdomains` module) – passive discovery via crt.sh certificate transparency logs
- **Crawler mode** (`crawler` module, `--crawl-max-pages`) – checks security-header consistency across multiple same-origin pages, not just the homepage
- **Technology/CVE fingerprinting** (`cve_fingerprint` module) – detects product/version from response headers and checks against a bundled signature dataset (`sentinelscan/data/cve_signatures.json`)
- **Signature database updates** (`--update-db`, `--update-url`) – refreshes the CVE signature dataset from a remote URL, installed as a user-level override
- **`--doctor`** – self-diagnosis command reporting Python version, optional dependency availability, and config paths
- **First-run authorized-use disclaimer** – shown once on stderr, never blocks; suppress via `SENTINELSCAN_SKIP_DISCLAIMER=1`
- **Named exit code contract** (`EXIT_OK`/`EXIT_ERROR`/`EXIT_GATE_TRIPPED` = 0/1/2), documented in USAGE.md and consistently applied across every code path
- **Config/profile files** (`--profile NAME`, `--profile-file PATH`) – TOML files setting defaults for a recurring scan setup; explicit CLI flags always override a profile value, which always overrides the built-in default
- **Man page** (`man/sentinelscan.1`) and **shell completions** (bash/zsh/fish, in `completions/`), packaged via `setup.py`'s `data_files` for real distribution

### Fixed
- `--follow-redirects` accepted the flag but could never be disabled; `--no-follow-redirects` now works via `argparse.BooleanOptionalAction`
- `ssl_tls` analyzer ignored a non-default port in the target URL and always checked port 443
- `datetime.utcnow()` deprecation warnings removed in favor of timezone-aware calls
- `cookies` analyzer no longer relies on `http.cookiejar`'s private `_rest` attribute; parses raw `Set-Cookie` headers via `http.cookies.SimpleCookie`, which also fixes corruption when a response sets multiple cookies
- Removed `/robots.txt` and `/sitemap.xml` from the OWASP sensitive-path list (they're supposed to be public; they were pure noise)
- `python -m sentinelscan` always exited 0 regardless of scan results — `__main__.py` called `main()` without `sys.exit()`, silently breaking `--exit-on-critical`/`--score-threshold` CI gates for anyone invoking the tool via `-m` instead of the installed `sentinelscan` command. Caught by a subprocess-based regression test.
- `crawler` module reported "Inconsistent Security Headers Across 1 Page(s)" when only a single page was crawled — inconsistency requires comparing at least two pages; a lone page's missing headers are already reported by the `headers` module.

### Changed
- Test coverage expanded from 11 tests (~35% coverage) to 62 tests (~89% coverage) across all analyzers, the scanner, and the CLI
- Codebase modernized to PEP 585/604 type hints (`dict`/`list`/`X | None`) and is now `ruff`/`black`/`mypy` clean, enforced in CI
- Added GitHub Actions CI: lint/type-check job plus a test matrix across Python 3.9–3.13

---

## [2.0.0] – Industrial Release

### Added
- **CookiesAnalyzer** – per-cookie checks for Secure, HttpOnly, SameSite attributes
- **CorsAnalyzer** – wildcard origin, origin reflection, null-origin, credentials misconfiguration
- **DnsAnalyzer** – SPF record validation (hard/soft/+all), DMARC policy enforcement check, MX records
- **PortsAnalyzer** – concurrent scan of 16 common ports with risk classification
- **Risk scoring engine** – numeric score per target (Critical=40, High=20, Medium=10, Low=5, Info=1)
- **Letter grade system** – A+ through F based on cumulative risk score
- **CI/CD exit codes** – `--exit-on-critical` and `--score-threshold` flags
- **Severity filter** – `--severity` flag to restrict output to chosen severity levels
- **Multi-target scanning** – pass multiple hostnames in a single invocation
- **Retry logic** – configurable `--retries` with exponential backoff via urllib3
- **Per-module timing** – each module reports elapsed milliseconds
- **OWASP mapping** – findings reference OWASP Top-10 categories (A01, A03, A05, A06)
- **Weak CSP detection** – flags `unsafe-inline`, `unsafe-eval`, `*`, `data:` directives
- **HSTS quality checks** – flags max-age below 6 months
- **Server/X-Powered-By** – flags information-disclosure response headers
- **Full test suite** – 11 unit tests covering all analyzers and all reporters
- **HTML reporter overhaul** – dark-themed professional audit report with severity cards, grades, remediation
- **JSON reporter** – adds `generated_at`, `sentinelscan_version`, `summary.by_severity`
- **`setup.py`** – pip-installable package with `sentinelscan` console script entry point
- **`[dns]` extra** – optional `dnspython` install for enhanced DNS checks

### Changed
- Headers analyzer now checks 6 security headers (up from 3)
- SSL analyzer now checks protocol version and cipher separately with distinct findings
- Scanner now shares a single HTTP response across all analyzers (efficiency improvement)
- HTML report redesigned with dark theme, grade badge, and per-module collapsible sections

### Fixed
- `getaddrinfo` errors now produce a clean `__error__` key instead of crashing
- SSL verification errors fall back gracefully and report a Critical finding

---

## [1.0.0] – Initial Release

### Added
- HeadersAnalyzer: CSP, X-Frame-Options, HSTS detection
- SslTlsAnalyzer: certificate validity, expiry, issuer, cipher
- OwaspAnalyzer: insecure cookies, redirect checks, raw response capture
- Text reporter
- JSON reporter
- HTML reporter (basic)
- CLI with `-m` and `-f` flags
- Windows PATH setup and global `sentinelscan` CLI command
