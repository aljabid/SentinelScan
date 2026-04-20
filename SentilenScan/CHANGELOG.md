# Changelog

All notable changes to SentinelScan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
