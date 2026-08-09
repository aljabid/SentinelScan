#  SentinelScan

**Web Security Scanner, modular and built in Python.**

SentinelScan scans web targets for misconfigurations, insecure headers, TLS/SSL issues, cookie flaws, CORS vulnerabilities, DNS security gaps, and exposed ports — producing audit-ready reports in Text, JSON, and HTML formats.

---

## Features

| Module | What It Checks |
|--------|---------------|
| `headers` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, info-disclosure headers |
| `ssl_tls` | Certificate validity/expiry, protocol version (TLS 1.0–1.3), cipher strength |
| `owasp` | Sensitive path exposure, error disclosure, directory listing, mixed content (OWASP Top-10 mapping) |
| `cookies` | Secure flag, HttpOnly flag, SameSite attribute per-cookie |
| `cors` | Wildcard origin, origin reflection, null-origin, credentials misconfiguration |
| `dns` | SPF, DMARC, MX records, DNS resolution |
| `ports` | 16 common ports — flags risky services (Telnet, RDP, Redis, MongoDB, etc.), grabs banners |
| `subdomains` | Passive subdomain enumeration via certificate transparency logs (crt.sh) |
| `crawler` | Crawls same-origin pages, flags inconsistent security headers across the site |
| `cve_fingerprint` | Detects product/version from response headers, checks against a bundled CVE signature dataset |

**Risk scoring** assigns a numeric score and letter grade (A+ → F) per target — useful for tracking posture over time.

**CI/CD gates** via `--exit-on-critical` and `--score-threshold` flags.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/aljabid/SentinelScan.git
cd sentinelscan

# Install (editable / development)
pip install -e .

# Install with DNS support
pip install -e ".[dns]"

# Verify
sentinelscan --version
```

---

## Quick Start

```bash
# Basic scan (all modules, text output)
sentinelscan example.com

# Specific modules only
sentinelscan example.com -m headers ssl_tls cors

# JSON output for automation
sentinelscan example.com -m all -f json -o results.json

# Professional HTML audit report
sentinelscan example.com -m all -f html -o report.html

# Scan multiple targets
sentinelscan example.com sub.example.com another.com -m all -f html -o report.html

# CI/CD gate: fail build if any Critical finding exists
sentinelscan example.com -m all --exit-on-critical

# CI/CD gate: fail build if risk score exceeds 50
sentinelscan example.com -m all --score-threshold 50

# Filter output to only High and Critical findings
sentinelscan example.com -m all --severity critical high

# Custom timeout and retries (useful for slow targets)
sentinelscan example.com --timeout 20 --retries 3

# CIDR range / host-list / stdin input
sentinelscan 10.0.0.0/28 -m ports --timing 4
sentinelscan -iL targets.txt -m all -f json

# Authenticated scanning
sentinelscan example.com -H "Authorization: Bearer TOKEN" --cookie "session=abc123"

# SARIF output for GitHub Code Scanning / CI dashboards
sentinelscan example.com -f sarif -o results.sarif
```

---

## Output Formats

### Text (default)
Color-coded terminal output with severity badges, remediation advice, and a summary table.

### JSON
Structured output with full findings, metadata, timing, and summary counts — suitable for SIEM ingestion, dashboards, or CI/CD pipelines.

### SARIF
SARIF 2.1.0 output for GitHub Code Scanning and other tool-chain integrations that consume the standard.

### HTML
A professional dark-themed audit report with:
- Summary cards (findings by severity)
- Per-target risk grade and score
- Per-module findings with remediation and references
- Evidence snippets with links to documentation

---

## Risk Grading

| Grade | Risk Score |
|-------|-----------|
| A+    | 0 |
| A     | 1–10 |
| B     | 11–25 |
| C     | 26–50 |
| D     | 51–80 |
| F     | 80+ |

Scores are calculated from finding severities: Critical=40, High=20, Medium=10, Low=5, Info=1.

---

## Architecture

```
sentinelscan/
├── cli.py              # Argument parsing, entry point, concurrency orchestration
├── scanner.py          # Dispatches analyzers concurrently, risk scoring
├── plugins.py           # Loads external analyzer plugins (no source edits needed)
├── config_file.py       # TOML profile loading (--profile / --profile-file)
├── analyzers/
│   ├── base.py         # BaseAnalyzer + Finding dataclass
│   ├── headers.py      # HTTP security headers
│   ├── ssl_tls.py      # TLS/SSL certificate & cipher analysis
│   ├── owasp.py        # OWASP Top-10 lightweight checks
│   ├── cookies.py      # Cookie security flags
│   ├── cors.py         # CORS policy analysis
│   ├── dns.py          # SPF, DMARC, DNS records
│   ├── ports.py        # Concurrent port scanning + banner grabbing
│   ├── subdomains.py   # Passive subdomain enumeration (crt.sh)
│   ├── crawler.py      # Multi-page crawl, header-consistency check
│   └── cve_fingerprint.py  # Version detection + bundled CVE signatures
├── data/
│   └── cve_signatures.json  # Bundled CVE dataset, refreshable via --update-db
├── updater.py           # Downloads a fresh signature dataset (--update-db)
└── reporters/
    ├── text_reporter.py
    ├── json_reporter.py
    ├── sarif_reporter.py
    └── html_reporter.py
```

Two ways to add a check:
1. **Built-in analyzer** (to contribute upstream): create `sentinelscan/analyzers/mycheck.py` inheriting `BaseAnalyzer`, implement `analyze()`, register in `scanner.py`'s `MODULE_MAP`
2. **Plugin** (local/team-specific, no source changes): drop a `.py` file exposing an `ANALYZER` attribute into `~/.config/sentinelscan/plugins/` — see [CONFIG.md](CONFIG.md#plugins-no-source-changes-required)

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
pytest tests/ -v --cov=sentinelscan --cov-report=term-missing
```

---

## CI/CD Integration Example (GitHub Actions)

```yaml
- name: Security Scan
  run: |
    pip install sentinelscan
    sentinelscan ${{ env.TARGET_HOST }} -m all -f json -o scan.json --exit-on-critical
  
- name: Upload Scan Report
  uses: actions/upload-artifact@v3
  with:
    name: security-scan
    path: scan.json
```

---

## Comparison

| Feature | SentinelScan v2 | Nmap |
|---------|----------------|------|
| Headers analysis | ✅ Deep | ❌ |
| TLS/SSL analysis | ✅ | Partial (scripts) |
| Cookie analysis | ✅ | ❌ |
| CORS testing | ✅ | ❌ |
| DNS (SPF/DMARC) | ✅ | ❌ |
| OWASP mapping | ✅ | ❌ |
| Port scanning | Basic | ✅ Deep |
| HTML reports | ✅ | ❌ |
| JSON output | ✅ | ✅ |
| CI/CD gates | ✅ | ❌ |
| Risk grading | ✅ | ❌ |
| Python extensible | ✅ | NSE (Lua) |

---

## Responsible Use

SentinelScan performs **active** probes against the targets you specify:
port connections, path enumeration, CORS/header requests. **Only scan
systems you own or have explicit written authorization to test.**
Unauthorized scanning may violate computer-crime laws (e.g. the US CFAA) and
the target's terms of service. The CLI prints a one-time reminder of this on
first run (see `SECURITY.md` for what's in and out of scope for this policy,
and `SENTINELSCAN_SKIP_DISCLAIMER=1` to suppress it in CI once you've read it).

**No telemetry.** SentinelScan does not phone home, does not collect
analytics, and does not send data anywhere except: the target(s) you
specify, `crt.sh` (only if you run the `subdomains` module), and the
configured signature-database URL (only if you explicitly run
`--update-db`). Nothing about your usage, targets, or findings is ever sent
to the SentinelScan project itself. Verify this yourself — it's ~2,000 lines
of Python with no analytics library imported anywhere in `install_requires`.

**Safe by default.** The default timing template (`-T3`, "normal") uses
moderate concurrency and a 10-second timeout — not the fastest the tool can
go. Faster, noisier scanning (`-T4`/`-T5`) is opt-in, not the default,
specifically so a first-time `sentinelscan example.com` doesn't come across
as aggressive probing against a target that didn't expect it.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
