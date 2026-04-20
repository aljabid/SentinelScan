# ⚔ SentinelScan

**Industrial-grade, modular web security scanner built in Python.**

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
| `ports` | 16 common ports — flags risky services (Telnet, RDP, Redis, MongoDB, etc.) |

**Risk scoring** assigns a numeric score and letter grade (A+ → F) per target — useful for tracking posture over time.

**CI/CD gates** via `--exit-on-critical` and `--score-threshold` flags.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/sentinelscan.git
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
```

---

## Output Formats

### Text (default)
Color-coded terminal output with severity badges, remediation advice, and a summary table.

### JSON
Structured output with full findings, metadata, timing, and summary counts — suitable for SIEM ingestion, dashboards, or CI/CD pipelines.

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
├── cli.py              # Argument parsing & entry point
├── scanner.py          # Orchestrator – dispatches analyzers
├── analyzers/
│   ├── base.py         # BaseAnalyzer + Finding dataclass
│   ├── headers.py      # HTTP security headers
│   ├── ssl_tls.py      # TLS/SSL certificate & cipher analysis
│   ├── owasp.py        # OWASP Top-10 lightweight checks
│   ├── cookies.py      # Cookie security flags
│   ├── cors.py         # CORS policy analysis
│   ├── dns.py          # SPF, DMARC, DNS records
│   └── ports.py        # Concurrent port scanning
└── reporters/
    ├── text_reporter.py
    ├── json_reporter.py
    └── html_reporter.py
```

Adding a new analyzer requires only:
1. Create `sentinelscan/analyzers/mycheck.py` inheriting `BaseAnalyzer`
2. Implement `analyze()` — call `self.add_finding()` for each issue
3. Register it in `scanner.py` MODULE_MAP and `cli.py` ALL_MODULES

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

## License

MIT License. See [LICENSE](LICENSE) for details.
