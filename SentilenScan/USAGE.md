# Usage Guide

## Basic Usage

```bash
sentinelscan <target> [options]
```

`<target>` can be a hostname (`example.com`) or URL (`https://example.com`).

---

## Common Commands

### Scan with all modules, text output
```bash
sentinelscan example.com
```

### Scan specific modules
```bash
sentinelscan example.com -m headers ssl_tls
sentinelscan example.com -m headers ssl_tls owasp cookies cors dns ports
```

### Available modules
- `headers` – HTTP security headers
- `ssl_tls` – TLS certificate and cipher analysis
- `owasp` – OWASP Top-10 lightweight checks
- `cookies` – Cookie security flags
- `cors` – Cross-origin resource sharing policy
- `dns` – SPF, DMARC, MX records
- `ports` – Common port scan

### Output formats
```bash
sentinelscan example.com -f text          # Default colored terminal output
sentinelscan example.com -f json          # JSON to stdout
sentinelscan example.com -f json -o results.json   # JSON to file
sentinelscan example.com -f html -o report.html    # HTML audit report
```

### Scan multiple targets
```bash
sentinelscan example.com sub.example.com -m all -f html -o multi-report.html
```

---

## All Options

| Flag | Default | Description |
|------|---------|-------------|
| `-m`, `--modules` | `all` | Modules to run |
| `-f`, `--format` | `text` | Output format: text, json, html |
| `-o`, `--output` | stdout | Write output to file |
| `--timeout` | `10` | Request timeout (seconds) |
| `--retries` | `2` | Retries on connection failure |
| `--severity` | all | Filter by severity: critical high medium low info |
| `--user-agent` | SentinelScan/2.0 | Custom User-Agent string |
| `--exit-on-critical` | off | Exit code 2 if any Critical finding |
| `--score-threshold` | `0` | Exit code 2 if risk score exceeds N |
| `--no-color` | off | Disable ANSI color in text output |
| `--verbose` / `-v` | off | Verbose/debug output |
| `--version` | — | Show version and exit |

---

## CI/CD Integration

### Fail build on Critical findings
```bash
sentinelscan production.example.com -m all --exit-on-critical
echo "Exit code: $?"   # 0 = safe, 2 = critical found
```

### Fail build if risk score too high
```bash
sentinelscan production.example.com -m all --score-threshold 40
```

### Save JSON artifact for further processing
```bash
sentinelscan production.example.com -m all -f json -o security-scan.json
```

---

## Interpreting Risk Grades

| Grade | Risk Score | Meaning |
|-------|-----------|---------|
| **A+** | 0 | Perfect – no findings |
| **A** | 1–10 | Excellent – minor info findings only |
| **B** | 11–25 | Good – some low/medium findings |
| **C** | 26–50 | Fair – multiple medium or some high findings |
| **D** | 51–80 | Poor – high severity findings present |
| **F** | 80+ | Critical risk – immediate action required |

---

## Understanding Severity Levels

| Level | Meaning | Example |
|-------|---------|---------|
| **Critical** | Immediate exploitation risk | Expired certificate, `+all` SPF, exposed Redis port |
| **High** | Significant risk, fix soon | Missing HSTS, missing CSP, weak TLS protocol |
| **Medium** | Moderate risk | Missing X-Frame-Options, SameSite missing, DMARC `p=none` |
| **Low** | Minor / informational risk | Server header disclosure, Referrer-Policy missing |
| **Info** | Informational, no risk | Certificate valid, strong cipher in use |

---

## Example: Full Audit Workflow

```bash
# 1. Quick check – text output
sentinelscan client-site.com

# 2. Deep scan – HTML report for client delivery
sentinelscan client-site.com -m all -f html -o client-audit-2024.html

# 3. JSON for automated tracking
sentinelscan client-site.com -m all -f json -o baseline.json

# 4. Recheck after fixes – compare scores
sentinelscan client-site.com -m all -f json -o post-fix.json
```
