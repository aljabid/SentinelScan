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
- `subdomains` – Passive subdomain enumeration via certificate transparency logs (crt.sh)
- `crawler` – Crawls same-origin pages (`--crawl-max-pages`, default 15) and flags inconsistent security headers across the site
- `cve_fingerprint` – Detects product/version from response headers, checks against a bundled CVE signature dataset

### Updating the CVE signature database
```bash
sentinelscan --update-db                          # refresh from the default source
sentinelscan --update-db --update-url https://...  # refresh from a custom source
```
This is a static, bundled dataset (not a live feed) — refresh it periodically. Downloaded data is installed as a user-level override at `~/.config/sentinelscan/cve_signatures.json`.

### Output formats
```bash
sentinelscan example.com -f text          # Default colored terminal output
sentinelscan example.com -f json          # JSON to stdout
sentinelscan example.com -f json -o results.json   # JSON to file
sentinelscan example.com -f html -o report.html    # HTML audit report
sentinelscan example.com -f sarif -o results.sarif # SARIF, for GitHub Code Scanning etc.
```

### Authenticated scanning
```bash
sentinelscan example.com -H "Authorization: Bearer TOKEN" -m owasp
sentinelscan example.com --cookie "session=abc123" -m all
```

### Custom plugins (no source changes)
```bash
sentinelscan example.com -m mycheck --plugin-dir ./plugins
sentinelscan example.com --no-plugins   # skip loading any plugins
```
See [CONFIG.md](CONFIG.md#plugins-no-source-changes-required) for how to write one.

### Config/profile files
Avoid retyping a long flag combination for a recurring scan setup:
```bash
sentinelscan example.com --profile production-audit
sentinelscan example.com --profile-file ./ci-scan.toml
```
CLI flags always override a profile's values. See [CONFIG.md](CONFIG.md#profiles) for the file format and the full list of profile-settable fields.

### Scan multiple targets
```bash
sentinelscan example.com sub.example.com -m all -f html -o multi-report.html
```

### Scan a CIDR range or a host-list file
```bash
sentinelscan 10.0.0.0/28 -m ports              # expands to individual hosts (capped at 1024)
sentinelscan -iL targets.txt -m all -f json     # one target per line, '#' comments allowed
cat targets.txt | sentinelscan - -m headers     # '-' reads targets from stdin
```

### Timing templates (nmap-style)
```bash
sentinelscan example.com -T 0    # paranoid – slowest, most polite
sentinelscan example.com -T 3    # normal (default)
sentinelscan example.com -T 5    # insane – fastest, most parallel
```
`-T` sets default timeout and scan concurrency together; pass `--timeout` explicitly to override just the timeout while keeping a template's concurrency.

---

## All Options

| Flag | Default | Description |
|------|---------|-------------|
| `-m`, `--modules` | `all` | Modules to run (built-in or plugin) |
| `-f`, `--format` | `text` | Output format: text, json, html, sarif |
| `-o`, `--output` | stdout | Write output to file |
| `-iL`, `--input-list` | — | Read targets from FILE (one per line, CIDR accepted) |
| `-T`, `--timing` | `3` | Timing template 0 (paranoid) – 5 (insane) |
| `--timeout` | from `-T` | Request timeout (seconds); overrides the template's timeout |
| `--retries` | `2` | Retries on connection failure |
| `--severity` | all | Filter by severity: critical high medium low info |
| `--user-agent` | SentinelScan/2.0 | Custom User-Agent string |
| `-H`, `--header` | — | Add a custom HTTP header (repeatable); for auth tokens etc. |
| `--cookie` | — | Raw Cookie header, for authenticated/session scanning |
| `--plugin-dir` | `~/.config/sentinelscan/plugins` | Directory to load custom analyzer plugins from |
| `--profile` | — | Load defaults from `~/.config/sentinelscan/profiles/NAME.toml` |
| `--profile-file` | — | Load defaults from an explicit TOML file |
| `--no-plugins` | off | Disable plugin loading entirely |
| `--exit-on-critical` | off | Exit code 2 if any Critical finding |
| `--score-threshold` | `0` | Exit code 2 if risk score exceeds N |
| `--no-color` | off | Disable ANSI color in text output |
| `--verbose` / `-v` | off | Verbose/debug output |
| `--version` | — | Show version and exit |
| `--doctor` | — | Run self-diagnosis (Python version, optional deps, config paths) and exit |
| `--update-db` | — | Download the latest CVE signature database and exit |

---

## Exit Codes

SentinelScan uses three exit codes, consistently, across every invocation:

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no CI/CD gate tripped (or `--doctor`/`--update-db` succeeded) |
| `1` | Usage or runtime error — bad target/CIDR, malformed `-H` header, unknown module, network failure fetching a plugin/signature update. **The scan did not complete.** |
| `2` | Scan completed successfully, but a CI/CD gate (`--exit-on-critical` and/or `--score-threshold`) tripped |

Distinguishing `1` from `2` matters for CI: a `1` means your pipeline's *invocation* was wrong (fix the command), while a `2` means the *scan ran fine and found a real problem* (fix the target, or knowingly accept the risk). Don't conflate them in a build script.

---

## CI/CD Integration

### Fail build on Critical findings
```bash
sentinelscan production.example.com -m all --exit-on-critical
echo "Exit code: $?"   # 0 = safe, 1 = scan error, 2 = critical found
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
