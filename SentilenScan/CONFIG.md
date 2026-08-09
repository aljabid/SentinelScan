# Configuration Reference

SentinelScan is configured via CLI flags. There is no config file required — all options are passed at runtime, making it straightforward to embed in scripts and pipelines.

## All CLI Options

### Target
```
sentinelscan <target> [<target2> ...]
```
One or more hostnames or URLs. Both `example.com` and `https://example.com` are accepted.

### Module Selection
```
-m / --modules [MODULE ...]
```
Choose which analyzers to run. Use `all` to run everything (default).

Available modules: `headers`, `ssl_tls`, `owasp`, `cookies`, `cors`, `dns`, `ports`

### Output Format
```
-f / --format {text,json,html,sarif}
```
Default: `text`. `sarif` emits SARIF 2.1.0, consumable by GitHub Code Scanning and most CI security dashboards.

### Output File
```
-o / --output FILE
```
Write report to a file instead of stdout.

### Network Options
```
--timeout SECONDS     # Default: derived from -T (normally 10)
--retries N           # Default: 2
--user-agent STRING   # Default: "SentinelScan/2.0 (Security Scanner)"
--follow-redirects / --no-follow-redirects   # Default: follow
-T / --timing 0-5     # nmap-style timing template; controls timeout + concurrency
```

### Authenticated Scanning
```
-H / --header 'Name: Value'   # Repeatable; e.g. -H 'Authorization: Bearer TOKEN'
--cookie 'name=value; ...'    # Raw Cookie header for session-authenticated scans
```
Use these to reach behind-login endpoints (admin panels, authenticated APIs) that an anonymous scan can't see.

### Target Input
```
<target> [<target2> ...]      # hostnames, URLs, or CIDR ranges (e.g. 10.0.0.0/28)
-iL / --input-list FILE       # one target per line, '#' comments allowed
-                              # '-' as a target reads from stdin
```
CIDR ranges are capped at 1024 hosts as a safety limit against accidental mass-scanning.

### Filtering
```
--severity critical high medium low info
```
Only include findings at these severity levels in output. Applies to all reporters.

### CI/CD Gate Options
```
--exit-on-critical    # Exit with code 2 if any Critical finding detected
--score-threshold N   # Exit with code 2 if cumulative risk score > N
```
See [USAGE.md](USAGE.md#exit-codes) for the full exit code contract (0 / 1 / 2).

### Display Options
```
--no-color            # Disable ANSI colors in text output
--verbose / -v        # Print debug information
```

### Diagnostics & Maintenance
```
--doctor              # Report Python version, optional deps, config paths; exits 1 if anything's missing
--update-db           # Refresh the bundled CVE signature dataset
--update-url URL      # Custom source for --update-db (advanced)
```

### Authorized-Use Disclaimer
On first run, SentinelScan prints a one-time reminder to stderr that active
scanning requires authorization from the target's owner. It never blocks —
set `SENTINELSCAN_SKIP_DISCLAIMER=1` to suppress it in CI, or it auto-suppresses
after the first run (marker file at `~/.config/sentinelscan/.disclaimer_shown`).

## Adding a Custom Analyzer

1. Create `sentinelscan/analyzers/mycheck.py`:

```python
from sentinelscan.analyzers.base import BaseAnalyzer
from typing import Any, Dict

class MyCheckAnalyzer(BaseAnalyzer):
    name = "mycheck"

    def analyze(self) -> Dict[str, Any]:
        # self.response   – the requests.Response object
        # self.session    – the requests.Session (make additional requests)
        # self.target     – hostname string
        # self.url        – full URL string
        # self.timeout    – timeout int

        if some_condition:
            self.add_finding(
                title="My Finding",
                description="What is wrong",
                severity="high",           # critical|high|medium|low|info
                remediation="How to fix it",
                reference="https://...",
                evidence="Proof string",
            )

        return {"extra_meta_key": "value"}
```

2. Register in `sentinelscan/scanner.py`:
```python
from sentinelscan.analyzers.mycheck import MyCheckAnalyzer

MODULE_MAP = {
    ...
    "mycheck": MyCheckAnalyzer,
}
```

3. Register in `sentinelscan/cli.py`:
```python
ALL_MODULES = ["headers", "ssl_tls", "owasp", "cookies", "ports", "dns", "cors", "mycheck"]
```

4. Use it:
```bash
sentinelscan example.com -m mycheck
sentinelscan example.com -m all   # included automatically
```

This path requires editing the source tree, so it's meant for checks you intend to upstream. For local or team-specific checks you don't want to fork the project for, use a **plugin** instead.

---

## Plugins (No Source Changes Required)

Drop a `.py` file into a plugin directory and it becomes selectable via `-m`, exactly like a built-in module — no editing `scanner.py` or `cli.py`.

1. Create the plugin file anywhere, e.g. `~/.config/sentinelscan/plugins/mycheck.py`:

```python
from sentinelscan.analyzers.base import BaseAnalyzer
from typing import Any, Dict

class MyCheckAnalyzer(BaseAnalyzer):
    name = "mycheck"

    def analyze(self) -> Dict[str, Any]:
        if some_condition:
            self.add_finding(
                title="My Finding",
                description="What is wrong",
                severity="high",
                remediation="How to fix it",
            )
        return {}

# Required: the loader looks for this exact module-level name.
ANALYZER = MyCheckAnalyzer
```

2. Use it — no registration step needed:
```bash
sentinelscan example.com -m mycheck
```

### Plugin directory resolution
Checked in this order:
1. `--plugin-dir DIR` on the command line
2. `SENTINELSCAN_PLUGIN_DIR` environment variable
3. `~/.config/sentinelscan/plugins/` (default)

Pass `--no-plugins` to disable plugin loading entirely (e.g. for a locked-down CI run). Files starting with `_` are ignored (useful for shared helper modules other plugins import from). A plugin that fails to import, has no `ANALYZER` attribute, or isn't a `BaseAnalyzer` subclass is skipped with a warning — it won't crash the scan.

---

## Profiles

A profile is a small TOML file that sets defaults for a recurring scan setup, so you don't retype the same flag combination every time.

```bash
sentinelscan example.com --profile production-audit    # loads ~/.config/sentinelscan/profiles/production-audit.toml
sentinelscan example.com --profile-file ./ci-scan.toml  # explicit path
```

**Precedence**: an explicit CLI flag always wins over a profile value, which always wins over the built-in default. This means a profile is safe to commit to a repo and share across a team — anyone can still override a single field ad hoc without editing the file.

### Example profile

```toml
# ~/.config/sentinelscan/profiles/production-audit.toml
modules = ["headers", "ssl_tls", "cors", "cookies", "dns"]
format = "json"
timing = 2
retries = 3
score_threshold = 40
```

```bash
sentinelscan example.com --profile production-audit -f html   # -f html overrides the profile's json
```

### Profile-settable fields

`modules`, `format`, `severity`, `timing`, `timeout`, `retries`, `user_agent`, `plugin_dir`, `crawl_max_pages`, `score_threshold`.

Deliberately **not** settable from a profile: `--output` (a fixed path would make every scan silently overwrite the same file), `--cookie`/`-H` (target-specific secrets don't belong in a shared file), `--verbose`/`--no-color`/`--exit-on-critical` (per-invocation session flags, not scan-setup defaults).

Setting an unrecognized field, or a value that fails validation (e.g. `format = "yaml"`), fails fast with a clear error rather than silently ignoring it.
