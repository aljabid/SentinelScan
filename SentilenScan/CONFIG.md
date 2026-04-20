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
-f / --format {text,json,html}
```
Default: `text`

### Output File
```
-o / --output FILE
```
Write report to a file instead of stdout.

### Network Options
```
--timeout SECONDS     # Default: 10
--retries N           # Default: 2
--user-agent STRING   # Default: "SentinelScan/2.0 (Security Scanner)"
--follow-redirects    # Default: enabled
```

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
Exit code 0 = pass, 2 = gate tripped.

### Display Options
```
--no-color            # Disable ANSI colors in text output
--verbose / -v        # Print debug information
```

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
