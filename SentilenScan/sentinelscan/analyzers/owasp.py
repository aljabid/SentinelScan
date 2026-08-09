"""OWASP Top-10 lightweight checks."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from sentinelscan.analyzers.base import BaseAnalyzer

SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/wp-config.php",
    "/phpinfo.php",
    "/admin",
    "/admin/login",
    "/.htaccess",
    "/server-status",
    "/api/v1/users",
    "/swagger.json",
    "/openapi.json",
    "/.DS_Store",
    "/crossdomain.xml",
]

ERROR_PATTERNS = [
    (r"(?i)(mysql_fetch|pg_query|ORA-\d+|syntax error.*sql)", "SQL Error Disclosure"),
    (r"(?i)(stack trace|at .+ line \d+)", "Stack Trace Exposure"),
    (r"(?i)(php warning|php notice|php error)", "PHP Error Disclosure"),
    (r"(?i)(exception in thread|java\.lang)", "Java Exception Disclosure"),
    (r"(?i)(debug mode|debug=true)", "Debug Mode Enabled"),
]


class OwaspAnalyzer(BaseAnalyzer):
    name = "owasp"

    def analyze(self) -> dict[str, Any]:
        if self.response is None:
            return {"error": "No HTTP response available"}

        body = ""
        try:
            body = self.response.text[:50000]  # Limit to 50KB
        except Exception:
            pass

        exposed_paths = []
        checked = []

        # A01 – Broken Access Control: sensitive path probing
        for path in SENSITIVE_PATHS:
            test_url = urljoin(self.url, path)
            checked.append(test_url)
            try:
                r = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    severity = "high" if r.status_code == 200 else "medium"
                    note = "accessible" if r.status_code == 200 else f"returned {r.status_code}"
                    if r.status_code != 404:
                        exposed_paths.append(path)
                        if path in ["/.git/config", "/.env", "/.env.production", "/wp-config.php"]:
                            severity = "critical"
                        self.add_finding(
                            title=f"Sensitive Path {note}: {path}",
                            description=f"Sensitive resource at {path} returned HTTP {r.status_code}.",
                            severity=severity,
                            remediation=f"Restrict access to {path} via web server configuration.",
                            evidence=f"URL: {test_url}  Status: {r.status_code}",
                        )
            except Exception as exc:
                self.log.debug("Probe failed for %s: %s", test_url, exc)

        # A03 – Injection: error message patterns in response body
        for pattern, name in ERROR_PATTERNS:
            match = re.search(pattern, body)
            if match:
                self.add_finding(
                    title=f"A03 – Error Information Disclosure: {name}",
                    description=f"The response body contains patterns suggesting {name.lower()}.",
                    severity="medium",
                    remediation="Disable verbose error messages in production. Log internally instead.",
                    evidence=match.group(0)[:200],
                )

        # A05 – Security Misconfiguration: check for directory listing
        try:
            r = self.session.get(self.url + "/nonexistent-path-xyz123", timeout=self.timeout, verify=False)
            if r.status_code == 200 and ("index of" in r.text.lower() or "parent directory" in r.text.lower()):
                self.add_finding(
                    title="A05 – Directory Listing Enabled",
                    description="The web server returns a directory listing for unknown paths.",
                    severity="high",
                    remediation="Disable directory listing in your web server configuration.",
                )
        except Exception as exc:
            self.log.debug("Directory listing probe failed: %s", exc)

        # A06 – Vulnerable and Outdated Components: check server/powered-by headers
        headers = {k.lower(): v for k, v in self.response.headers.items()}
        server = headers.get("server", "")
        version_pattern = re.search(r"[\d]+\.[\d]+", server)
        if version_pattern and server:
            self.add_finding(
                title="A06 – Server Version Disclosure",
                description=f"Server header discloses version: {server}",
                severity="low",
                remediation="Remove version information from the Server header.",
                evidence=f"Server: {server}",
            )

        # Check for mixed content hints (http: in https response)
        if self.url.startswith("https://") and "http://" in body:
            http_matches = re.findall(r'http://[^\s"\'<>]{5,50}', body)
            if http_matches:
                self.add_finding(
                    title="A05 – Potential Mixed Content",
                    description="HTTPS page contains references to HTTP resources.",
                    severity="medium",
                    remediation="Replace all HTTP resource links with HTTPS.",
                    evidence=", ".join(http_matches[:3]),
                )

        return {
            "paths_checked": len(SENSITIVE_PATHS),
            "exposed_paths": exposed_paths,
        }
