"""HTTP Security Headers Analyzer."""

from __future__ import annotations

from typing import Any, Dict

from sentinelscan.analyzers.base import BaseAnalyzer

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP header is missing. Without it, the site is vulnerable to XSS attacks.",
        "remediation": "Add a strict Content-Security-Policy header. Start with: "
                       "Content-Security-Policy: default-src 'self'",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options is missing, enabling potential clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is required)",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "X-Content-Type-Options is missing. Browsers may MIME-sniff responses.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS header is missing. The site may be downgraded to HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy is missing. Referrer data may leak to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy (formerly Feature-Policy) is missing.",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
}

INSECURE_HEADERS = {
    "Server": {
        "severity": "low",
        "description": "Server header reveals web server software and version.",
        "remediation": "Remove or genericise the Server header in your web server config.",
    },
    "X-Powered-By": {
        "severity": "low",
        "description": "X-Powered-By reveals technology stack information.",
        "remediation": "Remove the X-Powered-By header (e.g., set in Express: app.disable('x-powered-by'))",
    },
    "X-AspNet-Version": {
        "severity": "low",
        "description": "X-AspNet-Version exposes .NET framework version.",
        "remediation": "Remove X-AspNet-Version from IIS/ASP.NET configuration.",
    },
}

WEAK_CSP_DIRECTIVES = ["unsafe-inline", "unsafe-eval", "*", "data:"]


class HeadersAnalyzer(BaseAnalyzer):
    name = "headers"

    def analyze(self) -> Dict[str, Any]:
        if self.response is None:
            return {"error": "No HTTP response available"}

        headers = {k.lower(): v for k, v in self.response.headers.items()}
        present = []
        missing = []

        # Check required headers
        for header, meta in REQUIRED_HEADERS.items():
            key = header.lower()
            if key in headers:
                present.append(header)
                # Extra: check CSP quality
                if header == "Content-Security-Policy":
                    csp_val = headers[key]
                    for weak in WEAK_CSP_DIRECTIVES:
                        if weak in csp_val:
                            self.add_finding(
                                title=f"Weak CSP Directive: {weak}",
                                description=f"CSP contains '{weak}' which weakens its protection.",
                                severity="medium",
                                remediation=f"Remove '{weak}' from your CSP policy.",
                                reference=meta["reference"],
                                evidence=f"CSP value: {csp_val[:200]}",
                            )
                # Extra: check HSTS max-age
                if header == "Strict-Transport-Security":
                    hsts_val = headers[key]
                    for part in hsts_val.split(";"):
                        part = part.strip()
                        if part.startswith("max-age="):
                            try:
                                age = int(part.split("=")[1])
                                if age < 15768000:
                                    self.add_finding(
                                        title="HSTS max-age Too Short",
                                        description=f"HSTS max-age is {age}s (< 6 months). Recommend ≥ 1 year.",
                                        severity="medium",
                                        remediation="Set max-age=31536000 (1 year) or higher.",
                                        reference=meta["reference"],
                                        evidence=f"Current HSTS: {hsts_val}",
                                    )
                            except ValueError:
                                pass
            else:
                missing.append(header)
                self.add_finding(
                    title=f"Missing Header: {header}",
                    description=meta["description"],
                    severity=meta["severity"],
                    remediation=meta["remediation"],
                    reference=meta["reference"],
                )

        # Check information-leaking headers
        for header, meta in INSECURE_HEADERS.items():
            key = header.lower()
            if key in headers:
                self.add_finding(
                    title=f"Information Disclosure: {header}",
                    description=meta["description"],
                    severity=meta["severity"],
                    remediation=meta["remediation"],
                    evidence=f"{header}: {headers[key]}",
                )

        return {
            "headers_present": present,
            "headers_missing": missing,
            "total_headers": len(headers),
        }
