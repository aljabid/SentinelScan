"""Cookie Security Analyzer."""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Any

from sentinelscan.analyzers.base import BaseAnalyzer


class CookiesAnalyzer(BaseAnalyzer):
    name = "cookies"

    def analyze(self) -> dict[str, Any]:
        if self.response is None:
            return {"error": "No HTTP response available"}

        cookie_list: list[dict[str, Any]] = []

        for raw_header in self._raw_set_cookie_headers():
            parsed: SimpleCookie = SimpleCookie()
            try:
                parsed.load(raw_header)
            except Exception:
                continue
            for name, morsel in parsed.items():
                info: dict[str, Any] = {
                    "name": name,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                    "domain": morsel["domain"] or None,
                    "path": morsel["path"] or None,
                }
                cookie_list.append(info)
                self._evaluate_cookie(info)

        if not cookie_list:
            self.add_finding(
                title="No Cookies Detected",
                description="No Set-Cookie headers were found in the response.",
                severity="info",
            )

        return {"cookies": cookie_list, "total_cookies": len(cookie_list)}

    def _raw_set_cookie_headers(self) -> list[str]:
        # requests merges repeated Set-Cookie headers with ", ", which corrupts
        # Expires; the urllib3 raw header list preserves them individually.
        try:
            values = self.response.raw.headers.getlist("Set-Cookie")
            if values:
                return list(values)
        except Exception:
            pass
        header_val = self.response.headers.get("Set-Cookie") if hasattr(self.response, "headers") else None
        return [header_val] if header_val else []

    def _evaluate_cookie(self, info: dict[str, Any]) -> None:
        name = info["name"]
        is_session = any(k in name.lower() for k in ["session", "sess", "token", "auth", "jwt"])

        if not info["secure"]:
            severity = "high" if is_session else "medium"
            self.add_finding(
                title=f"Cookie Missing Secure Flag: {name}",
                description=f"Cookie '{name}' can be transmitted over HTTP.",
                severity=severity,
                remediation=f"Add the Secure flag to cookie '{name}'.",
                evidence=f"Set-Cookie: {name}=...",
            )

        if not info["httponly"]:
            severity = "high" if is_session else "medium"
            self.add_finding(
                title=f"Cookie Missing HttpOnly Flag: {name}",
                description=f"Cookie '{name}' is accessible via JavaScript (XSS risk).",
                severity=severity,
                remediation=f"Add the HttpOnly flag to cookie '{name}'.",
            )

        samesite = info["samesite"]
        if not samesite:
            self.add_finding(
                title=f"Cookie Missing SameSite Attribute: {name}",
                description=f"Cookie '{name}' has no SameSite attribute (CSRF risk).",
                severity="medium",
                remediation="Add SameSite=Strict or SameSite=Lax to the cookie.",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
            )
        elif samesite.lower() == "none" and not info["secure"]:
            self.add_finding(
                title=f"SameSite=None Without Secure: {name}",
                description="SameSite=None cookies must also have the Secure attribute.",
                severity="high",
                remediation="Add the Secure attribute when using SameSite=None.",
            )
