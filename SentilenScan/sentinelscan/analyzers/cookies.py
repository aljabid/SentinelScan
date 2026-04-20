"""Cookie Security Analyzer."""

from __future__ import annotations

from typing import Any, Dict, List

from sentinelscan.analyzers.base import BaseAnalyzer


class CookiesAnalyzer(BaseAnalyzer):
    name = "cookies"

    def analyze(self) -> Dict[str, Any]:
        if self.response is None:
            return {"error": "No HTTP response available"}

        cookies = self.response.cookies
        cookie_list: List[Dict[str, Any]] = []

        for cookie in cookies:
            info: Dict[str, Any] = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie._rest).lower(),
                "samesite": None,
                "domain": cookie.domain,
                "path": cookie.path,
            }

            # Extract SameSite from cookie attributes
            raw = str(cookie._rest)
            if "samesite=strict" in raw.lower():
                info["samesite"] = "Strict"
            elif "samesite=lax" in raw.lower():
                info["samesite"] = "Lax"
            elif "samesite=none" in raw.lower():
                info["samesite"] = "None"

            cookie_list.append(info)

            name = cookie.name
            is_session = any(k in name.lower() for k in ["session", "sess", "token", "auth", "jwt"])

            # Secure flag
            if not cookie.secure:
                severity = "high" if is_session else "medium"
                self.add_finding(
                    title=f"Cookie Missing Secure Flag: {name}",
                    description=f"Cookie '{name}' can be transmitted over HTTP.",
                    severity=severity,
                    remediation=f"Add the Secure flag to cookie '{name}'.",
                    evidence=f"Set-Cookie: {name}=...",
                )

            # HttpOnly flag
            if not info["httponly"]:
                severity = "high" if is_session else "medium"
                self.add_finding(
                    title=f"Cookie Missing HttpOnly Flag: {name}",
                    description=f"Cookie '{name}' is accessible via JavaScript (XSS risk).",
                    severity=severity,
                    remediation=f"Add the HttpOnly flag to cookie '{name}'.",
                )

            # SameSite
            if info["samesite"] is None:
                self.add_finding(
                    title=f"Cookie Missing SameSite Attribute: {name}",
                    description=f"Cookie '{name}' has no SameSite attribute (CSRF risk).",
                    severity="medium",
                    remediation="Add SameSite=Strict or SameSite=Lax to the cookie.",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                )
            elif info["samesite"] == "None" and not cookie.secure:
                self.add_finding(
                    title=f"SameSite=None Without Secure: {name}",
                    description="SameSite=None cookies must also have the Secure attribute.",
                    severity="high",
                    remediation="Add the Secure attribute when using SameSite=None.",
                )

        if not cookie_list:
            self.add_finding(
                title="No Cookies Detected",
                description="No Set-Cookie headers were found in the response.",
                severity="info",
            )

        return {"cookies": cookie_list, "total_cookies": len(cookie_list)}
