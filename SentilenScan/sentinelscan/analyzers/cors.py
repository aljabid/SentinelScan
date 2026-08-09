"""CORS (Cross-Origin Resource Sharing) Analyzer."""

from __future__ import annotations

from typing import Any

from sentinelscan.analyzers.base import BaseAnalyzer


class CorsAnalyzer(BaseAnalyzer):
    name = "cors"

    def analyze(self) -> dict[str, Any]:
        if self.session is None:
            return {"error": "No session available"}

        cors_meta: dict[str, Any] = {}

        # Test 1: Wildcard origin
        try:
            r = self.session.get(
                self.url,
                timeout=self.timeout,
                verify=False,
                headers={"Origin": "https://evil.com"},
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            cors_meta["allow_origin"] = acao
            cors_meta["allow_credentials"] = acac

            if acao == "*":
                self.add_finding(
                    title="CORS: Wildcard Origin",
                    description="Access-Control-Allow-Origin: * allows any origin to read responses.",
                    severity="medium",
                    remediation="Restrict CORS to trusted origins. Replace '*' with a specific domain.",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                )
            elif acao == "https://evil.com":
                sev = "critical" if acac.lower() == "true" else "high"
                self.add_finding(
                    title="CORS: Arbitrary Origin Reflection",
                    description="Server reflects arbitrary Origin header in ACAO response.",
                    severity=sev,
                    remediation="Validate the Origin header against an allowlist of trusted domains.",
                    evidence=f"ACAO: {acao}  ACAC: {acac}",
                )
            elif acao:
                self.add_finding(
                    title="CORS Policy Present",
                    description=f"Access-Control-Allow-Origin is set to: {acao}",
                    severity="info",
                )
            else:
                self.add_finding(
                    title="No CORS Headers",
                    description="No CORS headers found. Cross-origin requests will be blocked by browsers.",
                    severity="info",
                )

            # Check for credentials + wildcard
            if acao == "*" and acac.lower() == "true":
                self.add_finding(
                    title="CORS: Credentials with Wildcard Origin",
                    description="Combining ACAO: * with ACAC: true is invalid and dangerous.",
                    severity="high",
                    remediation="Never combine credentials: true with a wildcard origin.",
                )

        except Exception as exc:
            return {"error": str(exc)}

        # Test 2: Null origin
        try:
            r2 = self.session.get(
                self.url,
                timeout=self.timeout,
                verify=False,
                headers={"Origin": "null"},
            )
            acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
            if acao2 == "null":
                self.add_finding(
                    title="CORS: Null Origin Allowed",
                    description=(
                        "Server accepts 'null' as an allowed origin. "
                        "Attackers can exploit this via sandboxed iframes."
                    ),
                    severity="medium",
                    remediation="Remove 'null' from the CORS origin allowlist.",
                )
        except Exception as exc:
            self.log.debug("Null-origin CORS probe failed: %s", exc)

        return cors_meta
