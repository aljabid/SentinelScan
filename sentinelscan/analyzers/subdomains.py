"""Subdomain Enumeration Analyzer – passive discovery via certificate transparency logs."""

from __future__ import annotations

import json
import re
from typing import Any

from sentinelscan.analyzers.base import BaseAnalyzer

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
MAX_SUBDOMAINS_REPORTED = 200
_VALID_HOSTNAME = re.compile(r"^[a-z0-9.\-]+$")


class SubdomainsAnalyzer(BaseAnalyzer):
    name = "subdomains"

    def analyze(self) -> dict[str, Any]:
        hostname = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        base_domain = hostname[4:] if hostname.startswith("www.") else hostname

        try:
            resp = self.session.get(
                CRT_SH_URL.format(domain=base_domain),
                timeout=self.timeout,
                verify=False,
            )
        except Exception as exc:
            self.log.debug("crt.sh lookup failed for %s: %s", base_domain, exc)
            self.add_finding(
                title="Subdomain Enumeration Unavailable",
                description="Could not reach crt.sh to query certificate transparency data.",
                severity="info",
            )
            return {"subdomains": [], "source": "crt.sh"}

        subdomains: set[str] = set()
        if resp.status_code == 200 and resp.text.strip():
            try:
                entries = json.loads(resp.text)
            except ValueError:
                entries = []
            for entry in entries:
                for name in entry.get("name_value", "").split("\n"):
                    cleaned = name.strip().lower().lstrip("*.")
                    if cleaned and base_domain in cleaned and _VALID_HOSTNAME.match(cleaned):
                        subdomains.add(cleaned)

        sorted_subs = sorted(subdomains)[:MAX_SUBDOMAINS_REPORTED]

        if sorted_subs:
            preview = ", ".join(sorted_subs[:10]) + ("..." if len(sorted_subs) > 10 else "")
            self.add_finding(
                title=f"Subdomains Discovered via Certificate Transparency ({len(sorted_subs)})",
                description=(
                    f"Found {len(sorted_subs)} subdomain(s) for {base_domain} in public certificate "
                    "transparency logs. Review for forgotten/staging/dev hosts that may be less secured."
                ),
                severity="info",
                remediation="Ensure all discovered subdomains are intentional, inventoried, and secured.",
                evidence=preview,
            )
        else:
            self.add_finding(
                title="No Subdomains Found via Certificate Transparency",
                description=f"No subdomains for {base_domain} were found in crt.sh certificate transparency logs.",
                severity="info",
            )

        return {"subdomains": sorted_subs, "total_found": len(sorted_subs), "source": "crt.sh"}
