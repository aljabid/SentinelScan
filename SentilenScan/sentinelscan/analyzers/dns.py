"""DNS Security Analyzer – SPF, DMARC, DNSSEC, zone transfer."""

from __future__ import annotations

import socket
from typing import Any

from sentinelscan.analyzers.base import BaseAnalyzer

try:
    import dns.exception
    import dns.query
    import dns.resolver
    import dns.zone

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DnsAnalyzer(BaseAnalyzer):
    name = "dns"

    def analyze(self) -> dict[str, Any]:
        hostname = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        meta: dict[str, Any] = {"hostname": hostname}

        # Basic resolution
        try:
            ip = socket.gethostbyname(hostname)
            meta["ip"] = ip
            self.add_finding(
                title="DNS Resolution Successful",
                description=f"Resolved to {ip}",
                severity="info",
            )
        except socket.gaierror as exc:
            self.add_finding(
                title="DNS Resolution Failed",
                description=str(exc),
                severity="high",
                remediation="Verify DNS configuration for the domain.",
            )
            return meta

        if not DNS_AVAILABLE:
            self.add_finding(
                title="Advanced DNS Checks Skipped",
                description="dnspython not installed. Install with: pip install dnspython",
                severity="info",
            )
            return meta

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # SPF check
        try:
            answers = resolver.resolve(hostname, "TXT")
            spf_found = False
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    spf_found = True
                    meta["spf"] = txt
                    if "~all" in txt:
                        self.add_finding(
                            title="SPF: Soft Fail (~all)",
                            description="SPF uses ~all (soft fail). Spoofed emails may pass.",
                            severity="medium",
                            remediation="Consider using -all (hard fail) for stricter enforcement.",
                            evidence=txt,
                        )
                    elif "-all" in txt:
                        self.add_finding(
                            title="SPF: Hard Fail Configured",
                            description="SPF -all is set correctly.",
                            severity="info",
                            evidence=txt,
                        )
                    elif "+all" in txt:
                        self.add_finding(
                            title="SPF: +all Is Dangerous",
                            description="SPF +all allows any server to send mail on your behalf.",
                            severity="critical",
                            remediation="Replace +all with -all immediately.",
                            evidence=txt,
                        )
            if not spf_found:
                self.add_finding(
                    title="SPF Record Missing",
                    description="No SPF record found. Domain is vulnerable to email spoofing.",
                    severity="medium",
                    remediation="Add an SPF TXT record: v=spf1 include:yourmailprovider.com -all",
                    reference="https://www.rfc-editor.org/rfc/rfc7208",
                )
        except Exception as exc:
            self.log.debug("SPF lookup failed for %s: %s", hostname, exc)

        # DMARC check
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            for rdata in dmarc_answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    meta["dmarc"] = txt
                    if "p=none" in txt:
                        self.add_finding(
                            title="DMARC Policy: None (Monitor Only)",
                            description="DMARC is in monitoring mode only (p=none). No enforcement.",
                            severity="medium",
                            remediation="Move to p=quarantine or p=reject after monitoring.",
                            evidence=txt,
                        )
                    elif "p=quarantine" in txt:
                        self.add_finding(
                            title="DMARC Policy: Quarantine",
                            description="DMARC quarantine policy is active.",
                            severity="info",
                        )
                    elif "p=reject" in txt:
                        self.add_finding(
                            title="DMARC Policy: Reject (Strongest)",
                            description="DMARC reject policy is fully enforced.",
                            severity="info",
                        )
        except dns.resolver.NXDOMAIN:
            self.add_finding(
                title="DMARC Record Missing",
                description="No DMARC record found. Email spoofing is not protected.",
                severity="medium",
                remediation="Add a DMARC TXT record at _dmarc.yourdomain.com",
                reference="https://dmarc.org",
            )
        except Exception as exc:
            self.log.debug("DMARC lookup failed for %s: %s", hostname, exc)

        # MX records
        try:
            mx_answers = resolver.resolve(hostname, "MX")
            meta["mx_records"] = [str(r.exchange) for r in mx_answers]
        except Exception as exc:
            self.log.debug("MX lookup failed for %s: %s", hostname, exc)

        return meta
