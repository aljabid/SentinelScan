"""SSL/TLS Analyzer – certificate validation, cipher suites, protocol versions."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any, Dict

from sentinelscan.analyzers.base import BaseAnalyzer

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON",
    "ADH", "AECDH", "aNULL", "eNULL", "LOW", "EXP",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


class SslTlsAnalyzer(BaseAnalyzer):
    name = "ssl_tls"

    def analyze(self) -> Dict[str, Any]:
        target = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        port = 443

        meta: Dict[str, Any] = {
            "tls_enabled": False,
            "certificate": {},
            "cipher": {},
            "protocol": None,
        }

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    meta["tls_enabled"] = True
                    meta["protocol"] = ssock.version()

                    cipher_info = ssock.cipher()
                    meta["cipher"] = {
                        "name": cipher_info[0] if cipher_info else "unknown",
                        "protocol": cipher_info[1] if cipher_info else "unknown",
                        "bits": cipher_info[2] if cipher_info else 0,
                    }

                    cert = ssock.getpeercert()
                    if cert:
                        not_after_str = cert.get("notAfter", "")
                        not_before_str = cert.get("notBefore", "")

                        try:
                            not_after = ssl.cert_time_to_seconds(not_after_str)
                            not_before = ssl.cert_time_to_seconds(not_before_str)
                            expiry_dt = datetime.datetime.utcfromtimestamp(not_after)
                            days_left = (expiry_dt - datetime.datetime.utcnow()).days
                        except Exception:
                            days_left = None
                            expiry_dt = None

                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        san = cert.get("subjectAltName", [])

                        meta["certificate"] = {
                            "subject": subject.get("commonName", "unknown"),
                            "issuer": issuer.get("organizationName", "unknown"),
                            "not_after": not_after_str,
                            "not_before": not_before_str,
                            "days_until_expiry": days_left,
                            "san_count": len(san),
                        }

                        # Expiry checks
                        if days_left is not None:
                            if days_left < 0:
                                self.add_finding(
                                    title="Certificate Expired",
                                    description=f"TLS certificate expired {abs(days_left)} days ago.",
                                    severity="critical",
                                    remediation="Renew the TLS certificate immediately.",
                                )
                            elif days_left < 14:
                                self.add_finding(
                                    title="Certificate Expiring Very Soon",
                                    description=f"Certificate expires in {days_left} days.",
                                    severity="critical",
                                    remediation="Renew the TLS certificate immediately.",
                                    evidence=f"Expiry: {not_after_str}",
                                )
                            elif days_left < 30:
                                self.add_finding(
                                    title="Certificate Expiring Soon",
                                    description=f"Certificate expires in {days_left} days.",
                                    severity="high",
                                    remediation="Schedule certificate renewal.",
                                    evidence=f"Expiry: {not_after_str}",
                                )
                            elif days_left < 90:
                                self.add_finding(
                                    title="Certificate Expiring in < 90 Days",
                                    description=f"Certificate expires in {days_left} days.",
                                    severity="medium",
                                    remediation="Plan certificate renewal.",
                                    evidence=f"Expiry: {not_after_str}",
                                )
                            else:
                                self.add_finding(
                                    title="Certificate Valid",
                                    description=f"Certificate valid for {days_left} more days.",
                                    severity="info",
                                    evidence=f"Expiry: {not_after_str}",
                                )

                    # Protocol checks
                    protocol = meta.get("protocol", "")
                    if protocol in WEAK_PROTOCOLS:
                        self.add_finding(
                            title=f"Weak TLS Protocol: {protocol}",
                            description=f"{protocol} is considered insecure and should not be used.",
                            severity="critical",
                            remediation="Disable all protocols below TLS 1.2. Prefer TLS 1.3.",
                            reference="https://tools.ietf.org/html/rfc8996",
                            evidence=f"Negotiated protocol: {protocol}",
                        )
                    else:
                        self.add_finding(
                            title=f"Strong TLS Protocol: {protocol}",
                            description=f"{protocol} is a modern, secure protocol.",
                            severity="info",
                        )

                    # Cipher checks
                    cipher_name = meta["cipher"].get("name", "")
                    bits = meta["cipher"].get("bits", 0)
                    is_weak = any(w in cipher_name.upper() for w in WEAK_CIPHERS)
                    if is_weak:
                        self.add_finding(
                            title=f"Weak Cipher Suite: {cipher_name}",
                            description="A weak cipher suite was negotiated.",
                            severity="high",
                            remediation="Disable weak cipher suites in your server config. Prefer AESGCM suites.",
                            evidence=f"Cipher: {cipher_name} ({bits}-bit)",
                        )
                    elif bits and bits < 128:
                        self.add_finding(
                            title="Short Cipher Key Length",
                            description=f"Cipher key length is only {bits} bits.",
                            severity="high",
                            remediation="Use cipher suites with at least 128-bit key strength.",
                        )
                    else:
                        self.add_finding(
                            title=f"Strong Cipher Suite",
                            description=f"Cipher: {cipher_name} ({bits}-bit)",
                            severity="info",
                        )

        except ssl.SSLCertVerificationError as exc:
            meta["tls_enabled"] = True
            self.add_finding(
                title="TLS Certificate Verification Failed",
                description=str(exc),
                severity="critical",
                remediation="Ensure the certificate is signed by a trusted CA and the hostname matches.",
            )
        except ConnectionRefusedError:
            self.add_finding(
                title="TLS Not Available",
                description="Port 443 connection refused. TLS/HTTPS may not be configured.",
                severity="critical",
                remediation="Configure HTTPS on port 443.",
            )
        except socket.timeout:
            self.add_finding(
                title="TLS Connection Timeout",
                description="Connection to port 443 timed out.",
                severity="medium",
                remediation="Check firewall rules and server availability.",
            )
        except Exception as exc:
            self.add_finding(
                title="TLS Check Error",
                description=str(exc),
                severity="info",
            )

        return meta
