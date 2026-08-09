"""Port Scanner – checks common web-related ports and grabs service banners."""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any

from sentinelscan.analyzers.base import BaseAnalyzer

# Port: (service_name, risky_if_open)
COMMON_PORTS: dict[int, tuple[str, bool]] = {
    21: ("FTP", True),
    22: ("SSH", False),
    23: ("Telnet", True),
    25: ("SMTP", False),
    53: ("DNS", False),
    80: ("HTTP", False),
    443: ("HTTPS", False),
    445: ("SMB", True),
    3306: ("MySQL", True),
    3389: ("RDP", True),
    5432: ("PostgreSQL", True),
    6379: ("Redis", True),
    8080: ("HTTP-Alt", False),
    8443: ("HTTPS-Alt", False),
    8888: ("Dev Server", True),
    27017: ("MongoDB", True),
}

# Ports that stay silent until spoken to – send a minimal request before reading a banner.
_HTTP_LIKE_PORTS = {80, 8080, 8888}


def _probe_port(host: str, port: int, timeout: int) -> tuple[bool, str]:
    """Connect to a port and, if open, attempt a lightweight banner grab."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(min(timeout, 2))
                if port in _HTTP_LIKE_PORTS:
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                data = sock.recv(256)
                if data:
                    text = data.decode("utf-8", errors="replace").strip()
                    banner = text.splitlines()[0][:200] if text else ""
            except OSError:
                banner = ""
            return True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, ""


class PortsAnalyzer(BaseAnalyzer):
    name = "ports"

    def analyze(self) -> dict[str, Any]:
        hostname = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        open_ports: list[dict[str, Any]] = []
        closed_ports: list[int] = []
        max_workers = self.ctx.get("port_concurrency", 20)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_probe_port, hostname, port, min(self.timeout, 3)): port for port in COMMON_PORTS
            }
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open, banner = future.result()
                except Exception:
                    is_open, banner = False, ""

                # Sanitize here too (not just via Finding) since open_ports is exposed
                # as raw module metadata, independent of the findings list below.
                banner = "".join(c if c.isprintable() else " " for c in banner)

                if is_open:
                    service, risky = COMMON_PORTS[port]
                    open_ports.append({"port": port, "service": service, "risky": risky, "banner": banner})
                    banner_note = f" Banner: {banner}" if banner else ""
                    if risky:
                        severity = "critical" if port in [23, 3389, 6379, 27017] else "high"
                        self.add_finding(
                            title=f"Risky Port Open: {port}/{service}",
                            description=(
                                f"Port {port} ({service}) is publicly accessible "
                                f"and may expose sensitive services.{banner_note}"
                            ),
                            severity=severity,
                            remediation=f"Firewall port {port} from public access. Only allow from trusted IPs.",
                            evidence=f"Port {port} ({service}) is OPEN.{banner_note}",
                        )
                    else:
                        self.add_finding(
                            title=f"Port Open: {port}/{service}",
                            description=f"Port {port} ({service}) is open.{banner_note}",
                            severity="info",
                            evidence=banner or "",
                        )
                else:
                    closed_ports.append(port)

        open_ports.sort(key=lambda x: x["port"])

        return {
            "open_ports": open_ports,
            "closed_count": len(closed_ports),
            "total_checked": len(COMMON_PORTS),
        }
