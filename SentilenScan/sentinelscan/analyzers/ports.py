"""Port Scanner – checks common web-related ports."""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any, Dict, List, Tuple

from sentinelscan.analyzers.base import BaseAnalyzer

# Port: (service_name, risky_if_open)
COMMON_PORTS: Dict[int, Tuple[str, bool]] = {
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


def _check_port(host: str, port: int, timeout: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class PortsAnalyzer(BaseAnalyzer):
    name = "ports"

    def analyze(self) -> Dict[str, Any]:
        hostname = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        open_ports: List[Dict[str, Any]] = []
        closed_ports: List[int] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(_check_port, hostname, port, min(self.timeout, 3)): port
                for port in COMMON_PORTS
            }
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                except Exception:
                    is_open = False

                if is_open:
                    service, risky = COMMON_PORTS[port]
                    open_ports.append({"port": port, "service": service, "risky": risky})
                    if risky:
                        severity = "critical" if port in [23, 3389, 6379, 27017] else "high"
                        self.add_finding(
                            title=f"Risky Port Open: {port}/{service}",
                            description=f"Port {port} ({service}) is publicly accessible and may expose sensitive services.",
                            severity=severity,
                            remediation=f"Firewall port {port} from public access. Only allow from trusted IPs.",
                            evidence=f"Port {port} ({service}) is OPEN",
                        )
                    else:
                        self.add_finding(
                            title=f"Port Open: {port}/{service}",
                            description=f"Port {port} ({service}) is open.",
                            severity="info",
                        )
                else:
                    closed_ports.append(port)

        open_ports.sort(key=lambda x: x["port"])

        return {
            "open_ports": open_ports,
            "closed_count": len(closed_ports),
            "total_checked": len(COMMON_PORTS),
        }
