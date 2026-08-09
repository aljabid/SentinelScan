"""Technology & CVE Fingerprinting Analyzer.

Detects product/version strings from response headers (Server, X-Powered-By)
and checks them against a small bundled signature dataset
(`sentinelscan/data/cve_signatures.json`). This is a static, offline dataset —
not a live NVD feed. Refresh it with `sentinelscan --update-db`; see
`sentinelscan/updater.py`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sentinelscan.analyzers.base import BaseAnalyzer
from sentinelscan.updater import USER_SIGNATURES_PATH

_BUNDLED_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_signatures.json"

_VERSION_PATTERNS = {
    "nginx": re.compile(r"nginx/([\d.]+)", re.IGNORECASE),
    "apache": re.compile(r"apache/([\d.]+)", re.IGNORECASE),
    "openssh": re.compile(r"openssh[_/]([\d.]+)", re.IGNORECASE),
    "php": re.compile(r"php/([\d.]+)", re.IGNORECASE),
    "iis": re.compile(r"microsoft-iis/([\d.]+)", re.IGNORECASE),
}


def _load_signatures() -> dict[str, list[dict[str, Any]]]:
    for path in (USER_SIGNATURES_PATH, _BUNDLED_DATA_PATH):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return {}


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in version.split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


class CveFingerprintAnalyzer(BaseAnalyzer):
    name = "cve_fingerprint"

    def analyze(self) -> dict[str, Any]:
        if self.response is None:
            return {"error": "No HTTP response available"}

        signatures = _load_signatures()
        headers_text = " ".join(f"{k}: {v}" for k, v in self.response.headers.items())

        detected: list[dict[str, Any]] = []
        matched_cve = False

        for product, pattern in _VERSION_PATTERNS.items():
            match = pattern.search(headers_text)
            if not match:
                continue
            version = match.group(1)
            detected.append({"product": product, "version": version})
            found_version = _version_tuple(version)

            for sig in signatures.get(product, []):
                if found_version <= _version_tuple(sig["max_version"]):
                    matched_cve = True
                    self.add_finding(
                        title=f"Known Vulnerable Version: {product} {version} ({sig['cve']})",
                        description=sig["description"],
                        severity=sig.get("severity", "medium"),
                        remediation=f"Upgrade {product} beyond {sig['max_version']}.",
                        reference=f"https://nvd.nist.gov/vuln/detail/{sig['cve']}",
                        evidence=f"Detected {product}/{version} via response headers",
                    )

        if detected and not matched_cve:
            names = ", ".join(f"{d['product']}/{d['version']}" for d in detected)
            self.add_finding(
                title="No Known CVEs for Detected Versions",
                description=f"Detected {names}; none matched this tool's bundled signature dataset.",
                severity="info",
                evidence=names,
            )
        elif not detected:
            self.add_finding(
                title="No Fingerprintable Technology Versions Detected",
                description="No Server/X-Powered-By header exposed a recognized product+version string.",
                severity="info",
            )

        return {"detected": detected, "signature_count": sum(len(v) for v in signatures.values())}
