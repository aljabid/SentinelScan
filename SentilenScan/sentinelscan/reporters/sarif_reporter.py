"""SARIF 2.1.0 reporter – for GitHub Code Scanning and other tool-chain interop."""

from __future__ import annotations

import json
import re
from typing import Any

from sentinelscan import __version__

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SEVERITY_TO_SCORE = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "0.0",
}


def _rule_id(module_name: str, finding: dict[str, Any]) -> str:
    title = finding.get("title", "finding")
    base = title.split(":", 1)[0].strip()
    slug = re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-") or "finding"
    return f"{module_name}/{slug}"


class SarifReporter:
    def __init__(self, severity_filter: list[str] | None = None, no_color: bool = False) -> None:
        self.severity_filter = severity_filter or SEVERITY_ORDER

    def render(self, all_results: dict[str, Any]) -> str:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for target, target_results in all_results.items():
            meta = target_results.get("__meta__", {})
            artifact_uri = meta.get("final_url") or f"https://{target}"

            for module_name, mod_data in target_results.items():
                if module_name.startswith("__"):
                    continue
                for finding in mod_data.get("findings", []):
                    severity = finding.get("severity", "info")
                    if severity not in self.severity_filter:
                        continue

                    rule_id = _rule_id(module_name, finding)
                    if rule_id not in rules:
                        rules[rule_id] = {
                            "id": rule_id,
                            "name": rule_id.replace("/", "_"),
                            "shortDescription": {"text": finding.get("title", rule_id)},
                            "fullDescription": {"text": finding.get("description", "")},
                            "helpUri": finding.get("reference") or "",
                            "properties": {
                                "security-severity": SEVERITY_TO_SCORE.get(severity, "0.0"),
                                "tags": ["security", module_name],
                            },
                        }

                    message_parts = [finding.get("description") or finding.get("title", "")]
                    if finding.get("remediation"):
                        message_parts.append(f"Remediation: {finding['remediation']}")
                    if finding.get("evidence"):
                        message_parts.append(f"Evidence: {finding['evidence']}")

                    results.append(
                        {
                            "ruleId": rule_id,
                            "level": SEVERITY_TO_LEVEL.get(severity, "note"),
                            "message": {"text": " ".join(message_parts)},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}],
                            "properties": {"target": target, "module": module_name, "severity": severity},
                        }
                    )

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SentinelScan",
                            "version": __version__,
                            "informationUri": "https://github.com/aljabid/SentinelScan",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2, default=str)
