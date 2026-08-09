"""JSON reporter – structured machine-readable output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sentinelscan import __version__

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class JsonReporter:
    def __init__(self, severity_filter: list[str] | None = None, no_color: bool = False) -> None:
        self.severity_filter = severity_filter or SEVERITY_ORDER

    def render(self, all_results: dict[str, Any]) -> str:
        output: dict[str, Any] = {
            "sentinelscan_version": __version__,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "targets": {},
        }

        total_findings = 0
        severity_totals = {s: 0 for s in SEVERITY_ORDER}

        for target, results in all_results.items():
            meta = results.get("__meta__", {})
            modules_out = {}

            for mod_name, mod_data in results.items():
                if mod_name.startswith("__"):
                    continue
                filtered = [f for f in mod_data.get("findings", []) if f.get("severity") in self.severity_filter]
                for f in filtered:
                    sev = f.get("severity", "info")
                    severity_totals[sev] = severity_totals.get(sev, 0) + 1
                    total_findings += 1

                modules_out[mod_name] = {k: v for k, v in mod_data.items() if k not in ("findings", "_elapsed_ms")}
                modules_out[mod_name]["findings"] = filtered
                modules_out[mod_name]["elapsed_ms"] = mod_data.get("_elapsed_ms", 0)

            output["targets"][target] = {
                "meta": meta,
                "modules": modules_out,
            }

        output["summary"] = {
            "total_targets": len(all_results),
            "total_findings": total_findings,
            "by_severity": severity_totals,
        }

        return json.dumps(output, indent=2, default=str)
