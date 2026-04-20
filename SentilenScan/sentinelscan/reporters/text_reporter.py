"""Rich terminal text reporter."""

from __future__ import annotations

from typing import Any, Dict, List

SEVERITY_COLORS = {
    "critical": "\033[1;31m",   # Bold Red
    "high":     "\033[31m",     # Red
    "medium":   "\033[33m",     # Yellow
    "low":      "\033[36m",     # Cyan
    "info":     "\033[32m",     # Green
}
RESET = "\033[0m"
BOLD  = "\033[1m"

GRADE_COLORS = {
    "A+": "\033[1;32m", "A": "\033[32m", "B": "\033[33m",
    "C": "\033[33m", "D": "\033[31m", "F": "\033[1;31m",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class TextReporter:
    def __init__(self, severity_filter: List[str] = None, no_color: bool = False) -> None:
        self.severity_filter = severity_filter or SEVERITY_ORDER
        self.no_color = no_color

    def _c(self, color: str, text: str) -> str:
        if self.no_color:
            return text
        return f"{color}{text}{RESET}"

    def _sev_badge(self, severity: str) -> str:
        label = f"[{severity.upper():8}]"
        return self._c(SEVERITY_COLORS.get(severity, ""), label)

    def render(self, all_results: Dict[str, Any]) -> str:
        lines = []

        for target, results in all_results.items():
            meta = results.get("__meta__", {})
            grade = meta.get("risk_grade", "?")
            score = meta.get("risk_score", 0)
            grade_color = GRADE_COLORS.get(grade, "")

            lines.append(self._c(BOLD, f"╔══ TARGET: {target.upper()} ══"))
            lines.append(f"  URL         : {meta.get('final_url', target)}")
            lines.append(f"  HTTP Status : {meta.get('status_code', 'N/A')}")
            lines.append(f"  Risk Score  : {score}")
            lines.append(f"  Security Grade : {self._c(grade_color, grade)}")
            lines.append(f"  Modules Run : {', '.join(meta.get('scanned_modules', []))}")
            lines.append("")

            if results.get("__error__"):
                lines.append(f"  !! ERROR: {results['__error__']}")
                lines.append("")
                continue

            for module_name, mod_data in results.items():
                if module_name.startswith("__"):
                    continue

                findings = mod_data.get("findings", [])
                elapsed = mod_data.get("_elapsed_ms", 0)
                filtered = [f for f in findings if f.get("severity") in self.severity_filter]
                
                lines.append(self._c(BOLD, f"  ┌─ {module_name.upper()} ({elapsed}ms) ─"))

                if mod_data.get("error"):
                    lines.append(f"  │  ⚠ Error: {mod_data['error']}")

                if not filtered:
                    lines.append(f"  │  {self._c(SEVERITY_COLORS['info'], '✓ No findings in selected severity range')}")
                else:
                    # Group by severity
                    for sev in SEVERITY_ORDER:
                        sev_findings = [f for f in filtered if f.get("severity") == sev]
                        for f in sev_findings:
                            lines.append(f"  │  {self._sev_badge(sev)} {f['title']}")
                            if f.get("description"):
                                lines.append(f"  │             {f['description']}")
                            if f.get("remediation"):
                                lines.append(f"  │             {self._c(BOLD, 'Fix:')} {f['remediation']}")
                            if f.get("evidence"):
                                lines.append(f"  │             {self._c(BOLD, 'Evidence:')} {f['evidence'][:120]}")
                            lines.append("  │")
                lines.append("")

        # Summary table
        lines.append(self._c(BOLD, "─" * 60))
        lines.append(self._c(BOLD, "SUMMARY"))
        lines.append(self._c(BOLD, "─" * 60))
        for target, results in all_results.items():
            meta = results.get("__meta__", {})
            all_findings = [
                f for mod_name, mod_data in results.items()
                if not mod_name.startswith("__")
                for f in mod_data.get("findings", [])
            ]
            counts = {s: sum(1 for f in all_findings if f.get("severity") == s) for s in SEVERITY_ORDER}
            grade = meta.get("risk_grade", "?")
            grade_color = GRADE_COLORS.get(grade, "")
            lines.append(f"  {target:<40} Grade: {self._c(grade_color, grade)}")
            for sev in SEVERITY_ORDER:
                if counts[sev]:
                    lines.append(f"    {self._sev_badge(sev)} {counts[sev]} findings")
        lines.append("")

        return "\n".join(lines)
