"""HTML reporter – professional audit-grade report."""

from __future__ import annotations

import html as html_lib
from datetime import datetime, timezone
from typing import Any

from sentinelscan import __version__

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#16a34a",
}

GRADE_COLORS = {
    "A+": "#16a34a",
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#dc2626",
}


def _esc(text: str) -> str:
    return html_lib.escape(str(text))


class HtmlReporter:
    def __init__(self, severity_filter: list[str] | None = None, no_color: bool = False) -> None:
        self.severity_filter = severity_filter or SEVERITY_ORDER

    def render(self, all_results: dict[str, Any]) -> str:
        generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        targets_html = ""

        global_counts = {s: 0 for s in SEVERITY_ORDER}
        for results in all_results.values():
            for mod_name, mod_data in results.items():
                if mod_name.startswith("__"):
                    continue
                for f in mod_data.get("findings", []):
                    sev = f.get("severity", "info")
                    if sev in global_counts:
                        global_counts[sev] += 1

        # Build summary cards
        summary_cards = ""
        for sev in SEVERITY_ORDER:
            count = global_counts[sev]
            color = SEVERITY_COLORS[sev]
            summary_cards += f"""
            <div class="card" style="border-left: 4px solid {color}">
              <div class="card-count" style="color:{color}">{count}</div>
              <div class="card-label">{sev.capitalize()}</div>
            </div>"""

        # Build target sections
        for target, results in all_results.items():
            meta = results.get("__meta__", {})
            grade = meta.get("risk_grade", "?")
            score = meta.get("risk_score", 0)
            grade_color = GRADE_COLORS.get(grade, "#888")

            if results.get("__error__"):
                targets_html += f"""
                <div class="target-block">
                  <h2>{_esc(target)}</h2>
                  <div class="error">Error: {_esc(results['__error__'])}</div>
                </div>"""
                continue

            modules_html = ""
            for mod_name, mod_data in results.items():
                if mod_name.startswith("__"):
                    continue
                findings = [f for f in mod_data.get("findings", []) if f.get("severity") in self.severity_filter]
                elapsed = mod_data.get("_elapsed_ms", 0)

                findings_html = ""
                if not findings:
                    findings_html = '<p class="no-findings">✓ No findings in selected severity range</p>'
                else:
                    for sev in SEVERITY_ORDER:
                        for finding in [f for f in findings if f.get("severity") == sev]:
                            color = SEVERITY_COLORS.get(sev, "#888")
                            evidence_row = ""
                            if finding.get("evidence"):
                                evidence_row = f'<div class="evidence">Evidence: <code>{_esc(finding["evidence"][:300])}</code></div>'
                            fix_row = ""
                            if finding.get("remediation"):
                                fix_row = f'<div class="remediation">🔧 {_esc(finding["remediation"])}</div>'
                            ref_row = ""
                            if finding.get("reference"):
                                ref_row = f'<div class="reference"><a href="{_esc(finding["reference"])}" target="_blank">📖 Reference</a></div>'
                            findings_html += f"""
                            <div class="finding" style="border-left: 3px solid {color}">
                              <div class="finding-header">
                                <span class="badge" style="background:{color}">{sev.upper()}</span>
                                <span class="finding-title">{_esc(finding['title'])}</span>
                              </div>
                              <div class="finding-desc">{_esc(finding.get('description',''))}</div>
                              {fix_row}{evidence_row}{ref_row}
                            </div>"""

                modules_html += f"""
                <div class="module-block">
                  <div class="module-header">
                    <span class="module-name">{_esc(mod_name.replace('_',' ').upper())}</span>
                    <span class="module-time">{elapsed}ms</span>
                    <span class="module-count">{len(findings)} findings</span>
                  </div>
                  <div class="module-findings">{findings_html}</div>
                </div>"""

            targets_html += f"""
            <div class="target-block">
              <div class="target-header">
                <div>
                  <h2 class="target-name">{_esc(target)}</h2>
                  <div class="target-meta">
                    <span>Status: {meta.get('status_code','N/A')}</span>
                    <span>Score: {score}</span>
                    <span>URL: {_esc(meta.get('final_url', target))}</span>
                  </div>
                </div>
                <div class="grade-badge" style="color:{grade_color}; border-color:{grade_color}">{grade}</div>
              </div>
              {modules_html}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelScan Security Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  header {{ display: flex; justify-content: space-between; align-items: center; padding: 2rem 0 1rem; border-bottom: 1px solid #1e293b; margin-bottom: 2rem; }}
  .logo {{ font-size: 1.5rem; font-weight: 700; color: #38bdf8; letter-spacing: 2px; }}
  .meta {{ font-size: 0.8rem; color: #64748b; }}
  .summary-grid {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 1.2rem 1.5rem; min-width: 120px; flex: 1; }}
  .card-count {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px; }}
  .target-block {{ background: #1e293b; border-radius: 10px; padding: 1.5rem; margin-bottom: 2rem; }}
  .target-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; }}
  .target-name {{ font-size: 1.2rem; font-weight: 600; color: #f1f5f9; }}
  .target-meta {{ font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; display: flex; gap: 1rem; }}
  .grade-badge {{ font-size: 2.5rem; font-weight: 700; border: 3px solid; border-radius: 8px; padding: 0.3rem 0.8rem; line-height: 1; }}
  .module-block {{ background: #0f172a; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }}
  .module-header {{ display: flex; align-items: center; gap: 1rem; padding: 0.8rem 1rem; background: #162032; border-bottom: 1px solid #1e293b; }}
  .module-name {{ font-weight: 600; font-size: 0.85rem; letter-spacing: 1px; color: #7dd3fc; flex: 1; }}
  .module-time {{ font-size: 0.75rem; color: #475569; }}
  .module-count {{ font-size: 0.75rem; color: #64748b; background: #1e293b; padding: 2px 8px; border-radius: 12px; }}
  .module-findings {{ padding: 0.8rem 1rem; }}
  .finding {{ background: #1e293b; border-radius: 6px; padding: 0.8rem 1rem; margin-bottom: 0.6rem; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.4rem; }}
  .badge {{ font-size: 0.65rem; font-weight: 700; padding: 2px 7px; border-radius: 4px; color: #fff; letter-spacing: 0.5px; }}
  .finding-title {{ font-weight: 600; font-size: 0.9rem; }}
  .finding-desc {{ font-size: 0.82rem; color: #94a3b8; margin-bottom: 0.3rem; }}
  .remediation {{ font-size: 0.8rem; color: #86efac; margin-top: 0.3rem; }}
  .evidence {{ font-size: 0.78rem; color: #64748b; margin-top: 0.2rem; }}
  .evidence code {{ background: #0f172a; padding: 1px 4px; border-radius: 3px; font-family: monospace; }}
  .reference a {{ font-size: 0.78rem; color: #38bdf8; text-decoration: none; }}
  .no-findings {{ color: #22c55e; font-size: 0.85rem; padding: 0.3rem 0; }}
  .error {{ color: #f87171; padding: 1rem; background: #1e293b; border-radius: 6px; }}
  footer {{ text-align: center; color: #334155; font-size: 0.75rem; padding: 2rem 0; border-top: 1px solid #1e293b; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">⚔ SENTINELSCAN</div>
    <div class="meta">v{__version__} · Generated {generated}</div>
  </header>
  <div class="summary-grid">{summary_cards}</div>
  {targets_html}
  <footer>Generated by SentinelScan v{__version__} · Security audit report · {generated}</footer>
</div>
</body>
</html>"""
