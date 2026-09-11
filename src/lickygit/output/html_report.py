"""Standalone HTML report generator with dark theme."""

from __future__ import annotations

import html
from pathlib import Path

from lickygit.core.finding import Severity
from lickygit.core.scanner import ScanResult

_SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ffaa00",
    "MEDIUM": "#44aaff",
    "LOW": "#888888",
}


class HtmlReportFormatter:
    """Generate a standalone HTML report with embedded CSS (no external deps)."""

    def format(self, result: ScanResult) -> str:  # noqa: A003
        """Return complete HTML as a string."""
        counts = result.counts_by_severity

        # Build findings rows
        rows = ""
        for f in result.findings:
            color = _SEVERITY_COLOR.get(f.severity.value, "#888")
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{color}">{html.escape(f.severity.value)}</span></td>
              <td>{html.escape(f.rule_name)}</td>
              <td>{html.escape(f.file_path)}{(':' + str(f.line_number)) if f.line_number else ''}</td>
              <td><code>{html.escape(f.redacted_value)}</code></td>
              <td><code>{html.escape((f.commit_sha or "N/A")[:8])}</code></td>
              <td>{html.escape(f.commit_author)}</td>
              <td>{html.escape(f.detection_type.value)}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>lickyGit Scan Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #1a1a2e; color: #e0e0e0; padding: 2rem; }}
  h1 {{ color: #44ff88; margin-bottom: 0.5rem; font-size: 2rem; }}
  .subtitle {{ color: #888; margin-bottom: 2rem; }}
  .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: #16213e; border-radius: 12px; padding: 1.2rem 1.5rem; min-width: 140px; }}
  .card .label {{ font-size: 0.8rem; color: #888; text-transform: uppercase; }}
  .card .value {{ font-size: 1.8rem; font-weight: bold; margin-top: 0.3rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #16213e; border-radius: 12px; overflow: hidden; }}
  th {{ background: #0f3460; padding: 0.8rem 1rem; text-align: left; font-size: 0.85rem;
       text-transform: uppercase; color: #aaa; }}
  td {{ padding: 0.7rem 1rem; border-bottom: 1px solid #1a1a3e; font-size: 0.9rem; }}
  tr:hover td {{ background: #1a2a4e; }}
  code {{ background: #0a0a1a; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }}
  .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; color: #fff; }}
  .empty {{ text-align: center; padding: 3rem; color: #44ff88; font-size: 1.2rem; }}
  #filter {{ margin-bottom: 1rem; padding: 0.5rem 1rem; border-radius: 8px; border: 1px solid #333;
             background: #0f3460; color: #e0e0e0; font-size: 0.9rem; width: 300px; }}
</style>
</head>
<body>
<h1>🔍 lickyGit Scan Report</h1>
<p class="subtitle">Scanned {result.total_commits} commits, {result.total_files} files in {result.scan_duration:.2f}s</p>

<div class="cards">
  <div class="card"><div class="label">Total</div><div class="value">{len(result.findings)}</div></div>
  <div class="card"><div class="label">Critical</div><div class="value" style="color:#ff4444">{counts['CRITICAL']}</div></div>
  <div class="card"><div class="label">High</div><div class="value" style="color:#ffaa00">{counts['HIGH']}</div></div>
  <div class="card"><div class="label">Medium</div><div class="value" style="color:#44aaff">{counts['MEDIUM']}</div></div>
  <div class="card"><div class="label">Low</div><div class="value" style="color:#888">{counts['LOW']}</div></div>
</div>

{"<p class='empty'>✅ No secrets found!</p>" if not result.findings else f'''
<input id="filter" type="text" placeholder="Filter findings..." onkeyup="filterTable()">
<table id="findings">
<thead><tr>
  <th>Severity</th><th>Rule</th><th>File</th><th>Secret</th><th>Commit</th><th>Author</th><th>Type</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
<script>
function filterTable() {{
  const q = document.getElementById('filter').value.toLowerCase();
  document.querySelectorAll('#findings tbody tr').forEach(r => {{
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
'''}
</body>
</html>"""

    def write(self, result: ScanResult, path: str | Path) -> None:
        """Write HTML report to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.format(result), encoding="utf-8")
