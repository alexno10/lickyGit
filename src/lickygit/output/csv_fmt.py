"""CSV output formatter."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from lickygit.core.scanner import ScanResult

_COLUMNS = [
    "rule_id", "rule_name", "severity", "file_path", "line_number",
    "matched_text", "commit_sha", "commit_author", "commit_date",
    "detection_type",
]


class CsvFormatter:
    """Serialize scan results as CSV."""

    def format(self, result: ScanResult) -> str:  # noqa: A003
        """Return a CSV string."""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for f in result.findings:
            row = f.to_dict()
            writer.writerow({k: row.get(k, "") for k in _COLUMNS})
        return buf.getvalue()

    def write(self, result: ScanResult, path: str | Path) -> None:
        """Write CSV output to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.format(result), encoding="utf-8", newline="")
