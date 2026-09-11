"""JSON output formatter."""

from __future__ import annotations

import json
from pathlib import Path

from lickygit.core.scanner import ScanResult


class JsonFormatter:
    """Serialize scan results as JSON."""

    def __init__(self, *, pretty: bool = True) -> None:
        self.pretty = pretty

    def format(self, result: ScanResult) -> str:  # noqa: A003
        """Return a JSON string representation of *result*."""
        data = {
            "scan": {
                "duration_seconds": round(result.scan_duration, 3),
                "total_commits": result.total_commits,
                "total_files": result.total_files,
                "total_findings": len(result.findings),
                "counts_by_severity": result.counts_by_severity,
            },
            "findings": [f.to_dict() for f in result.findings],
        }
        indent = 2 if self.pretty else None
        return json.dumps(data, indent=indent, ensure_ascii=False)

    def write(self, result: ScanResult, path: str | Path) -> None:
        """Write JSON output to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.format(result), encoding="utf-8")
