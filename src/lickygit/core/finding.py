"""Data models for scan findings."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.Enum):
    """Severity level of a finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self < other


class DetectionType(enum.Enum):
    """How the secret was detected."""

    PATTERN = "PATTERN"
    KEYWORD = "KEYWORD"
    ENTROPY = "ENTROPY"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single secret finding in a Git repository."""

    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line_content: str
    matched_text: str
    commit_sha: str
    detection_type: DetectionType
    line_number: int | None = None
    commit_author: str = ""
    commit_date: str = ""
    entropy: float | None = None

    @property
    def redacted_value(self) -> str:
        """Show first 4 characters followed by '***'."""
        if len(self.matched_text) <= 4:
            return "***"
        return self.matched_text[:4] + "***"

    @property
    def fingerprint(self) -> str:
        """Unique stable identifier for baseline tracking."""
        import hashlib
        raw = f"{self.rule_id}:{self.file_path}:{self.matched_text}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dictionary suitable for serialization."""
        d = asdict(self)
        d["severity"] = self.severity.value
        d["detection_type"] = self.detection_type.value
        d["redacted_value"] = self.redacted_value
        d["fingerprint"] = self.fingerprint
        return d

    def __str__(self) -> str:
        loc = f"{self.file_path}"
        if self.line_number is not None:
            loc += f":{self.line_number}"
        return (
            f"[{self.severity.value}] {self.rule_name} in {loc} "
            f"({self.redacted_value}) @ {(self.commit_sha or 'N/A')[:8]}"
        )
