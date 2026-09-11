"""Configuration management — load from ``.lickygit.toml`` and merge with CLI args."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lickygit.core.finding import Severity
from lickygit.core.git_walker import DEFAULT_MAX_FILE_SIZE


@dataclass
class ScanConfig:
    """All options that control a scan run.

    Defaults are sensible for interactive terminal usage.
    """

    # ── repo ───────────────────────────────────────────────────────────
    repo_path: str = "."
    head_only: bool = False
    staged: bool = False
    max_workers: int = 4
    max_file_size: int = DEFAULT_MAX_FILE_SIZE

    # ── incremental / PR scanning ─────────────────────────────────────
    since_commit: str | None = None
    diff_base: str | None = None

    # ── detection ──────────────────────────────────────────────────────
    use_entropy: bool = True
    use_keywords: bool = True
    use_builtin_rules: bool = True
    entropy_threshold: float = 4.5
    custom_rules_path: str | None = None

    # ── filtering ──────────────────────────────────────────────────────
    exclude_paths: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)
    allowlist_path: str | None = None
    baseline_path: str | None = None
    generate_baseline_path: str | None = None
    min_severity: Severity = Severity.LOW

    # ── exit behaviour ─────────────────────────────────────────────────
    fail_on_severity: Severity | None = None

    # ── output ─────────────────────────────────────────────────────────
    output_format: str = "terminal"  # terminal | json | csv | sarif | html | gitlab
    output_file: str | None = None
    verbose: bool = False
    use_color: bool = True
    show_banner: bool = True

    # ── clone helpers ──────────────────────────────────────────────────
    clone_url: str | None = None
    delete_after_scan: bool = False


# ---------------------------------------------------------------------- #
# Known config keys (for validation)
# ---------------------------------------------------------------------- #

_KNOWN_SCAN_KEYS = {
    "head_only", "staged", "max_workers", "max_file_size", "severity",
    "since_commit", "diff_base", "fail_on_severity",
}
_KNOWN_DETECTION_KEYS = {
    "use_entropy", "use_keywords", "use_builtin_rules",
    "entropy_threshold", "custom_rules",
}
_KNOWN_FILTER_KEYS = {
    "exclude", "include", "allowlist", "baseline",
}
_KNOWN_OUTPUT_KEYS = {
    "format", "verbose", "color", "banner",
}


def validate_config(data: dict[str, Any]) -> list[str]:
    """Return a list of warnings for unrecognised configuration keys."""
    warnings: list[str] = []
    known_sections = {"scan", "detection", "filters", "output"}

    for section_name in data:
        if section_name not in known_sections:
            warnings.append(f"Unknown config section: [{section_name}]")

    section_map = {
        "scan": _KNOWN_SCAN_KEYS,
        "detection": _KNOWN_DETECTION_KEYS,
        "filters": _KNOWN_FILTER_KEYS,
        "output": _KNOWN_OUTPUT_KEYS,
    }
    for section_name, known_keys in section_map.items():
        section = data.get(section_name, {})
        if isinstance(section, dict):
            for key in section:
                if key not in known_keys:
                    warnings.append(f"Unknown key in [{section_name}]: '{key}'")

    return warnings


# ---------------------------------------------------------------------- #
# TOML loader
# ---------------------------------------------------------------------- #

def _load_toml(path: Path) -> dict[str, Any]:
    """Read a TOML file and return its data as a dict."""
    if sys.version_info >= (3, 11):
        import tomllib  # noqa: F811
    else:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError as exc:
            raise ImportError(
                "Install 'tomli' for Python <3.11: pip install tomli"
            ) from exc

    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _find_config_file(start: Path | None = None) -> Path | None:
    """Walk from *start* up to the filesystem root looking for ``.lickygit.toml``."""
    current = (start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        candidate = directory / ".lickygit.toml"
        if candidate.is_file():
            return candidate
    return None


_SEVERITY_MAP: dict[str, Severity] = {s.value.lower(): s for s in Severity}


def _parse_severity(value: str) -> Severity:
    try:
        return _SEVERITY_MAP[value.lower()]
    except KeyError:
        return Severity.LOW


def _parse_optional_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return _SEVERITY_MAP[value.lower()]
    except KeyError:
        return None


def load_config(path: str | Path | None = None) -> ScanConfig:
    """Load configuration from a ``.lickygit.toml`` file.

    If *path* is ``None``, searches the current directory and its parents.
    Returns a default :class:`ScanConfig` if no file is found.
    """
    config_path: Path | None
    if path is not None:
        config_path = Path(path)
        if not config_path.is_file():
            raise FileNotFoundError(f"Config file not found: {config_path}")
    else:
        config_path = _find_config_file()

    if config_path is None:
        return ScanConfig()

    data = _load_toml(config_path)

    # Validate config keys and print warnings
    config_warnings = validate_config(data)
    if config_warnings:
        import warnings as _warnings
        for w in config_warnings:
            _warnings.warn(f"Config ({config_path.name}): {w}")

    scan = data.get("scan", {})
    detection = data.get("detection", {})
    filters = data.get("filters", {})
    output = data.get("output", {})

    return ScanConfig(
        head_only=scan.get("head_only", False),
        staged=scan.get("staged", False),
        max_workers=scan.get("max_workers", 4),
        max_file_size=scan.get("max_file_size", DEFAULT_MAX_FILE_SIZE),
        min_severity=_parse_severity(scan.get("severity", "low")),
        since_commit=scan.get("since_commit"),
        diff_base=scan.get("diff_base"),
        fail_on_severity=_parse_optional_severity(scan.get("fail_on_severity")),
        use_entropy=detection.get("use_entropy", True),
        use_keywords=detection.get("use_keywords", True),
        use_builtin_rules=detection.get("use_builtin_rules", True),
        entropy_threshold=detection.get("entropy_threshold", 4.5),
        custom_rules_path=detection.get("custom_rules", None),
        exclude_paths=filters.get("exclude", []),
        include_paths=filters.get("include", []),
        allowlist_path=filters.get("allowlist", None),
        baseline_path=filters.get("baseline", None),
        output_format=output.get("format", "terminal"),
        verbose=output.get("verbose", False),
        use_color=output.get("color", True),
        show_banner=output.get("banner", True),
    )


# ---------------------------------------------------------------------- #
# Merge
# ---------------------------------------------------------------------- #

def merge_configs(file_config: ScanConfig, cli_overrides: dict[str, Any]) -> ScanConfig:
    """Create a new :class:`ScanConfig` by overlaying *cli_overrides* on *file_config*.

    Only keys present **and not-None** in *cli_overrides* take effect.
    """
    merged = ScanConfig(**{
        f.name: getattr(file_config, f.name)
        for f in file_config.__dataclass_fields__.values()  # type: ignore[attr-defined]
    })
    for key, value in cli_overrides.items():
        if value is not None and hasattr(merged, key):
            object.__setattr__(merged, key, value)
    return merged
