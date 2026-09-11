"""File-path filtering via glob patterns."""

from __future__ import annotations

from fnmatch import fnmatch


# Default patterns to exclude (binary, generated, vendored)
DEFAULT_EXCLUDE_PATTERNS: list[str] = [
    # Binaries / media
    "*.pyc", "*.pyo", "*.so", "*.dll", "*.exe", "*.bin",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.bmp", "*.webp",
    "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.mp3", "*.mp4", "*.avi", "*.mov",
    "*.zip", "*.tar.gz", "*.tgz", "*.rar", "*.7z", "*.jar", "*.war",
    "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx",
    # Lock / generated / examples / schemas
    "*.min.js", "*.min.css", "*.map", "*.lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock",
    "poetry.lock", "Cargo.lock", "composer.lock", "Gemfile.lock",
    "go.sum", "go.work.sum", "*.sum", "*.schema.json",
    "*.example", "*.sample", "*.template", ".env.example", ".env.sample", ".env.template",
    # Directories
    "node_modules/*", ".git/*", "vendor/*", "__pycache__/*",
    ".venv/*", "venv/*", ".tox/*", ".mypy_cache/*",
    "dist/*", "build/*", ".eggs/*", "target/*",
]


class PathFilter:
    """Decide whether a file should be scanned based on glob patterns.

    *exclude_patterns* are checked first. If a path matches any exclude
    pattern it is **skipped** - unless it also matches an *include_pattern*
    which takes precedence and forces scanning.
    """

    def __init__(
        self,
        exclude_patterns: list[str] | None = None,
        include_patterns: list[str] | None = None,
    ) -> None:
        self.exclude_patterns = (
            list(exclude_patterns) if exclude_patterns is not None
            else list(DEFAULT_EXCLUDE_PATTERNS)
        )
        self.include_patterns = list(include_patterns) if include_patterns else []

    def should_scan(self, file_path: str) -> bool:
        """Return *True* if *file_path* should be scanned."""
        # Normalize to forward slashes for cross-platform fnmatch
        normalized = file_path.replace("\\", "/")
        name = normalized.rsplit("/", 1)[-1]

        # Include patterns override excludes
        if self.include_patterns:
            if any(fnmatch(normalized, pat) or fnmatch(name, pat) for pat in self.include_patterns):
                return True

        # Check excludes against both relative path and basename
        for pat in self.exclude_patterns:
            if fnmatch(normalized, pat) or fnmatch(name, pat):
                return False

        return True
