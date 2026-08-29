"""Keyword + assignment detection (improved from gittyleaks)."""

from __future__ import annotations

import re
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Default keyword list
# --------------------------------------------------------------------------- #

DEFAULT_KEYWORDS: list[str] = [
    "api_key", "apikey",
    "access_key", "access_token",
    "auth_token",
    "client_secret",
    "connection_string", "conn_str",
    "database_url", "db_password", "db_pass",
    "encryption_key",
    "password", "passwd", "pwd",
    "private_key", "private-key",
    "secret", "secret_key",
    "token",
]

# --------------------------------------------------------------------------- #
# Values to ignore (false positives)
# --------------------------------------------------------------------------- #

_FALSE_POSITIVE_VALUES: set[str] = {
    "", "true", "false", "null", "none", "nil", "undefined",
    "todo", "fixme", "change_me", "changeme", "replace_me",
    "placeholder", "example", "test", "dummy", "sample",
    "your_api_key_here", "your-api-key-here", "insert_here",
    "xxx", "yyy", "zzz", "value", "val", "values", "string", "text", "var", "variable",
    "lambda", "function", "func", "callback", "handler",
    "latest", "stable", "nightly", "write", "read", "all", "root", "nobody",
    "required", "optional", "needed", "needed.", "default",
}

_FALSE_POSITIVE_PREFIXES: tuple[str, ...] = (
    "your-", "your_", "my-", "my_", "<", "${", "%(", "{{",
    "example", "test", "dummy", "sample", "fake", "lambda", "func",
    # Python env loaders
    "os.getenv", "os.environ", "process.env", "sys.getenv", "system.getenv",
    # Rust env loaders
    "std::env::var", "std::env::var_os", "env::var", "env::var_os",
    # Go env loaders
    "os.getenv", "os.lookupenv",
    # Java / C# env loaders
    "system.getenv", "environment.getenvironmentvariable",
    # Generic config/setting loaders
    "env(", "getenv(", "config(", "config.", "dotenv(", "settings.", "params.",
    "cfg.", "conf.", "options.", "opts.", "props.", "properties.",
    "self.", "this.", "request.", "update.", "ctx.", "context.", "auth.",
    "str(", "int(", "bool(", "dict(", "list(", "set(",
    # Type annotations (Rust, TypeScript, Go, etc.)
    "&str", "&[", "option<", "some(", "vec<", "box<", "arc<", "rc<",
    "string>", "result<", "hashmap<",
    # Doc / placeholder
    "...", "your ", "insert ",
)

_FALSE_POSITIVE_SUFFIXES: tuple[str, ...] = (
    ">", "}", ")", "...", "here", "_test", "-test",
    # Rust / C++ type closers
    ">()", ">>", ">();",
)

# --------------------------------------------------------------------------- #
# Line-level heuristics: skip entire lines matching these patterns
# --------------------------------------------------------------------------- #

# Comment-only lines (Python/Shell #, C/Rust //, SQL --, Lua --)
_COMMENT_RE = re.compile(
    r"^\s*(?://|#|--|/\*|\*|;|%|<!--)", re.MULTILINE,
)

# Function / method signatures across languages
_FUNC_SIGNATURE_RE = re.compile(
    r"(?:"
    r"\bfn\s+\w+\s*\("                     # Rust: fn name(
    r"|\bfunc\s+[\w(]"                      # Go: func name( or func (receiver)
    r"|\bdef\s+\w+\s*\("                    # Python: def name(
    r"|\bfunction\s+\w+\s*\("               # JS/PHP: function name(
    r"|\b(?:public|private|protected|static|async|override|virtual)\s+"  # Java/C#/TS modifiers
    r"|\)\s*->\s*"                           # Rust/Python return type: ) -> Type
    r"|\)\s*:\s*\w+"                         # TypeScript return type: ): Type
    r")",
    re.IGNORECASE,
)

# Import / use / include / require lines
_IMPORT_RE = re.compile(
    r"^\s*(?:import\s|from\s|use\s|require\s|include\s|#include\s)",
    re.IGNORECASE,
)

# Struct / class / type / interface / enum definitions
_TYPE_DEF_RE = re.compile(
    r"^\s*(?:struct\s|class\s|type\s|interface\s|enum\s|trait\s|impl\s)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Assignment patterns (covers most config formats)
# --------------------------------------------------------------------------- #

# Each pattern has named groups: `keyword` and `value`
_ASSIGNMENT_PATTERNS: list[re.Pattern[str]] = [
    # key = "value"  |  key = 'value'  |  key = value
    re.compile(
        r"""(?:^|[\s._-])(?P<keyword>{kw})"""
        r"""\s*[=:]\s*['"]?(?P<value>[^'"\s,;#][^'"\n]{{0,200}})['"]?""",
        re.IGNORECASE,
    ),
    # "key": "value"  (JSON)
    re.compile(
        r"""['"](?P<keyword>{kw})['"]"""
        r"""\s*:\s*['"](?P<value>[^'"]+)['"]""",
        re.IGNORECASE,
    ),
    # export KEY=value
    re.compile(
        r"""export\s+(?P<keyword>{kw})\s*=\s*['"]?(?P<value>[^'"\s]+)['"]?""",
        re.IGNORECASE,
    ),
    # key => value  (Ruby, PHP)
    re.compile(
        r"""['"]?(?P<keyword>{kw})['"]?\s*=>\s*['"]?(?P<value>[^'"\s,;]+)['"]?""",
        re.IGNORECASE,
    ),
]


@dataclass(frozen=True, slots=True)
class KeywordMatch:
    """A keyword-assignment match."""

    keyword: str
    value: str
    line_number: int
    line_content: str
    assignment_type: str  # "equals", "colon", "export", "arrow"


class KeywordDetector:
    """Detect secrets via keyword-assignment pattern matching.

    Looks for lines like ``PASSWORD = 's3cret'`` and captures the value,
    filtering out common placeholder / false-positive values.
    """

    def __init__(
        self,
        keywords: list[str] | None = None,
        case_sensitive: bool = False,
        min_value_length: int = 4,
    ) -> None:
        self.keywords = keywords or DEFAULT_KEYWORDS
        self.case_sensitive = case_sensitive
        self.min_value_length = min_value_length

        # Build compiled patterns with the keyword alternation baked in
        kw_alt = "|".join(re.escape(k) for k in self.keywords)
        flags = 0 if case_sensitive else re.IGNORECASE
        self._patterns: list[tuple[re.Pattern[str], str]] = []
        for idx, pat in enumerate(_ASSIGNMENT_PATTERNS):
            compiled = re.compile(pat.pattern.format(kw=kw_alt), flags)
            label = ["equals", "colon/json", "export", "arrow"][idx]
            self._patterns.append((compiled, label))

    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_noise_line(line: str) -> bool:
        """Return *True* if the entire line is structural code, not config."""
        stripped = line.strip()
        if not stripped:
            return True

        # Comment-only lines
        if _COMMENT_RE.match(stripped):
            return True

        # Function / method signatures
        if _FUNC_SIGNATURE_RE.search(stripped):
            return True

        # Import / use / require lines
        if _IMPORT_RE.match(stripped):
            return True

        # Struct / class / type definitions
        if _TYPE_DEF_RE.match(stripped):
            return True

        return False

    def _is_false_positive(self, value: str) -> bool:
        """Return *True* if the value is a known false-positive."""
        v = value.strip().strip("'\"").strip()

        if len(v) < self.min_value_length:
            return True

        v_lower = v.lower()
        if v_lower in _FALSE_POSITIVE_VALUES:
            return True
        if v_lower.startswith(_FALSE_POSITIVE_PREFIXES):
            return True
        if v_lower.endswith(_FALSE_POSITIVE_SUFFIXES):
            return True

        # Numbers or UID:GID (e.g. 1000:1000, 8080:8080)
        if v.replace(":", "").replace("-", "").isdigit():
            return True

        # All identical characters (e.g. "xxxxxxxx")
        if len(set(v)) == 1:
            return True

        # Value looks like a code expression (has parens, angle brackets, pipes)
        code_chars = sum(1 for c in v if c in "<>(){}|&;")
        if code_chars >= 2:
            return True

        return False

    # ------------------------------------------------------------------ #

    def scan_line(self, line: str, line_number: int = 0) -> list[KeywordMatch]:
        """Return all keyword-assignment matches found in *line*."""
        # Skip entire lines that are comments, function sigs, imports, etc.
        if self._is_noise_line(line):
            return []

        matches: list[KeywordMatch] = []
        for pattern, assign_type in self._patterns:
            for m in pattern.finditer(line):
                keyword = m.group("keyword")
                value = m.group("value").strip().rstrip("'\"`,;")

                if self._is_false_positive(value):
                    continue

                matches.append(
                    KeywordMatch(
                        keyword=keyword,
                        value=value,
                        line_number=line_number,
                        line_content=line,
                        assignment_type=assign_type,
                    )
                )
        return matches

    def scan_content(self, content: str) -> list[KeywordMatch]:
        """Scan every line of *content* and return all matches."""
        all_matches: list[KeywordMatch] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            all_matches.extend(self.scan_line(line, line_number=line_no))
        return all_matches
