"""Shannon entropy analysis for high-entropy string detection."""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EntropyMatch:
    """A substring with unusually high entropy."""

    text: str
    entropy: float
    encoding: str  # "hex", "base64", or "unknown"
    start_pos: int
    end_pos: int


# --------------------------------------------------------------------------- #
# Character sets
# --------------------------------------------------------------------------- #

_HEX_CHARS = set(string.hexdigits)
_BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=_-")

# Patterns that capture contiguous hex / base64 tokens
_HEX_RE = re.compile(r"[0-9a-fA-F]{8,}")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/=_-]{12,}")


# --------------------------------------------------------------------------- #
# Core entropy calculation
# --------------------------------------------------------------------------- #


def calculate_shannon_entropy(data: str) -> float:
    """Compute Shannon entropy (bits per character) of *data*.

    Returns ``0.0`` for an empty string.
    """
    if not data:
        return 0.0

    length = len(data)
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def calculate_hex_entropy(data: str) -> float:
    """Shannon entropy calculated **only** over the hex characters in *data*."""
    hex_only = "".join(ch for ch in data if ch in _HEX_CHARS)
    return calculate_shannon_entropy(hex_only)


def calculate_base64_entropy(data: str) -> float:
    """Shannon entropy calculated **only** over the base64 characters in *data*."""
    b64_only = "".join(ch for ch in data if ch in _BASE64_CHARS)
    return calculate_shannon_entropy(b64_only)


# --------------------------------------------------------------------------- #
# High-entropy string finder
# --------------------------------------------------------------------------- #


def _classify_encoding(token: str) -> str:
    """Return ``'hex'``, ``'base64'``, or ``'unknown'``."""
    charset = set(token)
    if charset <= _HEX_CHARS:
        return "hex"
    if charset <= _BASE64_CHARS:
        return "base64"
    return "unknown"


_URL_RE = re.compile(r"https?://", re.IGNORECASE)

# Context window: how many chars before/after a token to inspect
_CTX_WINDOW = 60


def _is_likely_non_secret(token: str, content: str, start: int, end: int) -> bool:
    """Return *True* if the token is probably NOT a secret.

    Heuristics:
    - Token is embedded inside a URL (https://...)
    - Token contains path separators (/) suggesting a file path or URL path
    - Token looks like a version string, commit hash in a lockfile context, etc.
    """
    # Check a small window around the token for URL context
    ctx_start = max(0, start - _CTX_WINDOW)
    ctx = content[ctx_start:end]
    if _URL_RE.search(ctx):
        return True

    # Path-like: contains slashes (URL paths, file paths)
    if "/" in token and token.count("/") >= 2:
        return True

    # Contains dashes like a slug/package-name (e.g. x86_64-unknown-linux-gnu)
    if "-" in token and token.count("-") >= 2:
        return True

    return False


def find_high_entropy_strings(
    content: str,
    *,
    min_length: int = 8,
    hex_threshold: float = 3.0,
    base64_threshold: float = 4.5,
) -> list[EntropyMatch]:
    """Find substrings in *content* whose Shannon entropy exceeds threshold.

    Two passes are performed:
    1. Hex tokens  (threshold default **3.0** - random hex ~ 4.0)
    2. Base64 tokens (threshold default **4.5** - random base64 ~ 5.17)

    Overlapping matches are deduplicated in favour of the higher-entropy one.
    """
    matches: dict[tuple[int, int], EntropyMatch] = {}

    for regex, label, threshold in [
        (_HEX_RE, "hex", hex_threshold),
        (_BASE64_RE, "base64", base64_threshold),
    ]:
        for m in regex.finditer(content):
            token = m.group()
            if len(token) < min_length:
                continue

            ent = calculate_shannon_entropy(token)
            if ent < threshold:
                continue

            # Filter out URLs, file paths, package slugs
            if _is_likely_non_secret(token, content, m.start(), m.end()):
                continue

            key = (m.start(), m.end())
            if key not in matches or matches[key].entropy < ent:
                matches[key] = EntropyMatch(
                    text=token,
                    entropy=ent,
                    encoding=label,
                    start_pos=m.start(),
                    end_pos=m.end(),
                )

    return sorted(matches.values(), key=lambda em: em.start_pos)
