# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Input sanitization — strip dangerous characters and content before redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Maximum input thresholds
MAX_INPUT_BYTES = 1_048_576  # 1 MB
MAX_LINE_COUNT = 50_000

# Null bytes and ASCII control characters (keep \t and \n)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Invisible / zero-width Unicode characters and bidi overrides
_INVISIBLE_UNICODE = re.compile(
    r"["
    r"\u00ad"          # soft hyphen
    r"\u034f"          # combining grapheme joiner
    r"\u061c"          # arabic letter mark
    r"\u115f\u1160"    # hangul fillers
    r"\u17b4\u17b5"    # khmer vowel inherent
    r"\u180e"          # mongolian vowel separator
    r"\u200b-\u200f"   # zero-width space, ZWNJ, ZWJ, LRM, RLM
    r"\u202a-\u202e"   # bidi embedding/override
    r"\u2060-\u2064"   # word joiner, invisible times/separator/plus
    r"\u2066-\u2069"   # bidi isolates
    r"\u206a-\u206f"   # deprecated formatting
    r"\ufeff"          # BOM / zero-width no-break space
    r"\ufff9-\ufffb"   # interlinear annotations
    r"]+"
)

# Base64-encoded blocks (could hide prompt injections)
_BASE64_BLOCK = re.compile(
    r"(?<!\w)[A-Za-z0-9+/]{200,}={0,2}(?!\w)"
)

# HTML tags and script elements
_HTML_SCRIPT = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_HTML_TAGS = re.compile(r"</?[a-zA-Z][^>]*>")

# Markdown image references with external URLs
_MD_EXTERNAL_IMAGE = re.compile(
    r"!\[[^\]]*\]\(https?://[^)]+\)"
)

# Excessive whitespace (3+ consecutive blank lines → 2)
_EXCESSIVE_BLANKS = re.compile(r"\n{4,}")
# Excessive spaces within a line (10+ → single space)
_EXCESSIVE_SPACES = re.compile(r"[^\S\n]{10,}")


@dataclass
class ValidationResult:
    """Result of input validation."""

    text: str
    is_valid: bool = True
    actions: list[str] = field(default_factory=list)
    error: str | None = None


def validate_input(text: str) -> ValidationResult:
    """Validate and sanitize input text.

    Returns cleaned text with a list of sanitization actions taken.
    Rejects oversized inputs outright (is_valid=False).
    """
    actions: list[str] = []

    # Size checks — reject, don't sanitize
    if len(text.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
        return ValidationResult(
            text=text,
            is_valid=False,
            error=f"Input exceeds {MAX_INPUT_BYTES} bytes",
        )

    if text.count("\n") >= MAX_LINE_COUNT:
        return ValidationResult(
            text=text,
            is_valid=False,
            error=f"Input exceeds {MAX_LINE_COUNT} lines",
        )

    cleaned = text

    # Strip null bytes and control characters
    result = _CONTROL_CHARS.sub("", cleaned)
    if result != cleaned:
        actions.append("stripped_control_chars")
        cleaned = result

    # Strip invisible Unicode
    result = _INVISIBLE_UNICODE.sub("", cleaned)
    if result != cleaned:
        actions.append("stripped_invisible_unicode")
        cleaned = result

    # Strip base64-encoded blocks
    result = _BASE64_BLOCK.sub("[BASE64_REMOVED]", cleaned)
    if result != cleaned:
        actions.append("removed_base64_blocks")
        cleaned = result

    # Strip script elements first (before generic HTML tag removal)
    result = _HTML_SCRIPT.sub("", cleaned)
    if result != cleaned:
        actions.append("removed_script_elements")
        cleaned = result

    # Strip remaining HTML tags
    result = _HTML_TAGS.sub("", cleaned)
    if result != cleaned:
        actions.append("removed_html_tags")
        cleaned = result

    # Strip markdown external images
    result = _MD_EXTERNAL_IMAGE.sub("[IMAGE_REMOVED]", cleaned)
    if result != cleaned:
        actions.append("removed_external_images")
        cleaned = result

    # Normalize excessive whitespace
    result = _EXCESSIVE_BLANKS.sub("\n\n\n", cleaned)
    result = _EXCESSIVE_SPACES.sub(" ", result)
    if result != cleaned:
        actions.append("normalized_whitespace")
        cleaned = result

    return ValidationResult(text=cleaned, is_valid=True, actions=actions)
