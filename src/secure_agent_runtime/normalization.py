"""Bounded text normalization and encoded-payload extraction."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

_ZERO_WIDTH = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u2060\ufeff"),
    None,
)
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])")


@dataclass(frozen=True, slots=True)
class TextView:
    name: str
    text: str


def normalize_text(text: str) -> str:
    """Normalize Unicode and remove format characters commonly used for evasion."""
    normalized = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return "".join(
        char for char in normalized if unicodedata.category(char) != "Cf" or char in "\n\t"
    )


def decoded_base64_fragments(
    text: str,
    *,
    max_tokens: int = 8,
    max_decoded_bytes: int = 4096,
) -> tuple[str, ...]:
    """Decode plausible base64 tokens under strict resource bounds."""
    decoded: list[str] = []
    for match in _B64_TOKEN.finditer(text):
        if len(decoded) >= max_tokens:
            break
        token = match.group(1)
        padding = "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(
                token.replace("-", "+").replace("_", "/") + padding,
                validate=True,
            )
        except (binascii.Error, ValueError):
            continue
        if not raw or len(raw) > max_decoded_bytes:
            continue
        try:
            candidate = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(char.isprintable() or char.isspace() for char in candidate)
        if printable / max(len(candidate), 1) >= 0.9:
            decoded.append(normalize_text(candidate))
    return tuple(decoded)


def analysis_views(text: str) -> tuple[TextView, ...]:
    normalized = normalize_text(text)
    views = [TextView("normalized", normalized)]
    for index, fragment in enumerate(decoded_base64_fragments(normalized), start=1):
        views.append(TextView(f"base64:{index}", fragment))
    return tuple(views)
