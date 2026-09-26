"""Text cleaning for the knowledge pipeline.

Everything that reaches the database goes through :func:`clean_document_text`:
Unicode is normalised, control/zero-width characters are removed, markup is
reduced to its human-readable text, and the result is length-capped so a text
bomb cannot exhaust memory. Nothing is ever executed or rendered as HTML.
"""

from __future__ import annotations

import re

from app.ai.normalization import normalize_text
from app.errors import InvalidInputError

#: Scripted/embedded content is dropped entirely: it is never support content.
ACTIVE_CONTENT_RE = re.compile(
    r"(?is)<(script|style|iframe|object|embed|applet|template)[^>]{0,300}>.*?</\1\s*>"
)
HTML_COMMENT_RE = re.compile(r"(?s)<!--.{0,2000}?-->")
LINK_RE = re.compile(r"!?\[([^\]]{0,300})\]\(([^)\s]{0,500})\)")
AUTOLINK_RE = re.compile(r"<(https?://[^>\s]{0,500})>")
HTML_TAG_RE = re.compile(r"</?[A-Za-z][^<>]{0,300}>")
CODE_FENCE_RE = re.compile(r"(?m)^\s*```[A-Za-z0-9_+-]{0,20}\s*$")

SUPPORTED_ENCODINGS: tuple[str, ...] = ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1")


def decode_bytes(data: bytes, *, max_chars: int) -> tuple[str, str]:
    """Decode raw bytes safely.

    Returns ``(text, encoding_used)``. Undecodable input never raises: the last
    resort is a lossy decode, and the text is always truncated to ``max_chars``.
    """
    if not data:
        return "", "utf-8"
    for encoding in SUPPORTED_ENCODINGS:
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        else:
            return text[:max_chars], encoding
    # Lossy fallback: replace undecodable bytes instead of failing the upload.
    return data.decode("utf-8", errors="replace")[:max_chars], "utf-8/lossy"


def clean_document_text(text: str, *, max_chars: int) -> str:
    """Normalise extracted document text into index-ready plain text."""
    if not text:
        return ""
    without_active = ACTIVE_CONTENT_RE.sub(" ", text)
    without_comments = HTML_COMMENT_RE.sub(" ", without_active)
    # Keep the anchor text of Markdown/HTML links, drop the URL.
    without_links = LINK_RE.sub(r"\1", without_comments)
    without_autolinks = AUTOLINK_RE.sub(r"\1", without_links)
    plain = HTML_TAG_RE.sub(" ", without_autolinks)
    plain = CODE_FENCE_RE.sub("", plain)
    cleaned = normalize_text(plain, max_length=max_chars + 1)
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars].rstrip()
    return cleaned


def ensure_meaningful_text(text: str, *, minimum_chars: int = 20) -> str:
    """Raise a client-safe error when a document yields no usable text."""
    if not text or len(text.strip()) < minimum_chars:
        raise InvalidInputError(
            "No readable text could be extracted from this file. "
            "Scanned/image-only documents and encrypted files are not supported."
        )
    return text
