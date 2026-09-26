"""Text normalisation used by the security guards and the ingestion pipeline.

Everything here treats its input as hostile: Unicode is normalised (NFKC),
zero-width and bidirectional-control characters are removed, homoglyphs are
folded to their ASCII lookalikes, and base64/ROT13-encoded segments are decoded
so that obfuscated instructions can still be matched by the guards.

No function in this module ever executes, evaluates or renders its input.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

#: Characters that are invisible but can smuggle or split keywords.
INVISIBLE_CHARS: str = (
    "\u00ad"  # soft hyphen
    "\u061c"  # Arabic letter mark
    "\u180e"  # Mongolian vowel separator
    "\u200b\u200c\u200d\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064"
    "\u2066\u2067\u2068\u2069"
    "\ufeff"
)
INVISIBLE_RE = re.compile(f"[{re.escape(INVISIBLE_CHARS)}]")

CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
WHITESPACE_RE = re.compile(r"[ \t\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]+")
NEWLINE_RE = re.compile(r"\n{3,}")

#: Cyrillic/Greek/fullwidth lookalikes commonly used to dodge keyword filters.
CONFUSABLES: dict[int, str] = str.maketrans(
    {
        "\u0430": "a",
        "\u0432": "b",
        "\u0433": "r",
        "\u0435": "e",
        "\u043a": "k",
        "\u043c": "m",
        "\u043d": "h",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0442": "t",
        "\u0445": "x",
        "\u0443": "y",
        "\u0456": "i",
        "\u0455": "s",
        "\u0458": "j",
        "\u04bb": "h",
        "\u0501": "d",
        "\u051b": "q",
        "\u051d": "w",
        "\u0410": "A",
        "\u0412": "B",
        "\u0413": "R",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
        "\u0423": "Y",
        "\u0406": "I",
        "\u0408": "J",
        "\u03b1": "a",
        "\u03b5": "e",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03bd": "v",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03c4": "t",
        "\u03c5": "u",
        "\u03c7": "x",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0396": "Z",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a5": "Y",
        "\u03a7": "X",
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
    }
)

_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_CANDIDATE_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi-control and control characters."""
    if not text:
        return ""
    return CONTROL_RE.sub("", INVISIBLE_RE.sub("", text))


def normalize_text(text: str, *, max_length: int | None = None) -> str:
    """Canonical form used for storage, indexing and guard matching."""
    if not text:
        return ""
    cleaned = unicodedata.normalize("NFKC", strip_invisible(text))
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    lines = [WHITESPACE_RE.sub(" ", line).strip() for line in cleaned.split("\n")]
    cleaned = "\n".join(lines)
    cleaned = NEWLINE_RE.sub("\n\n", cleaned).strip()
    if max_length is not None:
        cleaned = cleaned[:max_length]
    return cleaned


def fold_confusables(text: str) -> str:
    """Map common homoglyphs to their ASCII equivalents."""
    return text.translate(CONFUSABLES)


def _try_decode_base64(candidate: str) -> str | None:
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded.isprintable() and "\n" not in decoded:
        return None
    return decoded


def decode_obfuscated_segments(text: str) -> list[str]:
    """Return decoded variants of base64/hex/ROT13 encoded fragments."""
    decoded_parts: list[str] = []
    for match in _BASE64_CANDIDATE_RE.findall(text):
        decoded = _try_decode_base64(match)
        if decoded and any(char.isalpha() for char in decoded):
            decoded_parts.append(decoded)
    for match in _HEX_CANDIDATE_RE.findall(text):
        try:
            decoded = bytes.fromhex(match).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            decoded_parts.append(decoded)
    if len(text) >= 12:
        decoded_parts.append(codecs.decode(text, "rot_13"))
    return decoded_parts


def normalize_for_guard(text: str) -> str:
    """Aggressive canonical form for attack-pattern matching.

    Produces lowercase, homoglyph-folded, whitespace-collapsed text with the
    decoded form of any obfuscated fragment appended, so that
    ``"aWdub3JlIHlvdXIgcnVsZXM="`` matches the same patterns as plain English.
    """
    base = normalize_text(text)
    variants = [base, fold_confusables(base)]
    for decoded in decode_obfuscated_segments(base):
        normalized_decoded = normalize_text(decoded)
        variants.append(normalized_decoded)
        variants.append(fold_confusables(normalized_decoded))
    lowered = list(dict.fromkeys(variant.lower() for variant in variants if variant))
    # Keep the newline-preserving variants so line-anchored patterns still work,
    # and append whitespace-collapsed copies for patterns spanning line breaks.
    flattened = [WHITESPACE_RE.sub(" ", variant.replace("\n", " ")).strip() for variant in lowered]
    return "\n".join(lowered + flattened)
