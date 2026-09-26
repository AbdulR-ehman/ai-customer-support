"""Check the security header literals for homoglyphs or stray characters.

A Cyrillic "о" in "nosniff" looks identical to ASCII in most editors but is a
different byte, which silently breaks the header. This script fails loudly.

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\check_headers.py
"""

from __future__ import annotations

import pathlib
import sys
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.middleware.security_headers import SECURITY_HEADERS  # noqa: E402

#: Values that must be exactly these ASCII strings.
EXPECTED_EXACT: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Permitted-Cross-Domain-Policies": "none",
}


def describe(value: str) -> str:
    """Render a value with non-ASCII characters made visible."""
    return "".join(
        ch if ord(ch) < 128 else f"<U+{ord(ch):04X} {unicodedata.name(ch, '?')}>" for ch in value
    )


def main() -> int:
    problems: list[str] = []
    for name, expected in EXPECTED_EXACT.items():
        actual = SECURITY_HEADERS.get(name, "")
        if actual != expected:
            problems.append(f"{name}: expected {expected!r}, got {describe(actual)!r}")
        for ch in actual:
            if ord(ch) > 127:
                problems.append(f"{name}: non-ASCII character {describe(ch)!r}")

    # Every configured header, not just the ones above: a look-alike byte in any
    # value would silently weaken that header.
    for name, value in SECURITY_HEADERS.items():
        for ch in value:
            if ord(ch) > 127:
                problems.append(f"{name}: non-ASCII character {describe(ch)!r}")

    for line in problems:
        print(f"[PROBLEM] {line}")
    if problems:
        print(f"\n{len(problems)} problem(s) found.")
        return 1
    print("All security header values are clean ASCII.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
