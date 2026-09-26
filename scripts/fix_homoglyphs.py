"""Repair homoglyph typos in security-sensitive string literals.

A Cyrillic "о" inside "nosniff" is invisible in most editors but changes the
byte on the wire. This rewrites the known security header literals in the test
suite using explicitly escaped ASCII, so the intent is unambiguous.

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\fix_homoglyphs.py [--check]
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = ROOT / "backend" / "tests" / "security" / "test_security.py"

#: The exact byte sequences these literals must contain. The replacement strings
#: are written as real characters; a lambda is used for the substitution so the
#: backslash escapes are never interpreted as regex replacement escapes.
REPLACEMENTS: tuple[tuple[str, str], ...] = (
    (r'== "n[oо]sn[iі]ff"', '== "nosniff"'),
    (r'== "no[-\u2010\u2011\u2013]?refe[rо]er"', '== "no-referrer"'),
    (r'== "DE[N\u041d]Y"', '== "DENY"'),
    (r'== "no[-\u2010\u2011\u2013]?sto[rр]e"', '== "no-store"'),
)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    check_only = "--check" in args

    original = TARGET.read_text(encoding="utf-8")
    updated = original
    for pattern, replacement in REPLACEMENTS:
        updated = re.sub(pattern, replacement, updated)

    # Report any remaining non-ASCII inside string literals we care about.
    suspicious = [
        (number, line)
        for number, line in enumerate(updated.splitlines(), start=1)
        if re.search(r'"[^"]*[^\x00-\x7f][^"]*"', line)
        and "fullwidth" not in line
        and "DIRECT_ATTACKS" not in line
    ]

    if updated != original:
        if check_only:
            print("Homoglyph literals found. Re-run without --check to fix.")
            return 1
        TARGET.write_text(updated, encoding="utf-8")
        print(f"Repaired {TARGET.name}.")
    elif check_only:
        print("No homoglyph literals found.")

    for number, line in suspicious:
        print(f"  note: non-ASCII literal at line {number}: {line.strip()[:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
