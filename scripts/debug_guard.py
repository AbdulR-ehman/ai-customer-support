"""Print which injection pattern matches a given string (guard debugging).

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\debug_guard.py "some suspicious text"
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.ai.injection_patterns import INJECTION_PATTERNS  # noqa: E402
from app.ai.normalization import normalize_for_guard  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: debug_guard.py <text>")
        return 2
    text = " ".join(args)
    normalized = normalize_for_guard(text)
    print("--- input ---")
    print(repr(text))
    print("--- matches ---")
    found = False
    for category, label, pattern in INJECTION_PATTERNS:
        for match in pattern.finditer(normalized):
            found = True
            print(f"[{category}] {label}: {match.group(0)!r}")
    if not found:
        print("(no pattern matched)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
