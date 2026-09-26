"""Print the exact bytes of lines matching a pattern in a file.

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\show_bytes.py <file> <substring>
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) < 2:
        print("usage: show_bytes.py <file> <substring>")
        return 2

    path = pathlib.Path(args[0])
    if not path.is_absolute():
        path = ROOT / path
    needle = args[1]

    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle not in line and needle not in line.lower():
            continue
        escaped = "".join(ch if 32 <= ord(ch) < 127 else f"\\u{ord(ch):04x}" for ch in line)
        print(f"{number}: {escaped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
