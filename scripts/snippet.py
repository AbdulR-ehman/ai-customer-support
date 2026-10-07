"""Extract a line range of a file for inspection (development helper)."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    path = Path(sys.argv[1])
    start = int(sys.argv[2])
    end = int(sys.argv[3])
    out = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    lines = path.read_text(encoding="utf-8").splitlines()
    chunk = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start - 1, min(end, len(lines))))
    if out:
        out.write_text(chunk, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(chunk)


if __name__ == "__main__":
    main()
