"""Exercise the upload filename sanitizer against a list of hostile names.

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\check_filename_rules.py
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.errors import AppError  # noqa: E402
from app.knowledge.uploads import sanitize_filename  # noqa: E402

MUST_REJECT = (
    "../evil.txt",
    "..\\..\\evil.txt",
    "/etc/passwd.txt",
    "C:\\Windows\\evil.txt",
    "document.txt:secret",
    "CON.txt",
    "nul.md",
    "null\x00byte.txt",
    "..%2f..%2fevil.txt",
    "~/evil.txt",
    "shell.php.txt",
    "a.pdf.exe",
    "payload.exe",
    "\\\\server\\share\\evil.txt",  # UNC path
    "//server/share/evil.txt",  # UNC path, POSIX separators
    "\\\\?\\C:\\evil.txt",  # Windows device namespace
    "..%2e%2e/evil.txt",  # encoded dots, unencoded separator
    "invoice.pdf.php",  # double extension with allowlisted prefix
)
# Normalised rather than rejected, but still reduced to a safe label.
MUST_ACCEPT = (
    "refund-policy.md",
    "billing guidelines.txt",
    "Acme Support 2026.pdf",
    "trailing. .txt",
)


def main() -> int:
    problems = 0
    for name in MUST_REJECT:
        try:
            result = sanitize_filename(name)
        except AppError:
            print(f"[ok rejected] {name!r}")
        else:
            problems += 1
            print(f"[PROBLEM accepted] {name!r} -> {result!r}")

    for name in MUST_ACCEPT:
        try:
            result = sanitize_filename(name)
        except AppError as exc:
            problems += 1
            print(f"[PROBLEM rejected] {name!r}: {exc}")
        else:
            print(f"[ok accepted] {name!r} -> {result!r}")

    print(f"\n{problems} problem(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
