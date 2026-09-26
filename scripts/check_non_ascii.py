"""Scan project sources for homoglyph and invisible characters.

A Cyrillic "о" inside "nosniff" is invisible in most editors but is a different
byte on the wire, which silently disables a protection. This script flags exactly
that risk class *inside string literals*:

* letters that masquerade as ASCII (Cyrillic/Greek/fullwidth/mathematical forms,
  or anything that NFKC-folds to an ASCII letter or digit);
* invisible characters (Unicode ``Cf`` format characters: zero-width joiners,
  bidi overrides) and stray control characters.

Legitimate typography (em dash, ellipsis, arrows, bullets, accented letters) and
comments/docstrings are ignored on purpose. ``backend/tests`` is not scanned by
default because it deliberately contains hostile payloads; pass it explicitly to
audit it anyway.

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\check_non_ascii.py [paths...]
"""

from __future__ import annotations

import ast
import pathlib
import sys
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Scanned by default. Add arguments to widen the sweep.
SCAN_DIRS = ("backend/app", "frontend/src", "scripts")
SKIP_PARTS = {"__pycache__", ".venv", "node_modules", "logs", ".git", "storage"}

#: Modules that exist to describe or match the very characters we hunt for.
ALLOWED_FILES = {
    "injection_patterns.py",  # multilingual attack-pattern table
    "normalization.py",  # homoglyph folding map
    "fix_homoglyphs.py",  # repair tool whose patterns match homoglyphs
    "check_non_ascii.py",  # this scanner (documents the risk)
}

#: Unicode script names whose letters are commonly used as ASCII look-alikes.
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "FULLWIDTH", "MATHEMATICAL")


def describe(ch: str) -> str:
    return f"U+{ord(ch):04X} {unicodedata.name(ch, '?')}"


def is_suspicious(ch: str) -> bool:
    """True when a character can masquerade as ASCII, or is invisible."""
    if ord(ch) < 128:
        return False
    category = unicodedata.category(ch)
    if category in {"Cf", "Cc"}:  # zero-width joiners, bidi overrides, controls
        return True
    name = unicodedata.name(ch, "")
    if any(script in name for script in CONFUSABLE_SCRIPTS):
        return True
    folded = unicodedata.normalize("NFKC", ch)
    return len(folded) == 1 and folded.isascii() and folded.isalnum()


def _docstring_ids(tree: ast.AST) -> set[int]:
    """Ids of docstring constants (prose, not protocol strings)."""
    found: set[int] = set()
    owners = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    for node in ast.walk(tree):
        if not isinstance(node, owners):
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            found.add(id(first.value))
    return found


def _literal_lines(path: pathlib.Path) -> set[int] | None:
    """Line numbers covered by string literals, or None for non-Python files."""
    if path.suffix != ".py":
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return set()
    docstrings = _docstring_ids(tree)
    lines: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
        ):
            start = node.lineno
            end = node.end_lineno or start
            lines.update(range(start, end + 1))
    return lines


def scan(path: pathlib.Path) -> list[str]:
    """Return one finding string per suspicious line."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    if path.name in ALLOWED_FILES:
        return []

    literal_lines = _literal_lines(path)
    findings: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if literal_lines is not None and number not in literal_lines:
            continue  # comments and docstrings carry prose, not protocol bytes
        offenders = [ch for ch in line if is_suspicious(ch)]
        if not offenders:
            continue
        rendered = " ".join(describe(ch) for ch in offenders)
        findings.append(f"{path.relative_to(ROOT)}:{number}: {rendered} -> {line.strip()[:80]}")
    return findings


def _targets(args: list[str]) -> list[pathlib.Path]:
    if args:
        return [pathlib.Path(a) for a in args]
    found: list[pathlib.Path] = []
    for directory in SCAN_DIRS:
        base = ROOT / directory
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if (
                path.is_file()
                and path.suffix in {".py", ".ts", ".tsx"}
                and not SKIP_PARTS.intersection(path.parts)
            ):
                found.append(path)
    return found


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    targets = _targets(args)

    findings: list[str] = []
    for path in sorted(targets):
        findings.extend(scan(path))

    report_lines = findings or [
        f"Scanned {len(targets)} file(s): no homoglyphs or invisible characters."
    ]
    report_lines.append(f"Scanned {len(targets)} file(s); {len(findings)} suspicious line(s).")
    # Written as UTF-8 because the console codepage cannot render the characters.
    output = ROOT / "logs" / "non_ascii_report.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(report_lines), encoding="utf-8")

    print(f"Wrote {output} ({len(findings)} finding(s)).")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
