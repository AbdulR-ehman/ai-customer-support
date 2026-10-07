"""Run the pytest suite and write a short report to ``logs/pytest_report.txt``.

Shell output capture is unreliable on this machine, so the summary is written
to a file as well as printed.

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\run_tests.py [pytest args...]
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPORT = ROOT / "logs" / "pytest_report.txt"
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    # Keep pytest output short: assertion lines and the summary are what matter.
    args = ["-q", "--tb=line", *args]

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [str(PYTHON), "-m", "pytest", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    output = (completed.stdout or "") + (completed.stderr or "")
    # Keep the tail: the summary line and the last failures are what matter.
    lines = output.splitlines()
    tail = lines[-60:]
    summary = [
        line for line in lines if " passed" in line or " failed" in line or " error" in line
    ][-3:]

    report = "\n".join(["=== pytest ===", *summary, "", "--- tail ---", *tail])
    REPORT.write_text(report, encoding="utf-8")

    print(report)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
