"""Import the bundled fictional knowledge-base documents.

Reads every ``knowledge_base/documents/*.{txt,md,pdf}`` file and runs it through
the normal ingestion pipeline (validate -> extract -> clean -> chunk -> index).
Ingestion is idempotent, so running this script twice does not create duplicates.

Usage (from the project root):
    .\\.venv\\Scripts\\python.exe scripts\\seed_knowledge.py
    .\\.venv\\Scripts\\python.exe scripts\\seed_knowledge.py --rebuild
"""

from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import get_settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.knowledge.extraction import ALLOWED_EXTENSIONS  # noqa: E402
from app.logging_config import configure_logging, log_event  # noqa: E402
from app.main import create_schema  # noqa: E402
from app.models.document import SOURCE_SEED  # noqa: E402
from app.services import knowledge as knowledge_service  # noqa: E402

DOCUMENT_DIR = ROOT / "knowledge_base" / "documents"

CONTENT_TYPES = {".txt": "text/plain", ".md": "text/markdown", ".pdf": "application/pdf"}


def document_title(path: pathlib.Path) -> str:
    """Derive a readable title from the filename (plain text, rendered as text)."""
    stem = path.stem
    parts = [p for p in stem.replace("_", "-").split("-") if p]
    if parts and parts[0][:2].isdigit():
        parts = parts[1:]
    return " ".join(p.capitalize() for p in parts) or stem


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the Acme Support knowledge base.")
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Rebuild the FTS index after importing (repairs a damaged index).",
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    logger = configure_logging(settings)
    create_schema(settings)

    if not DOCUMENT_DIR.is_dir():
        print(f"No document directory at {DOCUMENT_DIR}", file=sys.stderr)
        return 1

    files = sorted(
        path
        for path in DOCUMENT_DIR.iterdir()
        if path.is_file() and path.suffix.lower() in ALLOWED_EXTENSIONS
    )
    if not files:
        print(f"No .txt/.md/.pdf documents found in {DOCUMENT_DIR}", file=sys.stderr)
        return 1

    created = duplicates = failed = 0
    with session_scope() as db:
        for path in files:
            title = document_title(path)
            try:
                result = knowledge_service.ingest_bytes(
                    db,
                    settings,
                    raw_filename=path.name,
                    content_type=CONTENT_TYPES.get(path.suffix.lower(), ""),
                    data=path.read_bytes(),
                    uploaded_by=None,
                    title=title,
                    source=SOURCE_SEED,
                )
            except Exception as exc:
                failed += 1
                print(f"  FAILED  {path.name}: {exc}")
                continue

            if result.created:
                created += 1
                print(
                    f"  indexed {path.name}: {result.chunk_count} chunk(s)"
                    + (f", {result.flagged_chunks} flagged" if result.flagged_chunks else "")
                )
            else:
                duplicates += 1
                print(f"  skipped {path.name}: already ingested")

        if args.rebuild:
            rebuilt = knowledge_service.rebuild_index(db, settings)
            print(f"Rebuilt the search index with {rebuilt} chunk(s).")

    print()
    print(f"Seeded {created} document(s), skipped {duplicates}, failed {failed}.")
    log_event(
        logger,
        "knowledge_seeded",
        created=created,
        duplicates=duplicates,
        failed_count=failed,
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
