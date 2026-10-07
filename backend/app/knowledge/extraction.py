"""Text extraction for TXT, Markdown and PDF documents.

Safety properties
-----------------
* The file **extension allowlist** and the **magic bytes** must agree; a file
  named ``.pdf`` that does not start with ``%PDF-`` is rejected, and scripts are
  never executed or rendered.
* PDFs are never decrypted (encrypted files are rejected), page count and
  extracted character count are capped, and a wall-clock deadline stops runaway
  extraction, so a "PDF bomb" cannot exhaust memory or CPU.
* ``pypdf`` only reads text operators; embedded JavaScript and attachments are
  never executed.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.errors import InvalidInputError, UnsupportedMediaTypeError
from app.knowledge.cleaning import clean_document_text, decode_bytes

logger = logging.getLogger("app.knowledge.extraction")

PDF_MAGIC = b"%PDF-"
ALLOWED_EXTENSIONS: tuple[str, ...] = (".txt", ".md", ".pdf")
KIND_TEXT = "text"
KIND_PDF = "pdf"

#: Advisory content types accepted per kind (browsers are inconsistent here).
ALLOWED_CONTENT_TYPES: dict[str, frozenset[str]] = {
    KIND_TEXT: frozenset(
        {
            "",
            "text/plain",
            "text/markdown",
            "text/x-markdown",
            "text/x-web-markdown",
            "application/octet-stream",
            "text/*",
        }
    ),
    KIND_PDF: frozenset({"", "application/pdf", "application/x-pdf", "application/octet-stream"}),
}


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """Outcome of extracting text from one document."""

    text: str
    kind: str
    page_count: int | None
    encoding: str | None
    truncated: bool


def detect_kind(filename: str, content_type: str | None, data: bytes) -> str:
    """Decide whether the bytes are an allowed text or PDF document."""
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise UnsupportedMediaTypeError("Only .txt, .md and .pdf documents can be uploaded.")
    normalized_content_type = (content_type or "").split(";")[0].strip().lower()
    if extension == ".pdf":
        if not data.startswith(PDF_MAGIC):
            raise UnsupportedMediaTypeError(
                "This file has a .pdf extension but is not a valid PDF document."
            )
        _check_content_type(normalized_content_type, KIND_PDF)
        return KIND_PDF

    if data.startswith(PDF_MAGIC):
        raise UnsupportedMediaTypeError("The file content is a PDF but the extension is not .pdf.")
    if looks_binary(data):
        raise UnsupportedMediaTypeError("The file does not look like a text document.")
    _check_content_type(normalized_content_type, KIND_TEXT)
    return KIND_TEXT


def _check_content_type(content_type: str, kind: str) -> None:
    allowed = ALLOWED_CONTENT_TYPES[kind]
    if content_type in allowed or content_type.startswith("text/"):
        return
    raise UnsupportedMediaTypeError("The submitted file type is not supported.")


def looks_binary(data: bytes, *, sample_size: int = 4096) -> bool:
    """Heuristic binary sniff: NUL bytes or too many non-text control bytes."""
    sample = data[:sample_size]
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    suspicious = sum(1 for byte in sample if byte < 9 or (13 < byte < 32) or byte == 127)
    return suspicious / len(sample) > 0.05


def extract_text(
    filename: str,
    content_type: str | None,
    data: bytes,
    *,
    max_chars: int,
    max_pdf_pages: int,
    timeout_seconds: float,
) -> ExtractionResult:
    """Extract clean, index-ready text from an allowed document."""
    kind = detect_kind(filename, content_type, data)
    if kind == KIND_PDF:
        return _extract_pdf(
            data,
            max_chars=max_chars,
            max_pdf_pages=max_pdf_pages,
            timeout_seconds=timeout_seconds,
        )

    raw_text, encoding = decode_bytes(data, max_chars=max_chars)
    cleaned = clean_document_text(raw_text, max_chars=max_chars)
    return ExtractionResult(
        text=cleaned,
        kind=KIND_TEXT,
        page_count=None,
        encoding=encoding,
        truncated=len(raw_text) >= max_chars,
    )


def _extract_pdf(
    data: bytes,
    *,
    max_chars: int,
    max_pdf_pages: int,
    timeout_seconds: float,
) -> ExtractionResult:
    deadline = time.monotonic() + timeout_seconds
    try:
        reader = PdfReader(BytesIO(data), strict=False)
    except PdfReadError as exc:
        raise InvalidInputError(
            "This PDF could not be read. It may be corrupted or truncated."
        ) from exc

    if reader.is_encrypted:
        raise InvalidInputError(
            "Encrypted (password-protected) PDFs are not supported. "
            "Please upload an unprotected copy."
        )

    try:
        page_count = len(reader.pages)
    except Exception as exc:
        raise InvalidInputError("This PDF could not be read. Its page tree is damaged.") from exc

    if page_count == 0:
        raise InvalidInputError("This PDF contains no pages.")
    if page_count > max_pdf_pages:
        raise InvalidInputError(
            f"This PDF has more than the {max_pdf_pages} page limit and was rejected."
        )

    parts: list[str] = []
    total_chars = 0
    truncated = False
    for page in reader.pages:
        if time.monotonic() > deadline:
            truncated = True
            break
        try:
            page_text = page.extract_text() or ""
        except Exception:
            # One malformed page must not discard the rest of the document; the
            # failure is logged (without document content) and the page skipped.
            logger.debug("PDF page text extraction failed; skipping the page")
            continue
        if not page_text:
            continue
        remaining = max_chars - total_chars
        if remaining <= 0:
            truncated = True
            break
        parts.append(page_text[:remaining])
        total_chars += len(parts[-1])
        if total_chars >= max_chars:
            truncated = True
            break

    combined = "\n\n".join(parts)
    cleaned = clean_document_text(combined, max_chars=max_chars)
    return ExtractionResult(
        text=cleaned,
        kind=KIND_PDF,
        page_count=page_count,
        encoding=None,
        truncated=truncated,
    )
