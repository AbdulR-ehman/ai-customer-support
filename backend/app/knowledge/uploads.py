"""File-upload hardening: filename sanitising, streaming size caps, safe paths.

Uploaded files are never trusted: they are read with a hard byte cap enforced
*while* streaming, stored under a random UUID name outside any served directory,
and the original name is kept only as sanitised metadata.
"""

from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from app.ai.normalization import strip_invisible
from app.errors import InvalidInputError, PayloadTooLargeError, UnsupportedMediaTypeError
from app.knowledge.extraction import ALLOWED_EXTENSIONS, detect_kind

#: Windows device names that must never be used as a file name.
WINDOWS_RESERVED_NAMES: frozenset[str] = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

#: Extensions that must never survive inside a filename (double-extension tricks).
DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".dll",
        ".scr",
        ".com",
        ".pif",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".msi",
        ".msp",
        ".jar",
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".phtml",
        ".asp",
        ".aspx",
        ".jsp",
        ".jspx",
        ".cgi",
        ".pl",
        ".py",
        ".pyc",
        ".rb",
        ".sh",
        ".bash",
        ".zsh",
        ".hta",
        ".lnk",
        ".reg",
        ".url",
        ".svg",
        ".html",
        ".htm",
        ".xhtml",
        ".shtml",
        ".swf",
        ".apk",
        ".iso",
        ".vhd",
    }
)

UNSAFE_NAME_CHARS_RE = re.compile(r"[^\w\s.\-()\[\]]", re.UNICODE)
MAX_FILENAME_LENGTH = 150
STREAM_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class UploadInfo:
    """Validated upload metadata."""

    original_filename: str
    stored_filename: str
    kind: str
    content_type: str
    size_bytes: int


#: Filename shapes that are refused outright. Silently rewriting them would hide
#: an attack attempt, so a request carrying one is rejected instead.
TRAVERSAL_MARKERS: tuple[str, ...] = (
    "..",
    "%2e%2e",  # encoded ".."
    "%2f",  # encoded "/"
    "%5c",  # encoded "\"
    "\\",  # Windows separator
    "/",  # POSIX separator
    "\x00",  # null byte
    ":",  # drive letters and NTFS alternate data streams
    "~",  # home-directory expansion
)


def _reject_unsafe_name(name: str) -> None:
    """Refuse a filename that carries a traversal or special-file marker."""
    lowered = name.lower()
    for marker in TRAVERSAL_MARKERS:
        if marker in lowered:
            raise InvalidInputError("The uploaded file name is not allowed.")

    # A Windows reserved device name is refused rather than renamed.
    # WINDOWS_RESERVED_NAMES is lowercase, so normalise both sides.
    stem = Path(name.replace("\\", "/")).stem.strip().lower()
    if stem in WINDOWS_RESERVED_NAMES:
        raise InvalidInputError("That file name is reserved and cannot be used.")


def sanitize_filename(raw_name: str | None) -> str:
    """Validate and reduce an untrusted filename to a safe, display-only label.

    Path traversal, null bytes, alternate data streams and Windows reserved names
    are **rejected** (see :func:`_reject_unsafe_name`). The remaining cosmetic
    normalisation (control characters, Unicode confusables, double extensions and
    the extension allowlist) is applied afterwards, because a name can still be
    dangerous after the raw text looks harmless.
    """
    name = (raw_name or "").strip()
    if not name:
        raise InvalidInputError("The uploaded file needs a name.")

    # Reject before any rewriting, so the original is what gets checked.
    _reject_unsafe_name(name)

    name = name.replace("\\", "/").split("/")[-1]
    name = name.replace("\x00", "")
    name = strip_invisible(name)
    name = unicodedata.normalize("NFKC", name)
    name = UNSAFE_NAME_CHARS_RE.sub("_", name)
    name = name.strip().strip(".").strip()
    name = re.sub(r"\s+", " ", name)

    if not name:
        raise InvalidInputError("The uploaded file needs a name.")

    suffix = Path(name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise UnsupportedMediaTypeError("Only .txt, .md and .pdf documents can be uploaded.")

    stem = Path(name).stem
    for segment in (part for part in stem.split(".") if part):
        if f".{segment.lower()}" in DANGEROUS_EXTENSIONS:
            raise UnsupportedMediaTypeError(
                "This filename uses a double extension, which is not allowed."
            )
    if not stem:
        raise InvalidInputError("The uploaded file needs a name.")
    if stem.lower() in WINDOWS_RESERVED_NAMES:
        raise InvalidInputError("That file name is reserved and cannot be used.")

    # Never allow a trailing dot/space (Windows strips them, creating mismatches).
    stem = stem.rstrip(" .") or "document"
    max_stem_length = max(1, MAX_FILENAME_LENGTH - len(suffix))
    return f"{stem[:max_stem_length]}{suffix}"


def make_stored_filename(original_filename: str) -> str:
    """Random UUID storage name with the fixed, allowlisted extension."""
    suffix = Path(original_filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise UnsupportedMediaTypeError("Only .txt, .md and .pdf documents can be uploaded.")
    return f"{uuid.uuid4().hex}{suffix}"


def read_limited(stream: BinaryIO, max_bytes: int) -> bytes:
    """Read at most ``max_bytes``, refusing oversized uploads while streaming.

    The limit is checked before the offending chunk is appended, so the process
    never holds more than ``max_bytes`` (plus one chunk) in memory.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(STREAM_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise PayloadTooLargeError(
                f"The file is larger than the {max_bytes // (1024 * 1024)} MB limit."
            )
        chunks.append(chunk)
    return b"".join(chunks)


def resolve_storage_path(directory: Path, stored_filename: str) -> Path:
    """Resolve a storage path, refusing anything that escapes ``directory``."""
    root = directory.resolve()
    if stored_filename != Path(stored_filename).name:
        raise InvalidInputError("The requested file path is not allowed.")
    candidate = (root / stored_filename).resolve()
    if candidate != root and root not in candidate.parents:
        raise InvalidInputError("The requested file path is not allowed.")
    return candidate


def validate_upload(
    *,
    raw_filename: str | None,
    content_type: str | None,
    data: bytes,
    max_bytes: int,
) -> UploadInfo:
    """Validate name, size, extension and magic bytes as a single step."""
    if not data:
        raise InvalidInputError("The uploaded file is empty.")
    if len(data) > max_bytes:
        raise PayloadTooLargeError(
            f"The file is larger than the {max_bytes // (1024 * 1024)} MB limit."
        )
    safe_name = sanitize_filename(raw_filename)
    kind = detect_kind(safe_name, content_type, data)
    return UploadInfo(
        original_filename=safe_name,
        stored_filename=make_stored_filename(safe_name),
        kind=kind,
        content_type=(content_type or "").split(";")[0].strip().lower() or "text/plain",
        size_bytes=len(data),
    )


def safe_error_message(message: object, *, fallback: str = "Processing failed.") -> str:
    """Sanitise an internal error message before storing or displaying it."""
    text = strip_invisible(str(message)).replace("\n", " ").strip()
    if not text:
        return fallback
    return text[:400]
