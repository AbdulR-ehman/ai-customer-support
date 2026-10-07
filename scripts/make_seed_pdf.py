"""Generate the fictional Acme Support knowledge PDF.

Written with a hand-built PDF 1.4 file so the project needs no extra PDF-writing
dependency. The output is a normal, unencrypted, single-font PDF that ``pypdf``
can extract text from, and it is committed alongside the other seed documents.

Run:  python scripts/make_seed_pdf.py
"""

from __future__ import annotations

import pathlib
import zlib

OUTPUT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "knowledge_base"
    / "documents"
    / "11-billing-guidelines.pdf"
)

TITLE = "Acme Support - Billing Guidelines"
PAGES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Acme Support Billing Guidelines",
        (
            "This guide is fictional sample content for the Acme Support",
            "portfolio project. It describes invoicing and payment rules.",
        ),
    ),
    (
        "Invoice schedule",
        (
            "Invoices are issued on the same calendar day each month.",
            "Annual contracts are invoiced once at the start of the term.",
            "Payment is due within 14 days of the invoice date.",
        ),
    ),
    (
        "Late payment",
        (
            "A late payment reminder is sent 3 days after the due date.",
            "After 14 days overdue the subscription is paused.",
            "Data is retained for 60 days while a subscription is paused.",
        ),
    ),
    (
        "Credits and adjustments",
        (
            "Prorated credits appear on the next invoice automatically.",
            "Manual credits require a support request and approval.",
            "Credits expire 12 months after they are issued.",
        ),
    ),
)

#: Helvetica widths (per 1000 units) for the printable ASCII range we use.
CHAR_WIDTH = 6.0
PAGE_WIDTH = 612
PAGE_HEIGHT = 792
MARGIN = 72
BODY_SIZE = 11
LINE_HEIGHT = 18


def _escape(text: str) -> str:
    """Escape a string for a PDF literal string object."""
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)").replace("\r", "")


def _page_stream(lines: tuple[str, ...]) -> bytes:
    """Build the content stream that draws one page of text."""
    parts = [
        "BT",
        f"/F1 {BODY_SIZE} Tf",
        f"{LINE_HEIGHT} TL",
        f"{MARGIN} {PAGE_HEIGHT - MARGIN} Td",
    ]
    for line in lines:
        # Bold-looking headers are faked with a slightly larger font reset.
        if line and line[0].isupper() and line == line.title():
            parts.append(f"/F1 {BODY_SIZE + 3} Tf")
            parts.append(f"({_escape(line)}) Tj")
            parts.append(f"/F1 {BODY_SIZE} Tf")
        else:
            parts.append(f"({_escape(line)}) Tj")
        parts.append("T*")
    parts.append("ET")
    return "\n".join(parts).encode("latin-1", errors="replace")


def build_pdf() -> bytes:
    """Assemble a minimal, valid, single-font PDF with one page per section."""
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)  # 1-based object number

    # 1: catalog, 2: page tree, 3: font, then page/content pairs.
    catalog_id = add(b"")  # placeholder, filled in below
    pages_id = add(b"")
    font_id = add(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    )

    page_ids: list[int] = []
    for heading, body_lines in PAGES:
        lines = (heading, "", *body_lines)
        stream = _page_stream(lines)
        compressed = zlib.compress(stream)
        content_id = add(
            b"<< /Length "
            + str(len(compressed)).encode("ascii")
            + b" /Filter /FlateDecode >>\nstream\n"
            + compressed
            + b"\nendstream"
        )
        page_id = add(
            b"<< /Type /Page /Parent "
            + str(pages_id).encode("ascii")
            + b" 0 R /MediaBox [0 0 "
            + f"{PAGE_WIDTH} {PAGE_HEIGHT}".encode("ascii")
            + b"] /Resources << /Font << /F1 "
            + str(font_id).encode("ascii")
            + b" 0 R >> >> /Contents "
            + str(content_id).encode("ascii")
            + b" 0 R >>"
        )
        page_ids.append(page_id)

    objects[catalog_id - 1] = (
        b"<< /Type /Catalog /Pages " + str(pages_id).encode("ascii") + b" 0 R >>"
    )
    kids = b" ".join(str(pid).encode("ascii") + b" 0 R" for pid in page_ids)
    objects[pages_id - 1] = (
        b"<< /Type /Pages /Count "
        + str(len(page_ids)).encode("ascii")
        + b" /Kids ["
        + kids
        + b"] >>"
    )

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += str(number).encode("ascii") + b" 0 obj\n" + body + b"\nendobj\n"

    xref_offset = len(out)
    out += b"xref\n0 " + str(len(objects) + 1).encode("ascii") + b"\n"
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode("ascii")
        + b" /Root "
        + str(catalog_id).encode("ascii")
        + b" 0 R /Info << /Title ("
        + _escape(TITLE).encode("latin-1", "replace")
        + b") >> >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(out)


def main() -> int:
    data = build_pdf()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(data)
    print(f"wrote {OUTPUT} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
