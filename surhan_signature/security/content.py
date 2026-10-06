"""Validation for untrusted HTML and signature images."""

from __future__ import annotations

import base64
import html
import io
import re

from PIL import Image, UnidentifiedImageError

MAX_SIGNATURE_BYTES = 2 * 1024 * 1024
MAX_HTML_BYTES = 512 * 1024


def sanitize_document_html(value: str | None) -> str:
    text = str(value or "")
    if len(text.encode("utf-8")) > MAX_HTML_BYTES:
        raise ValueError("Document HTML exceeds the 512KB limit.")
    try:
        import bleach

        return bleach.clean(
            text,
            tags=["p", "br", "div", "span", "strong", "b", "em", "i", "u", "s", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "h1", "h2", "h3", "h4", "blockquote", "hr"],
            attributes={"*": ["class", "dir", "lang"], "td": ["colspan", "rowspan"], "th": ["colspan", "rowspan"]},
            protocols=[],
            strip=True,
            strip_comments=True,
        )
    except ImportError:
        # Fail safely on minimal installations: preserve text, not markup.
        text = re.sub(r"<\s*(script|style)[^>]*>.*?<\s*/\s*\1\s*>", "", text, flags=re.I | re.S)
        text = re.sub(r"<[^>]+>", "", text)
        return html.escape(text)


def decode_signature_image(file_name: str, encoded: str) -> tuple[str, bytes]:
    name = str(file_name or "").strip()
    if not name or any(char in name for char in ("/", "\\", "\x00")):
        raise ValueError("Invalid signature file name.")
    try:
        raw = base64.b64decode(str(encoded or ""), validate=True)
    except Exception as exc:
        raise ValueError("Signature image is not valid Base64.") from exc
    if not raw or len(raw) > MAX_SIGNATURE_BYTES:
        raise ValueError("Signature image must be between 1 byte and 2MB.")
    try:
        with Image.open(io.BytesIO(raw)) as image:
            image.verify()
        with Image.open(io.BytesIO(raw)) as image:
            fmt = str(image.format or "").upper()
            width, height = image.size
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ValueError("Uploaded content is not a valid image.") from exc
    if fmt not in {"PNG", "JPEG"}:
        raise ValueError("Only genuine PNG and JPEG images are allowed.")
    if width < 1 or height < 1 or width * height > 16_000_000:
        raise ValueError("Signature image dimensions are unsafe.")
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    expected = "png" if fmt == "PNG" else "jpg"
    if suffix not in ({"png"} if fmt == "PNG" else {"jpg", "jpeg"}):
        raise ValueError("File extension does not match image content.")
    return expected, raw
