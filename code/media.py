"""Local, deterministic text extraction for evidence files.

PDFs and screenshots may carry evidence not present in structured tables. This module
uses only local Poppler/Tesseract executables, with shell=False and bounded time/input.
It never executes document content or connects to a network.

The structured extractors preserve method/tool/version/warnings for auditability.
read_text(path) is a convenience interface for callers processing one evidence file
through a shared in-memory cache.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_PDF_PAGES = 30
COMMAND_TIMEOUT_SECONDS = 90


def _version(command: str, args: list[str]) -> str:
    exe = shutil.which(command)
    if not exe:
        return "unavailable"
    try:
        result = subprocess.run(
            [exe, *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    first = (result.stdout or result.stderr).strip().splitlines()
    return first[0][:160] if first else "version unavailable"


def _result(
    text: str = "",
    *,
    method: str = "none",
    tool: str = "none",
    tool_version: str = "n/a",
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "text": text.strip(),
        "method": method,
        "tool": tool,
        "tool_version": tool_version,
        "warnings": warnings or [],
    }


def _check_file(path: str | os.PathLike[str]) -> tuple[Path | None, str | None]:
    file_path = Path(path)
    try:
        if not file_path.is_file():
            return None, "not a regular file"
        if file_path.stat().st_size > MAX_INPUT_BYTES:
            return None, f"file exceeds {MAX_INPUT_BYTES} byte extraction limit"
    except OSError as exc:
        return None, f"cannot access file: {exc.__class__.__name__}"
    return file_path, None


def _run(args: list[str], *, timeout: int = COMMAND_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )


def _pdf_pages(path: Path) -> int | None:
    exe = shutil.which("pdfinfo")
    if not exe:
        return None
    try:
        info = _run([exe, str(path)], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"^Pages:\s+(\d+)\s*$", info.stdout, re.MULTILINE)
    return int(match.group(1)) if match else None


def _ocr_pdf_pages(path: Path, page_count: int) -> tuple[str, list[str]]:
    warnings: list[str] = []
    render_exe = shutil.which("pdftoppm")
    ocr_exe = shutil.which("tesseract")
    if not render_exe or not ocr_exe:
        return "", ["scanned PDF OCR unavailable (requires pdftoppm and tesseract)"]

    texts: list[str] = []
    with tempfile.TemporaryDirectory(prefix="orchestrate-media-") as temp_name:
        prefix = str(Path(temp_name) / "page")
        try:
            rendered = _run(
                [
                    render_exe,
                    "-f", "1",
                    "-l", str(page_count),
                    "-r", "220",
                    "-png",
                    str(path),
                    prefix,
                ],
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "", ["PDF page rendering failed or timed out"]
        if rendered.returncode != 0:
            return "", ["PDF page rendering failed"]

        page_paths = sorted(Path(temp_name).glob("page-*.png"))
        if not page_paths:
            return "", ["PDF renderer produced no pages"]
        if len(page_paths) < page_count:
            warnings.append(f"rendered {len(page_paths)} of {page_count} PDF pages")

        for page_path in page_paths[:page_count]:
            try:
                result = _run([ocr_exe, str(page_path), "stdout", "-l", "eng", "--psm", "6"])
            except (OSError, subprocess.TimeoutExpired):
                warnings.append(f"OCR failed or timed out on {page_path.name}")
                continue
            if result.returncode == 0 and result.stdout.strip():
                texts.append(result.stdout.strip())
            elif result.returncode != 0:
                warnings.append(f"OCR could not read {page_path.name}")
    return "\n\n".join(texts), warnings


def extract_pdf(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Extract PDF text, OCRing rendered pages only when no usable text layer exists."""
    file_path, error = _check_file(path)
    if error:
        return _result(warnings=[error])
    assert file_path is not None

    pdftotext = shutil.which("pdftotext")
    pdf_version = _version("pdftotext", ["-v"])
    if not pdftotext:
        return _result(tool="pdftotext", tool_version="unavailable", warnings=["pdftotext is not installed"])

    page_count = _pdf_pages(file_path)
    warnings: list[str] = []
    if page_count is None:
        warnings.append("could not determine PDF page count")
        page_limit = MAX_PDF_PAGES
    else:
        page_limit = min(page_count, MAX_PDF_PAGES)
        if page_count > MAX_PDF_PAGES:
            warnings.append(f"PDF has {page_count} pages; only first {MAX_PDF_PAGES} processed")

    try:
        args = [pdftotext, "-layout", "-enc", "UTF-8", "-f", "1", "-l", str(page_limit)]
        args.extend([str(file_path), "-"])
        extracted = _run(args)
    except (OSError, subprocess.TimeoutExpired):
        return _result(tool="pdftotext", tool_version=pdf_version, warnings=warnings + ["PDF text extraction failed or timed out"])

    if extracted.returncode != 0:
        warnings.append("pdftotext could not read this PDF")
        text = ""
    else:
        text = extracted.stdout.strip()

    if len(text) >= 40:
        return _result(text, method="pdf_text", tool="pdftotext", tool_version=pdf_version, warnings=warnings)

    # Empty/near-empty text layers commonly indicate a scanned PDF. Render at a
    # fixed resolution and OCR locally; retain the fallback warning for provenance.
    ocr_page_count = page_limit if page_count is not None else MAX_PDF_PAGES
    ocr_text, ocr_warnings = _ocr_pdf_pages(file_path, ocr_page_count)
    if ocr_text:
        warnings.append("used OCR fallback for a scanned or text-poor PDF")
        return _result(
            ocr_text,
            method="pdf_ocr",
            tool="pdftoppm+tesseract",
            tool_version=f"{_version('pdftoppm', ['-v'])}; {_version('tesseract', ['--version'])}",
            warnings=warnings + ocr_warnings,
        )
    if not text:
        warnings.extend(ocr_warnings)
    return _result(text, method="pdf_text", tool="pdftotext", tool_version=pdf_version, warnings=warnings)


def extract_image(path: str | os.PathLike[str]) -> dict[str, Any]:
    """OCR a raster evidence image locally with Tesseract."""
    file_path, error = _check_file(path)
    if error:
        return _result(warnings=[error])
    assert file_path is not None

    tesseract = shutil.which("tesseract")
    version = _version("tesseract", ["--version"])
    if not tesseract:
        return _result(tool="tesseract", tool_version="unavailable", warnings=["tesseract is not installed"])
    try:
        result = _run([tesseract, str(file_path), "stdout", "-l", "eng", "--psm", "6"])
    except (OSError, subprocess.TimeoutExpired):
        return _result(tool="tesseract", tool_version=version, warnings=["image OCR failed or timed out"])
    if result.returncode != 0:
        return _result(tool="tesseract", tool_version=version, warnings=["tesseract could not read image"])
    return _result(result.stdout, method="image_ocr", tool="tesseract", tool_version=version)


def extract_media(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Dispatch PDF and raster media to the matching local extractor."""
    suffix = Path(path).suffix.lower()
    if suffix == ".pdf":
        return extract_pdf(path)
    if suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}:
        return extract_image(path)
    return _result(warnings=[f"unsupported media type: {suffix or '(no extension)'}"])


def _read_text_uncached(path_string: str) -> str:
    path = Path(path_string)
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return extract_pdf(path)["text"]
    if suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}:
        return extract_image(path)["text"]
    try:
        if not path.is_file():
            return ""
        if path.stat().st_size > MAX_INPUT_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


@functools.lru_cache(maxsize=256)
def _cached_read_text(path_string: str, modified_ns: int, size: int) -> str:
    # mtime and size are part of the key so changed evidence is not served stale.
    del modified_ns, size
    return _read_text_uncached(path_string)


def read_text(path: str | os.PathLike[str]) -> str:
    """Read structured text or extract PDF/image text; caches per path/mtime/size."""
    file_path, error = _check_file(path)
    if error:
        return ""
    assert file_path is not None
    try:
        stat = file_path.stat()
    except OSError:
        return ""
    return _cached_read_text(str(file_path), stat.st_mtime_ns, stat.st_size)


def clear_cache() -> None:
    """Clear the process-local read_text cache, for callers refreshing a dataset."""
    _cached_read_text.cache_clear()
