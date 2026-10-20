"""File-name helpers shared by extraction, normalization and triage.

A file name is a weak indicator on its own: `invoice.pdf` is on a million disks. What makes one worth a
look is where it was seen (named as an attachment or download) or how it is dressed: an executable hiding
behind a document extension (`invoice.pdf.exe`) is a classic way to get someone to open it. Names are only
extracted when the text labels them as files (see extract.py) or when they are dressed like that, so that
ordinary logs full of `config.json` and `libc.so.6` do not fill the indicator list.
"""

from __future__ import annotations

import re

# Extensions people expect to be safe to open.
DOCUMENT_EXTENSIONS = frozenset(
    "doc docx docm dot rtf xls xlsx xlsm xlsb csv ppt pptx pptm pdf txt jpg jpeg png gif bmp tif tiff mp3 mp4 avi htm html".split()
)
# Extensions that run code or hide it (programs, scripts, shortcuts, installers, macro hosts).
EXECUTABLE_EXTENSIONS = frozenset(
    "exe scr bat cmd pif vbs vbe jse wsf wsh hta lnk ps1 jar msi dll cpl".split()
)

_EXTENSION = re.compile(r"\.([A-Za-z0-9]{1,10})$")
_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f/\\:*?\"<>|]")
MAX_FILENAME = 255


def extension(name: str) -> str:
    m = _EXTENSION.search(name)
    return m.group(1).lower() if m else ""


def valid_filename(name: str) -> bool:
    """A plausible file name: bounded, no path separators or control characters, and an extension."""
    if not name or len(name) > MAX_FILENAME or name != name.strip() or _FORBIDDEN.search(name):
        return False
    stem = name[: -len(extension(name)) - 1] if extension(name) else ""
    return bool(extension(name)) and bool(stem.strip(". ")) and not name.startswith(".")


def disguised_executable(name: str) -> bool:
    """True for `invoice.pdf.exe`: a document extension immediately followed by an executable one."""
    parts = name.lower().rsplit(".", 2)
    return len(parts) == 3 and bool(parts[0].strip()) and parts[1] in DOCUMENT_EXTENSIONS and parts[2] in EXECUTABLE_EXTENSIONS
