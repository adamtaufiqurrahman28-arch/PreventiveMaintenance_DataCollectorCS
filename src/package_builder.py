from __future__ import annotations

from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile


def build_zip(files: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output.getvalue()
