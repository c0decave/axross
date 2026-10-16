"""Reading, exporting and removing file metadata with the scripting API."""

from __future__ import annotations

import io
import json
import os
import tempfile
from pathlib import Path

COVERS = (
    "metadata",
    "remove_metadata",
    "export_metadata",
)


def _photo_with_metadata() -> bytes:
    """A small JPEG that carries an EXIF artist and a comment."""
    from PIL import Image

    exif = Image.Exif()
    exif[0x013B] = "Example Artist"  # Artist
    exif[0x0112] = 1  # Orientation (kept by the removal)
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (20, 120, 220)).save(
        buf, "JPEG", exif=exif.tobytes(), comment=b"example comment"
    )
    return buf.getvalue()


def run(base_dir: str | os.PathLike[str] | None = None) -> dict:
    """Read one photo's metadata, export a folder, clean it as a copy."""
    import axross

    tmp_ctx = None
    if base_dir is None:
        tmp_ctx = tempfile.TemporaryDirectory()
        root = Path(tmp_ctx.name)
    else:
        root = Path(base_dir)
        root.mkdir(parents=True, exist_ok=True)
    try:
        local = axross.localfs()
        photo = root / "photo.jpg"
        photo.write_bytes(_photo_with_metadata())

        report = axross.metadata(local, str(photo))
        artist = [f.value for f in report.fields if f.name == "Artist"]

        exported = json.loads(axross.export_metadata(local, str(root), fmt="json"))

        # mode="copy" leaves the original alone and writes photo.clean.jpg.
        results = axross.remove_metadata(local, str(photo), mode="copy")
        cleaned = axross.metadata(local, results[0].output)
        return {
            "artist": artist,
            "exported_files": len(exported["files"]),
            "status": results[0].status,
            "removable_after": cleaned.removable,
        }
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


if __name__ == "__main__":
    print(run())
