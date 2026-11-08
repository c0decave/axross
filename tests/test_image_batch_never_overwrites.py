"""Image Batch never writes over a file in ``resized/`` (review round 2).

Before: the names already in ``resized/`` were compared case-sensitively.
On a case-insensitive file system (an SMB share, a Windows or macOS
volume) ``IMG.png`` became ``IMG.jpg``, which *is* the ``img.jpg``
written last week - and that file was overwritten. A file that came
after the listing was overwritten too. Now names are compared casefolded
and the target is checked with ``exists`` right before it is written.
"""

from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load():
    spec = importlib.util.spec_from_file_location(
        "image_batch_never_overwrites", ROOT / "resources" / "extensions" / "image_batch.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.convert = lambda data, edge, fmt, quality=88: b"NEW"
    return module


class Item:
    def __init__(self, name: str) -> None:
        self.name, self.is_dir = name, False


class CaseInsensitiveFS:
    """Files by path; a path names the same file whatever its case. With
    *hidden*, the listing of resized/ misses those files (they came after
    it, or a server does not list them)."""

    def __init__(self, files: dict[str, bytes], hidden: tuple[str, ...] = ()) -> None:
        self.files = dict(files)
        self.hidden = {h.lower() for h in hidden}

    def _key(self, path: str) -> str | None:
        return next((k for k in self.files if k.lower() == path.lower()), None)

    def join(self, *parts):
        return "/".join(parts)

    def exists(self, path):
        return self._key(path) is not None or path.lower() == "/p/resized"

    def mkdir(self, path):
        pass

    def list_dir(self, path):
        prefix = path.lower() + "/"
        return [Item(k.rsplit("/", 1)[1]) for k in self.files
                if k.lower().startswith(prefix) and k.lower() not in self.hidden]

    def open_read(self, path):
        return io.BytesIO(self.files[self._key(path)])

    def open_write(self, path):
        fs = self

        class Writer:
            def __enter__(self):
                return self

            def write(self, data):
                fs.files[fs._key(path) or path] = data

            def __exit__(self, *exc):
                return False

        return Writer()


def test_sad_a_name_differing_only_in_case_is_not_overwritten():
    IB = _load()
    fs = CaseInsensitiveFS({"/p/resized/img.jpg": b"OLD", "/p/IMG.png": b"png"})
    written, skipped = IB.run_batch(fs, "/p", ["IMG.png"], 0, "JPEG")
    assert skipped == []
    assert written == ["IMG (2).jpg"]
    assert fs.files["/p/resized/img.jpg"] == b"OLD"
    assert fs.files["/p/resized/IMG (2).jpg"] == b"NEW"


def test_edge_two_inputs_differing_only_in_case_get_two_names():
    IB = _load()
    fs = CaseInsensitiveFS({"/p/a.png": b"1", "/p/A.bmp": b"2"})
    written, _skipped = IB.run_batch(fs, "/p", ["a.png", "A.bmp"], 0, "PNG")
    assert sorted(n.casefold() for n in written) == ["a (2).png", "a.png"]


def test_sad_a_file_the_listing_did_not_show_is_not_overwritten():
    IB = _load()
    fs = CaseInsensitiveFS({"/p/resized/x.webp": b"OLD", "/p/x.png": b"png"},
                           hidden=("/p/resized/x.webp",))
    written, _skipped = IB.run_batch(fs, "/p", ["x.png"], 0, "WebP")
    assert written == ["x (2).webp"]
    assert fs.files["/p/resized/x.webp"] == b"OLD"
