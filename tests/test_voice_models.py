"""Voices and the Whisper model (core.voice_models): pinned URLs and
SHA-256 sums, an atomic download into ~/.local/share/axross/voice/ that
refuses a mismatch."""

from __future__ import annotations

import hashlib
import io
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import voice_models as VM  # noqa: E402


def _model(tmp_files: dict[str, bytes], *, bad: str = "") -> VM.VoiceModel:
    files = tuple(
        VM.ModelFile(name, f"https://example.invalid/{name}",
                     "0" * 64 if name == bad else hashlib.sha256(data).hexdigest(), len(data))
        for name, data in tmp_files.items()
    )
    return VM.VoiceModel("test-model", "Test", "voice", "de", "male", files)


class _Opener:
    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.payloads = payloads
        self.urls: list[str] = []

    def __call__(self, url, timeout=None):
        self.urls.append(url)
        return io.BytesIO(self.payloads[url.rsplit("/", 1)[1]])


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    return tmp_path / "share" / "axross" / "voice"


# -- the catalogue -------------------------------------------------------------------------


def test_happy_every_model_is_pinned_to_https_and_a_sha256():
    assert {m.id for m in VM.MODELS} >= {"piper-de-thorsten", "piper-de-kerstin", "piper-en-ryan",
                                         "piper-en-lessac", "whisper-base", "whisper-small"}
    for model in VM.MODELS:
        assert model.files, model.id
        for f in model.files:
            assert f.url.startswith("https://huggingface.co/"), f.url
            assert "/resolve/main/" not in f.url, "pin a commit, not a branch"
            assert len(f.sha256) == 64 and int(f.sha256, 16) >= 0
            assert f.size > 0


def test_happy_each_voice_has_its_onnx_and_config():
    for model in VM.MODELS:
        if model.kind == "voice":
            names = [f.name for f in model.files]
            assert any(n.endswith(".onnx") for n in names)
            assert any(n.endswith(".onnx.json") for n in names)


def test_edge_ids_are_unique_and_lookup_works():
    ids = [m.id for m in VM.MODELS]
    assert len(ids) == len(set(ids))
    assert VM.model("whisper-base").kind == "whisper"
    assert VM.model("nope") is None


def test_happy_data_dir_follows_xdg(data_dir):
    assert VM.data_dir() == data_dir


def test_edge_data_dir_without_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert VM.data_dir() == tmp_path / ".local" / "share" / "axross" / "voice"


# -- download ------------------------------------------------------------------------------


def test_happy_download_verifies_and_installs(data_dir):
    files = {"a.onnx": b"x" * 5000, "a.onnx.json": b"{}"}
    model = _model(files)
    seen = []
    path = VM.download(model, opener=_Opener(files), progress=lambda done, total: seen.append(
        (done, total)))
    assert path == data_dir / "test-model"
    assert (path / "a.onnx").read_bytes() == files["a.onnx"]
    assert VM.installed(model)
    assert seen[-1] == (5002, 5002)
    assert not [p for p in data_dir.iterdir() if p.name.startswith(".")]


def test_sad_a_checksum_mismatch_is_refused_and_leaves_nothing(data_dir):
    files = {"a.onnx": b"x" * 10, "a.onnx.json": b"{}"}
    model = _model(files, bad="a.onnx.json")
    with pytest.raises(VM.DownloadError, match="SHA-256"):
        VM.download(model, opener=_Opener(files))
    assert not VM.installed(model)
    assert not data_dir.exists() or not any(data_dir.iterdir())


def test_sad_more_bytes_than_pinned_are_refused(data_dir):
    files = {"a.onnx": b"x" * 10}
    model = _model(files)
    with pytest.raises(VM.DownloadError, match="larger"):
        VM.download(model, opener=_Opener({"a.onnx": b"x" * 11}))
    assert not VM.installed(model)


def test_sad_fewer_bytes_than_pinned_are_refused(data_dir):
    files = {"a.onnx": b"x" * 10}
    with pytest.raises(VM.DownloadError):
        VM.download(_model(files), opener=_Opener({"a.onnx": b"x" * 9}))


def test_sad_a_non_https_url_is_refused(data_dir):
    model = VM.VoiceModel("m", "M", "voice", "de", "male",
                          (VM.ModelFile("a", "http://example.invalid/a", "0" * 64, 1),))
    with pytest.raises(VM.DownloadError, match="https"):
        VM.download(model, opener=_Opener({"a": b"x"}))


def test_sad_a_network_error_is_a_download_error(data_dir):
    def opener(url, timeout=None):
        raise OSError("no route to host")

    with pytest.raises(VM.DownloadError, match="no route"):
        VM.download(_model({"a.onnx": b"x"}), opener=opener)
    assert not data_dir.exists() or not any(data_dir.iterdir())


def test_edge_cancel_stops_and_leaves_nothing(data_dir):
    cancel = threading.Event()
    cancel.set()
    files = {"a.onnx": b"x" * 10}
    with pytest.raises(VM.DownloadCancelled):
        VM.download(_model(files), opener=_Opener(files), cancel=cancel)
    assert not data_dir.exists() or not any(data_dir.iterdir())


def test_edge_a_broken_old_install_is_replaced(data_dir):
    files = {"a.onnx": b"good"}
    model = _model(files)
    old = data_dir / "test-model"
    old.mkdir(parents=True)
    (old / "a.onnx").write_bytes(b"bad!")
    (old / "stale.txt").write_text("x")
    VM.download(model, opener=_Opener(files))
    assert (old / "a.onnx").read_bytes() == b"good"
    assert not (old / "stale.txt").exists()


def test_edge_installed_checks_the_size_of_every_file(data_dir):
    files = {"a.onnx": b"good", "a.onnx.json": b"{}"}
    model = _model(files)
    VM.download(model, opener=_Opener(files))
    (data_dir / "test-model" / "a.onnx.json").write_bytes(b"{} ")
    assert not VM.installed(model)
    os.remove(data_dir / "test-model" / "a.onnx.json")
    assert not VM.installed(model)


def test_happy_paths_of_an_installed_voice(data_dir):
    files = {"v.onnx": b"m", "v.onnx.json": b"{}"}
    model = _model(files)
    VM.download(model, opener=_Opener(files))
    onnx, config = VM.voice_paths(model)
    assert onnx.name == "v.onnx" and config.name == "v.onnx.json"
