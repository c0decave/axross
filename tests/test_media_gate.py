"""A local video is probed in a separate process before Qt Multimedia opens it.

Qt Multimedia's FFmpeg backend demuxes and decodes inside axross: a file
that crashes FFmpeg's demuxer or a codec's start takes the whole program
down. Before the media viewer hands a video to QMediaPlayer, ffprobe (when
installed) opens it in a child with a time bound; a file whose probe crashes
or hangs is refused with the reason. A probe that merely cannot read the
file refuses nothing (Qt says why itself), nor does a missing ffprobe.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import media_gate as MG  # noqa: E402
from core import metadata_formats as MF  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the fake ffprobe is a sh script")


@pytest.fixture(autouse=True)
def _fresh_cache():
    MG.forget()
    yield
    MG.forget()


@pytest.fixture
def fake_ffprobe(monkeypatch, tmp_path):
    """ffprobe as a sh script with *body*; its calls are counted in a file."""

    def use(body: str) -> Path:
        calls = tmp_path / "calls"
        script = tmp_path / "ffprobe"
        script.write_text(f'#!/bin/sh\necho "$@" >> "{calls}"\n{body}\n')
        script.chmod(0o755)
        monkeypatch.setattr(MF, "ffprobe_path", lambda: str(script))
        return calls

    return use


def _video(tmp_path: Path, name: str = "v.mp4") -> Path:
    path = tmp_path / name
    path.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 100)
    return path


def test_happy_a_file_the_probe_reads_is_played(fake_ffprobe, tmp_path):
    calls = fake_ffprobe('echo \'{"format": {"format_name": "mov,mp4"}}\'; exit 0')
    assert MG.probe_refusal(str(_video(tmp_path))) is None
    argv = calls.read_text().split()
    assert "-protocol_whitelist" in argv and argv[argv.index("-protocol_whitelist") + 1] == "file"
    assert any(a.startswith("file:") for a in argv)


def test_sad_a_file_that_crashes_the_probe_is_refused(fake_ffprobe, tmp_path):
    fake_ffprobe("kill -SEGV $$")
    reason = MG.probe_refusal(str(_video(tmp_path)))
    assert reason is not None and "crash" in reason


def test_sad_a_file_that_hangs_the_probe_is_refused_in_time(fake_ffprobe, monkeypatch, tmp_path):
    monkeypatch.setattr(MG, "PROBE_SECONDS", 1.0)
    fake_ffprobe("exec sleep 30")
    started = time.monotonic()
    reason = MG.probe_refusal(str(_video(tmp_path)))
    assert time.monotonic() - started < 6
    assert reason is not None and "1 s" in reason


def test_sad_the_media_viewer_refuses_a_video_whose_probe_crashes(fake_ffprobe, tmp_path):
    from core import media_load as ML
    from core.local_fs import LocalFS
    from core.media_collect import VIDEO, MediaItem

    fake_ffprobe("kill -SEGV $$")
    path = _video(tmp_path)
    st = path.stat()
    item = MediaItem(path=str(path), name=path.name, kind=VIDEO, size=st.st_size,
                     mtime=st.st_mtime, folder="")
    with pytest.raises(ML.MediaUnavailable) as caught:
        ML.prepare(LocalFS(), item, cancel=threading.Event())
    assert "crash" in str(caught.value)


def test_edge_a_probe_that_cannot_read_the_file_refuses_nothing(fake_ffprobe, tmp_path):
    fake_ffprobe("echo 'Invalid data found' >&2; exit 1")
    assert MG.probe_refusal(str(_video(tmp_path))) is None


def test_edge_without_ffprobe_the_file_is_played_as_before(monkeypatch, tmp_path):
    monkeypatch.setattr(MF, "ffprobe_path", lambda: None)
    assert MG.probe_refusal(str(_video(tmp_path))) is None


def test_edge_the_same_file_is_probed_once(fake_ffprobe, tmp_path):
    calls = fake_ffprobe("exit 0")
    path = str(_video(tmp_path))
    MG.probe_refusal(path)
    MG.probe_refusal(path)
    assert len(calls.read_text().splitlines()) == 1
    # changed: probed again
    Path(path).write_bytes(b"other" * 50)
    MG.probe_refusal(path)
    assert len(calls.read_text().splitlines()) == 2
