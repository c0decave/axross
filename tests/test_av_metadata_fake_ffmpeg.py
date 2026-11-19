"""Audio/video metadata through a fake ffprobe / ffmpeg (no FFmpeg on the
test machines): the exact command lines - ``-c copy``, ``-map_metadata
-1``, ``-map_chapters -1``, data streams dropped, an audio file's cover
(an attached picture) dropped, a video's pictures kept, inputs as
``file:`` paths that never read as options - and what happens when the
tool fails or leaves metadata behind. The whole Remove Metadata flow
(in place, the original kept in the trash) runs through them too."""
from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

from core import extension_code_cache as ECC
from core import metadata_formats as MF
from core import metadata_tools as MT

_PROBE = r'''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_FF_LOG"], "a") as log:
    log.write(json.dumps(["ffprobe", *args]) + "\n")
src = args[args.index("-i") + 1]
assert src.startswith("file:"), src
path = src[len("file:"):]
side = path + ".probe.json"
if os.path.exists(side):
    sys.stdout.write(open(side).read())
else:
    sys.stdout.write(json.dumps({"format": {"format_name": "mp3"}, "streams": []}))
'''

_MPEG = r'''
import json, os, shutil, sys
args = sys.argv[1:]
with open(os.environ["FAKE_FF_LOG"], "a") as log:
    log.write(json.dumps(["ffmpeg", *args]) + "\n")
if os.environ.get("FAKE_FF_FAIL"):
    sys.stderr.write("first line\nInvalid data found when processing input\n")
    sys.exit(1)
src = args[args.index("-i") + 1][len("file:"):]
dst = args[-1]
assert dst.startswith("file:"), dst
dst = dst[len("file:"):]
assert not os.path.exists(dst)  # -n: never over a file
shutil.copyfile(src, dst)
if os.environ.get("FAKE_FF_DIRTY"):
    shutil.copyfile(src + ".probe.json", dst + ".probe.json")
'''


@pytest.fixture
def fake_ff(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("ffprobe", _PROBE), ("ffmpeg", _MPEG)):
        script = bin_dir / name
        script.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "ff.log"
    log.write_text("")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_FF_LOG", str(log))
    monkeypatch.delenv("FAKE_FF_FAIL", raising=False)
    monkeypatch.delenv("FAKE_FF_DIRTY", raising=False)

    def calls():
        return [json.loads(line) for line in log.read_text().splitlines()]

    return calls


def _media(folder: Path, name: str, probe: dict) -> Path:
    path = folder / name
    path.write_bytes(b"\x00media bytes")
    (folder / (name + ".probe.json")).write_text(json.dumps(probe))
    return path


TAGGED_AUDIO = {
    "format": {"format_name": "mp3", "duration": "1.0",
               "tags": {"artist": "Someone", "encoder": "Lavf"}},
    "streams": [
        {"index": 0, "codec_type": "audio", "codec_name": "mp3",
         "tags": {"language": "eng"}},
        {"index": 1, "codec_type": "video", "codec_name": "mjpeg", "width": 300, "height": 300,
         "disposition": {"attached_pic": 1}, "tags": {"comment": "Cover (front)"}},
    ],
    "chapters": [{"start_time": "0.0", "tags": {"title": "Intro"}}],
}


def _ffmpeg_argv(calls) -> list[str]:
    runs = [c for c in calls if c[0] == "ffmpeg"]
    assert len(runs) == 1, runs
    return runs[0][1:]


def _pairs(argv: list[str]) -> list[tuple[str, str]]:
    return list(zip(argv, argv[1:]))


def test_happy_audio_command_line(tmp_path, fake_ff):
    src = _media(tmp_path, "-song.mp3", TAGGED_AUDIO)  # a name that looks like an option
    dst = tmp_path / "out" / "clean.mp3"
    dst.parent.mkdir()
    MF.av_clean(str(src), str(dst), MF.AUDIO)
    argv = _ffmpeg_argv(fake_ff())
    pairs = _pairs(argv)
    assert ("-c", "copy") in pairs
    assert ("-map_metadata", "-1") in pairs and ("-map_chapters", "-1") in pairs
    assert ("-protocol_whitelist", "file") in pairs
    assert ("-format_whitelist", MF.FFMPEG_FORMATS) in pairs
    assert ("-i", "file:" + str(src)) in pairs
    assert argv[-1] == "file:" + str(dst) and argv[-2] == "-n"
    assert "-nostdin" in argv
    maps = [b for a, b in pairs if a == "-map"]
    assert maps == ["0", "-0:d?", "-0:v?"]  # all, but no data streams and no cover
    assert argv.index("-i") < argv.index("-map")  # the maps are of input 0
    assert dst.read_bytes() == src.read_bytes()


def test_happy_video_keeps_its_pictures(tmp_path, fake_ff):
    src = _media(tmp_path, "clip.mp4", {"format": {"format_name": "mov,mp4"}, "streams": []})
    dst = tmp_path / "clean.mp4"
    MF.av_clean(str(src), str(dst), MF.VIDEO)
    maps = [b for a, b in _pairs(_ffmpeg_argv(fake_ff())) if a == "-map"]
    assert maps == ["0", "-0:d?"]  # a video's video streams are its content


def test_happy_the_cover_is_removable_in_audio_only(tmp_path, fake_ff):
    src = _media(tmp_path, "song.mp3", TAGGED_AUDIO)
    fields, error, _ = MF.av_fields(str(src), MF.AUDIO)
    assert not error
    by_name = {(f.group, f.name): f for f in fields}
    assert by_name[("Stream 1", "attached picture")].removable
    assert by_name[("Tags", "artist")].removable
    assert not by_name[("Tags", "encoder")].removable  # Lavf: the remux's own
    assert not by_name[("Stream 0", "language")].removable
    assert by_name[("Chapters", "chapter 1")].value == "Intro"
    fields, _, _ = MF.av_fields(str(src), MF.VIDEO)
    assert not {(f.group, f.name): f for f in fields}[("Stream 1", "attached picture")].removable
    probe = [c for c in fake_ff() if c[0] == "ffprobe"][0][1:]
    assert ("-protocol_whitelist", "file") in _pairs(probe)
    assert probe[-2:] == ["-i", "file:" + str(src)]


def test_sad_metadata_left_behind_is_an_error(tmp_path, fake_ff, monkeypatch):
    monkeypatch.setenv("FAKE_FF_DIRTY", "1")
    src = _media(tmp_path, "song.mp3", TAGGED_AUDIO)
    with pytest.raises(MF.FormatError, match="left metadata behind"):
        MF.av_clean(str(src), str(tmp_path / "clean.mp3"), MF.AUDIO)


def test_sad_ffmpeg_failing_says_its_last_line(tmp_path, fake_ff, monkeypatch):
    monkeypatch.setenv("FAKE_FF_FAIL", "1")
    src = _media(tmp_path, "song.mp3", TAGGED_AUDIO)
    with pytest.raises(MF.FormatError, match="ffmpeg: Invalid data found"):
        MF.av_clean(str(src), str(tmp_path / "clean.mp3"), MF.AUDIO)


@pytest.fixture
def home(tmp_path, monkeypatch):
    real = tmp_path / "home"
    (real / ".config").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setattr(ECC, "_SECRET", [], raising=False)
    return real


def test_happy_remove_in_place_keeps_the_original_in_the_trash(home, fake_ff):
    from core import trash as T
    from core.local_fs import LocalFS
    from core.security_mode import current_policy

    if not current_policy().allow_auto_preview:
        pytest.skip("this security mode runs no ffmpeg")
    folder = home / "music"
    folder.mkdir()
    src = _media(folder, "song.mp3", TAGGED_AUDIO)
    os.chmod(src, 0o640)
    before = src.read_bytes()
    result = MT.remove_metadata(LocalFS(), str(src), mode=MT.MODE_IN_PLACE)
    assert result.status == MT.CLEANED, result.error
    assert result.output == str(src) and result.trash_id
    assert stat.S_IMODE(os.stat(src).st_mode) == 0o640
    entries = [e for e in T.list_trash(LocalFS()) if e.trash_id == result.trash_id]
    assert entries and entries[0].original_path == str(src)
    assert (home / T.TRASH_DIRNAME / result.trash_id).read_bytes() == before


def test_sad_remove_with_a_failing_ffmpeg_leaves_the_file(home, fake_ff, monkeypatch):
    from core.local_fs import LocalFS
    from core.security_mode import current_policy

    if not current_policy().allow_auto_preview:
        pytest.skip("this security mode runs no ffmpeg")
    monkeypatch.setenv("FAKE_FF_FAIL", "1")
    folder = home / "music"
    folder.mkdir()
    src = _media(folder, "song.mp3", TAGGED_AUDIO)
    before = src.read_bytes()
    result = MT.remove_metadata(LocalFS(), str(src), mode=MT.MODE_IN_PLACE)
    assert result.status == MT.ERROR and "Invalid data" in result.error
    assert src.read_bytes() == before
    assert sorted(os.listdir(folder)) == ["song.mp3", "song.mp3.probe.json"]
