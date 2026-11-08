#!/usr/bin/env python3
"""Short narrated videos of Help > Tours, in English and German.

Two stages, because they need different environments:

``frames``  (axross with PyQt6) starts the main window offscreen in the
            language of the video, runs every tour of ``ui.tours.TOURS``
            step by step and saves a screenshot of each step (the real
            window with the tour's spotlight and callout) plus a manifest.

``render``  (piper-tts and ffmpeg, e.g. from imageio-ffmpeg) speaks the
            narration of ``scripts/tour_narration.json`` for each step
            with the pinned Piper voices of core.voice_models and joins
            screenshots and speech into one MP4 per tour and language.

German narration marks English words with braces - ``{Transfer Dock}`` -
and the German voice says them the English way, in one voice: each word
from ``scripts/tour_pronunciation.json`` (a German spelling of the English
sound, "Pane" -> "Pejn"), any other word with English phonemes (espeak-ng
"en-us"). The spelling came out clearer: Whisper recognised 10 of 18 test
terms spelt that way, 7 of 18 as English phonemes in the German voice.

    python scripts/tour_videos.py frames --out DIR [--lang en de]
    python scripts/tour_videos.py render --frames DIR --out DIR --voices DIR
    python scripts/tour_videos.py manifest --videos DIR [--tag tour-videos-N]

``manifest`` writes ``resources/tours/tour_videos.json`` (core.tour_videos):
the release tag and each video's asset name, size and SHA-256, and copies
the videos to ``DIR/release/`` under those names - the files to attach to
that release. A new tag for every new set of videos: an axross that pinned
the old files keeps fetching them from the old release.

The videos' release must never become GitHub's "Latest" release: the
updater (core.self_update) reads ``releases/latest``, and a tag such as
``tour-videos-1`` is no version - every update check would fail. So it is
a prerelease, created with ``--latest=false``, before the app release
(docs/PACKAGING.md, "Release flow", step 7)::

    gh release create tour-videos-1 --prerelease --latest=false \
        --title "axross tour videos (tour-videos-1)" \
        --notes "The narrated videos of Help > Tours." DIR/release/*.mp4
    gh api repos/c0decave/axross/releases/latest --jq .tag_name  # still vX.Y.Z

The voices are the ones axross itself downloads (core.voice_models, SHA-256
pinned); ``--voices`` is the folder holding ``piper-de-thorsten`` and
``piper-en-ryan``. Nothing here is imported by axross at run time.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import wave
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NARRATION = ROOT / "scripts" / "tour_narration.json"
PRONUNCIATION = ROOT / "scripts" / "tour_pronunciation.json"
#: Window size of the screenshots (16:10; the handbook's small-screen size).
SIZE = (1280, 800)
#: Piper voice per language (core.voice_models ids).
VOICES = {"en": "piper-en-ryan", "de": "piper-de-thorsten"}
#: Silence after each spoken part, seconds.
PAUSE = 0.6
#: Length of the crossfade between two steps, seconds.
FADE = 0.4

_BRACED = re.compile(r"\{([^{}]+)\}")
_WORD_GAP = re.compile(r"[\s-]+")


# -- stage 1: frames ----------------------------------------------------------------------


def capture_frames(out: Path, languages: list[str]) -> Path:
    """Screenshots of every tour step per language; returns the manifest."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    sys.path.insert(0, str(ROOT))
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv[:1])
    from core import i18n

    manifest: dict = {"size": list(SIZE), "languages": {}}
    for language in languages:
        home = Path(tempfile.mkdtemp(prefix=f"axross-tour-{language}-"))
        os.environ["HOME"] = str(home)
        for var, sub in (("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"),
                         ("XDG_STATE_HOME", ".local/state"), ("XDG_CACHE_HOME", ".cache")):
            os.environ[var] = str(home / sub)
        i18n.install(language)
        demo_files(home)
        from ui.tours import TOURS

        window = first_start_window(home)
        window.show()
        _pump(app, 1.0)
        tours = []
        for tour in TOURS:
            folder = out / language / tour.id
            folder.mkdir(parents=True, exist_ok=True)
            tours.append(capture_tour(app, window, tour, folder, out))
        manifest["languages"][language] = tours
        window._quit_with_transfers = True
        window.close()
        window.deleteLater()
        _pump(app, 0.5)
    path = out / "manifest.json"
    path.write_text(json.dumps(manifest, indent=1, ensure_ascii=False), encoding="utf-8")
    return path


#: What the panes of the videos show: a home with a few everyday files
#: (an empty one showed only .cache and .config, which looked like nothing).
DEMO_TREE = {
    "Documents/report-2026.pdf": 182_000, "Documents/invoice-0815.pdf": 64_000,
    "Documents/notes.md": 2_400, "Pictures/holiday-01.jpg": 2_300_000,
    "Pictures/holiday-02.jpg": 2_100_000, "Projects/website/index.html": 5_100,
    "Projects/website/style.css": 1_800, "Music/demo.flac": 4_000_000,
    "backup.tar.gz": 12_000_000, "todo.txt": 300, "server-setup.sh": 1_200,
}


def demo_files(home: Path) -> None:
    """Fill *home* with :data:`DEMO_TREE` (sparse files of the given sizes)."""
    for rel, size in DEMO_TREE.items():
        path = home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.truncate(size)


def first_start_window(home: Path):
    """The main window as a user's first start shows it: two panes side by
    side, the source and the target pane, and the docks of a first start.
    A bare MainWindow() has one pane, so the tour steps about the target
    pane framed the wrong thing. The session and recents files are the
    ones in *home*: the window's class kept the paths of the real home,
    whose saved layout then replaced the first start's (and was
    overwritten on close)."""
    from ui.main_window import MainWindow

    config = home / ".config" / "axross"
    MainWindow._SESSION_FILE = config / "session.json"
    MainWindow._RECENTS_FILE = config / "recents.json"
    window = MainWindow()
    window._reconnect_timer.stop()
    window.resize(*SIZE)
    if not window.apply_first_start_layout():
        window.apply_layout_preset(window.FIRST_START_PRESET)
    return window


def capture_tour(app, window, tour, folder: Path, out: Path) -> dict:
    """Screenshots of each step of *tour* and of the window after it; the
    status bar starts and ends empty - the previous tour's "Tour finished"
    message stood in every frame of the next one."""
    from ui.tour_engine import TourRunner

    window.statusBar().clearMessage()
    runner = TourRunner(window, tour)
    steps = []
    if runner.start():
        seen = set()
        while runner.running and runner.index not in seen:
            seen.add(runner.index)
            _pump(app, 0.6)
            step = runner.step
            shot = folder / f"{runner.index:02d}.png"
            window.grab().save(str(shot))
            steps.append({"index": runner.index, "title": step.title,
                          "png": str(shot.relative_to(out))})
            runner.next()
        runner.end()
    window.statusBar().clearMessage()
    _pump(app, 0.3)
    first = folder / "intro.png"
    window.grab().save(str(first))
    return {"id": tour.id, "title": tour.title, "intro_png": str(first.relative_to(out)),
            "steps": steps}


def _pump(app, seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)


# -- stage 2: speech and video ------------------------------------------------------------


def speech_parts(text: str, language: str) -> list[tuple[str, str]]:
    """``[(kind, text)]``: German text split into German and braced English
    parts; English text is one part. Kinds: "native", "english"."""
    if language != "de":
        return [("native", text)]
    parts, last = [], 0
    for match in _BRACED.finditer(text):
        if match.start() > last:
            parts.append(("native", text[last:match.start()]))
        parts.append(("english", match.group(1)))
        last = match.end()
    if last < len(text):
        parts.append(("native", text[last:]))
    return [(k, t) for k, t in parts if t]


def load_respellings(language: str) -> dict[str, str]:
    """``{english word: how the voice of *language* should read it}``."""
    data = json.loads(PRONUNCIATION.read_text(encoding="utf-8"))
    return {k.lower(): v for k, v in data.get(language, {}).items()}


def english_words(part: str, respellings: dict[str, str]) -> list[tuple[str, str]]:
    """``[(kind, text)]`` for one braced English term: words with a respelling
    as "native" text, runs of the others as one "english" part."""
    out: list[tuple[str, str]] = []
    for word in _WORD_GAP.split(part.strip()):
        if not word:
            continue
        spelt = respellings.get(word.lower())
        kind, text = ("native", spelt) if spelt else ("english", word)
        if out and out[-1][0] == kind:
            out[-1] = (kind, f"{out[-1][1]} {text}")
        else:
            out.append((kind, text))
    return out


def piper_input(text: str, language: str, phonemize, respellings: dict | None = None) -> str:
    """The text Piper reads: each English word of a German text as its
    respelling, or else as ``[[ phonemes ]]``. *phonemize(lang, text)*
    returns espeak-ng phonemes as one string."""
    out = []
    for kind, part in speech_parts(text, language):
        if kind != "english":
            out.append(part)
            continue
        lead = " " if part[:1].isspace() else ""
        for sub, words in english_words(part, respellings or {}):
            if sub == "native":
                out.append(f"{lead}{words} ")
            else:
                out.append(f"{lead}[[ {phonemize('en-us', words)} ]] ")
            lead = ""
    joined = re.sub(r"\s+", " ", "".join(out)).strip()
    # no space before punctuation, after a phoneme block or a respelt word
    return re.sub(r"(\]\]|\w) ([.,;:!?])", r"\1\2", joined)


def plain_text(text: str) -> str:
    """The narration without its pronunciation marks (for subtitles)."""
    return _BRACED.sub(lambda m: m.group(1), text)


def render(frames: Path, out: Path, voices: Path, languages: list[str] | None = None) -> list[Path]:
    """One MP4 per tour and language from *frames* (stage 1) and the narration."""
    import imageio_ffmpeg
    from piper import PiperVoice
    from piper.phonemize_espeak import EspeakPhonemizer

    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    manifest = json.loads((frames / "manifest.json").read_text(encoding="utf-8"))
    narration = json.loads(NARRATION.read_text(encoding="utf-8"))["tours"]
    espeak = EspeakPhonemizer()

    def phonemize(lang: str, text: str) -> str:
        return "".join(sum(espeak.phonemize(lang, text), []))

    made = []
    for language, tours in manifest["languages"].items():
        if languages and language not in languages:
            continue
        voice_dir = voices / VOICES[language]
        onnx = next(voice_dir.glob("*.onnx"))
        voice = PiperVoice.load(str(onnx))
        respellings = load_respellings(language)
        for tour in tours:
            script = narration[tour["id"]]
            segments = [(frames / tour["intro_png"], script["intro"][language])]
            segments += [(frames / s["png"], script["steps"][s["title"]][language])
                         for s in tour["steps"]]
            segments.append((frames / tour["intro_png"], script["outro"][language]))
            target = out / language / f"{tour['id']}.mp4"
            target.parent.mkdir(parents=True, exist_ok=True)
            _render_tour(ffmpeg, voice, segments, language, phonemize, respellings, target)
            made.append(target)
            print(f"{target}  ({_duration(target, ffmpeg):.0f} s, "
                  f"{target.stat().st_size / 1e6:.1f} MB)")
    return made


def _render_tour(ffmpeg, voice, segments, language, phonemize, respellings, target: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="axross-tour-render-") as tmp:
        tmp_path = Path(tmp)
        clips = []
        for i, (png, text) in enumerate(segments):
            wav = tmp_path / f"{i:02d}.wav"
            _speak(voice, piper_input(text, language, phonemize, respellings), wav)
            seconds = _wav_seconds(wav) + PAUSE
            clip = tmp_path / f"{i:02d}.mp4"
            subprocess.run([
                ffmpeg, "-loglevel", "error", "-y", "-loop", "1", "-framerate", "25",
                "-i", str(png), "-i", str(wav), "-t", f"{seconds:.2f}",
                "-vf", f"scale={SIZE[0]}:{SIZE[1]},format=yuv420p,"
                       f"fade=t=in:st=0:d={FADE},fade=t=out:st={max(0.0, seconds - FADE):.2f}:d={FADE}",
                "-af", f"apad=pad_dur={PAUSE}",
                "-c:v", "libx264", "-preset", "slow", "-tune", "stillimage", "-crf", "28",
                "-c:a", "aac", "-b:a", "64k", "-ar", "44100", "-ac", "1", "-shortest",
                str(clip)], check=True)
            clips.append(clip)
        listing = tmp_path / "list.txt"
        listing.write_text("".join(f"file '{c}'\n" for c in clips), encoding="utf-8")
        subprocess.run([ffmpeg, "-loglevel", "error", "-y", "-f", "concat", "-safe", "0",
                        "-i", str(listing), "-c", "copy", "-movflags", "+faststart",
                        str(target)], check=True)


def _speak(voice, text: str, wav: Path) -> None:
    with wave.open(str(wav), "wb") as out:
        voice.synthesize_wav(text, out)


def _wav_seconds(wav: Path) -> float:
    with wave.open(str(wav), "rb") as w:
        return w.getnframes() / float(w.getframerate())


def _duration(path: Path, ffmpeg: str) -> float:
    probe = subprocess.run([ffmpeg, "-i", str(path)], capture_output=True, text=True)
    match = re.search(r"Duration: (\d+):(\d+):([\d.]+)", probe.stderr)
    if not match:
        return 0.0
    h, m, s = match.groups()
    return int(h) * 3600 + int(m) * 60 + float(s)


TOUR_MANIFEST = ROOT / "resources" / "tours" / "tour_videos.json"


def asset_name(language: str, tour_id: str) -> str:
    """The release asset name of one video."""
    return f"axross-tour-{language}-{tour_id}.mp4"


def write_manifest(videos: Path, tag: str, target: Path = TOUR_MANIFEST) -> dict:
    """Pin every ``videos/<lang>/<tour>.mp4`` in *target*; copy them to
    ``videos/release/`` under their asset names."""
    import hashlib
    import shutil

    release = videos / "release"
    release.mkdir(parents=True, exist_ok=True)
    pins = {}
    for mp4 in sorted(videos.glob("*/*.mp4")):
        language, tour_id = mp4.parent.name, mp4.stem
        if language == "release":
            continue
        name = asset_name(language, tour_id)
        shutil.copyfile(mp4, release / name)
        pins[f"{language}/{tour_id}"] = {
            "file": name, "size": mp4.stat().st_size,
            "sha256": hashlib.sha256(mp4.read_bytes()).hexdigest()}
    data = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
    data.update({"tag": tag, "videos": pins})
    target.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    f = sub.add_parser("frames", help="screenshots of every tour step (needs PyQt6)")
    f.add_argument("--out", type=Path, required=True)
    f.add_argument("--lang", nargs="+", default=["en", "de"])
    r = sub.add_parser("render", help="speech and video (needs piper-tts and ffmpeg)")
    r.add_argument("--frames", type=Path, required=True)
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--voices", type=Path, required=True)
    r.add_argument("--lang", nargs="+")
    m = sub.add_parser("manifest", help="pin the rendered videos in resources/tours/tour_videos.json "
                       "(their release: a prerelease, --latest=false)")
    m.add_argument("--videos", type=Path, required=True)
    m.add_argument("--tag", default="tour-videos-1")
    args = parser.parse_args(argv)
    if args.command == "frames":
        print(capture_frames(args.out, args.lang))
    elif args.command == "manifest":
        data = write_manifest(args.videos, args.tag)
        print(f"{TOUR_MANIFEST}: {len(data['videos'])} videos for release {args.tag}")
        print(f"attach them to a prerelease that never becomes Latest:\n"
              f"  gh release create {args.tag} --prerelease --latest=false "
              f"--title 'axross tour videos ({args.tag})' --notes 'The narrated videos of "
              f"Help > Tours.' {args.videos / 'release'}/*.mp4\n"
              f"  gh api repos/c0decave/axross/releases/latest --jq .tag_name  # still vX.Y.Z")
    else:
        render(args.frames, args.out, args.voices, args.lang)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
