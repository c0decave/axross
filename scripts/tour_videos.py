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
and those are spoken with English phonemes (espeak-ng "en-us") by the
German voice, so IT terms keep their English pronunciation in one voice.

    python scripts/tour_videos.py frames --out DIR [--lang en de]
    python scripts/tour_videos.py render --frames DIR --out DIR --voices DIR

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
#: Window size of the screenshots (16:10; the handbook's small-screen size).
SIZE = (1280, 800)
#: Piper voice per language (core.voice_models ids).
VOICES = {"en": "piper-en-ryan", "de": "piper-de-thorsten"}
#: Silence after each spoken part, seconds.
PAUSE = 0.6
#: Length of the crossfade between two steps, seconds.
FADE = 0.4

_BRACED = re.compile(r"\{([^{}]+)\}")


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


def piper_input(text: str, language: str, phonemize) -> str:
    """The text Piper reads: English parts of a German text as ``[[ phonemes ]]``.
    *phonemize(lang, text)* returns espeak-ng phonemes as one string."""
    out = []
    for kind, part in speech_parts(text, language):
        if kind == "english":
            lead = " " if part[:1].isspace() else ""
            out.append(f"{lead}[[ {phonemize('en-us', part.strip())} ]] ")
        else:
            out.append(part)
    joined = re.sub(r"\s+", " ", "".join(out)).strip()
    return re.sub(r"\]\] ([.,;:!?])", r"]]\1", joined)  # no space before punctuation


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
        for tour in tours:
            script = narration[tour["id"]]
            segments = [(frames / tour["intro_png"], script["intro"][language])]
            segments += [(frames / s["png"], script["steps"][s["title"]][language])
                         for s in tour["steps"]]
            segments.append((frames / tour["intro_png"], script["outro"][language]))
            target = out / language / f"{tour['id']}.mp4"
            target.parent.mkdir(parents=True, exist_ok=True)
            _render_tour(ffmpeg, voice, segments, language, phonemize, target)
            made.append(target)
            print(f"{target}  ({_duration(target, ffmpeg):.0f} s, "
                  f"{target.stat().st_size / 1e6:.1f} MB)")
    return made


def _render_tour(ffmpeg, voice, segments, language, phonemize, target: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="axross-tour-render-") as tmp:
        tmp_path = Path(tmp)
        clips = []
        for i, (png, text) in enumerate(segments):
            wav = tmp_path / f"{i:02d}.wav"
            _speak(voice, piper_input(text, language, phonemize), wav)
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
    args = parser.parse_args(argv)
    if args.command == "frames":
        print(capture_frames(args.out, args.lang))
    else:
        render(args.frames, args.out, args.voices, args.lang)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
