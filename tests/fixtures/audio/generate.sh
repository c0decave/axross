#!/bin/sh
# Test fixtures of tests/test_media_player.py: one second of a 440 Hz sine
# (left channel, right silent), 44.1 kHz stereo, written by Python's wave
# module, then encoded by ffmpeg (libmp3lame, libvorbis, flac).
set -eu
cd "$(dirname "$0")"
python3 - <<'PY'
import math, struct, wave
with wave.open("sine.wav", "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(44100)
    w.writeframes(b"".join(struct.pack("<hh", int(8000 * math.sin(2 * math.pi * 440 * i / 44100)), 0)
                           for i in range(44100)))
PY
ffmpeg -hide_banner -loglevel error -y -i sine.wav -codec:a libmp3lame -b:a 128k sine.mp3
ffmpeg -hide_banner -loglevel error -y -i sine.wav -codec:a libvorbis sine.ogg
ffmpeg -hide_banner -loglevel error -y -i sine.wav sine.flac
