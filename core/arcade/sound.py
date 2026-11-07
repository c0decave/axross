"""The Arcade's sounds, synthesised at run time - no sample, no recording,
nothing taken from anywhere: oscillators (square, pulse, triangle, saw,
sine, noise), pitch sweeps, an ADSR envelope, vibrato, a one-pole low-pass
per voice (raw squares at 22 kHz are harsh: a cutoff a few octaves above
the note makes them round) and a feedback echo, rendered to 16-bit mono
PCM. Effects are recipes (:data:`EFFECTS`), each game's title jingle
among them; each world's music is composed from its seed
(:func:`compose`): a chord progression of the world's scale, a bass line,
arpeggios, a melody built from a motif that is repeated and varied, and a
drum kit made of noise and a falling sine - so every tune is axross's own.

Loops are seamless: the tails of notes that ring past the loop's end are
folded back onto its start (:func:`render_tune`).

Qt-free: :func:`render` gives bytes, :func:`wav` a WAV file's bytes; the
window plays them on the Audio Mixer's "Arcade" channel (ui/arcade_audio.py).
"""

from __future__ import annotations

import array
import io
import math
import random
import struct
import wave
from dataclasses import dataclass, field

RATE = 22050


@dataclass(frozen=True)
class Voice:
    wave: str = "square"            # square | pulse | triangle | saw | sine | noise
    freq: float = 440.0
    freq_end: float | None = None   # a sweep to this frequency
    duration: float = 0.2
    attack: float = 0.005
    decay: float = 0.05
    sustain: float = 0.6
    release: float = 0.05
    volume: float = 0.5
    duty: float = 0.5               # square / pulse
    duty_end: float | None = None   # pulse: the duty sweeps to this
    vibrato: float = 0.0            # depth in semitones
    vibrato_rate: float = 6.0
    delay: float = 0.0              # start offset inside the effect
    cutoff: float = 0.0             # low-pass in Hz (0: none)


@dataclass(frozen=True)
class Effect:
    voices: tuple[Voice, ...]
    echo: float = 0.0               # 0 .. 0.6, feedback of a 90 ms echo


def _osc(kind: str, phase: float, duty: float, rng: random.Random) -> float:
    p = phase % 1.0
    if kind in ("square", "pulse"):
        return 1.0 if p < duty else -1.0
    if kind == "triangle":
        return 4.0 * p - 1.0 if p < 0.5 else 3.0 - 4.0 * p
    if kind == "saw":
        return 2.0 * p - 1.0
    if kind == "sine":
        return math.sin(2 * math.pi * p)
    return rng.uniform(-1.0, 1.0)


def _env(t: float, v: Voice) -> float:
    if t < v.attack:
        return t / v.attack if v.attack else 1.0
    t -= v.attack
    if t < v.decay:
        return 1.0 - (1.0 - v.sustain) * (t / v.decay if v.decay else 1.0)
    hold = v.duration - v.attack - v.decay - v.release
    t -= v.decay
    if t < hold:
        return v.sustain
    t -= max(hold, 0.0)
    return max(0.0, v.sustain * (1.0 - t / v.release)) if v.release else 0.0


def _add_voice(buf: list, v: Voice, rate: int, rng: random.Random) -> None:
    """Mix one voice into *buf* (floats). The inner loop is plain Python;
    it avoids per-sample calls where it can."""
    start = int(v.delay * rate)
    count = min(int(v.duration * rate), len(buf) - start)
    if count <= 0:
        return
    f0 = v.freq
    df = 0.0 if v.freq_end is None else (v.freq_end - v.freq) / max(count - 1, 1)
    duty0 = v.duty
    dduty = 0.0 if v.duty_end is None else (v.duty_end - v.duty) / max(count - 1, 1)
    alpha = 1.0 - math.exp(-2 * math.pi * v.cutoff / rate) if v.cutoff else 0.0
    vib, vib_w = v.vibrato, 2 * math.pi * v.vibrato_rate / rate
    vol = v.volume
    kind = v.wave
    two_pi = 2 * math.pi
    inv_rate = 1.0 / rate
    phase = 0.0
    y = 0.0
    noise_hold, noise_value = 0, 0.0
    attack_n = max(1, int(v.attack * rate))
    decay_n = int(v.decay * rate)
    release_n = int(v.release * rate)
    hold_end = max(attack_n + decay_n, count - release_n)
    sustain = v.sustain
    for i in range(count):
        f = f0 + df * i
        if vib:
            f *= 2 ** (vib * math.sin(vib_w * i) / 12)
        phase += f * inv_rate
        if kind == "noise":
            # sample-and-hold noise: its "pitch" is how often it changes
            noise_hold -= 1
            if noise_hold <= 0:
                noise_value = rng.uniform(-1.0, 1.0)
                noise_hold = max(1, int(rate / max(f, 1.0)))
            s = noise_value
        elif kind == "sine":
            s = math.sin(two_pi * phase)
        else:
            p = phase % 1.0
            if kind == "triangle":
                s = 4.0 * p - 1.0 if p < 0.5 else 3.0 - 4.0 * p
            elif kind == "saw":
                s = 2.0 * p - 1.0
            else:
                s = 1.0 if p < duty0 + dduty * i else -1.0
        if alpha:
            y += alpha * (s - y)
            s = y
        if i < attack_n:
            e = i / attack_n
        elif i < attack_n + decay_n:
            e = 1.0 - (1.0 - sustain) * (i - attack_n) / decay_n
        elif i < hold_end:
            e = sustain
        else:
            e = sustain * max(0.0, 1.0 - (i - hold_end) / max(release_n, 1))
        buf[start + i] += s * e * vol


def _render_float(effect: Effect, rate: int, extra: float = 0.0) -> list:
    length = max((v.delay + v.duration for v in effect.voices), default=0.0)
    if effect.echo:
        length += 0.09 * 3                      # room for the echo to ring out
    n = int((length + extra) * rate) + 1
    buf = [0.0] * n
    rng = random.Random(1234)
    for v in effect.voices:
        _add_voice(buf, v, rate, rng)
    if effect.echo:
        lag = int(0.09 * rate)
        fb = effect.echo
        for j in range(lag, n):
            buf[j] += buf[j - lag] * fb
    return buf


def _to_pcm(buf: list, peak_to: int = 29000) -> bytes:
    # every effect to the same peak: how loud it plays is the mixer's gain
    peak = max((abs(x) for x in buf), default=0.0) or 1.0
    k = peak_to / peak
    pcm = array.array("h", (int(max(-peak_to, min(peak_to, x * k))) for x in buf))
    if pcm.itemsize != 2:
        raise RuntimeError("16-bit samples needed")
    return pcm.tobytes() if struct.pack("=h", 1) == struct.pack("<h", 1) else _swap(pcm)


def render(effect: Effect, rate: int = RATE) -> bytes:
    """16-bit little-endian mono PCM of *effect*."""
    return _to_pcm(_render_float(effect, rate))


def _swap(pcm: array.array) -> bytes:
    pcm.byteswap()
    return pcm.tobytes()


def wav(pcm: bytes, rate: int = RATE) -> bytes:
    out = io.BytesIO()
    with wave.open(out, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)
    return out.getvalue()


def _v(**kw) -> Voice:
    return Voice(**kw)


def _hz(note: int) -> float:
    return 440.0 * 2 ** ((note - 69) / 12)


def _notes(notes, *, wave="pulse", step=0.09, length=0.11, volume=0.3, cutoff=3200.0, duty=0.3, **kw):
    """A run of MIDI notes, one every *step* seconds."""
    return tuple(_v(wave=wave, freq=_hz(n), duration=length, delay=i * step, volume=volume, cutoff=cutoff,
                    duty=duty, **kw) for i, n in enumerate(notes))


#: The game sounds. Names are what the games' events are called.
EFFECTS: dict[str, Effect] = {
    # maze games
    "bit": Effect((_v(wave="pulse", freq=1046, freq_end=1568, duration=0.045, volume=0.25, duty=0.25,
                      cutoff=5200, release=0.02),
                   _v(wave="sine", freq=2093, duration=0.03, delay=0.018, volume=0.12))),
    "key": Effect(_notes((72, 76, 79, 84), step=0.05, length=0.09, volume=0.32, cutoff=4200)
                  + (_v(wave="sine", freq=_hz(96), duration=0.25, delay=0.2, volume=0.18, release=0.2),),
                  echo=0.3),
    "daemon": Effect((_v(wave="saw", freq=220, freq_end=1760, duration=0.22, volume=0.35, vibrato=1.2,
                         cutoff=3000),
                      _v(wave="sine", freq=1760, freq_end=2637, duration=0.12, delay=0.18, volume=0.25)),
                     echo=0.25),
    "caught": Effect((_v(wave="triangle", freq=784, freq_end=98, duration=0.75, volume=0.5, vibrato=0.9,
                         vibrato_rate=9, release=0.25),
                      _v(wave="pulse", freq=392, freq_end=49, duration=0.6, volume=0.2, duty=0.4,
                         duty_end=0.1, cutoff=1400),
                      _v(wave="noise", freq=900, freq_end=120, duration=0.3, delay=0.45, volume=0.15,
                         cutoff=1800))),
    "jump": Effect((_v(wave="pulse", freq=330, freq_end=880, duration=0.13, volume=0.3, duty=0.2,
                       duty_end=0.45, cutoff=3500),
                    _v(wave="triangle", freq=880, freq_end=523, duration=0.14, delay=0.13, volume=0.22))),
    "level": Effect(_notes((72, 76, 79, 84, 79, 88), step=0.085, length=0.12, volume=0.3, cutoff=3800)
                    + (_v(wave="triangle", freq=_hz(48), duration=0.6, volume=0.3, release=0.3),),
                    echo=0.35),
    "extra-life": Effect(_notes((79, 83, 86, 91), wave="triangle", step=0.07, length=0.1, volume=0.4,
                                cutoff=0), echo=0.3),
    # cave game
    "dig": Effect((_v(wave="noise", freq=3200, freq_end=900, duration=0.06, volume=0.22, release=0.03,
                      cutoff=2600),
                   _v(wave="sine", freq=160, freq_end=90, duration=0.05, volume=0.12))),
    "rock": Effect((_v(wave="noise", freq=700, freq_end=180, duration=0.18, volume=0.45, release=0.1,
                       cutoff=1200),
                    _v(wave="sine", freq=90, freq_end=45, duration=0.16, volume=0.5))),
    "gem": Effect((_v(wave="triangle", freq=_hz(91), duration=0.07, volume=0.3),
                   _v(wave="triangle", freq=_hz(96), duration=0.09, delay=0.05, volume=0.25),
                   _v(wave="sine", freq=_hz(103), duration=0.18, delay=0.09, volume=0.12, release=0.15)),
                  echo=0.28),
    "exit-open": Effect(_notes((67, 72, 76, 79, 84), wave="pulse", step=0.1, length=0.2, volume=0.28,
                               vibrato=0.25, cutoff=3000) +
                        (_v(wave="triangle", freq=_hz(43), duration=0.7, volume=0.3, release=0.3),),
                        echo=0.4),
    "crushed": Effect((_v(wave="noise", freq=500, freq_end=60, duration=0.6, volume=0.6, release=0.3,
                          cutoff=1500),
                       _v(wave="saw", freq=220, freq_end=40, duration=0.6, volume=0.3, cutoff=900),
                       _v(wave="sine", freq=70, freq_end=35, duration=0.4, volume=0.5))),
    "crawler": Effect((_v(wave="noise", freq=1500, freq_end=300, duration=0.3, volume=0.4, cutoff=2400),
                       _v(wave="triangle", freq=1200, freq_end=1800, duration=0.2, delay=0.15, volume=0.3))),
    "time": Effect((_v(wave="pulse", freq=1760, duration=0.05, volume=0.25, duty=0.2, cutoff=5000),)),
    "push": Effect((_v(wave="noise", freq=400, duration=0.08, volume=0.25, cutoff=1500),)),
    # light trails
    "turn": Effect((_v(wave="pulse", freq=660, freq_end=740, duration=0.03, volume=0.15, duty=0.2, cutoff=3000),)),
    "crash": Effect((_v(wave="noise", freq=2500, freq_end=80, duration=0.9, volume=0.6, release=0.4,
                        cutoff=3000),
                     _v(wave="saw", freq=330, freq_end=30, duration=0.7, volume=0.35, cutoff=1500),
                     _v(wave="sine", freq=90, freq_end=30, duration=0.5, volume=0.4)), echo=0.3),
    "boost": Effect((_v(wave="saw", freq=150, freq_end=600, duration=0.3, volume=0.3, vibrato=0.5, cutoff=2200),
                     _v(wave="noise", freq=5000, freq_end=2000, duration=0.25, volume=0.08, cutoff=4000))),
    "round": Effect(_notes((69, 73, 76, 81), step=0.1, length=0.14, volume=0.3, cutoff=3400), echo=0.35),
    "countdown": Effect((_v(wave="sine", freq=880, duration=0.12, volume=0.35),
                         _v(wave="pulse", freq=1760, duration=0.05, volume=0.08, duty=0.25, cutoff=4000))),
    "go": Effect((_v(wave="pulse", freq=1320, duration=0.25, volume=0.32, duty=0.35, cutoff=4000),
                  _v(wave="sine", freq=660, duration=0.3, volume=0.25)), echo=0.3),
    # the picker
    "select": Effect((_v(wave="sine", freq=1175, freq_end=1319, duration=0.05, volume=0.25, release=0.03),)),
    "start": Effect(_notes((76, 83, 88), wave="triangle", step=0.06, length=0.12, volume=0.35, cutoff=0),
                    echo=0.25),
}

# --- title jingles: each game's own, under two seconds ---------------------------------------


def _jingle_chase() -> Effect:
    """Byte Chase: chirping data bits that climb into a bright chord."""
    run = _notes((60, 67, 72, 76, 79, 84, 79, 84, 88), step=0.07, length=0.07, volume=0.22, cutoff=5000,
                 duty=0.25)
    chord = tuple(_v(wave="pulse", freq=_hz(n), duration=0.75, delay=0.66, volume=0.18, duty=0.3,
                     duty_end=0.12, cutoff=3200, vibrato=0.15, release=0.4) for n in (72, 76, 79, 84))
    bass = (_v(wave="triangle", freq=_hz(36), duration=0.4, volume=0.35),
            _v(wave="triangle", freq=_hz(48), duration=0.8, delay=0.66, volume=0.35, release=0.4))
    return Effect(run + chord + bass, echo=0.25)


def _jingle_tilt() -> Effect:
    """Tilt Maze: a bouncy hop up the board, a boing, a happy landing."""
    hops = tuple(_v(wave="triangle", freq=_hz(n), freq_end=_hz(n + 7), duration=0.11, delay=i * 0.13,
                    volume=0.35) for i, n in enumerate((60, 64, 67, 72)))
    boing = (_v(wave="sine", freq=180, freq_end=620, duration=0.25, delay=0.55, volume=0.3, vibrato=2.0,
                vibrato_rate=14),)
    land = tuple(_v(wave="pulse", freq=_hz(n), duration=0.6, delay=0.85, volume=0.18, duty=0.4, cutoff=2600,
                    release=0.35) for n in (67, 72, 76))
    return Effect(hops + boing + land + (_v(wave="triangle", freq=_hz(43), duration=0.7, delay=0.85, volume=0.3,
                                            release=0.35),), echo=0.2)


def _jingle_rockfall() -> Effect:
    """Rockfall: a rumble, three stones landing, a crystal chime."""
    rumble = (_v(wave="noise", freq=260, freq_end=90, duration=0.9, volume=0.35, cutoff=600, attack=0.2,
                 release=0.3),)
    thuds = tuple(v for i in range(3) for v in (
        _v(wave="sine", freq=110, freq_end=40, duration=0.18, delay=0.3 + i * 0.2, volume=0.55),
        _v(wave="noise", freq=900, freq_end=200, duration=0.1, delay=0.3 + i * 0.2, volume=0.2, cutoff=1500)))
    chime = tuple(_v(wave="triangle", freq=_hz(n), duration=0.5, delay=0.85 + i * 0.08, volume=0.22,
                     release=0.35) for i, n in enumerate((81, 88, 93, 100)))
    return Effect(rumble + thuds + chime, echo=0.3)


def _jingle_trails() -> Effect:
    """Trail Runner: an engine rising past the listener, then a hit."""
    sweep = (_v(wave="saw", freq=80, freq_end=640, duration=0.8, volume=0.3, cutoff=1800, vibrato=0.3,
                vibrato_rate=18, attack=0.1),
             _v(wave="saw", freq=81, freq_end=648, duration=0.8, volume=0.22, cutoff=2400, attack=0.1),
             _v(wave="noise", freq=6000, freq_end=1500, duration=0.7, volume=0.06, cutoff=5000, attack=0.3))
    hit = tuple(_v(wave="pulse", freq=_hz(n), duration=0.55, delay=0.82, volume=0.2, duty=0.5, duty_end=0.2,
                   cutoff=3000, release=0.3) for n in (57, 64, 69, 76))
    kick = (_v(wave="sine", freq=120, freq_end=40, duration=0.25, delay=0.8, volume=0.6),)
    return Effect(sweep + hit + kick, echo=0.3)


EFFECTS.update({"intro-chase": _jingle_chase(), "intro-tilt": _jingle_tilt(),
                "intro-rockfall": _jingle_rockfall(), "intro-trails": _jingle_trails()})


# --- music -----------------------------------------------------------------------------------

SCALES = {
    "minor": (0, 2, 3, 5, 7, 8, 10),
    "dorian": (0, 2, 3, 5, 7, 9, 10),
    "major": (0, 2, 4, 5, 7, 9, 11),
    "mixolydian": (0, 2, 4, 5, 7, 9, 10),
    "phrygian": (0, 1, 3, 5, 7, 8, 10),
}

#: Chord progressions as scale degrees (0 = the key's own chord), four bars each.
PROGRESSIONS = ((0, 5, 3, 4), (0, 3, 4, 3), (0, 6, 5, 4), (0, 2, 3, 4), (0, 3, 5, 4), (0, 5, 2, 4))
MELODY_VOLUME = 0.22


@dataclass
class Tune:
    tempo: int
    scale: str
    root: int                      # MIDI note of the key
    bars: int
    notes: list = field(default_factory=list)   # (start beat, length beats, midi note, wave, volume)


def compose(seed: int, *, bars: int = 8, mood: str = "") -> Tune:
    """A loop of *bars* bars in 4/4, composed from *seed*: a progression
    of the scale's chords (resolving to the fifth at the end, back to the
    start on the loop), a bass that walks on the beats, an arpeggio in
    eighths, a melody from a two-bar motif - repeated, moved to the next
    chord, varied - and drums."""
    rng = random.Random(seed * 7907 + 13)
    scale_name = mood or rng.choice(sorted(SCALES))
    scale = SCALES[scale_name]
    root = rng.choice((45, 47, 48, 50, 52))          # A2 .. E3
    tune = Tune(tempo=rng.randrange(112, 150), scale=scale_name, root=root, bars=bars)
    prog = list(rng.choice(PROGRESSIONS))
    degrees = [prog[b % 4] for b in range(bars)]
    degrees[-1] = 4

    def note(degree: int, octave: int = 0) -> int:
        return root + 12 * (degree // 7 + octave) + scale[degree % 7]

    # the motif: (beat, length, step from the chord's root) over two bars
    rhythm = rng.choice(((0, 1, 1.5, 2, 3), (0, 0.5, 1, 2, 2.5, 3), (0, 1.5, 2, 3, 3.5), (0, 1, 2, 2.5, 3)))
    motif = []
    for bar in range(2):
        pos = rng.choice((0, 2, 4))
        for i, beat in enumerate(rhythm):
            nxt = rhythm[i + 1] if i + 1 < len(rhythm) else 4
            motif.append((bar * 4 + beat, nxt - beat, pos))
            pos = max(-2, min(9, pos + rng.choice((-2, -1, -1, 1, 1, 2, 0))))
    arp_shape = rng.choice(((0, 1, 2, 1), (0, 2, 1, 2), (0, 1, 2, 3)))
    fill = rng.random() < 0.5
    for bar, degree in enumerate(degrees):
        chord = [degree, degree + 2, degree + 4, degree + 7]
        for beat in range(4):                         # bass: root, fifth on 3 now and then, a walk to the next
            d = degree + (4 if beat == 2 and rng.random() < 0.5 else 0)
            if beat == 3 and bar + 1 < bars and rng.random() < 0.4:
                d = degrees[bar + 1] - 1
            tune.notes.append((bar * 4 + beat, 0.85, note(d, -1), "triangle", 0.45))
        for eighth in range(8):                       # arpeggio
            d = chord[arp_shape[eighth % 4] % 4]
            tune.notes.append((bar * 4 + eighth / 2, 0.42, note(d, 1), "square", 0.12))
        half = bar % 2                                # which bar of the motif
        vary = (bar // 2) % 2 == 1                    # every second time round: the answer
        for beat, length, step in motif:              # melody: the motif on this chord
            if (beat >= 4) != bool(half):
                continue
            b = beat - 4 * half
            if vary and half and rng.random() < 0.6:
                step += rng.choice((1, -1, 2))
            if bar == bars - 1 and b >= 2:
                if b == 2:
                    tune.notes.append((bar * 4 + 2, 1.8, root + 24, "square", MELODY_VOLUME))   # home
                continue
            if rng.random() < 0.9:
                d = degree + step
                tune.notes.append((bar * 4 + b, length * 0.9, root + 24 + 12 * (d // 7) + scale[d % 7],
                                   "square", MELODY_VOLUME))
        for beat in range(4):                         # drums
            if beat in (0, 2):
                tune.notes.append((bar * 4 + beat, 0.4, 0, "kick", 0.5))
            if beat in (1, 3):
                tune.notes.append((bar * 4 + beat, 0.3, 0, "snare", 0.3))
        if fill and bar % 4 == 3:
            tune.notes.append((bar * 4 + 3.5, 0.3, 0, "snare", 0.18))
        else:
            tune.notes.append((bar * 4 + 2.5, 0.3, 0, "kick", 0.32))
        for eighth in range(8):
            tune.notes.append((bar * 4 + eighth / 2, 0.1, 0, "hat", 0.09 if eighth % 2 else 0.05))
    return tune


def _tune_voices(start: float, length: float, n: int, w: str, vol: float, beat_s: float) -> tuple:
    at, dur = start * beat_s, max(0.05, length * beat_s)
    if w == "kick":
        return (Voice(wave="sine", freq=125, freq_end=42, duration=0.16, delay=at, volume=vol, attack=0.002,
                      decay=0.1, sustain=0.2, release=0.05),)
    if w == "snare":
        return (Voice(wave="noise", freq=7000, freq_end=3000, duration=0.12, delay=at, volume=vol * 0.6,
                      attack=0.002, decay=0.05, sustain=0.3, release=0.05, cutoff=5000),
                Voice(wave="triangle", freq=200, freq_end=150, duration=0.07, delay=at, volume=vol * 0.5,
                      attack=0.002, decay=0.04, sustain=0.2, release=0.02))
    if w == "hat":
        return (Voice(wave="noise", freq=11000, duration=0.03, delay=at, volume=vol, attack=0.001, decay=0.01,
                      sustain=0.4, release=0.015),)
    if w == "triangle":                                  # the bass
        return (Voice(wave="triangle", freq=_hz(n), duration=dur, delay=at, volume=vol, attack=0.006,
                      decay=0.08, sustain=0.65, release=0.05, cutoff=1400),)
    if vol == MELODY_VOLUME:                             # the melody: rounder, a touch of vibrato
        return (Voice(wave="pulse", freq=_hz(n), duration=dur, delay=at, volume=vol, attack=0.008, decay=0.1,
                      sustain=0.55, release=0.06, duty=0.5, duty_end=0.3, vibrato=0.12, vibrato_rate=5.5,
                      cutoff=3600),)
    return (Voice(wave="pulse", freq=_hz(n), duration=dur, delay=at, volume=vol, attack=0.004, decay=0.06,
                  sustain=0.4, release=0.04, duty=0.25, cutoff=2600),)


def render_tune(tune: Tune, rate: int = RATE) -> bytes:
    beat_s = 60.0 / tune.tempo
    voices = tuple(v for start, length, n, w, vol in tune.notes
                   for v in _tune_voices(start, length, n, w, vol, beat_s))
    total = int(tune.bars * 4 * beat_s * rate)
    buf = _render_float(Effect(voices), rate, extra=0.5)
    # a seamless loop: what rings past the end is heard at the start
    out = buf[:total] + [0.0] * max(0, total - len(buf))
    for j in range(total, len(buf)):
        out[j - total] += buf[j]
    return _to_pcm(out, 26000)
