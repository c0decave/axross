"""A flash meter after WCAG 2.3.1 / 2.3.2: frames in, the most transitions
in any second over any area that counts (the reading of axross-amp's own
meter, its primary one, in numpy).

- Each pixel's relative luminance (sRGB made linear, then Y) is followed in
  time: a *transition* is a change of at least 0.1 from its last highest to
  a lowest (or back) with the darker below 0.8.
- The area: a quarter of WCAG's 10 degree field - a third of the picture
  each way (the picture taken as the whole screen: the face full screen,
  the strictest case), slid over it in twelfths. A field *transits* when,
  within 34 ms, the pixels transiting in it the same way (all brightening,
  or all darkening) cover a quarter of it - each rise of that over the
  quarter the other way from the field's last transition (a flash is a pair
  of opposing changes).
- Red: likewise in (R - G - B) x 320 of saturated red pixels (R over
  R + G + B at least 0.8, linear), a change of at least 20.

WCAG allows three flashes - six transitions - in any second.
"""

from __future__ import annotations

import numpy as np

ALLOWED = 6

_LEVELS = np.arange(256, dtype=np.float64) / 255.0
_LINEAR = np.where(_LEVELS <= 0.04045, _LEVELS / 12.92,
                   ((_LEVELS + 0.055) / 1.055) ** 2.4).astype(np.float32)


class _Tracks:
    """Every pixel's transitions of one quantity."""

    def __init__(self, step: float, darker: float | None) -> None:
        self.step, self.darker = step, darker
        self.extreme = None
        self.direction = None

    def push(self, value: np.ndarray) -> np.ndarray:
        if self.extreme is None:
            self.extreme = value.copy()
            self.direction = np.zeros(value.shape, np.int8)
            return np.zeros(value.shape, np.int8)
        extreme, direction = self.extreme, self.direction
        further = ((direction == 1) & (value > extreme)) | ((direction == -1) & (value < extreme))
        extreme[further] = value[further]
        falls = ~further & (direction >= 0) & (extreme - value >= self.step)
        rises = ~further & (direction <= 0) & (value - extreme >= self.step) & ~falls
        out = np.zeros(value.shape, np.int8)
        if self.darker is None:
            out[falls], out[rises] = -1, 1
        else:
            out[falls & (value < self.darker)] = -1
            out[rises & (extreme < self.darker)] = 1
        direction[falls], direction[rises] = -1, 1
        extreme[falls | rises] = value[falls | rises]
        return out


class FlashMeter:
    """Frames (``(h, w, 3)`` uint8, sRGB) shown *fps* a second."""

    def __init__(self, width: int, height: int, fps: int) -> None:
        self.fps = fps
        self.at_once = max(1, round(0.034 * fps))
        fw, fh = width // 3, height // 3
        sx, sy = max(1, width // 12), max(1, height // 12)
        self.fields = [(x, y, fw, fh) for y in range(0, height - fh + 1, sy)
                       for x in range(0, width - fw + 1, sx)]
        self.frame = 0
        self._kinds = {}
        for kind, step, darker in (("luminance", 0.1, 0.8), ("red", 20.0, None)):
            self._kinds[kind] = {
                "tracks": _Tracks(step, darker),
                "at": np.full((height, width), -10 ** 9),
                "way": np.zeros((height, width), np.int8),
                "events": [[] for _ in self.fields],
                "over": [[False, False] for _ in self.fields],
                "last": [0] * len(self.fields),
            }

    def push(self, rgb: np.ndarray) -> None:
        light = _LINEAR[rgb]
        luminance = 0.2126 * light[..., 0] + 0.7152 * light[..., 1] + 0.0722 * light[..., 2]
        total = light.sum(axis=-1)
        saturated = (total > 0) & (light[..., 0] >= 0.8 * total)
        red = np.where(saturated, np.maximum(light[..., 0] - light[..., 1] - light[..., 2], 0.0)
                       * 320.0, 0.0).astype(np.float32)
        for kind, value in (("luminance", luminance), ("red", red)):
            self._push(self._kinds[kind], value)
        self.frame += 1

    def _push(self, state: dict, value: np.ndarray) -> None:
        frame = self.frame
        moved = state["tracks"].push(value)
        changed = moved != 0
        state["at"][changed] = frame
        state["way"][changed] = moved[changed]
        recent = frame - state["at"] < self.at_once
        sums = []
        for sign in (1, -1):
            area = (recent & (state["way"] == sign)).astype(np.int32)
            sums.append(np.pad(area.cumsum(0).cumsum(1), ((1, 0), (1, 0))))
        for k, (x, y, fw, fh) in enumerate(self.fields):
            quarter = fw * fh / 4
            for j, sign in enumerate((1, -1)):
                table = sums[j]
                area = table[y + fh, x + fw] - table[y, x + fw] - table[y + fh, x] + table[y, x]
                over = area >= quarter
                if over and not state["over"][k][j] and state["last"][k] != sign:
                    state["events"][k].append(frame)
                    state["last"][k] = sign
                state["over"][k][j] = over

    def worst(self, kind: str = "luminance") -> int:
        """The most transitions of *kind* in any second of any field."""
        most = 0
        for events in self._kinds[kind]["events"]:
            first = 0
            for i, frame in enumerate(events):
                while frame - events[first] >= self.fps:
                    first += 1
                most = max(most, i - first + 1)
        return most
