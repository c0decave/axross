"""The kaleidoscope does not flash in a small face at the fastest settings.

Round 2 made the bars turn together (at most five times a second); in the
default face that kept the kaleidoscope safe. In a dock-sized face (120 x
90, 200 x 150) at 60 frames a second without smoothing a synth gated at
8 Hz still flashed it 7 and 9 times a second: its petals, orbs and spikes
follow six group means of the bars and the peak, which together turned
more often than any one bar. Those seven values now have a flash guard of
their own, three turns a second.
"""

from __future__ import annotations

import pytest

from tests.test_media_player_flash_safe import ALLOWED, RED_AND_WHITE, measure


@pytest.mark.parametrize("size", [(120, 90), (200, 150), (320, 180)])
@pytest.mark.parametrize("music, scheme", [("gate8", "classic"), ("gate8", "redwhite"),
                                           ("burst8", "classic"), ("gate10", "redwhite")])
def test_safety_the_kaleidoscope_of_a_small_face_does_not_flash(size, music, scheme):
    custom = RED_AND_WHITE if scheme == "redwhite" else None
    result = measure("kaleidoscope", 0.0, music=music, size=size, fps=60, smoothing=0,
                     scheme="custom" if custom else scheme, custom=custom)
    assert max(result) <= ALLOWED, result
