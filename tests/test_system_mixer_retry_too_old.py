"""Try Again after "pactl too old" checks pactl again (review round 2).

Before: the System Mixer page shows Try Again for "unavailable" and for
"too old", and the button calls ``SystemMixer.refresh()``. refresh()
retried ``start()`` only after "idle" and "unavailable": after "too old"
it did nothing, so a pactl upgraded meanwhile was never noticed until
axross restarted. Now "too old" is retried like "unavailable".
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import system_mixer as SM  # noqa: E402
from tests.test_system_mixer import (  # noqa: E402, F401 - fake, mixers: fixtures
    FP,
    fake,
    make,
    mixers,
    set_knob,
    wait_until,
)


def test_sad_try_again_after_too_old_finds_the_upgraded_pactl(fake, mixers):
    set_knob(fake, version="15.0")
    mixer, _rec = make(mixers, ready=False)
    assert wait_until(lambda: mixer.state() == SM.STATE_TOO_OLD)
    set_knob(fake, version="16.1")  # pactl was upgraded
    mixer.refresh()  # what Try Again calls
    assert wait_until(lambda: mixer.state() == SM.STATE_READY, 20), mixer.reason()
    assert FP.calls(fake["log"]).count(["--version"]) == 2
