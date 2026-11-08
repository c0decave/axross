"""Folder Treemap stops its walks when it is switched off or reloaded
(review round 2).

Before: the extension had no ``deactivate``. A walk only learnt it was
stale from a newer walk, so after Extensions > Manage > off (or Reload) a
walk of a large remote folder went on listing it - up to 20,000 round
trips - for an extension that was gone. Now ``deactivate`` makes every
running walk stale; it stops at its next listing.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from tests.test_folder_treemap_markdown_stale import Api, Ctx, Tree, _load  # noqa: E402


class Slow(Tree):
    def list_dir(self, path):
        time.sleep(0.002)
        return super().list_dir(path)


def test_sad_a_running_walk_stops_when_the_extension_is_switched_off():
    FT = _load("folder_treemap")
    api = Api()
    FT.activate(api)
    tree = Slow()
    api.handlers["path_changed"][0](Ctx(tree, "/srv/big"))
    worker = threading.Thread(target=api.run, args=(0,), daemon=True)
    worker.start()
    time.sleep(0.1)
    FT.deactivate(api)
    worker.join(2)
    assert not worker.is_alive(), "the walk goes on after the extension was switched off"
    assert tree.listings < 200


def test_edge_an_event_after_deactivate_starts_no_walk():
    """A path change that reaches the old module late starts nothing."""
    FT = _load("folder_treemap")
    api = Api()
    FT.activate(api)
    FT.deactivate(api)
    tree = Tree()
    api.handlers["path_changed"][0](Ctx(tree, "/srv/late"))
    assert api.jobs == []
    assert tree.listings == 0
