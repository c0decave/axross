"""Help > Features… lists the tools of the forensic and VirtualBox extensions
(wish-list item 12 gap).

The Forensic Tools extension runs qemu-img, The Sleuth Kit (fls, icat),
TestDisk and PhotoRec; the VirtualBox extension VBoxManage. None of them
was in the External tools group, so the Features window could not say
they were missing or how to get them. They are external programs: found on
PATH (VBoxManage also where VirtualBox puts it), installed with the
system's package manager - never pip.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import features as F  # noqa: E402

NEW = ("tool:qemu-img", "tool:sleuthkit", "tool:testdisk", "tool:virtualbox")


def _found():
    return {f.key: f for f in F.collect()}


def test_happy_the_extension_tools_are_external_tools():
    found = _found()
    assert found["tool:qemu-img"].commands == ("qemu-img",)
    assert found["tool:sleuthkit"].commands == ("fls", "icat")
    assert found["tool:testdisk"].commands == ("testdisk", "photorec")
    assert found["tool:virtualbox"].commands == ("VBoxManage",)
    for key in NEW:
        assert found[key].group == "External tools" and found[key].pip_extra is None


@pytest.mark.parametrize("key, family, command", [
    ("tool:qemu-img", "arch", "sudo pacman -S --needed qemu-img"),
    ("tool:qemu-img", "debian", "sudo apt install qemu-utils"),
    ("tool:sleuthkit", "arch", "sudo pacman -S --needed sleuthkit"),
    ("tool:sleuthkit", "fedora", "sudo dnf install sleuthkit"),
    ("tool:testdisk", "debian", "sudo apt install testdisk"),
    ("tool:virtualbox", "arch", "sudo pacman -S --needed virtualbox"),
    ("tool:virtualbox", "macos", "brew install --cask virtualbox"),
])
def test_happy_how_to_get_is_the_distro_package(key, family, command):
    assert F.how_to_get(_found()[key], family=family) == command


def test_happy_available_when_every_command_is_on_path(monkeypatch):
    on_path = {"qemu-img", "fls", "icat", "testdisk", "photorec", "VBoxManage"}
    monkeypatch.setattr(F.shutil, "which",
                        lambda cmd: f"/usr/bin/{cmd}" if cmd in on_path else None)
    found = _found()
    assert all(found[key].available for key in NEW)


def test_sad_one_missing_command_makes_the_tool_missing(monkeypatch):
    monkeypatch.setattr(F.shutil, "which", lambda cmd: "/usr/bin/fls" if cmd == "fls" else None)
    monkeypatch.setattr(F.os.path, "isfile", lambda path: False)
    found = _found()
    assert not found["tool:sleuthkit"].available  # fls without icat
    assert not any(found[key].available for key in NEW)
    for key in NEW:
        assert "axross[" not in F.how_to_get(found[key], family="arch")


def test_edge_vboxmanage_outside_path_counts_where_the_extension_finds_it(monkeypatch):
    monkeypatch.setattr(F.shutil, "which", lambda cmd: None)
    monkeypatch.setattr(F.os.path, "isfile", lambda path: path == F.VBOXMANAGE_PATHS[0])
    assert _found()["tool:virtualbox"].available
    # The same places the VirtualBox extension looks (resources/extensions/virtualbox.py).
    spec = importlib.util.spec_from_file_location(
        "vbox_ext_for_features", ROOT / "resources" / "extensions" / "virtualbox.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)  # its dataclasses look it up
    spec.loader.exec_module(module)
    assert tuple(module._KNOWN_PATHS) == F.VBOXMANAGE_PATHS


def test_edge_a_family_without_a_package_gets_the_plain_description():
    text = F.how_to_get(_found()["tool:sleuthkit"], family="windows")
    assert "fls / icat" in text and "pip" not in text


def test_e2e_the_features_window_lists_them_under_missing_only(monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from ui.features_dialog import FeaturesDialog

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(F.shutil, "which", lambda cmd: None)
    monkeypatch.setattr(F.os.path, "isfile", lambda path: False)
    dlg = FeaturesDialog()
    dlg.show()
    app.processEvents()
    try:
        dlg.missing_only.setChecked(True)
        shown = {dlg.feature_at(r).key: r for r in range(dlg.table.rowCount())}
        assert set(NEW) <= set(shown)
        dlg.table.selectRow(shown["tool:sleuthkit"])
        dlg.copy_command()
        assert QApplication.clipboard().text() == F.how_to_get(_found()["tool:sleuthkit"])
    finally:
        dlg.close()
