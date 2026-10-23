"""The VirtualBox extension (punch-list item 7).

Operator: *„rechter mausklick auf vbox files, laufernder vbox config
hinzufuegen"*; decided: ``.vbox`` -> ``VBoxManage registervm``; ``.vdi`` /
``.vmdk`` -> attach to a chosen VM.

The host has no VirtualBox: a stub ``VBoxManage`` prints what the real one
prints (``list vms``, ``showvminfo --machinereadable``, its error lines) and
logs every argument list it gets.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import extensions as EX  # noqa: E402


def load():
    path = EX.bundled_dir() / "virtualbox.py"
    spec = importlib.util.spec_from_file_location("example_virtualbox", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # as ui/extension_host.py does (dataclasses need it)
    spec.loader.exec_module(module)
    return module


VB = load()

UUID = "8a8e9b3c-1111-4222-8333-944455556666"
VMINFO = f'''name="Ubuntu Server"
UUID="{UUID}"
VMState="poweroff"
storagecontrollername0="IDE"
storagecontrollertype0="PIIX4"
storagecontrollerinstance0="0"
storagecontrollermaxportcount0="2"
storagecontrollerportcount0="2"
storagecontrollerbootable0="on"
storagecontrollername1="SATA"
storagecontrollertype1="IntelAhci"
storagecontrollerinstance1="0"
storagecontrollermaxportcount1="30"
storagecontrollerportcount1="1"
storagecontrollerbootable1="on"
"IDE-0-0"="none"
"IDE-0-1"="none"
"IDE-1-0"="emptydrive"
"IDE-1-1"="none"
"SATA-0-0"="/vms/ubuntu/disk.vdi"
"SATA-ImageUUID-0-0"="0c5e5b6f-aaaa-bbbb-cccc-dddddddddddd"
'''


@pytest.fixture
def stub(tmp_path):
    """A VBoxManage that answers like the real one and logs its argv."""
    log = tmp_path / "calls"
    info = tmp_path / "vminfo"
    info.write_text(VMINFO)
    exe = tmp_path / "VBoxManage"
    exe.write_text(f'''#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
case "$1" in
  list) printf '"Ubuntu Server" {{{UUID}}}\\n"Win 11" {{11111111-2222-3333-4444-555555555555}}\\n';;
  showvminfo) cat "{info}";;
  registervm)
    case "$2" in *broken*) echo "VBoxManage: error: Machine settings file '$2' is invalid" >&2;
      echo "VBoxManage: error: Details: code VBOX_E_FILE_ERROR" >&2; exit 1;; esac;;
  storageattach|storagectl) ;;
  *) exit 2;;
esac
''')
    exe.chmod(0o755)
    return str(exe), log


def calls(log) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


# -- happy ------------------------------------------------------------------------------


def test_happy_register_a_vbox_file(stub):
    exe, log = stub
    assert VB.register("/vms/new/new.vbox", exe) == "/vms/new/new.vbox"
    assert calls(log) == ["registervm /vms/new/new.vbox"]


def test_happy_list_and_parse_vms(stub):
    exe, _log = stub
    vms = VB.parse_vms(VB.run([exe, "list", "vms"]))
    assert vms == [("Ubuntu Server", UUID), ("Win 11", "11111111-2222-3333-4444-555555555555")]


def test_happy_parse_the_machine(stub):
    state, ctls = VB.parse_machine(VMINFO)
    assert state == "poweroff"
    ide, sata = ctls
    assert (ide.name, ide.type, ide.ports) == ("IDE", "PIIX4", 2)
    assert sata.used == {(0, 0): "/vms/ubuntu/disk.vdi"}
    # IDE: master 0-0 free; SATA: port 0 taken, one port only -> grows to 2.
    assert ide.free_slot() == (0, 0, False)
    assert sata.free_slot() == (1, 0, True)


def test_happy_attach_grows_the_sata_controller_and_attaches(stub):
    exe, log = stub
    slot = VB.attach("/data/extra.vdi", UUID, "SATA", exe)
    assert slot.startswith("SATA port 1 device 0")
    assert calls(log)[1:] == [
        f"storagectl {UUID} --name SATA --portcount 2",
        f"storageattach {UUID} --storagectl SATA --port 1 --device 0 --type hdd "
        f"--medium /data/extra.vdi",
    ]


def test_happy_the_context_actions_are_offered_for_the_right_files():
    actions = []

    class Api:
        window = None

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            actions.append((label, applies_to, extensions))

    VB.activate(Api())
    assert ("Register in VirtualBox", "single_file", (".vbox",)) in actions
    assert ("Attach to VirtualBox VM…", "single_file", VB.DISK_SUFFIXES) in actions


# -- sad --------------------------------------------------------------------------------


def test_sad_vboxmanage_errors_are_reported_readably(stub):
    exe, _log = stub
    with pytest.raises(VB.VBoxError, match="is invalid"):
        VB.register("/vms/broken.vbox", exe)


def test_sad_no_vboxmanage(monkeypatch):
    monkeypatch.setattr(VB, "vboxmanage", lambda: None)
    with pytest.raises(VB.VBoxError, match="not found"):
        VB.register("/x.vbox")
    with pytest.raises(VB.VBoxError, match="not found"):
        VB.attach("/x.vdi", UUID, "SATA")


def test_sad_an_unknown_controller(stub):
    exe, _log = stub
    with pytest.raises(VB.VBoxError, match="no controller"):
        VB.attach("/x.vdi", UUID, "SCSI", exe)


def test_sad_a_full_controller():
    ctl = VB.Controller("SATA", "IntelAhci", 1, 1, {(0, 0): "/a.vdi"})
    assert ctl.free_slot() is None
    assert VB.disk_controllers([ctl]) == []
    with pytest.raises(VB.VBoxError, match="no free port"):
        VB.attach_argvs("VBoxManage", UUID, ctl, "/x.vdi")


# -- edge -------------------------------------------------------------------------------


def test_edge_names_with_quotes_and_garbage_lines():
    text = '"My \\"VM\\"" {' + UUID + '}\nnot a vm line\n"<inaccessible>" {' + UUID + '}\n'
    assert [n for n, _u in VB.parse_vms(text)] == ['My \\"VM\\"', "<inaccessible>"]


def test_edge_a_path_with_spaces_stays_one_argument(stub):
    exe, log = stub
    VB.attach("/my disks/a b.vmdk", UUID, "IDE", exe)
    assert calls(log)[-1].endswith("--medium /my disks/a b.vmdk")
    argv = VB.attach_argvs(exe, UUID, VB.parse_machine(VMINFO)[1][0], "/my disks/a b.vmdk")
    assert argv[-1][-1] == "/my disks/a b.vmdk"


def test_edge_floppy_controllers_are_skipped():
    floppy = VB.Controller("Floppy", "I82078", 1, 1)
    assert VB.disk_controllers([floppy]) == []


def test_e2e_loads_in_the_window_and_offers_the_entries(tmp_path, monkeypatch):
    import time

    from PyQt6.QtCore import QItemSelectionModel
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    info = next(e for e in EX.discover() if e.module_name == "virtualbox")
    EX.set_enabled(info.ext_id, True)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        host = win.extension_host
        end = time.time() + 10
        while host.module(info.ext_id) is None and time.time() < end:
            app.processEvents()
        assert host.error(info.ext_id) == ""
        folder = tmp_path / "vms"
        folder.mkdir()
        for name in ("m.vbox", "d.vdi", "n.txt"):
            (folder / name).write_text("x")
        pane = win._active_pane
        pane.navigate(str(folder))

        def labels_for(name):
            pane._table.clearSelection()
            for row in range(pane._proxy.rowCount()):
                index = pane._proxy.index(row, 0)
                if index.data() == name:
                    pane._table.selectionModel().select(
                        index, QItemSelectionModel.SelectionFlag.Select
                        | QItemSelectionModel.SelectionFlag.Rows)
            return [a.text() for a in pane._build_context_menu().actions()]

        assert "Register in VirtualBox" in labels_for("m.vbox")
        assert "Attach to VirtualBox VM…" in labels_for("d.vdi")
        other = labels_for("n.txt")
        assert "Register in VirtualBox" not in other and "Attach to VirtualBox VM…" not in other
    finally:
        win.close()
        win.deleteLater()
