"""Names from outside axross are text in every label and tooltip.

A file, track, Bluetooth device, sound card, program or share is named
by whoever made it. Qt renders a tooltip - and a label in AutoText -
as rich text when it looks like markup (``Qt.mightBeRichText``), so a
name ``<img width=4000 height=4000 src=x>`` laid a window out 4000
pixels wide and ``<b>x</b>`` restyled the text around it. The fixes
came one place at a time; this walks every label text and every tooltip
(widgets, actions, list/tree/table items) of the windows that show such
names - with markup-named fixtures - and asserts none is rendered as
markup (tests/markup_probe.py).
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.markup_probe import BOLD, BOLD_FILE, WIDE, markup_leaks, shown  # noqa: E402

APP = QApplication.instance() or QApplication([])


def assert_text_only(root, payloads=(WIDE, BOLD), *, must_show: bool = True) -> int:
    """No markup rendered under *root*; how many places show a payload as
    text (at least one when *must_show*: the names reached the window)."""
    APP.processEvents()
    leaks, seen = markup_leaks(root, payloads)
    assert not leaks, "\n".join(leaks)
    assert seen or not must_show, "the markup names never reached the window"
    return seen


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- the helper


def test_happy_plain_tooltip_shows_exactly_the_text():
    from ui.plain_text import plain_tooltip

    assert plain_tooltip("") == ""
    for text in (WIDE, BOLD, "a  b\nc & d", "&lt;b&gt;", "plain"):
        tip = plain_tooltip(text)
        assert shown(tip) == text


def test_happy_plain_message_is_plain_text():
    from PyQt6.QtWidgets import QMessageBox

    from ui.plain_text import plain_message

    box = plain_message(None, QMessageBox.Icon.Warning, "T", f"{BOLD}: refused")
    try:
        assert box.textFormat() == Qt.TextFormat.PlainText and box.text() == f"{BOLD}: refused"
    finally:
        box.deleteLater()


# --------------------------------------------------------------------------- Duplicate Finder


def test_sad_duplicate_finder(tmp_path):
    from core import cas as CAS
    from core.local_fs import LocalFS
    from unittest import mock

    with mock.patch.object(CAS, "_DEFAULT_DB", tmp_path / "cas.sqlite"):
        from ui.cas_dialog import CasDuplicatesDialog

        tree = tmp_path / WIDE
        tree.mkdir()
        for name in (WIDE, BOLD_FILE, "plain.txt"):
            (tree / name).write_bytes(b"same\n")
        fs = LocalFS()
        CAS.rebuild(fs, str(tree), backend_id="LocalFS:Local")

        class _Pane:
            backend = fs
            current_path = str(tree)

        dlg = CasDuplicatesDialog(_Pane())
        try:
            group = dlg._tree.topLevelItem(0)
            dlg._tree.setCurrentItem(group.child(0))
            assert_text_only(dlg, (WIDE, BOLD_FILE))
        finally:
            dlg.deleteLater()


# --------------------------------------------------------------------------- Media Player


def test_sad_media_player(tmp_path, monkeypatch):
    from core import audio_route as AR

    MP = _load("bundled_media_player_markup", "resources/extensions/media_player.py")
    monkeypatch.setenv("HOME", str(tmp_path))
    AR.forget()
    panel = MP.PlayerPanel(engine=MP.PendingEngine(), output_lister=list, open_mixer=lambda: None)
    try:
        panel.show()
        for name in (WIDE, BOLD_FILE):
            panel._append(str(tmp_path / f"{name}.wav"))
        bad = panel._append(str(tmp_path / f"{WIDE} broken.wav"))
        panel._current = bad
        panel._track_failed(f"{BOLD} no audio")
        panel.play_item(panel.playlist.item(0))
        assert_text_only(panel, (WIDE, BOLD_FILE, BOLD))
    finally:
        panel.close()
        panel.deleteLater()
        AR.forget()


# --------------------------------------------------------------------------- System Information


def test_sad_system_information(tmp_path):
    from core import system_info as SI
    from tests.system_info_fixture import build_laptop, fake_usage
    from ui import system_info_window as W

    root = build_laptop(tmp_path / "root")

    names = {"model", "vendor", "name", "product", "monitor", "label", "chip", "verdict",
             "manufacturer", "mapped", "driver", "technology", "reason", "title"}

    def markup(value, key=""):
        """Every name the machine reports (a disk's model, a USB product
        string, a sensor's label ...) with markup in front."""
        if isinstance(value, dict):
            return {k: markup(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [markup(v, key) for v in value]
        if isinstance(value, str) and key in names and value:
            return f"{BOLD}{WIDE} {value}"
        return value

    class MarkupInfo(SI.SystemInfo):
        """A machine whose every name is markup."""

        def gather(self, *args, **kwargs):
            report = super().gather(*args, **kwargs)
            for section in report["sections"]:
                section["data"] = markup(section["data"])
                section["reason"] = markup(section.get("reason", ""), "reason")
                for f in section["fields"]:
                    if not f["ident"]:
                        f["value"] = f"{BOLD} {f['value']}"
                for t in section["tables"]:
                    t["rows"] = [[f"{WIDE} {c} and a long tail so it gets a tooltip" if c
                                  else c for c in row] for row in t["rows"]]
            report["sections"].append(SI.unavailable("x", "Extra", f"{BOLD}: refused"))
            return report

    class _Sampler:
        def sample(self):
            return {}

    win = W.SystemInfoWindow(
        None, sampler_factory=_Sampler, interval=0.5,
        info_factory=lambda: MarkupInfo(root, usage=fake_usage, hostname=WIDE, system="Linux"))
    try:
        win.resize(1100, 760)
        win.show()
        end = 200
        while (win.report is None or not win.refresh_button.isEnabled()) and end:
            APP.processEvents()
            QApplication.instance().thread().msleep(25)
            end -= 1
        assert win.report is not None
        assert_text_only(win)
        win.show_ids.setChecked(True)  # the computer name too
        assert_text_only(win)
    finally:
        win.close()
        win.deleteLater()


# --------------------------------------------------------------------------- Bluetooth

HCI = "/org/bluez/hci0"
#: Two devices nearby named with markup: one paired and connected (an
#: audio device with services), one only seen by the scan.
BT_DEVICES = (
    ("C0:FF:EE:00:00:01", WIDE, {"Paired": True, "Connected": True, "Trusted": True,
                                 "Icon": "audio-headset", "Class": 0x240404,
                                 "UUIDs": ["0000110b-0000-1000-8000-00805f9b34fb"]}),
    ("C0:FF:EE:00:00:02", BOLD, {"on_scan": True}),
)


def _bt_path(address: str) -> str:
    return f"{HCI}/dev_{address.replace(':', '_')}"


@pytest.fixture
def bluetooth(tmp_path):
    pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")
    from bluez_testkit import FakeBluezBus, wait_until

    from core import audio_route
    from core import bluetooth as BT

    BTX = _load("bundled_bluetooth_ext_markup", "resources/extensions/bluetooth.py")
    bus = FakeBluezBus()
    bus.command("add_adapter", name="hci0", props={"Powered": True, "Alias": BOLD})
    for address, name, extra in BT_DEVICES:
        extra = dict(extra)
        on_scan = extra.pop("on_scan", False)
        spec = {"address": address,
                "props": {"Name": name, "Alias": name, "RSSI": -55, **extra}}
        if on_scan:
            spec["on_scan"] = True
        bus.command("add_device", **spec)
    client = BT.BluezClient(bus=bus.qt_connection())
    sinks = [("bluez_output.C0_FF_EE_00_00_01.1", f"{WIDE} {BOLD}"),
             ("alsa_output.pci", f"{BOLD} Built-in Audio")]
    panel = BTX.BluetoothPanel(client, sink_lister=lambda: list(sinks),
                               audio_settings_path=tmp_path / "audio.json",
                               link_settings_path=tmp_path / "bt.json")
    panel.resize(900, 420)
    panel.show()
    panel.start()
    assert wait_until(lambda: client.state == "ready")
    assert wait_until(lambda: panel._row_of(_bt_path(BT_DEVICES[0][0])) >= 0)
    try:
        yield panel, wait_until
    finally:
        panel.shutdown()
        panel.close()
        panel.deleteLater()
        bus.close()
        audio_route.forget()


def test_sad_bluetooth_panel_map_details_and_add_device(bluetooth):
    panel, wait_until = bluetooth
    connected = _bt_path(BT_DEVICES[0][0])
    panel.scan_button.click()
    assert wait_until(lambda: panel._row_of(_bt_path(BT_DEVICES[1][0])) >= 0, 5)
    panel.select_path(connected)
    panel._reconnecting(connected, 1)
    assert_text_only(panel)
    dialog = panel.open_details(connected)
    assert dialog is not None
    for tab in range(dialog.tabs.count()):
        dialog.tabs.setCurrentIndex(tab)
        assert_text_only(dialog)  # the title names the device on every tab
    dialog.close()
    add = panel.open_add_device()
    assert wait_until(lambda: add.list.count() > 0, 5)
    add.list.item(0).setSelected(True)
    assert_text_only(add, must_show=False)  # the rows' text is the name, never markup
    add.add_selected()  # "Adding <name>…", then its outcome
    assert_text_only(add)
    assert wait_until(lambda: add.finished_ok is not None, 5)
    assert_text_only(add)
    add.close()


# --------------------------------------------------------------------------- Audio Mixer


def test_sad_audio_mixer(tmp_path, monkeypatch):
    import fake_pactl as FP
    from bluez_testkit import wait_until

    from core import system_mixer as SM
    from ui import system_mixer_page as SMP

    state = FP.default_state()
    for sink, name in zip(state["sinks"], (BOLD, WIDE)):
        sink["description"] = name
        for port in sink.get("ports", []):
            port["description"] = f"{name} port"
    for source in state["sources"]:
        source["description"] = f"{BOLD} {source['description']}"
    for stream, name in zip(state["sink-inputs"] + state["source-outputs"],
                            (WIDE, BOLD, WIDE)):
        stream["properties"]["application.name"] = name
        stream["properties"]["media.name"] = f"{name} media"
    for card in state["cards"]:
        card["properties"]["device.description"] = WIDE
        for profile in card["profiles"].values():
            profile["description"] = f"{BOLD} {profile['description']}"
    paths = FP.install(tmp_path, state)
    monkeypatch.setenv("PATH", f"{paths['bin']}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_PACTL_STATE", str(paths["state"]))
    monkeypatch.setenv("FAKE_PACTL_LOG", str(paths["log"]))
    mixer = SM.SystemMixer(timeout_ms=15000)
    page = SMP.SystemMixerPage(mixer)
    try:
        page.resize(800, 700)
        page.show()
        assert wait_until(lambda: mixer.state() == SM.STATE_READY, 20), mixer.reason()
        assert wait_until(lambda: len(page.rows["outputs"]) == 2
                          and len(page.rows["cards"]) == 2, 20)
        assert_text_only(page)
    finally:
        page.shutdown()
        page.close()
        page.deleteLater()


# --------------------------------------------------------------------------- the network search


def test_sad_a_share_that_cannot_be_opened_is_named_as_text(monkeypatch):
    """Find on Network Hosts: a hit's share that cannot be opened is named
    in a message box - plain text, the share's name is the server's."""
    from types import SimpleNamespace

    from PyQt6.QtWidgets import QMessageBox, QWidget

    import core.smb_client as SMB
    from ui.main_window import MainWindow

    def refuse(*_a, **_k):
        raise OSError(f"{BOLD} logon refused")

    monkeypatch.setattr(SMB, "SmbSession", refuse)
    boxes = []

    def record(box):
        boxes.append((box.text(), box.textFormat()))
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "exec", record)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: boxes.append(
        (a[2] if len(a) > 2 else k.get("text"), Qt.TextFormat.AutoText)))
    window = QWidget()
    try:
        hit = SimpleNamespace(host=WIDE, share=BOLD, path="/x")
        login = SimpleNamespace(username="u", domain="", password="", port=445)
        MainWindow._sweep_backend(window, hit, login, lambda _s: None)
        end = 400
        while not boxes and end:
            APP.processEvents()
            QApplication.instance().thread().msleep(10)
            end -= 1
        assert boxes, "no message"
        text, fmt = boxes[0]
        assert BOLD in text and WIDE in text
        assert fmt == Qt.TextFormat.PlainText
    finally:
        window.deleteLater()
