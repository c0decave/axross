"""Icons and feature offers from the feature/icon/menu audit (2026-11-08).

* IRC, Matrix and XMPP all showed the same speech bubble: three chat panels
  could not be told apart in the docked-windows bar. The Work Prompts window
  borrowed the handbook's book and the MCP catalogue the generic puzzle.
* An extension's right-click entries could not have an icon
  (``add_context_action`` had no ``icon=``), so the bundled ones (Checksum,
  Backup Repositories, Entropy, Forensic, Image Batch, VirtualBox) showed
  none, unlike the windows they open.
* Help > Features… did not offer the ``chat`` extra (Matrix, XMPP) nor
  ``bluetooth-raw``; the Matrix and XMPP panels and the Bluetooth panel told
  the user to type a pip command instead.
"""

from __future__ import annotations

import ast
import os
import re
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

APP = QApplication.instance() or QApplication([])
EXTENSIONS = ROOT / "resources" / "extensions"


def _calls(path: Path, name: str) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [c for c in ast.walk(tree) if isinstance(c, ast.Call)
            and getattr(c.func, "attr", getattr(c.func, "id", "")) == name]


def _keyword(call: ast.Call, name: str):
    return next((k.value.value for k in call.keywords if k.arg == name
                 and isinstance(k.value, ast.Constant)), None)


def test_happy_each_chat_network_has_an_icon_of_its_own():
    from core import chat_irc, chat_matrix, chat_xmpp
    from ui import icon_provider as IP
    from ui.chat_panel import protocol_icon

    icons = {}
    for network in ("irc", "matrix", "xmpp"):
        (call,) = _calls(EXTENSIONS / f"{network}.py", "add_dock")
        icons[network] = _keyword(call, "icon")
    assert icons == {"irc": "irc", "matrix": "matrix", "xmpp": "xmpp"}
    drawings = {IP.ICONS[name] for name in (*icons.values(), "chat")}
    assert len(drawings) == 4  # none is the generic bubble, none another's
    for protocol in (chat_irc.PROTOCOL, chat_matrix.PROTOCOL, chat_xmpp.PROTOCOL):
        assert protocol_icon(protocol) == protocol.name
    assert protocol_icon(SimpleNamespace(name="smoke-signals")) == "chat"


def test_happy_work_prompts_and_the_mcp_catalog_have_their_own_icons():
    from ui import icon_provider as IP

    for rel, borrowed in (("ui/work_prompts_dialog.py", "book"),
                          ("ui/mcp_catalog_dialog.py", "extensions")):
        names = [c.args[1].value for c in _calls(ROOT / rel, "set_window_icon")]
        assert names and borrowed not in names, (rel, names)
        assert all(IP.has_icon(n) for n in names)


def test_sad_every_bundled_context_entry_brings_its_icon():
    from ui.icon_provider import has_icon

    missing, unknown = [], []
    for path in sorted(EXTENSIONS.rglob("*.py")):
        for call in _calls(path, "add_context_action"):
            name = _keyword(call, "icon")
            if name is None:
                missing.append(f"{path.name}:{call.lineno}")
            elif not has_icon(name):
                unknown.append(f"{path.name}:{call.lineno} {name}")
    assert missing == [] and unknown == []


def test_happy_a_context_entry_shows_its_icon_and_one_without_none(monkeypatch):
    from ui import extension_host as XH

    api = XH.ExtensionAPI(None, SimpleNamespace(module_name="t"))
    api.add_context_action("Checksums", lambda ctx: None, icon="shield")
    api.add_context_action("Plain", lambda ctx: None)
    host = SimpleNamespace(_loaded={"t": (None, api)}, is_live=lambda a: True,
                           call=lambda *a: None)
    monkeypatch.setattr(XH, "context_of", lambda pane: SimpleNamespace(items=[]))
    menu = QMenu()
    XH.ExtensionHost.add_context_actions(host, None, menu)
    entries = {a.text(): a for a in menu.actions() if not a.isSeparator()}
    assert set(entries) == {"Checksums", "Plain"}
    assert not entries["Checksums"].icon().isNull()
    assert entries["Checksums"].property("axIcon") == "shield"  # drawn again on a theme switch
    assert entries["Plain"].icon().isNull()
    menu.deleteLater()


def test_happy_features_offers_the_chat_and_bluetooth_raw_extras():
    from core import features as F

    extras = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"]["optional-dependencies"]
    by_key = {f.key: f for f in F.collect()}
    for extra in ("chat", "bluetooth-raw"):
        feature = by_key[f"extra:{extra}"]
        assert feature.pip_extra == extra and extra in extras
        assert tuple(extras[extra]) == feature.requirements


def test_sad_a_partial_chat_install_is_not_reported_as_installed(monkeypatch):
    """The chat extra is several packages: one of them missing is missing."""
    from core import features as F

    real = F._importable
    monkeypatch.setattr(F, "_importable", lambda m: m != "slixmpp" and (m in ("nio", "vodozemac",
                                                                              "omemo", "twomemo")
                                                                    or real(m)))
    chat = next(f for f in F.collect() if f.key == "extra:chat")
    assert chat.available is False


def test_sad_missing_chat_libraries_point_at_features_not_at_pip(monkeypatch):
    from core import chat_matrix, chat_xmpp

    for module in ("nio", "slixmpp"):
        monkeypatch.setitem(sys.modules, module, None)  # import fails
    # UX round 7 (L3): one separator convention - "→" in menu paths, "–" as dash.
    for text in (chat_matrix.nio_missing(), chat_xmpp.libraries_missing()):
        assert text and "Help → Features…" in text and "pip install" not in text
    source = (EXTENSIONS / "bluetooth.py").read_text(encoding="utf-8")
    assert not re.search(r"pip install", source)


def test_happy_the_chat_panel_links_what_is_missing_to_features(tmp_path, monkeypatch):
    from unittest import mock

    from core import chat_matrix
    from ui.chat_panel import ChatPanel

    monkeypatch.setattr("pathlib.Path.home", mock.MagicMock(return_value=tmp_path))
    panel = ChatPanel(chat_matrix.PROTOCOL)
    opened = []
    panel.show_missing("Matrix needs <nio>", opened.append)
    assert "&lt;nio&gt;" in panel.empty.text()  # the text is text, not markup
    panel.empty.linkActivated.emit("extra:chat")
    assert opened == ["extra:chat"]
    panel.shutdown()
    panel.deleteLater()
