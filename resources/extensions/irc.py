"""IRC: a panel with your IRC networks, their channels and private
conversations (core.chat_irc, ui/chat_panel.py).

TLS with the certificate checked by default (a self-signed server is
trusted by its pinned fingerprint), SASL SCRAM-SHA-256 / PLAIN / EXTERNAL
login, NickServ, channels with topic and members, /me, notices, nick
completion with Tab, /commands (/help lists them), reconnect with the
channels rejoined; a conversation opens in a window of its own with
*Window*. IRC has no end-to-end encryption - the panel says so.
"""

from __future__ import annotations

from core import chat_irc
from core.i18n import tr
from ui.chat_panel import ChatPanel

EXTENSION = {
    "name": "IRC",
    "version": "1.0",
    "description": "An IRC client: networks, channels and private messages in a panel, "
    "TLS with certificate pinning and SASL login.",
    "author": "axross",
}

_PANELS: list[ChatPanel] = []


def activate(api):
    panel = ChatPanel(chat_irc.PROTOCOL)
    panel.attention.connect(api.notify)
    _PANELS.append(panel)
    api.add_dock(tr("IRC"), panel, icon="irc")
    panel.connect_autostart()


def deactivate(api):
    while _PANELS:
        _PANELS.pop().shutdown()
