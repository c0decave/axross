"""XMPP (Jabber): a panel with your XMPP accounts, contacts, one-to-one
chats with OMEMO end-to-end encryption, and group chats
(core.chat_xmpp, ui/chat_panel.py, ui/chat_security.py).

*Encryption…* on a chat lists the contact's OMEMO devices with their
fingerprints: mark one verified after comparing it, trust or distrust it.
New devices are trusted blindly until a device of that contact is verified
(or always asked, as the account says); a contact request is asked.
"""

from __future__ import annotations

import dataclasses

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox

from core import chat as C
from core import chat_xmpp as X
from core.i18n import tr
from ui.chat_panel import ChatPanel
from ui.chat_security import DevicesDialog
from ui.plain_text import plain_message

EXTENSION = {
    "name": "XMPP",
    "version": "1.0",
    "description": "An XMPP (Jabber) client: contacts, chats with OMEMO end-to-end encryption, "
    "group chats; TLS with certificate pinning.",
    "author": "axross",
}

_PANELS: list[ChatPanel] = []


def _wait(client: X.XmppClient, coro, timeout: float = 15.0):
    return client.runner.submit(coro).result(timeout)


def show_security(panel, client: X.XmppClient, key: str) -> None:
    if client.state != C.STATE_ONLINE:
        QMessageBox.information(panel, tr("Encryption"), tr("Connect first."))
        return
    conv = client.conversation(key)
    if conv is not None and conv.kind == C.CONV_CHANNEL:
        QMessageBox.information(panel, tr("Encryption"), tr(
            "Group chats are not end-to-end encrypted here: the room's server can read them."))
        return
    jid = key if conv is not None and conv.kind == C.CONV_DIRECT else client.jid
    own = _wait(client, client.own_device())

    def devices():
        return _wait(client, client.devices_of(jid))

    def set_trust(device, trust):
        mapping = {"verified": X.TRUST_VERIFIED, "trusted": X.TRUST_BLIND, "distrusted": X.TRUST_DISTRUSTED,
                   "undecided": X.TRUST_UNDECIDED}
        client.set_trust(device.user_id, device.identity_key, mapping[trust])

    head = tr(C.ENC_TEXT.get(conv.encryption, "")) if conv is not None else ""
    dialog = DevicesDialog(panel, tr("OMEMO - {jid}").format(jid=jid) + (f" ({head})" if head else ""), own,
                           devices, set_trust, None, fingerprint_text=lambda f: f,
                           trust_choices=("verified", "trusted", "distrusted", "undecided"))
    dialog.exec()


def handle_request(panel, client: X.XmppClient, request) -> bool:
    if isinstance(request, X.TrustRequest):
        lines = "\n".join(f"{d.device_id}: {d.fingerprint}" for d in request.devices)
        box = QMessageBox(panel)
        box.setTextFormat(Qt.TextFormat.PlainText)  # the JID is the other side's
        box.setWindowTitle(tr("New OMEMO Devices"))
        box.setText(tr("{jid} has devices nobody decided on. Messages are encrypted for them only when "
                       "you trust them.").format(jid=request.jid))
        box.setInformativeText(lines)
        verified = box.addButton(tr("I Compared Them - Verified"), QMessageBox.ButtonRole.AcceptRole)
        trust = box.addButton(tr("Trust Without Comparing"), QMessageBox.ButtonRole.YesRole)
        box.addButton(tr("Distrust"), QMessageBox.ButtonRole.RejectRole)
        box.exec()
        clicked = box.clickedButton()
        client.answer(request, "verified" if clicked is verified else clicked is trust)
        return True
    if isinstance(request, X.SubscriptionRequest):
        box = plain_message(panel, QMessageBox.Icon.Question, tr("Contact Request"), tr(
            "{jid} wants to see when you are online and to add you as a contact. Allow?").format(jid=request.jid),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        client.answer(request, box.exec() == QMessageBox.StandardButton.Yes)
        return True
    return False


PROTOCOL = dataclasses.replace(X.PROTOCOL, handle_request=handle_request, show_security=show_security)


def activate(api):
    panel = ChatPanel(PROTOCOL)
    missing = X.libraries_missing()
    if missing:
        panel.empty.setText(tr(missing))
    panel.attention.connect(api.notify)
    _PANELS.append(panel)
    api.add_dock(tr("XMPP"), panel, icon="chat")
    panel.connect_autostart()


def deactivate(api):
    while _PANELS:
        _PANELS.pop().shutdown()
