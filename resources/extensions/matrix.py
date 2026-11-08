"""Matrix: a panel with your Matrix accounts, their rooms and direct chats,
end-to-end encrypted (core.chat_matrix on matrix-nio with vodozemac,
ui/chat_panel.py, ui/chat_security.py).

*Encryption…* on a room lists every device of its members with its
fingerprint and trust: verify one interactively (compare emoji - also with
Element), mark it verified after comparing the fingerprint, blacklist or
ignore it; export and import the room keys. A verification another device
starts, an invitation and the emoji to compare are asked in dialogs.
"""

from __future__ import annotations

import dataclasses

from PyQt6.QtWidgets import QDialog, QMessageBox

from core import chat as C
from core import chat_matrix as M
from core.i18n import tr
from ui.chat_panel import ChatPanel
from ui.chat_security import DevicesDialog, SasDialog, ask_passphrase, pick_open, pick_save
from ui.plain_text import plain_message

EXTENSION = {
    "name": "Matrix",
    "version": "1.0",
    "description": "A Matrix client: rooms and direct chats in a panel, end-to-end encrypted, "
    "with device verification (emoji) and key export.",
    "author": "axross",
}

_PANELS: list[ChatPanel] = []


def show_security(panel, client: M.MatrixClient, key: str) -> None:
    if client.state != C.STATE_ONLINE:
        QMessageBox.information(panel, tr("Encryption"), tr("Connect first."))
        return
    conv = client.conversation(key)
    in_room = conv is not None and conv.kind != C.CONV_SERVER

    def devices():
        return client.room_devices(key) if in_room else client.devices(client.user_id)

    def export(dialog):
        path = pick_save(dialog, tr("Export Room Keys"), "element-keys.txt")
        passphrase = path and ask_passphrase(dialog, tr("Export Room Keys"), confirm=True)
        if path and passphrase:
            client.export_keys(path, passphrase)

    def import_(dialog):
        path = pick_open(dialog, tr("Import Room Keys"))
        passphrase = path and ask_passphrase(dialog, tr("Import Room Keys"), confirm=False)
        if path and passphrase:
            client.import_keys(path, passphrase)

    title = tr("Encryption - {title}").format(title=conv.title if conv else client.user_id)
    head = tr(C.ENC_TEXT.get(conv.encryption, "")) if in_room else tr("Your other devices")
    dialog = DevicesDialog(panel, f"{title} ({head})", client.own_device(), devices,
                           lambda d, trust: client.set_trust(d.user_id, d.device_id, trust),
                           lambda d: client.verify(d.user_id, d.device_id),
                           fingerprint_text=M.fingerprint_text,
                           extra_buttons=(("Export Keys…", export), ("Import Keys…", import_)))
    dialog.exec()


def _ask(panel, title: str, text: str) -> bool:
    """Yes / No on *text* as plain text: room, device and user names come
    from other users, and the static QMessageBox calls would render their
    markup (a clickable file:// link, say)."""
    box = plain_message(panel, QMessageBox.Icon.Question, title, text,
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    return box.exec() == QMessageBox.StandardButton.Yes


def _tell(panel, title: str, text: str, icon=QMessageBox.Icon.Information) -> None:
    plain_message(panel, icon, title, text).exec()


def handle_request(panel, client: M.MatrixClient, request) -> bool:
    if isinstance(request, M.InviteRequest):
        answer = _ask(panel, tr("Invitation"), tr(
            "{inviter} invites you to {room}. Join?").format(inviter=request.inviter or tr("Someone"),
                                                           room=request.room_name))
        client.answer(request, answer)
        return True
    if isinstance(request, M.VerificationRequest):
        who = f"{request.user_id} ({request.device_id}{', ' + request.device_name if request.device_name else ''})"
        answer = _ask(panel, tr("Verification"), tr(
            "{who} wants to verify with this device. Accept?").format(who=who))
        client.answer(request, answer)
        return True
    if isinstance(request, M.SasRequest):
        dialog = SasDialog(panel, f"{request.user_id} ({request.device_id})", request.emoji, request.decimals)
        client.answer(request, dialog.exec() == QDialog.DialogCode.Accepted)
        return True
    if isinstance(request, M.VerificationResult):
        if request.ok:
            _tell(panel, tr("Verification"), tr("{user}'s device {device} is verified.").format(
                user=request.user_id, device=request.device_id))
        else:
            _tell(panel, tr("Verification"), tr("The verification was cancelled: {reason}").format(
                reason=request.reason or tr("no reason given")), QMessageBox.Icon.Warning)
        return True
    return False


PROTOCOL = dataclasses.replace(M.PROTOCOL, handle_request=handle_request, show_security=show_security)


def activate(api):
    panel = ChatPanel(PROTOCOL)
    missing = M.nio_missing(load=False)  # nio itself only when it connects
    if missing:
        # with a link to Help > Features…, which installs the chat extra
        panel.show_missing(tr(missing), getattr(api.window, "_show_features", None))
    panel.attention.connect(api.notify)
    _PANELS.append(panel)
    api.add_dock(tr("Matrix"), panel, icon="matrix")
    panel.connect_autostart()


def deactivate(api):
    while _PANELS:
        _PANELS.pop().shutdown()
