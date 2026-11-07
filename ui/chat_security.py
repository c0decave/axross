"""Encryption dialogs of the chat panel, shared by Matrix and XMPP: the
devices (keys) of a conversation with their fingerprints and trust, and the
short authentication string to compare during an interactive verification.

A device's trust is one of "verified" (the user compared its fingerprint or
an emoji/number string), "blacklisted" (it gets no keys), "ignored" (keys
go to it without a warning) and "unset". Nothing here decides trust on its
own: every change is a button the user pressed.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon

TRUST_TEXT = {"verified": "Verified", "blacklisted": "Blacklisted", "ignored": "Ignored",
              "unset": "Not verified", "trusted": "Trusted (not verified)", "distrusted": "Distrusted",
              "undecided": "Not decided"}


class DevicesDialog(QDialog):
    """Devices of a conversation: *devices()* gives DeviceInfo-like objects
    (user_id, device_id, name, fingerprint, trust); *set_trust(device,
    trust)* and *verify(device)* act on one (verify may be None)."""

    def __init__(self, parent, title: str, own, devices, set_trust, verify=None, *,
                 fingerprint_text=lambda f: f, trust_choices=("verified", "blacklisted", "ignored", "unset"),
                 extra_buttons=()) -> None:
        super().__init__(parent)
        set_window_icon(self, "shield")
        self.setWindowTitle(title)
        self.resize(820, 420)
        self._devices, self._set_trust, self._verify = devices, set_trust, verify
        self._fp = fingerprint_text
        layout = QVBoxLayout(self)
        if own is not None:
            mono = QFont("monospace")
            mono.setStyleHint(QFont.StyleHint.Monospace)
            label = QLabel(tr("This device: {device}").format(device=own.device_id))
            fp = QLineEdit(fingerprint_text(own.fingerprint))
            fp.setReadOnly(True)
            fp.setFont(mono)
            layout.addWidget(label)
            layout.addWidget(fp)
        hint = QLabel(tr("Compare a fingerprint with the one the other device shows (in person or over "
                         "another channel you trust) before you mark it verified."))
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([tr("User"), tr("Device"), tr("Fingerprint"), tr("Trust")])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        from ui.column_fit import ColumnFitter

        # the fingerprint takes the free width; every column stays draggable
        self._columns = ColumnFitter(self.table, fill=2)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        if verify is not None:
            b = QPushButton(tr("Verify Interactively…"))
            b.clicked.connect(self._start_verify)
            row.addWidget(b)
        labels = {"verified": "Mark Verified", "blacklisted": "Blacklist", "ignored": "Ignore", "unset": "Reset",
                  "trusted": "Trust", "distrusted": "Distrust", "undecided": "Reset"}
        for trust in trust_choices:
            b = QPushButton(tr(labels.get(trust, trust)))
            b.clicked.connect(lambda _=False, t=trust: self._apply(t))
            row.addWidget(b)
        for label, callback in extra_buttons:
            b = QPushButton(tr(label))
            b.clicked.connect(lambda _=False, cb=callback: cb(self))
            row.addWidget(b)
        row.addStretch(1)
        layout.addLayout(row)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        self.refresh()
        add_close_corner(self)

    def refresh(self) -> None:
        devices = list(self._devices())
        self._shown = devices
        self.table.setRowCount(len(devices))
        for r, d in enumerate(devices):
            name = f"{d.device_id}" + (f" ({d.name})" if getattr(d, "name", "") else "")
            for c, text in enumerate((d.user_id, name, self._fp(d.fingerprint), tr(TRUST_TEXT.get(d.trust, d.trust)))):
                item = QTableWidgetItem(text)
                if c == 3 and d.trust in ("blacklisted", "distrusted"):
                    item.setForeground(Qt.GlobalColor.red)
                self.table.setItem(r, c, item)

    def selected(self):
        rows = self.table.selectionModel().selectedRows()
        return self._shown[rows[0].row()] if rows else None

    def _apply(self, trust: str) -> None:
        device = self.selected()
        if device is None:
            return
        if trust in ("verified", "trusted"):
            answer = QMessageBox.question(self, tr("Mark Verified"), tr(
                "Does the other device show exactly this fingerprint?\n\n{fp}").format(fp=self._fp(device.fingerprint)))
            if answer != QMessageBox.StandardButton.Yes:
                return
        self._set_trust(device, trust)
        device.trust = trust
        self.refresh()

    def _start_verify(self) -> None:
        device = self.selected()
        if device is not None and self._verify is not None:
            self._verify(device)
            QMessageBox.information(self, tr("Verification"), tr(
                "The other device was asked. Accept there; the emoji to compare appear here."))


class SasDialog(QDialog):
    """Emoji (and numbers) of a verification: do they match the other device?"""

    def __init__(self, parent, who: str, emoji, decimals) -> None:
        super().__init__(parent)
        set_window_icon(self, "key")
        self.setWindowTitle(tr("Compare"))
        layout = QVBoxLayout(self)
        intro = QLabel(tr("Compare these with what {who} shows. Match only if every one is the same, "
                          "in the same order.").format(who=who))
        intro.setTextFormat(Qt.TextFormat.PlainText)  # the device id is the other side's
        intro.setWordWrap(True)
        layout.addWidget(intro)
        grid = QGridLayout()
        big = QFont(self.font())
        big.setPointSize(big.pointSize() * 2 + 4)
        for i, (symbol, name) in enumerate(list(emoji)[:7]):
            s = QLabel(symbol)
            s.setFont(big)
            s.setAlignment(Qt.AlignmentFlag.AlignCenter)
            n = QLabel(tr(name))
            n.setAlignment(Qt.AlignmentFlag.AlignCenter)
            grid.addWidget(s, 0, i)
            grid.addWidget(n, 1, i)
        layout.addLayout(grid)
        if decimals:
            numbers = QLabel(" - ".join(str(d) for d in decimals))
            numbers.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(numbers)
        buttons = QDialogButtonBox()
        self.match = buttons.addButton(tr("They Match"), QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(tr("They Don't Match"), QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        add_close_corner(self)


def ask_passphrase(parent, title: str, confirm: bool) -> str | None:
    text, ok = QInputDialog.getText(parent, title, tr("Passphrase:"), QLineEdit.EchoMode.Password)
    if not ok or not text:
        return None
    if confirm:
        again, ok = QInputDialog.getText(parent, title, tr("The passphrase again:"), QLineEdit.EchoMode.Password)
        if not ok or again != text:
            QMessageBox.warning(parent, title, tr("The passphrases differ."))
            return None
    return text


def pick_save(parent, title: str, name: str) -> str | None:
    path, _ = QFileDialog.getSaveFileName(parent, title, name)
    return path or None


def pick_open(parent, title: str) -> str | None:
    path, _ = QFileDialog.getOpenFileName(parent, title)
    return path or None
