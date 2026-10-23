"""The Quick Connect list, with a right-click menu per profile.

Left click (or Enter) connects as before. Right click on a profile opens
a small menu instead of connecting:

* **Connect** - the same as a left click: the list closes, the new pane
  becomes the active one.
* **Connect in Background** - the connection opens in a new pane, but the
  list stays open and the active pane stays where it is, so several
  profiles can be opened one after the other.
* **Edit Config…** - the list closes and the connection dialog opens with
  that profile loaded.
* **Delete Connection Config…** - the list closes; after a confirmation
  the profile is deleted, with its stored password.

A QMenu triggers an action on the release of any mouse button, the right
one included, so the right button is taken off the menu's own handling.
"""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QMenu

PROFILE_MENU_LABELS = ("Connect", "Connect in Background", "Edit Config…")
DELETE_LABEL = "Delete Connection Config…"


class QuickConnectMenu(QMenu):
    """A QMenu whose profile entries carry a right-click menu."""

    def __init__(
        self,
        title: str,
        parent=None,
        *,
        on_connect: Callable,
        on_background: Callable,
        on_edit: Callable,
        on_delete: Callable | None = None,
    ) -> None:
        super().__init__(title, parent)
        self._on_connect = on_connect
        self._on_background = on_background
        self._on_edit = on_edit
        self._on_delete = on_delete
        self._profiles: dict[QAction, object] = {}

    def add_profile(self, label: str, profile) -> QAction:
        """An entry that connects to *profile* on a left click."""
        action = self.addAction(label)
        self._profiles[action] = profile
        action.triggered.connect(lambda _checked=False, p=profile: self._on_connect(p))
        return action

    def profile_of(self, action: QAction | None):
        return self._profiles.get(action) if action is not None else None

    def build_profile_menu(self, profile) -> QMenu:
        """The right-click menu for *profile*, in the operator's order."""
        menu = QMenu(self)
        connect, background, edit = (menu.addAction(text) for text in PROFILE_MENU_LABELS)
        connect.triggered.connect(lambda _checked=False: self._connect_now(profile))
        background.triggered.connect(lambda _checked=False: self._on_background(profile))
        edit.triggered.connect(lambda _checked=False: self._edit(profile))
        if self._on_delete is not None:
            # Apart from the harmless entries: this one destroys something.
            menu.addSeparator()
            delete = menu.addAction(DELETE_LABEL)
            delete.triggered.connect(lambda _checked=False: self._delete(profile))
        return menu

    def _connect_now(self, profile) -> None:
        self.close()
        self._on_connect(profile)

    def _edit(self, profile) -> None:
        self.close()
        self._on_edit(profile)

    def _delete(self, profile) -> None:
        # The list closes first: its entries would name a deleted profile.
        self.close()
        self._on_delete(profile)

    def show_profile_menu(self, action: QAction, global_pos: QPoint) -> bool:
        """Open the right-click menu for *action*; False when it is not a
        profile entry (sections, Connection Manager)."""
        profile = self.profile_of(action)
        if profile is None:
            return False
        self.setActiveAction(action)
        self.exec_profile_menu(self.build_profile_menu(profile), global_pos)
        return True

    def exec_profile_menu(self, menu: QMenu, global_pos: QPoint) -> None:
        """Run *menu* modally. Separate so a test can drive it."""
        try:
            menu.exec(global_pos)
        finally:
            menu.deleteLater()

    # -- the right button never triggers an entry ---------------------------
    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.RightButton:
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.RightButton:
            event.accept()
            action = self.actionAt(event.position().toPoint())
            self.show_profile_menu(action, event.globalPosition().toPoint())
            return
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt override
        # The context-menu key (or Shift+F10) opens the menu for the
        # highlighted entry, so the keyboard reaches it too.
        key = event.key()
        if key == Qt.Key.Key_Menu or (
            key == Qt.Key.Key_F10 and event.modifiers() == Qt.KeyboardModifier.ShiftModifier
        ):
            action = self.activeAction()
            if action is not None:
                geo = self.actionGeometry(action)
                if self.show_profile_menu(action, self.mapToGlobal(geo.center())):
                    event.accept()
                    return
        super().keyPressEvent(event)


__all__ = ["DELETE_LABEL", "PROFILE_MENU_LABELS", "QuickConnectMenu"]
