from __future__ import annotations

import itertools
import json
import logging
import threading
from html import escape
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import (
    QEvent,
    QItemSelection,
    QItemSelectionModel,
    QMimeData,
    QModelIndex,
    QPoint,
    QRect,
    Qt,
    QTimer,
    QUrl,
    pyqtSignal,
)
from PyQt6.QtGui import QDrag, QKeySequence, QPainter, QPixmap
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRubberBand,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core.file_type import BINARY_SIGNATURES
from core.i18n import format_decimal, tr, tr_n
from core.open_limits import describe_limit, max_open_bytes
from core.redaction import redact_url
from core.thread_relay import GuiCall
from core.user_errors import describe
from models.file_item import NAV_NAMES, FileItem
from models.file_table_model import (
    COL_NAME,
    FileSortProxyModel,
    FileTableModel,
    prepare_listing,
)
from ui.column_fit import detach_header_selection
from ui.format_utils import backend_label
from ui.plain_text import as_written
from ui.pane_drag import PANE_MIME_TYPE, DraggableHeader, PaneDropZones
from ui.scan_job import ScanJob


def _is_safe_leaf_name(name: str) -> bool:
    """Reject filenames / link names that carry a path-traversal
    component, a NUL byte, or empty strings. Used by the
    Create-Symlink / Create-Hardlink / Rename dialogs to stop a
    clipboard-paste typo from unintentionally placing the new entry
    outside the current directory.

    This is a UX guard, not a security barrier — the backend is free
    to refuse anything its own permissions check would reject anyway.
    But refusing ``..`` upfront means the user sees a clean dialog
    error instead of an OSError after a partial create.
    """
    try:
        from core.path_policy import safe_leaf

        safe_leaf(name)
    except ValueError:
        return False
    return True


#: Right-click entries by command: (icon, key). The icon is the one the
#: toolbar or a dock shows for the same command (``ui.icon_provider``), so a
#: command looks the same everywhere. The key is the one the pane's
#: ``eventFilter`` or a window QAction already reacts to (see
#: ``ui.shortcuts_dialog.SHORTCUTS``); the entry only *shows* it. It carries
#: the key with ``Qt.WidgetShortcut`` on a menu that never takes focus, so
#: Qt never sees a second owner: two live owners of one key make Qt fire
#: neither ("Ambiguous shortcut overload").
CONTEXT_COMMANDS: dict[str, tuple[str | None, str | None]] = {
    # open / view the selection
    "open": (None, "Return"),
    "open-with": ("file", None),
    "open-text": ("file", None),
    "open-hex": ("code", None),
    "open-root": ("shield", None),
    "preview-archive": ("archive", None),
    "extract": ("download", None),
    "view-selected-media": ("media-view", None),
    # clipboard / edit
    "copy": (None, "Ctrl+C"),
    "copy-path": (None, None),
    "cut": (None, "Ctrl+X"),
    "paste": (None, "Ctrl+V"),
    "rename": ("edit", "F2"),
    "batch-rename": ("edit", None),
    # transfer
    "copy-to-target": ("copy-right", "F5"),
    "move-to-target": ("move-right", "F6"),
    "pack": ("pack", None),
    # protect
    "encrypt": ("key", None),
    "decrypt": ("key", None),
    # remove
    "trash": ("trash", "Del"),
    "delete": ("x", "Shift+Del"),
    # create in this folder
    "new-folder": ("folder", "F7"),
    "new-file": ("plus", None),
    "new-symlink": (None, None),
    "new-hardlink": (None, None),
    "xlink": (None, None),
    # info / analysis
    "identify": (None, None),
    "identify-folder": (None, None),
    "analyse-sift": ("analysis", None),
    "analyse-folder-sift": ("analysis", None),
    "disk-image": ("disk-usage", None),
    "checksum": (None, None),
    "versions": (None, None),
    "calculate-size": ("disk-usage", None),
    "link-target": (None, None),
    "permissions": ("lock", None),
    "properties": ("settings", "Alt+Return"),
    "metadata": ("metadata", None),
    "metadata-remove": ("metadata", None),
    "metadata-export": ("metadata", None),
    "duplicates": ("duplicates", "Ctrl+Shift+D"),
    "find-files": ("find-index", None),
    # this folder
    "refresh": ("refresh", "Ctrl+R"),
    "view-mode": ("thumbnails", "Ctrl+Shift+G"),
    "media-view": ("media-view", None),
    # F8 as in View → Bookmarks; Ctrl+D in the file list does the same.
    "bookmark": ("bookmark", "F8"),
    "trash-browser": ("trash", None),
    "terminal": ("terminal", None),
    "external-terminal": ("terminal", None),
    "fuse-ro": (None, None),
    "fuse-rw": (None, None),
    "fuse-unmount": (None, None),
    # agent
    "send-to-agent": ("bot", None),
    # the pane itself
    "send-to-workspace": (None, None),
    # submenus of the right-click menu
    "metadata-menu": ("metadata", None),
    "analyse-menu": ("analysis", None),
    "links-menu": (None, None),
    "more-menu": (None, None),
}


def decorate_command(action, command: str):
    """Give a right-click *action* the icon and the shown key of *command*
    (see :data:`CONTEXT_COMMANDS`) and tag it with ``axCommand``/``axIcon``
    so the window can tell commands apart without matching labels."""
    from PyQt6.QtGui import QKeySequence

    from ui.icon_provider import icon

    icon_name, key = CONTEXT_COMMANDS[command]
    action.setProperty("axCommand", command)
    if icon_name:
        action.setProperty("axIcon", icon_name)
        action.setIcon(icon(icon_name))
    if key:
        action.setShortcut(QKeySequence(key))
        action.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        action.setShortcutVisibleInContextMenu(True)
    return action


def _sanitize_clipboard_text(text: str) -> tuple[str, bool]:
    """Escape control characters that would turn a clipboard payload
    into a shell-injection primitive when pasted into a terminal.

    Remote filesystems can expose files with newlines in their names
    (deliberate on most POSIX backends). If the user selects such a
    file and copies its path to the clipboard, a later paste into a
    shell promptly runs whatever came after the newline. We escape
    ``\\n`` / ``\\r`` / ``\\t`` / NUL to backslash-escapes so the
    clipboard stays a single visible line and the next paste is
    obviously-weird rather than silently-dangerous.

    Returns ``(sanitized, had_control_chars)``.
    """
    translations = {
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        "\x00": "\\x00",
    }
    had_any = any(ch in text for ch in translations)
    if not had_any:
        return text, False
    out = text
    for raw, escaped in translations.items():
        out = out.replace(raw, escaped)
    return out, True


def _shown_name(name: str, limit: int = 200) -> str:
    """*name* as a question shows it: a control, line-break, bidi or other
    format character as its code (``\\u202e``) - "invoice\\u202efdp.exe"
    read as "invoiceexe.pdf", and a name with 40 line breaks pushed the
    names after it out of the Delete question - and a very long one cut in
    the middle (its end, the extension, stays)."""
    shown = "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(name))
    if len(shown) <= limit:
        return shown
    head = (limit - 1) // 2
    return shown[:head] + "…" + shown[-(limit - 1 - head):]


def _dialog_item_names(items, limit: int = 5) -> str:
    """A short list of the selected items' names (:func:`_shown_name`), not
    escaped: the question shows its whole text as written
    (:func:`ui.plain_text.as_written`) - escaped here too, "Tom & Jerry"
    read "Tom &amp; Jerry"."""
    shown = ", ".join(_shown_name(i.name) for i in items[:limit])
    if len(items) > limit:
        shown += f" ... (+{len(items) - limit} more)"
    return shown


def skipped_links_note(result, limit: int = 10) -> str:
    """The line telling the user which symbolic links an extract left out
    (``core.archive.ExtractResult.skipped_links``); "" when it left none.

    The names come from the archive: a control or bidi character is shown
    as its code (``\\u202e``), never acted on."""
    skipped = [str(name) for name in (getattr(result, "skipped_links", None) or ())]
    if not skipped:
        return ""
    shown = [
        "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in name)
        for name in skipped[:limit]
    ]
    names = ", ".join(shown) + (", …" if len(skipped) > limit else "")
    return tr_n(
        len(skipped),
        "{n} symbolic link was not extracted: {names}",
        "{n} symbolic links were not extracted: {names}",
        names=names,
    )


#: Never handed to the desktop's default application from an archive: a
#: launcher or script there may run instead of being shown.
_NO_SYSTEM_APP_EXTENSIONS = frozenset({
    ".desktop", ".sh", ".bash", ".zsh", ".run", ".bin", ".appimage", ".exe", ".msi",
    ".bat", ".cmd", ".com", ".ps1", ".vbs", ".jar", ".py", ".pl", ".rb", ".command",
    ".app", ".deb", ".rpm", ".flatpakref",
})


def open_local_file_in_viewer(
    parent: QWidget | None, path: str, *, read_only: bool = True, view: str | None = None
) -> str:
    """Open a LOCAL file at *path* the way the file pane opens a file.

    Used for an archive member extracted to a temp folder. The same order
    as :meth:`FilePaneWidget._on_double_click` (reported: archive members
    had no syntax highlighting and a PDF only opened in the hex editor):

    * an image -> the image viewer,
    * a PDF or a video -> the media viewer, that file alone,
    * text -> a tab of the window's editor (highlighting, read-only),
    * any other binary -> the desktop's default application (xdg-open on
      the extracted copy) when the security mode allows external viewers
      and it is no launcher or script, else the hex editor.

    *view* ``"hex"`` or ``"text"`` skips the choice (the archive's
    Hex View / Text View). Returns what was opened (``"image"``,
    ``"media"``, ``"text"``, ``"hex"``, ``"system"``) or ``""`` when nothing
    was. A broken preview never crashes the caller.
    """
    import os as _os

    from core.local_fs import LocalFS
    from ui import viewer_window as VW

    name = _os.path.basename(path)
    backend = LocalFS()
    # Windows of their own (VW.show_independent): a modal viewer froze the
    # editor and the main window until it was closed.
    owner = VW.owner_window(parent)

    def hex_view() -> str:
        from ui.hex_editor import HexEditorDialog

        VW.show_independent(
            HexEditorDialog(backend, path, parent=owner, read_only=read_only, background=True)
        )
        return "hex"

    def text_view() -> str:
        opener = getattr(owner, "open_in_editor", None)
        if callable(opener):
            opener(backend, path, read_only=read_only)
            return "text"
        from ui.text_editor import TextEditorDialog

        dlg = TextEditorDialog(backend, path, parent=owner, read_only=read_only)
        if dlg.loaded:
            VW.show_independent(dlg)
            return "text"
        dlg.deleteLater()
        return ""

    try:
        if view == "hex":
            return hex_view()
        if view == "text":
            return text_view()
        if FilePaneWidget._looks_like_image(name):
            from ui.image_viewer import ImageViewerDialog

            dlg = ImageViewerDialog(backend, path, siblings=[path], parent=owner)
            if dlg.loaded:
                VW.show_independent(dlg)
                return "image"
            dlg.deleteLater()
            return ""
        if _open_local_media(owner, path, name):
            return "media"
        if not _classify_local_file_is_binary(backend, path, name):
            return text_view()
        if _open_with_system_app(path, name):
            return "system"
        return hex_view()
    except Exception as exc:  # noqa: BLE001 — a preview must never crash the app
        log.warning("Could not open %s in a viewer: %s", path, exc)
        return ""


def _open_local_media(owner, path: str, name: str) -> bool:
    """*path* alone in the media viewer when it is a PDF or video the viewer
    can show here (QtPdf / Qt Multimedia, the security mode)."""
    import os as _os

    from core import media_collect as MC
    from core.local_fs import LocalFS
    from core.security_mode import current_policy
    from ui import media_viewer as MV

    kind = MC.classify(name)
    if kind not in (MC.PDF, MC.VIDEO):
        return False
    if kind == MC.PDF and not MV.pdf_supported():
        return False
    if kind == MC.VIDEO and not MV.video_supported():
        return False
    if not current_policy().allow_auto_preview:
        return False
    options = MV.MediaViewOptions(kinds=frozenset({kind}), start_mode=MV.START_BROWSE)
    dialog = MV.MediaViewerDialog(LocalFS(), _os.path.dirname(path), options,
                                  only_names={name}, parent=owner)
    dialog.show()
    dialog.start()
    return True


def _open_with_system_app(path: str, name: str) -> bool:
    """Hand *path* to the desktop's default application (xdg-open). Not for
    launchers and scripts, not with the execute bit (cleared first: an
    extracted member keeps its archive mode), not when the security mode
    forbids external viewers."""
    import os as _os
    import stat as _stat
    import sys as _sys

    from core.security_mode import current_policy

    if not current_policy().allow_external_viewer:
        return False
    if _os.path.splitext(name)[1].lower() in _NO_SYSTEM_APP_EXTENSIONS:
        return False
    if _sys.platform.startswith("win") or _sys.platform == "darwin":
        return False  # xdg-open only; elsewhere the hex editor as before
    try:
        mode = _os.lstat(path).st_mode
        if not _stat.S_ISREG(mode):
            return False
        if mode & 0o111:
            _os.chmod(path, _stat.S_IMODE(mode) & ~0o111)
    except OSError:
        return False
    from core.desktop_open import spawn_opener

    if spawn_opener(path):
        log.info("Opened %s with the default application", path)
        return True
    return False


def _classify_local_file_is_binary(backend, path: str, name: str) -> bool:
    """Binary/text sniff for :func:`open_local_file_in_viewer`.

    Reuses ``FilePaneWidget``'s extension tables + magic-byte
    signatures (shared constants, not behaviour) so a standalone caller
    routes a file the same way the file pane would, without needing a
    live pane instance."""
    lower = name.lower()
    for ext in FilePaneWidget._BINARY_EXTENSIONS:
        if lower.endswith(ext):
            return True
    for ext in FilePaneWidget._TEXT_EXTENSIONS:
        if lower.endswith(ext):
            return False
    try:
        with backend.open_read(path) as f:
            header = f.read(512)
    except (OSError, ValueError):
        return False
    if not header:
        return False
    for offset, magic in FilePaneWidget._BINARY_MAGIC:
        if header[offset : offset + len(magic)] == magic:
            return True
    return b"\x00" in header


def _dialog_lines(lines) -> str:
    """Lines for a message box whose whole text goes through
    :func:`ui.plain_text.as_written`: each shown as :func:`_shown_name` does
    (no control or bidi character acts), not escaped - escaped here too,
    "Tom & Jerry" read "Tom &amp; Jerry"."""
    return "\n".join(_shown_name(str(line), 400) for line in lines)


_UNSET = object()  # "no precomputed value" marker


def _set_style(widget: QWidget, css: str) -> None:
    """``setStyleSheet`` only when the text changes: Qt re-polishes on every
    call, and every click re-applied the same three sheets to every pane."""
    if widget.styleSheet() != css:
        widget.setStyleSheet(css)


def _shorten_path(path: str, limit: int = 60) -> str:
    return path if len(path) <= limit else "…" + path[-(limit - 1) :]


# Paths a pane is deleting or moving to the trash. A second Delete of the
# same path - or of a folder above or below it - from any pane is refused
# while the first runs, instead of racing it. Claimed on the GUI thread;
# released by the GUI thread when the delete ends before its removal phase,
# else by the worker once its last remove() has returned.
_REMOVAL_LOCK = threading.Lock()
_REMOVAL_CLAIMS: dict[int, tuple[object, list[str]]] = {}
_REMOVAL_TOKENS = itertools.count(1)


def _removal_key(backend) -> object:
    """Every LocalFS shares one file system; another backend is its own."""
    from core.local_fs import LocalFS

    return "local" if isinstance(backend, LocalFS) else ("backend", id(backend))


def _paths_overlap(a: str, b: str) -> bool:
    """*a* and *b* are the same entry, or one lies inside the other."""
    a, b = a.rstrip("/\\") or a, b.rstrip("/\\") or b
    if a == b:
        return True
    return any(
        b.startswith(a.rstrip(sep) + sep) or a.startswith(b.rstrip(sep) + sep)
        for sep in ("/", "\\")
    )


def _claim_removal(backend, paths: list[str]) -> tuple[int | None, list[str]]:
    """Claim *paths* for one delete: ``(token, [])``, or ``(None, busy)``
    with the paths another running delete already holds."""
    key = _removal_key(backend)
    with _REMOVAL_LOCK:
        busy = [
            p
            for k, held in _REMOVAL_CLAIMS.values()
            if k == key
            for p in paths
            if any(_paths_overlap(p, h) for h in held)
        ]
        if busy:
            return None, sorted(set(busy))
        token = next(_REMOVAL_TOKENS)
        _REMOVAL_CLAIMS[token] = (key, list(paths))
        return token, []


def _release_removal(token: int | None) -> None:
    """Give the paths of *token* free again; a second call does nothing."""
    with _REMOVAL_LOCK:
        _REMOVAL_CLAIMS.pop(token, None)


def _paths_in_removal() -> list[str]:
    """Every path a delete currently holds (diagnostics and tests)."""
    with _REMOVAL_LOCK:
        return sorted(p for _k, held in _REMOVAL_CLAIMS.values() for p in held)


#: Double extensions kept whole when F2 selects a name without its extension.
_DOUBLE_EXTENSIONS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz", ".tar.lzma")


def rename_stem_length(name: str) -> int:
    """How much of *name* Rename selects: the part before the extension
    ("report" of "report.pdf", "backup" of "backup.tar.gz"); all of a name
    without one or a dot file (".bashrc")."""
    lower = name.lower()
    for ext in _DOUBLE_EXTENSIONS:
        if lower.endswith(ext) and len(name) > len(ext):
            return len(name) - len(ext)
    dot = name.rfind(".")
    return dot if dot > 0 else len(name)


def _select_in_modal_line_edit(text: str, length: int) -> None:
    """Select the first *length* characters in the open input dialog's line
    edit, when it shows *text* (QInputDialog.getText offers no selection)."""
    from PyQt6.QtWidgets import QApplication, QLineEdit

    dialog = QApplication.activeModalWidget()
    if dialog is None:
        return
    for edit in dialog.findChildren(QLineEdit):
        if edit.text() == text:
            edit.setSelection(0, length)
            return


def _removal_cancelled_text(trash: bool) -> str:
    """The status line of a Delete / Move to Trash stopped before anything went."""
    return (tr("Move to Trash cancelled – nothing was touched.") if trash
            else tr("Delete cancelled – nothing was deleted."))


def removal_preview_text(preview) -> str:
    """What a Delete / Move to Trash takes with it, for its question:
    "In total: 3 files, 1 folder, 180.1 KB; 1 of them hidden" - in the
    interface language, the size human-readable. (``OperationPreview.summary``
    stays the terse English line scripts print.)"""
    from ui.format_utils import human_bytes

    parts = []
    if preview.files or not preview.dirs:
        parts.append(tr_n(preview.files, "{n} file", "{n} files"))
    if preview.dirs:
        parts.append(tr_n(preview.dirs, "{n} folder", "{n} folders"))
    parts.append(human_bytes(preview.bytes_total))
    text = tr("In total: {what}").format(what=", ".join(parts))
    extra = []
    if preview.hidden_count:
        extra.append(tr_n(preview.hidden_count, "{n} of them hidden", "{n} of them hidden"))
    if preview.conflicts:
        extra.append(tr_n(len(preview.conflicts), "{n} conflict", "{n} conflicts"))
    if preview.warnings:
        extra.append(tr_n(len(preview.warnings), "{n} entry could not be read",
                          "{n} entries could not be read"))
    if preview.truncated:
        extra.append(tr("the count stopped early, there may be more"))
    return "; ".join([text, *extra])


class _RemovalResult:
    """What the removal phase did: ``done`` entries removed, ``errors`` one
    line per failed entry, ``not_attempted`` entries a cancel (or a stop)
    kept, ``aborted`` when an unexpected exception stopped the run, and
    ``partial`` - ``(name, removed inside)`` - for a folder a cancel
    stopped halfway: part of it is gone, the folder and the rest stay.
    ``questions`` - ``(name, path, is_dir, ConfirmationRequired)`` - the
    entries the backend wants a yes for (INBOX of an IMAP server whose
    folders live below it, a DFS link): nothing of them was deleted, and
    they are counted in ``not_attempted``."""

    def __init__(
        self,
        done: int,
        errors: list[str],
        not_attempted: int,
        aborted: bool,
        partial: tuple[str, int] | None = None,
        questions: list | None = None,
    ) -> None:
        self.done = done
        self.errors = errors
        self.not_attempted = not_attempted
        self.aborted = aborted
        self.partial = partial
        self.questions = list(questions or ())


def _run_removal(backend, entries, trash: bool, cancelled, report,
                 options: dict | None = None) -> _RemovalResult:
    """Remove (or move to the trash) each ``(name, path, is_dir)`` in turn.

    Runs on a worker thread. *cancelled* is checked between entries, and -
    for a delete - also between the entries inside a folder, where the
    backend walks the tree itself (core.removal_cancel: local paths, SMB,
    SFTP, FTP). A folder stopped that way is reported in ``partial`` with
    the number of entries removed inside it; one stopped before anything
    inside went counts as not attempted. A backend that removes a tree in
    one server request finishes that entry first. An OSError is recorded
    and the next entry goes ahead (as the synchronous loop did); any other
    exception is a backend defect and stops the run, so nothing more is
    removed after it. The trash entries of one run share a journal batch:
    Ctrl+Z restores them together (core.undo).
    """
    from core.operation_journal import journal_batch, new_batch_id

    with journal_batch(new_batch_id() if trash else "", begin="trash", entries=len(entries)):
        result = _run_removal_entries(backend, entries, trash, cancelled, report, options)
    if not trash and (result.done or result.partial):
        # Ctrl+Z after it says the delete cannot be undone (core.undo).
        from core.undo import record_delete

        record_delete(backend, [path for _name, path, _is_dir in entries],
                      result.done + (1 if result.partial else 0))
    return result


def _run_removal_entries(backend, entries, trash: bool, cancelled, report,
                         options: dict | None = None) -> _RemovalResult:
    """*options*: ``{path: {keyword: True}}`` - the yes the person gave to
    a backend's question (:class:`core.backend.ConfirmationRequired`)."""
    from core import removal_cancel as RC
    from core import trash as T
    from core.backend import ConfirmationRequired
    from core.user_errors import describe

    done, errors, attempted, aborted = 0, [], 0, False
    questions: list = []
    partial: tuple[str, int] | None = None
    what = "Trash" if trash else "Delete"
    for index, (name, path, is_dir) in enumerate(entries):
        if cancelled():
            break
        report(index, len(entries), name)
        attempted += 1

        def inside(count: int, _path: str, index=index, name=name) -> None:
            report(index, len(entries),
                   tr("{name}: {count} removed inside").format(name=name, count=count))

        try:
            if trash:
                T.trash(backend, path)
            else:
                with RC.cancellable_removal(cancelled, inside):
                    backend.remove(path, recursive=is_dir, **(options or {}).get(path, {}))
        except ConfirmationRequired as exc:
            if trash:
                errors.append(f"{name}: {describe(exc)}")
                continue
            # Nothing of it was deleted: asked about once the run is over.
            log.info("Delete of %s needs a yes (%s)", path, exc.kind)
            questions.append((name, path, is_dir, exc))
            attempted -= 1
            continue
        except RC.RemovalCancelled as exc:
            if exc.removed:
                partial = (name, exc.removed)
                log.info("Delete cancelled inside %s: %d entries removed", path, exc.removed)
            else:
                attempted -= 1  # nothing of it was touched
            break
        except OSError as exc:
            log.error("%s failed for %s: %s", what, name, exc)
            errors.append(f"{name}: {describe(exc)}")
            continue
        except Exception as exc:  # noqa: BLE001 — reported to the user, run stopped
            log.exception("%s stopped at %s: unexpected error", what, name)
            errors.append(f"{name}: {describe(exc)}")
            aborted = True
            break
        done += 1
        log.info("%s: %s", "Trashed" if trash else "Deleted", path)
    return _RemovalResult(done, errors, len(entries) - attempted, aborted, partial, questions)


# Buttons the pane handles itself: the two side buttons walk the history,
# the wheel click opens the row under the pointer.
_EXTRA_MOUSE_BUTTONS = (
    Qt.MouseButton.BackButton,
    Qt.MouseButton.ForwardButton,
    Qt.MouseButton.MiddleButton,
)


def _drop_action(event) -> Qt.DropAction:
    """Ctrl copies, anything else moves: read from the event itself, whose
    modifiers are those of the drop (QApplication's can lag behind)."""
    if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
        return Qt.DropAction.CopyAction
    return Qt.DropAction.MoveAction


class _DragTableView(QTableView):
    """QTableView subclass that delegates drag initiation and drop handling to the parent pane."""

    def __init__(self, pane: FilePaneWidget, parent=None):
        super().__init__(parent or pane)
        from ui.drag_autoscroll import DragAutoScroll

        #: Scrolls near the top / bottom edge while a drag hovers there.
        self.drag_scroll = DragAutoScroll(self)
        self._pane = pane
        self._band: QRubberBand | None = None
        self._band_origin: QPoint | None = None
        self._band_base: QItemSelection | None = None
        self._band_pending = False

    def mousePressEvent(self, event) -> None:
        pos = event.position().toPoint()
        if self._pane._handle_extra_mouse_button(event.button(), pos):
            event.accept()
            return
        if event.button() == Qt.MouseButton.LeftButton:
            index = self.indexAt(pos)
            ctrl = bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)
            if not index.isValid():
                # Empty space: keep the default (clears the selection unless
                # Ctrl is held) and start a selection box that follows the mouse.
                super().mousePressEvent(event)
                self._start_band(pos, ctrl)
                return
            if index.column() != 0:
                # A row outside the Name column (Size, Modified, ...): a click
                # selects the row as usual, a drag beyond the drag distance
                # draws the box, so long lists can be box-selected too. A drag
                # that starts on the name stays a file drag.
                super().mousePressEvent(event)
                self._start_band(pos, ctrl, needs_drag_distance=True)
                return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if self._band_origin is not None and event.buttons() & Qt.MouseButton.LeftButton:
            pos = event.position().toPoint()
            if self._band_pending:
                origin = self._band_origin - self._scroll_offset()
                if (pos - origin).manhattanLength() < QApplication.startDragDistance():
                    event.accept()  # still a click; Qt must not start a file drag either
                    return
                self._band_pending = False
            self._update_band(pos)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if self._band_origin is not None and event.button() == Qt.MouseButton.LeftButton:
            was_click = self._band_pending  # never dragged far enough: a plain click
            self._end_band()
            if not was_click:
                event.accept()
                return
        # The press already acted; the matching release must not reach
        # the selection logic either.
        if event.button() in _EXTRA_MOUSE_BUTTONS:
            event.accept()
            return
        super().mouseReleaseEvent(event)

    # --- selection box ----------------------------------------------------
    def _scroll_offset(self) -> QPoint:
        return QPoint(self.horizontalScrollBar().value(), self.verticalScrollBar().value())

    def _start_band(self, pos: QPoint, additive: bool, needs_drag_distance: bool = False) -> None:
        self._band_origin = pos + self._scroll_offset()  # content coordinates
        # The row the box started on, as a row: a rectangle clipped to the
        # viewport lost it once the drag scrolled it out of view, and only
        # the rows on screen were selected.
        self._band_origin_row = self._row_at_y(pos.y())
        self._band_pending = needs_drag_distance
        self._band_base = QItemSelection(self.selectionModel().selection()) if additive else None
        if self._band is None:
            self._band = QRubberBand(QRubberBand.Shape.Rectangle, self.viewport())

    def _update_band(self, pos: QPoint) -> None:
        viewport = self.viewport()
        # Dragging past the top / bottom edge scrolls the list.
        bar = self.verticalScrollBar()
        if pos.y() < 0:
            bar.setValue(bar.value() - bar.singleStep())  # a step, not 20 rows
        elif pos.y() > viewport.height():
            bar.setValue(bar.value() + bar.singleStep())
        origin = self._band_origin - self._scroll_offset()
        rect = QRect(origin, pos).normalized().intersected(viewport.rect())
        self._band.setGeometry(rect)
        self._band.show()
        here = self._row_at_y(min(max(pos.y(), 0), max(viewport.height() - 1, 0)))
        start = getattr(self, "_band_origin_row", -1)
        if start < 0 or here < 0:
            self._select_rows(-1, -1)
        else:
            self._select_rows(min(start, here), max(start, here))

    def _row_at_y(self, y: int) -> int:
        """The row at viewport height *y*; below the last row the row
        count (one past the last: empty space selects nothing)."""
        row = self.rowAt(y)
        if row < 0 and y >= 0:
            row = self.model().rowCount()
        return row

    def _select_rows(self, first: int, last: int) -> None:
        model = self.model()
        selection = QItemSelection()
        if self._band_base is not None:
            selection.merge(self._band_base, QItemSelectionModel.SelectionFlag.Select)
        last_col = model.columnCount() - 1
        last = min(last, model.rowCount() - 1)
        if 0 <= first <= last:
            for row in range(first, last + 1):
                # "." and ".." are navigation, not something to copy or delete.
                if model.data(model.index(row, 0)) in NAV_NAMES:
                    continue
                selection.select(model.index(row, 0), model.index(row, last_col))
        self.selectionModel().select(
            selection,
            QItemSelectionModel.SelectionFlag.ClearAndSelect
            | QItemSelectionModel.SelectionFlag.Rows,
        )

    def _end_band(self) -> None:
        self._band_origin = None
        self._band_pending = False
        self._band_base = None
        if self._band is not None:
            self._band.hide()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._pane._fit_name_column()

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        # A theme or font change changes how wide every text is.
        if event.type() in (QEvent.Type.FontChange, QEvent.Type.StyleChange):
            self._pane._content_widths_changed()

    def startDrag(self, supportedActions) -> None:
        self._pane._start_drag()

    def dragEnterEvent(self, event) -> None:
        self._pane.dragEnterEvent(event, origin=self.viewport())

    def dragMoveEvent(self, event) -> None:
        pos = event.position().toPoint()
        self.drag_scroll.move(pos)
        folder = self._pane._folder_at(pos)
        self._pane.dragMoveEvent(event, folder, origin=self.viewport())
        if event.isAccepted() and not event.mimeData().hasFormat(PANE_MIME_TYPE):
            self._pane._show_drop_hint(pos, folder, event.dropAction())
        else:
            self._pane._hide_drop_hint()

    def dragLeaveEvent(self, event) -> None:
        self.drag_scroll.stop()
        self._pane._hide_drop_hint()
        self._pane.dragLeaveEvent(event)

    def dropEvent(self, event) -> None:
        self.drag_scroll.stop()
        self._pane._hide_drop_hint()
        self._pane.dropEvent(
            event, self._pane._folder_at(event.position().toPoint()), origin=self.viewport()
        )


if TYPE_CHECKING:
    from core.backend import FileBackend
    from models.file_item import FileItem

log = logging.getLogger(__name__)
TRANSFER_MIME_TYPE = "application/x-axross-transfer"


def filesystem_key(backend) -> str:
    """Which filesystem *backend* shows, for comparing two panes: every
    local pane shares the local disk, a remote one is named by its backend
    (as ``MainWindow._pane_serves_bookmark`` does). Names and types only,
    no backend call - safe in drag handlers."""
    from core.local_fs import LocalFS

    if isinstance(backend, LocalFS):
        return "Local"
    return f"remote:{backend.name}"


def decode_transfer_payload(mime: QMimeData | None) -> dict[str, object] | None:
    """The pane drag payload as ``{"paths", "source_pane_id", "dirs",
    "filesystem"}``, or ``None`` for anything else (another program's text
    or URLs, garbage).

    ``dirs`` is the subset of ``paths`` the source listing showed as
    folders; a missing or malformed field means no folders. ``filesystem``
    is the source pane's :func:`filesystem_key`, None when the payload does
    not name one. Pure parsing: nothing here touches a filesystem, so it is
    safe in drag handlers."""
    if mime is None or not mime.hasFormat(TRANSFER_MIME_TYPE):
        return None
    try:
        raw = bytes(mime.data(TRANSFER_MIME_TYPE)).decode("utf-8")
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        log.debug("Ignoring malformed drag payload", exc_info=True)
        return None
    if not isinstance(payload, dict):
        return None
    paths = payload.get("paths")
    source_pane_id = payload.get("source_pane_id")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        return None
    if not isinstance(source_pane_id, str):
        return None
    dirs = payload.get("dirs")
    dragged = set(paths)
    if isinstance(dirs, list):
        dirs = [d for d in dirs if isinstance(d, str) and d in dragged]
    else:
        dirs = []
    filesystem = payload.get("filesystem")
    if not isinstance(filesystem, str):
        filesystem = None
    return {
        "paths": paths,
        "source_pane_id": source_pane_id,
        "dirs": dirs,
        "filesystem": filesystem,
    }


#: Widest the drag picture gets (logical pixels); a long name is elided.
_DRAG_PIXMAP_MAX_WIDTH = 340


def drag_pixmap(names: list[str], dirs: int) -> QPixmap:
    """The picture a file drag carries under the mouse: a folder or file
    icon, the first name (elided) and "+N more" for several items. *dirs*
    is how many of *names* are folders."""
    from PyQt6.QtGui import QColor, QFontMetrics

    from ui.icon_provider import icon

    app = QApplication.instance()
    font = app.font() if app is not None else QLabel().font()
    metrics = QFontMetrics(font)
    palette = app.palette() if app is not None else QLabel().palette()
    first = names[0] if names else ""
    extra = f"  +{len(names) - 1} more" if len(names) > 1 else ""
    pad, icon_size = 6, 20
    room = _DRAG_PIXMAP_MAX_WIDTH - icon_size - 3 * pad - metrics.horizontalAdvance(extra)
    text = metrics.elidedText(first, Qt.TextElideMode.ElideMiddle, max(40, room)) + extra
    width = min(_DRAG_PIXMAP_MAX_WIDTH, icon_size + 3 * pad + metrics.horizontalAdvance(text))
    height = max(icon_size, metrics.height()) + 2 * pad
    ratio = app.devicePixelRatio() if app is not None else 1.0
    pix = QPixmap(int(width * ratio), int(height * ratio))
    pix.setDevicePixelRatio(ratio)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    back = QColor(palette.highlight().color())
    back.setAlpha(210)
    painter.setBrush(back)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(0, 0, width, height, 5, 5)
    kind = "folder" if names and dirs == len(names) else "file"
    if len(names) > 1 and dirs:
        kind = "folder"
    painter.drawPixmap(
        pad, (height - icon_size) // 2, icon(kind, icon_size).pixmap(icon_size, icon_size)
    )
    painter.setPen(palette.highlightedText().color())
    painter.setFont(font)
    painter.drawText(QRect(icon_size + 2 * pad, 0, width - icon_size - 3 * pad, height),
                     Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, text)
    painter.end()
    return pix


_MIN_COLUMN_WIDTH = 60
# Size, Modified, Permissions, Owner
#: Bytes Show Checksum reads at a time (a cancel is seen between two).
CHECKSUM_CHUNK = 1024 * 1024
#: Seconds Mount as FUSE waits for the kernel to show the mount.
FUSE_MOUNT_WAIT_S = 5


def _stream_sha256(backend, path: str, total: int, cancelled, report) -> str | None:
    """SHA-256 of *path* read through *backend*, on a worker thread;
    None when *cancelled()* turned true. *report(done, total, path)*
    after each chunk."""
    import hashlib

    digest = hashlib.sha256()
    done = 0
    with backend.open_read(path) as fh:
        while not cancelled():
            chunk = fh.read(CHECKSUM_CHUNK)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
            done += len(chunk)
            report(done, total, path)
    return None


def _read_header(backend, path: str, size: int = 512) -> bytes:
    """The first *size* bytes of *path* ("" when it cannot be read)."""
    try:
        with backend.open_read(path) as fh:
            return fh.read(size) or b""
    except (OSError, ValueError):
        return b""


def _link_is_dir(backend, folder: str, path: str) -> bool:
    """Whether the link *path* (in *folder*) leads to a folder."""
    try:
        target = backend.readlink(path)
        if not target:
            return False
        if not target.startswith(backend.separator()):
            target = backend.join(folder, target)
        return backend.stat(target).is_dir
    except OSError:
        return False


def _sweep_orphans(backend, path: str, items: list) -> None:
    """core.atomic_recovery.sweep_orphans of *path*, on a worker; logs only."""
    try:
        from core import atomic_recovery as AR

        removed = AR.sweep_orphans(backend, path, prefetched_entries=items)
        if removed:
            log.info("atomic_recovery: removed %d orphan(s) under %s", removed, path)
    except Exception as exc:  # noqa: BLE001 - never more than a log line
        log.debug("atomic_recovery sweep skipped for %s: %s", path, exc)


def _human_size(size: int) -> str:
    return FileItem(name="", size=size).size_human


_DEFAULT_COLUMN_WIDTHS = {1: 90, 2: 150, 3: 110, 4: 150}
# How many rows the content-width measurement reads, and how many of the
# longest texts per column it measures exactly. A listing larger than
# _MEASURE_ROWS is judged by its first rows in the current sort order.
_MEASURE_ROWS = 5000
_MEASURE_LONGEST = 8


def _may_hold_media(item) -> bool:
    """A selected entry View Selected Media… has something to show for: a
    folder (or a link to one) or a file of a media kind
    (core.media_collect.classify)."""
    if getattr(item, "is_nav", False):
        return False
    if getattr(item, "is_dir", False):
        return True
    from core.media_collect import classify

    return classify(getattr(item, "name", "")) is not None


class FilePaneWidget(QWidget):
    """Reusable file browser pane, works with any FileBackend."""

    path_changed = pyqtSignal(str)
    view_mode_changed = pyqtSignal(str)  # "details" or "thumbnails"
    file_activated = pyqtSignal(str)  # full path of activated file
    # (path, ok) when a background load ends; ok is False for failures and cancels.
    navigation_finished = pyqtSignal(str, bool)
    #: the connection's protection (the security badge) changed
    security_changed = pyqtSignal()
    transfer_requested = pyqtSignal(list)  # list of full paths to transfer (copy)
    move_requested = pyqtSignal(list)  # list of full paths to move
    #: Paste (Ctrl+V, right-click): move the pending Cut (ui.cut_clipboard)
    #: into this pane's current folder; the main window does the move.
    paste_requested = pyqtSignal()
    # paths, target pane, source pane id, is_move
    # paths, target pane, source pane id, move?, folder dropped on ("" = current)
    drop_transfer_requested = pyqtSignal(list, object, str, bool, str)
    selection_changed = pyqtSignal()
    pane_focused = pyqtSignal()
    bookmark_requested = pyqtSignal(str, str)  # path, backend_name
    close_requested = pyqtSignal()  # user clicked X on pane
    set_as_target_requested = pyqtSignal()  # user wants this pane as target
    # dragged_pane_id, target_pane, position ("left"/"right"/"top"/"bottom")
    pane_drop_requested = pyqtSignal(str, object, str)
    cycle_pane_requested = pyqtSignal(bool)  # True = next, False = previous
    open_bookmarks_requested = pyqtSignal()  # Ctrl+B
    # The pane does not own the duplicate-finder dialog; the main window
    # does, because the index spans every connection rather than one pane.
    open_duplicates_requested = pyqtSignal()
    #: Find in This Folder…: the folder to search. The main window owns the
    #: Find Files dialog (it searches folders of several panes).
    find_files_requested = pyqtSignal(str)
    # Open Terminal Here: the folder to open a shell in. The main window owns
    # the terminal dock and decides between a local and an SSH shell.
    open_terminal_requested = pyqtSignal(str)
    #: Send to Agent: the selected paths (or the folder shown) for the
    #: Agent dock's current tab. The main window owns the dock.
    send_to_agent_requested = pyqtSignal(list)
    # New Agent Tab Here: the local folder shown, "" on a remote backend.
    new_agent_tab_requested = pyqtSignal(str)
    #: Analyse with sift: [(path, FileItem), ...] of the selected files, as the
    #: right-click menu showed them. The main window owns the Analysis dock.
    analyse_requested = pyqtSignal(list)
    #: Analyse Folder with sift: the folder (selected, else the one shown).
    analyse_folder_requested = pyqtSignal(str)
    def __init__(
        self,
        backend: FileBackend,
        parent: QWidget | None = None,
        async_initial_load: bool = False,
    ):
        super().__init__(parent)
        self._backend = backend
        self._current_path = backend.home()
        self._loading = False
        self._history: list[str] = []
        self._history_pos: int = 0
        # Background folder loads (see navigate_async).
        self._nav_job = ScanJob(self, interval_ms=100)
        self._nav_job.finished.connect(self._on_nav_finished)
        self._nav_lock = threading.Lock()  # one listing per pane at a time
        self._nav_ctx: dict = {}
        self._history_navigating = False  # suppress history push during back/forward
        # Auto-refresh via core.watch — one watcher at a time, scoped
        # to the currently displayed directory. Toggleable per-pane; on
        # by default only where watching is cheap (local, in-process or a
        # push watcher) - a remote folder would be listed every 2 s.
        self._watcher = None
        self._watched_path: str | None = None
        from core import watch as _watch

        self._watch_enabled = _watch.auto_refresh_by_default(backend)
        self._watch_debounce: QTimer | None = None
        #: The number of the watcher's last report of a change, and the last
        #: report's number when the listing shown was asked for (-1: unknown).
        #: Numbers, not times: on Windows with Python 3.12 time.monotonic()
        #: ticks every 15.6 ms, and a change made in the same tick as a
        #: listing looked older than it and was never shown.
        self._watch_counter = itertools.count(1)
        self._watch_report = 0
        self._shown_listing_after = -1
        self._shutting_down = False
        #: Open metadata windows (see open_metadata).
        self.metadata_dialogs: list = []
        #: Open Identify File Type windows (see identify_file_type).
        self.file_type_dialogs: list = []
        #: path -> (size, is a disk image) from Identify File Type on this
        #: backend: the menu offers Disk Image… for an image by content
        #: without reading a remote file itself (_content_says_disk_image).
        self._identified_images: dict[str, tuple[int | None, bool]] = {}

        self._setup_ui()
        from ui.cut_clipboard import cut_clipboard

        cut_clipboard().changed.connect(self._apply_cut_marks)
        # The debounce timer is created in the GUI thread so its
        # singleShot fire happens in this thread too. Both ends of
        # the chain go through wrapper methods so subclasses (and
        # tests) can intercept by patching the instance attribute —
        # connecting straight to ``self.refresh`` would freeze the
        # bound method at connect time.
        self._watch_debounce = QTimer(self)
        self._watch_debounce.setSingleShot(True)
        self._watch_debounce.setInterval(250)
        # Lambdas (not bound-method connects) so attribute lookup
        # happens at fire time — important for tests that patch the
        # instance method post-construction.
        self._watch_timeout_slot = lambda: self._on_debounce_fired()
        self._watch_event_slot = lambda: self._on_watch_event_signal()
        self._watch_debounce.timeout.connect(self._watch_timeout_slot)
        # The watcher thread reports through this, not through a signal of
        # the pane: a pane deleted with its window (no shutdown()) may be
        # being deleted while the thread reports (core/thread_relay.py).
        self._watch_call = GuiCall(self._on_watch_call)
        self.destroyed.connect(lambda *_: self._mark_destroyed())

        if async_initial_load:
            self.navigate_async(self._current_path)
        else:
            self.navigate(self._current_path)

    @property
    def backend(self) -> FileBackend:
        return self._backend

    @property
    def current_path(self) -> str:
        return self._current_path

    def _setup_ui(self) -> None:
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAcceptDrops(True)
        self.setMinimumWidth(220)
        self.setMinimumHeight(150)

        # Outer frame for visible colored border
        self._border_frame = QFrame(self)
        self._border_frame.setFrameShape(QFrame.Shape.Box)
        self._border_frame.setLineWidth(3)
        self._border_frame.setObjectName("axPaneBorder")
        self._border_frame.setStyleSheet(
            "QFrame#axPaneBorder { border: 3px solid #888; border-radius: 4px; }"
        )

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        outer_layout.addWidget(self._border_frame)

        layout = QVBoxLayout(self._border_frame)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Header with backend name + role badge + target button + close button
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(4)

        # How the connection is protected (cleartext, TLS, SSH, SMB3 ...),
        # always in sight: ui/security_badge.py
        from ui.security_badge import SecurityBadge

        self._security_badge = SecurityBadge(self)
        self._security_badge.setObjectName("axSecurityBadge")  # the tours point at it
        header_layout.addWidget(self._security_badge)
        self.navigation_finished.connect(lambda _path, _ok: self.refresh_security())

        header = DraggableHeader(self)
        header.setCursor(Qt.CursorShape.OpenHandCursor)
        header.setToolTip(tr("Drag to rearrange pane"))
        header_layout.addWidget(header)
        self._header_label = header
        self.update_header_color()

        # Role badge (SOURCE / TARGET / —)
        self._role_label = QLabel()
        self._role_label.setFixedHeight(20)
        self._role_label.setStyleSheet(
            "QLabel { font-size: 10px; font-weight: bold; padding: 1px 6px; border-radius: 3px; }"
        )
        header_layout.addWidget(self._role_label)

        header_layout.addStretch()

        # "Set as Target" button
        self._btn_target = QPushButton("\u25ce")  # ◎
        self._btn_target.setObjectName("axPaneTarget")
        self._btn_target.setFixedSize(20, 20)
        self._btn_target.setToolTip(tr("Set as transfer target"))
        # padding 0: the theme's "QPushButton { padding: 4px 8px }" left a
        # contents box 4 px wide, and ◎ showed as a clipped sliver.
        self._btn_target.setStyleSheet(
            "QPushButton { border: none; padding: 0px; font-size: 14px; } "
            "QPushButton:hover { background: #58a55c; color: white; border-radius: 3px; }"
        )
        self._btn_target.clicked.connect(self.set_as_target_requested.emit)
        header_layout.addWidget(self._btn_target)

        self._btn_close = QPushButton("\u2715")
        self._btn_close.setFixedSize(20, 20)
        self._btn_close.setToolTip(tr("Close pane"))
        self._btn_close.setStyleSheet(
            "QPushButton { border: none; font-size: 12px; } "
            "QPushButton:hover { background: #c0392b; color: white; border-radius: 3px; }"
        )
        self._btn_close.clicked.connect(self.close_requested.emit)
        header_layout.addWidget(self._btn_close)

        layout.addLayout(header_layout)

        # Path bar
        path_bar = QHBoxLayout()
        path_bar.setSpacing(2)

        self._btn_up = QPushButton("\u2191")
        self._btn_up.setFixedWidth(30)
        self._btn_up.setToolTip(tr("Parent folder"))
        self._btn_up.clicked.connect(self._go_up)
        path_bar.addWidget(self._btn_up)

        self._btn_home = QPushButton("\u2302")
        self._btn_home.setFixedWidth(30)
        self._btn_home.setToolTip(tr("Home folder"))
        self._btn_home.clicked.connect(self._go_home)
        path_bar.addWidget(self._btn_home)

        self._btn_bookmark = QPushButton("\u2606")
        self._btn_bookmark.setFixedWidth(30)
        self._btn_bookmark.setToolTip(tr("Bookmark the current folder"))
        self._btn_bookmark.clicked.connect(self._add_bookmark)
        path_bar.addWidget(self._btn_bookmark)

        self._path_edit = QLineEdit()
        self._path_edit.setObjectName("axPathEdit")
        self._path_edit.setProperty("axHelpTopic", "path-bar")  # F1: ui.handbook
        self._path_edit.returnPressed.connect(self._on_path_entered)
        path_bar.addWidget(self._path_edit)

        self._btn_refresh = QPushButton("\u21bb")
        self._btn_refresh.setFixedWidth(30)
        self._btn_refresh.setToolTip(tr("Refresh"))
        self._btn_refresh.clicked.connect(lambda _c=False: self.refresh_async())
        path_bar.addWidget(self._btn_refresh)

        # Auto-refresh toggle: on for local folders, off for remote ones
        # until the user turns it on (see core.watch.auto_refresh_by_default).
        self._btn_watch = QPushButton("\u25c9")  # ◉ (filled = on)
        self._btn_watch.setFixedWidth(30)
        self._btn_watch.setCheckable(True)
        self._btn_watch.setChecked(self._watch_enabled)
        self._btn_watch.setToolTip(
            tr("Auto-refresh when the folder changes. On by default for local "
            "folders; off for remote ones, where it lists the folder again "
            "every 2 seconds – click to turn it on for this pane.")
        )
        self._btn_watch.toggled.connect(self._on_watch_toggled)
        path_bar.addWidget(self._btn_watch)

        # A screen reader reads these buttons' glyph (↑ ⌂ ☆ ↻ ◉ ◎ ✕) or
        # nothing at all: each gets a name (review round 3).
        for btn, name in (
            (self._btn_target, tr("Set as transfer target")),
            (self._btn_close, tr("Close pane")),
            (self._btn_up, tr("Parent folder")),
            (self._btn_home, tr("Home folder")),
            (self._btn_bookmark, tr("Bookmark the current folder")),
            (self._btn_refresh, tr("Refresh")),
            (self._btn_watch, tr("Auto-refresh")),
        ):
            btn.setAccessibleName(name)

        layout.addLayout(path_bar)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(2)

        filter_label = QLabel(tr("Filter:"))
        filter_label.setFixedWidth(40)
        filter_bar.addWidget(filter_label)

        self._filter_edit = QLineEdit()
        self._filter_edit.setObjectName("axPaneFilter")
        self._filter_edit.setProperty("axHelpTopic", "path-bar")
        self._filter_edit.setPlaceholderText(tr("Type to filter files…"))
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.textChanged.connect(self._on_filter_changed)
        filter_bar.addWidget(self._filter_edit)

        layout.addLayout(filter_bar)

        # Loading indicator
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # Indeterminate
        self._progress_bar.setFixedHeight(3)
        self._progress_bar.setTextVisible(False)
        # Keep the layout cell reserved while the bar is hidden.
        # Without this, Qt drops the cell on hide() and everything below
        # slides up by the bar's height plus the layout spacing — 3 + 2 =
        # 5 px. navigate() shows the bar on entry and hides it in its
        # finally block, so every single directory change made the file
        # list twitch down and back up.
        _bar_policy = self._progress_bar.sizePolicy()
        _bar_policy.setRetainSizeWhenHidden(True)
        self._progress_bar.setSizePolicy(_bar_policy)
        self._progress_bar.hide()
        layout.addWidget(self._progress_bar)

        # File table
        self._model = FileTableModel(self)
        self._proxy = FileSortProxyModel(self)
        self._proxy.setSourceModel(self._model)
        # The count in the status line follows the rows shown.
        self._count_text = ""
        self._count_pending = False
        for signal in (self._proxy.rowsInserted, self._proxy.rowsRemoved,
                       self._proxy.modelReset, self._proxy.layoutChanged):
            signal.connect(self._count_changed)
        #: The window's "Show Hidden Files" for this pane, and the folder a
        #: Reveal showed hidden entries in for its entry (None: none).
        self._hidden_pref = False
        self._reveal_hidden_in: str | None = None
        self._proxy.setFilterKeyColumn(0)  # Filter on name column
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setSortRole(Qt.ItemDataRole.DisplayRole)

        self._table = _DragTableView(self)
        self._table.setModel(self._proxy)
        detach_header_selection(self._table)
        # Tags (core.tags): dots in the Name column, listed in its tooltip.
        from ui.tag_ui import TagDotsDelegate

        self._model.tag_lookup = self._tags_of_item
        self._table.setItemDelegateForColumn(0, TagDotsDelegate(self))
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.selectionModel().selectionChanged.connect(lambda: self.selection_changed.emit())
        # A new listing resets the model, which drops the selection without a
        # selectionChanged: say so, or a listener keeps the old folder's file.
        self._proxy.modelReset.connect(lambda: self.selection_changed.emit())
        # What a column needs depends on what it shows: measure again, once,
        # after the listing changes (see _content_width).
        self._content_widths: dict[int, int] = {}
        self._content_fit_pending = False
        # Columns the fitting hid to give a name room (never a user choice).
        self._fit_hidden: set[int] = set()
        for signal in (
            self._proxy.modelReset,
            self._proxy.layoutChanged,
            self._proxy.rowsInserted,
            self._proxy.rowsRemoved,
            self._proxy.dataChanged,
        ):
            signal.connect(self._content_widths_changed)

        # Enable drag & drop on the table
        self._table.setDragEnabled(True)
        self._table.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self._table.setAcceptDrops(True)
        self._table.viewport().setAcceptDrops(True)
        self._table.setDefaultDropAction(Qt.DropAction.CopyAction)
        self._table.setDropIndicatorShown(True)
        # While a file drag is over the list: a frame around the row the
        # drop goes into and "Move to <folder>" beside the cursor - a drop
        # on ".." goes one folder up, which nothing else shows.
        viewport = self._table.viewport()
        self._drop_row_marker = QFrame(viewport)
        self._drop_row_marker.setObjectName("axDropRowMarker")
        self._drop_row_marker.setStyleSheet(
            "#axDropRowMarker { border: 2px solid palette(highlight); border-radius: 3px; }")
        self._drop_hint = QLabel(viewport)
        self._drop_hint.setObjectName("axDropHint")
        self._drop_hint.setStyleSheet(
            "#axDropHint { background: palette(tooltip-base); color: palette(tooltip-text);"
            " border: 1px solid palette(highlight); border-radius: 3px; padding: 2px 6px; }")
        for widget in (self._drop_row_marker, self._drop_hint):
            widget.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            widget.hide()

        # Column sizing — every divider is draggable. Name takes whatever
        # width the other columns leave, so the columns always fill the
        # pane (no empty tail); dragging the divider right of Name moves
        # space between Name and the next visible column. Double-click on
        # a divider fits that column to its content.
        header = self._table.horizontalHeader()
        header.setSectionsMovable(True)
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(_MIN_COLUMN_WIDTH)
        self._fitting = False
        for col in range(self._model.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            if col != 0:
                header.resizeSection(col, _DEFAULT_COLUMN_WIDTHS.get(col, 100))
        # Apply persisted prefs (widths + hidden columns) and wire
        # up the right-click "show/hide column" menu and the
        # save-on-resize hook. ``_apply_column_prefs`` handles bad /
        # missing files gracefully.
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_header_menu)
        header.sectionResized.connect(self._on_section_resized)
        header.sectionMoved.connect(self._on_section_moved)
        self._apply_column_prefs()

        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)

        layout.addWidget(self._table, stretch=1)

        # Status bar with disk usage
        # The message is cut with "…" (whole in its tooltip) and keeps its
        # room before the free space does (ui.elided_label; UX review
        # round 7: "2 Pfade in die Zwische" at 1024x600).
        from ui.elided_label import ElidedLabel, MessageFirstRow

        self._status = ElidedLabel()
        self._disk_label = ElidedLabel()
        self._disk_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        status_layout = MessageFirstRow(self._status, self._disk_label)
        self._status_row = status_layout
        status_layout.setSpacing(8)

        status_layout.addWidget(self._status)

        # Shown only while a folder loads in the background.
        self._cancel_nav_btn = QPushButton(tr("Cancel"))
        self._cancel_nav_btn.setToolTip(tr("Stop loading this folder (Esc)"))
        self._cancel_nav_btn.clicked.connect(self.cancel_navigation)
        self._cancel_nav_btn.hide()
        status_layout.addWidget(self._cancel_nav_btn)

        # Shown only while Calculate Size walks in the background.
        self._cancel_size_btn = QPushButton(tr("Cancel"))
        self._cancel_size_btn.setToolTip(tr("Stop calculating the size"))
        self._cancel_size_btn.clicked.connect(self._cancel_dir_size)
        self._cancel_size_btn.hide()
        status_layout.addWidget(self._cancel_size_btn)
        self._size_job: ScanJob | None = None
        # Shown only while Show Checksum asks the backend or reads the file.
        self._cancel_checksum_btn = QPushButton(tr("Cancel"))
        self._cancel_checksum_btn.setToolTip(tr("Stop the checksum"))
        self._cancel_checksum_btn.clicked.connect(self._cancel_checksum)
        self._cancel_checksum_btn.hide()
        status_layout.addWidget(self._cancel_checksum_btn)
        self._checksum_job: ScanJob | None = None
        # What a file is / where a link leads, read for a double-click, F3, F4.
        self._probe_job: ScanJob | None = None
        self._probe_text = ""
        self._probe_then = (None, None, None)
        # New Folder / New File / Rename: their backend calls (see _run_op).
        self._op_job: ScanJob | None = None
        self._op_text = ""
        self._op_then = (None, "", "", None)
        # Shown only while Delete / Move to Trash runs in the background.
        self._cancel_delete_btn = QPushButton(tr("Cancel"))
        self._cancel_delete_btn.setToolTip(tr("Stop the delete after the entry in progress"))
        self._cancel_delete_btn.clicked.connect(self._cancel_removal)
        self._cancel_delete_btn.hide()
        status_layout.addWidget(self._cancel_delete_btn)
        self._removal_job: ScanJob | None = None
        # The running delete: phase "check" (the walk before the question)
        # or "remove"; empty while none runs.
        self._removal_ctx: dict = {}
        # Edit > Settings > General > Activate a pane: resting the mouse here makes this the active
        # pane after the configured delay (core.pane_activation).
        self._hover_timer = QTimer(self)
        self._hover_timer.setSingleShot(True)
        self._hover_timer.timeout.connect(self._activate_by_hover)

        status_layout.addStretch()

        # Which proxy carries this pane's connection (empty = direct).
        self._proxy_label = QLabel()
        self._proxy_label.setProperty("role", "muted")
        self._proxy_label.hide()
        status_layout.addWidget(self._proxy_label)

        self._disk_label.setProperty("role", "muted")
        status_layout.addWidget(self._disk_label)

        layout.addLayout(status_layout)

        for widget in (
            self,
            self._table,
            self._table.viewport(),
            self._path_edit,
            self._filter_edit,
            self._btn_up,
            self._btn_home,
            self._btn_refresh,
            self._btn_bookmark,
        ):
            widget.installEventFilter(self)

        # Pane rearrangement drops (ui/pane_drag.py), shared with terminal panes
        self._pane_drop = PaneDropZones(self)
        self._drop_overlay = self._pane_drop.overlay

    def _fetch_listing(self, path: str) -> tuple[str, list]:
        """Backend part of a navigation: normalised path + listing (with the
        ".." row). Touches no widget, so it may run on a worker thread."""
        path = self._backend.normalize(path)
        items = self._backend.list_dir(path)
        # Prepend ".." entry for navigating up (except at root), and "." -
        # this folder, a drop target for a drag from the other pane.
        parent = self._backend.parent(path)
        if parent != path:
            items.insert(0, FileItem(name="..", is_dir=True))
        items.insert(0, FileItem(name=".", is_dir=True))
        # Sorted for the model's current sort and the filter's facts worked
        # out here, off the GUI thread (models.file_table_model) - and the
        # orphan-temp check _apply_listing makes (115 ms per 100,000 names).
        from core import atomic_recovery as AR

        listing = prepare_listing(items, self._model)
        listing.has_orphan_name = AR.any_orphan_name(getattr(i, "name", "") for i in items)
        return path, listing

    def _read_disk_usage(self, path: str):
        """``(total, used, free)`` or ``None``; safe on a worker thread."""
        try:
            return self._backend.disk_usage(path)
        except Exception as e:  # noqa: BLE001 — usage is a nicety
            log.debug("Disk usage unavailable for %s on %s: %s", path, self._backend.name, e)
            return None

    def _apply_listing(self, path: str, items: list, history="push", usage=_UNSET,
                       listed_after: int = -1, keep_sizes: bool = False) -> None:
        """UI part of a navigation. *history* is ``"push"`` (record the path),
        ``"keep"`` (refresh: leave the history alone) or an int (back / forward:
        move to that position). *listed_after* is the watcher's last report
        when the listing was asked for (-1: unknown) - a change reported up
        to then is in it (_on_debounce_fired)."""
        self._shown_listing_after = listed_after
        # The same folder again (F5, an operation, the watcher): the model
        # reset drops the selection, so it is taken by name and given back -
        # and the view stays where the user scrolled it (see _keep_place).
        same_folder = path == self._current_path
        keep = self._selection_by_name() if same_folder else None
        places = self._scroll_places() if same_folder else None
        # Calculated folder sizes go with a reload the user asked for (F5)
        # and with another folder; a refresh of its own keeps them.
        self._model.set_items(items, keep_sizes=keep_sizes and same_folder)
        self._keep_place(places, keep)
        if listed_after >= 0 and self._watch_report > listed_after:
            # A change reported while the folder was being listed may not be
            # in it: look again. (A report during a load was dropped before -
            # a change on a slow server stayed unseen.)
            if self._watch_debounce is not None:
                self._watch_debounce.start()
        if history == "push":
            if not self._history or path != self._history[self._history_pos]:
                # Truncate forward history and append
                self._history = self._history[: self._history_pos + 1]
                self._history.append(path)
                self._history_pos = len(self._history) - 1
        elif isinstance(history, int):
            self._history_pos = history
        if self._reveal_hidden_in is not None and path != self._reveal_hidden_in:
            # Hidden entries were shown for one Reveal in that folder only.
            self._reveal_hidden_in = None
            self._proxy.show_hidden = self._hidden_pref
        self._current_path = path
        self._apply_cut_marks()
        self._retire_stale_menus()
        self._path_edit.setText(path)
        self._status.setText(self._items_text())
        self.path_changed.emit(path)
        log.debug("Navigated to %s", path)
        if usage is _UNSET:
            self._update_disk_usage()
        else:
            self._show_disk_usage(usage)
        # Switch the auto-refresh watcher to the new path. We
        # start AFTER the successful navigation so a transient
        # OSError above doesn't leave a stale watcher attached. It starts
        # from this listing instead of listing the folder again.
        self._start_watcher(self._raw_listing(self._backend, path, items))
        # Opportunistic crash-recovery sweep — only the directory
        # we just landed in, only files older than the conservative
        # default age. Reuse the listing we already fetched so a
        # remote backend doesn't pay for a second list_dir. Only when
        # the listing holds a candidate (a name check, no I/O), and then
        # on a thread of its own: a remove() per orphan on a server held
        # the window. It only logs; a backend that cannot remove() (a
        # read-only mount) cannot break navigation.
        from core import atomic_recovery as AR

        orphan = getattr(items, "has_orphan_name", None)
        if orphan is None:
            orphan = AR.any_orphan_name(getattr(i, "name", "") for i in items)
        if orphan:
            backend = self._backend
            threading.Thread(target=_sweep_orphans, args=(backend, path, list(items)),
                             name="orphan-sweep", daemon=True).start()

    def navigate(self, path: str) -> None:
        """Load *path* and wait for it (programmatic callers and tests).
        The UI itself uses :meth:`navigate_async`."""
        if self._nav_ctx:
            # Supersede a background load like a new navigate_async does:
            # its late result would otherwise replace this listing.
            self._nav_job.abandon()
            self._end_loading()
        self._progress_bar.show()
        self._status.setText(tr("Loading…"))
        QApplication.processEvents()

        try:
            listed_after = self._watch_report
            path, items = self._fetch_listing(path)
            # Track history (skip during back/forward and refresh)
            self._apply_listing(path, items, "keep" if self._history_navigating else "push",
                                listed_after=listed_after)
        except OSError as e:
            log.error("Navigation failed: %s", e)
            self._feedback(tr("Error: {error}").format(error=describe(e, path)))
        finally:
            self._progress_bar.hide()

    # --- background loading -------------------------------------------------
    @property
    def is_loading(self) -> bool:
        return bool(self._nav_ctx)

    def navigate_async(
        self, path: str, history="push", quiet: bool = False, fallback: str | None = None,
        keep_sizes: bool = False,
    ) -> None:
        """Load *path* on a worker thread. The current listing stays shown
        and usable; a status line with a Cancel button reports the load
        (``quiet=True`` for background refreshes: no busy UI). A new call
        supersedes a running one; its late result is dropped. The folder
        changes only once the listing arrived: a failure or cancel leaves
        the pane where it was - or, with *fallback*, a failure (not a
        cancel) loads *fallback* instead (a restored folder that is gone
        comes back as home, decided off the GUI thread)."""
        self._status_before = self._status.text()
        self._nav_ctx = {"path": path, "history": history, "quiet": quiet,
                         "fallback": fallback, "keep_sizes": keep_sizes}
        if not quiet:
            self._progress_bar.show()
            self._cancel_nav_btn.show()
            self._status.setText(tr("Loading {path}…").format(path=_shorten_path(path)))

        def work(cancel, progress):
            # One listing at a time on this backend: a superseded load that is
            # still inside list_dir finishes before the next one starts.
            with self._nav_lock:
                if cancel():
                    return None
                listed_after = self._watch_report
                real, items = self._fetch_listing(path)
                return real, items, self._read_disk_usage(real), listed_after

        self._nav_job.start(work, replace=True)

    def refresh_async(self, quiet: bool = False, keep_sizes: bool = False) -> None:
        """Reload the current folder in the background; history untouched.
        *keep_sizes*: a refresh of its own (watcher, operation), not one the
        user asked for - calculated folder sizes stay."""
        self.navigate_async(self._current_path, history="keep", quiet=quiet,
                            keep_sizes=keep_sizes)

    def refresh_after_change(self, quiet: bool = False) -> None:
        """Show the current folder again after an operation changed it,
        loading in the background instead of blocking the GUI thread.

        A running navigation to another folder is left alone - the pane is
        leaving this one, and the synchronous refresh did not cut it off
        either. A load of this folder is replaced: it may have started
        before the change."""
        ctx = self._nav_ctx
        if ctx and ctx["path"] != self._current_path:
            return
        self.refresh_async(quiet=quiet, keep_sizes=True)

    def cancel_navigation(self) -> None:
        """Stop a running background load (the pane stays where it was)."""
        if not self._nav_ctx:
            return
        ctx = self._nav_ctx
        self._nav_job.abandon()
        self._end_loading()
        if not ctx["quiet"]:
            self._status.setText(tr("Cancelled – still in {path}").format(
                path=_shorten_path(self._current_path)))
        self.navigation_finished.emit(ctx["path"], False)

    def _end_loading(self) -> None:
        self._nav_ctx = {}
        self._progress_bar.hide()
        self._cancel_nav_btn.hide()

    def _on_nav_finished(self, kind: str, value, cancelled: bool) -> None:
        ctx = self._nav_ctx
        if not ctx or self._shutting_down:
            return
        self._end_loading()
        if kind == "error":
            fallback = ctx.get("fallback")
            if fallback and fallback != ctx["path"]:
                log.info("Cannot open %s (%s); showing %s instead", ctx["path"], value, fallback)
                self.navigation_finished.emit(ctx["path"], False)
                self.navigate_async(fallback, history=ctx["history"], quiet=ctx["quiet"])
                return
            log.error("Navigation failed: %s", value)
            if not ctx["quiet"]:
                self._feedback(tr("Error: {error}").format(
                    error=describe(value, ctx["path"])))
            self.navigation_finished.emit(ctx["path"], False)
            return
        if value is None:  # the worker saw the cancel flag first
            self.navigation_finished.emit(ctx["path"], False)
            return
        path, items, usage, listed_after = value
        self._apply_listing(path, items, ctx["history"], usage, listed_after=listed_after,
                            keep_sizes=ctx.get("keep_sizes", False))
        self.navigation_finished.emit(path, True)

    def refresh(self) -> None:
        self._history_navigating = True
        try:
            self.navigate(self._current_path)
        finally:
            self._history_navigating = False

    # ------------------------------------------------------------------
    # Auto-refresh via core.watch
    # ------------------------------------------------------------------
    def _on_watch_toggled(self, on: bool) -> None:
        self._watch_enabled = on
        if on:
            # The listing shown is the watcher's first picture: without it
            # the watcher listed the folder itself, on the GUI thread (a
            # round trip on a server).
            model = self._model
            shown = [model.get_item(row) for row in range(model.rowCount())]
            self._start_watcher(self._raw_listing(self._backend, self._current_path,
                                                  [i for i in shown if i is not None]))
        else:
            self._stop_watcher()

    @staticmethod
    def _raw_listing(backend, path: str, items: list) -> list:
        """*items* without the "." and ".." rows that _fetch_listing put in front."""
        if items and items[0].name == "." and items[0].is_dir:
            items = items[1:]
        if items and items[0].name == ".." and backend.parent(path) != path:
            return items[1:]
        return items

    def _start_watcher(self, listing: list | None = None) -> None:
        """Start a watcher for ``self._current_path`` when needed.

        *listing* is the backend's listing of that path, if one was just
        fetched; the watcher then starts without listing it again.

        Skips the (expensive) restart when the existing watcher is
        already pointing at the current path — refresh() goes through
        navigate() which calls us, so without this guard every poll
        event would tear down and rebuild a watcher thread for the
        same directory.
        """
        if not self._watch_enabled:
            self._stop_watcher()
            return
        if self._watcher is not None and self._watched_path == self._current_path:
            return
        self._stop_watcher()
        try:
            from core import watch as W

            self._watcher = W.watch(
                self._backend,
                self._current_path,
                self._on_backend_change,
                interval=2.0,
                initial_entries=listing,
            )
            self._watched_path = self._current_path
            log.debug("Watcher started for %s", self._current_path)
        except Exception as exc:  # noqa: BLE001 — never let watch crash the pane
            log.warning("Could not start watcher for %s: %s", self._current_path, exc)
            self._watcher = None
            self._watched_path = None

    def _stop_watcher(self, wait: bool = False) -> None:
        """Idempotently stop the current watcher and forget it. Only
        *wait* (closing the pane) waits for its thread: a poll under way
        is a list_dir on a server, and every folder change waited up to a
        second for it; a stopped watcher reports nothing more."""
        if self._watcher is None:
            self._watched_path = None
            return
        try:
            self._watcher.stop(timeout=1.0 if wait else 0.0)
        except Exception as exc:  # noqa: BLE001 — never block shutdown
            log.debug("Watcher.stop() raised: %s", exc)
        finally:
            self._watcher = None
            self._watched_path = None

    def _mark_destroyed(self) -> None:
        self._shutting_down = True

    def _on_backend_change(self, event_type: str, path: str, kind: str) -> None:
        """Watcher callback. Runs on a background thread, so we just
        emit a signal — the GUI thread debounces it into a refresh."""
        if self._shutting_down:
            return
        self._note_watch_report()
        log.debug("Watch event: %s %s (%s)", event_type, path, kind)
        # Queued into the GUI thread (directly when already on it); dropped
        # once the pane is deleted.
        self._watch_call()

    def _on_watch_call(self) -> None:
        self._watch_event_slot()

    def _on_watch_event_signal(self) -> None:
        """GUI-thread bounce for a watch report: just (re)start the
        debounce timer. Wrapped so tests can patch this attribute."""
        if self._shutting_down:
            return
        if self._watch_debounce is not None:
            self._watch_debounce.start()

    def _note_watch_report(self) -> None:
        """The watcher reported a change (any thread)."""
        self._watch_report = next(self._watch_counter)

    def _on_debounce_fired(self) -> None:
        """Debounce timeout — issue the actual refresh. Wrapped so
        tests can patch this attribute and so subclasses can override."""
        if self._shutting_down:
            return
        if self.is_loading:
            # A navigation / refresh is fetching fresh data; a change it
            # may have missed is caught when it is shown (_apply_listing).
            return
        if self._watch_report <= self._shown_listing_after:
            # The listing shown was asked for after the last change the
            # watcher reported: it has that change. An operation's own
            # refresh and the watcher's report of the same change listed
            # the folder twice - a second round trip to a server.
            return
        self.refresh_async(quiet=True, keep_sizes=True)

    def shutdown(self) -> None:
        """Stop background resources owned by this pane.

        Qt does not send ``closeEvent`` for every teardown path:
        ``deleteLater()`` is common in tests and in dynamic splitter
        layouts. Keep cleanup explicit and idempotent so watcher
        threads cannot outlive the widget they report into.
        """
        self._shutting_down = True
        self._drop_own_cut()
        self._nav_job.abandon()
        self._hover_timer.stop()
        if getattr(self, "_size_job", None) is not None:
            self._size_job.abandon()
        if getattr(self, "_checksum_job", None) is not None:
            self._checksum_job.abandon()
        if getattr(self, "_probe_job", None) is not None:
            self._probe_job.abandon()
        if getattr(self, "_op_job", None) is not None:
            self._op_job.abandon()
        if getattr(self, "_removal_job", None) is not None:
            # A removal stops after the entry in progress; its worker gives
            # the claimed paths free when that entry has returned.
            self._removal_job.abandon()
        ctx = getattr(self, "_removal_ctx", None)
        if ctx:
            if ctx["phase"] != "remove":
                _release_removal(ctx["token"])
            self._removal_ctx = {}
        if getattr(self, "_pack_job", None) is not None:
            self._pack_job.abandon()  # the pack stops and removes its temp file
        if getattr(self, "_thumbs", None) is not None:
            self._thumbs.shutdown()
        if self._watch_debounce is not None:
            try:
                self._watch_debounce.stop()
                self._watch_debounce.timeout.disconnect(self._watch_timeout_slot)
            except (TypeError, RuntimeError):
                pass
        self._stop_watcher(wait=True)  # no watcher thread outlives its pane
        handle = getattr(self, "_fuse_handle", None)
        if handle is not None:
            from ui.off_gui import run_off_gui

            try:
                run_off_gui(handle.unmount)  # up to ~15 s: off the GUI thread
            except Exception as exc:  # noqa: BLE001 — never block close
                log.debug("FilePane shutdown: FUSE unmount failed: %s", exc)
            self._fuse_handle = None

    def deleteLater(self) -> None:
        self.shutdown()
        super().deleteLater()

    def closeEvent(self, event) -> None:
        """Stop the watcher thread and unmount any active FUSE mount
        before the widget goes away.

        FUSE: a mount holding a stale backend reference would hang
        kernel callers when the connection dies; unmount here so the
        kernel detaches before we let go of the backend handle.
        """
        self.shutdown()
        super().closeEvent(event)

    def _go_back(self) -> None:
        """Navigate to the previous path in history (Alt+Left)."""
        if self._history_pos > 0:
            pos = self._history_pos - 1
            # The position moves only once the folder has loaded.
            self.navigate_async(self._history[pos], history=pos)

    def _go_forward(self) -> None:
        """Navigate to the next path in history (Alt+Right)."""
        if self._history_pos < len(self._history) - 1:
            pos = self._history_pos + 1
            self.navigate_async(self._history[pos], history=pos)

    def _view_selected(self) -> None:
        """Open selected file read-only (F3) — routes to the best
        viewer: image for supported MIMEs (local only), the media viewer
        for a PDF, text for text files, hex for everything else binary."""
        items = self.selected_file_items()
        files = [i for i in items if not i.is_dir]
        if len(files) != 1:
            return
        item = files[0]
        full_path = self._safe_item_path(item)
        if full_path is None:
            return
        if self._looks_like_image(item.name) and self._open_image_viewer(full_path):
            return
        if self._open_document_viewer(full_path, item.name):
            return
        self._when_binary_known(full_path, item.name, lambda binary: (
            self._open_hex_editor(full_path, read_only=True) if binary
            else self._open_editor(full_path, read_only=True)))

    @staticmethod
    def _looks_like_image(name: str) -> bool:
        """Cheap extension-based sniff; the real allowlist check lives
        inside core.previews.thumbnail(). This just avoids calling
        into the image pipeline for a .txt file."""
        lower = name.lower()
        return lower.endswith(
            (
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".bmp",
                ".webp",
                ".tif",
                ".tiff",
                ".ppm",
                ".pgm",
                ".pbm",
                ".pnm",
            )
        )

    def _open_image_viewer(self, path: str) -> bool:
        """Open *path* in the ImageViewerDialog. Returns True if the
        dialog opened, False if we should fall back to another viewer
        (e.g. remote backend where previews are disabled)."""
        from core import previews as P
        from ui.image_viewer import ImageViewerDialog

        # Gate on is_local — previews refuses remote anyway, but we
        # short-circuit here to avoid a pop-up that just says "remote
        # not supported" when the user probably expects a text fallback.
        if not P._is_local_backend(self._backend):
            return False
        # Build a sibling list so Prev/Next works inside the current dir.
        siblings: list[str] = []
        try:
            for it in self._backend.list_dir(self._current_path):
                if not it.is_dir and self._looks_like_image(it.name):
                    sibling = self._safe_item_path(it, warn=False)
                    if sibling is not None:
                        siblings.append(sibling)
        except OSError:
            siblings = [path]
        if path not in siblings:
            siblings.append(path)
        from ui import viewer_window as VW

        dlg = ImageViewerDialog(
            self._backend,
            path,
            siblings=sorted(siblings),
            parent=VW.owner_window(self),
            source_pane=self,
        )
        if dlg.loaded:
            VW.show_independent(dlg)
        else:  # it said why; nothing to show
            dlg.deleteLater()
        return True

    def _open_document_viewer(self, path: str, name: str) -> bool:
        """Open the PDF *name* (in this folder) on its own in the media
        viewer - "document mode": file navigation has nothing to step to,
        the page control turns its pages. Returns False when *name* is no
        PDF or the viewer cannot show it (QtPdf missing, the security mode
        blocks the media viewer); the caller then opens the hex editor."""
        from core import media_collect as MC
        from core.security_mode import current_policy
        from ui import media_viewer as MV

        if MC.classify(name) != MC.PDF:
            return False
        if not MV.pdf_supported():
            log.info(
                "Opening %s in the hex editor: PDF viewing needs QtPdf, "
                "which cannot be loaded here",
                path,
            )
            return False
        policy = current_policy()
        if not policy.allow_auto_preview:
            log.info(
                "Opening %s in the hex editor: the '%s' security mode blocks the media viewer",
                path,
                policy.name,
            )
            return False
        options = MV.MediaViewOptions(kinds=frozenset({MC.PDF}), start_mode=MV.START_BROWSE)
        self.open_media_viewer(options, only_names={name})
        return True

    #: The last media-view choices, shared by every pane for the session.
    _media_view_defaults = None

    def open_metadata(self, action: str = "show"):
        """Open the metadata window on the selection (files and folders) or,
        with nothing selected, on this folder. *action* is ``show``,
        ``remove`` or ``export``; returns the window."""
        from ui.metadata_dialog import MetadataDialog

        targets: list[tuple[str, bool]] = []
        for item in self.selected_file_items():
            path = self._safe_item_path(item, warn=False)
            if path is not None:
                targets.append((path, bool(item.is_dir)))
        if not targets:
            targets = [(self._current_path, True)]
        dlg = MetadataDialog(self._backend, targets, action=action, parent=self)
        dlg.changed.connect(lambda: self.refresh_after_change(quiet=True))
        self.metadata_dialogs.append(dlg)
        dlg.destroyed.connect(
            lambda _obj=None, d=dlg: self.metadata_dialogs.remove(d)
            if d in self.metadata_dialogs
            else None
        )
        dlg.show()
        dlg.start()
        return dlg

    def show_disk_image(self, path: str | None = None):
        """Disk Image…: the partitions and file systems of the selected
        image, with a loop mount for a local one (ui/disk_image_dialog.py).
        Returns the window, or None without an image."""
        from ui.disk_image_dialog import DiskImageDialog

        if path is None:
            items = self.selected_file_items()
            if len(items) != 1:
                return None
            path = self._safe_item_path(items[0], warn=False)
            if path is None:
                return None
        dlg = DiskImageDialog(self._backend, path, parent=self,
                              open_folder=getattr(self.window(), "open_local_folder", None))
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dlg.show()
        dlg.start()
        return dlg

    def identify_file_type(self):
        """Open the Identify File Type window on the selection: the real type
        of each entry from its content, what its extension claims and
        whether they disagree. Returns the window, or ``None`` when nothing
        is selected."""
        from ui.file_type_dialog import FileTypeDialog

        paths = [
            path
            for path in (self._safe_item_path(i, warn=False) for i in self.selected_file_items())
            if path is not None
        ]
        if not paths:
            return None
        dlg = FileTypeDialog(self._backend, paths, parent=self)
        backend = self._backend
        dlg.identified.connect(
            lambda path, info, b=backend: self._remember_file_type(b, path, info)
        )
        self.file_type_dialogs.append(dlg)
        dlg.destroyed.connect(
            lambda _obj=None, d=dlg: self.file_type_dialogs.remove(d)
            if d in self.file_type_dialogs
            else None
        )
        dlg.show()
        dlg.start()
        return dlg

    #: Identify results kept per pane; the oldest go first beyond this.
    _IDENTIFIED_LIMIT = 2048

    def _remember_file_type(self, backend, path: str, info) -> None:
        """Keep whether Identify found *path* to be a disk image (with its
        size, so a changed file is not trusted) - only for the backend the
        pane still shows."""
        from core.disk_image import type_says_image

        if backend is not self._backend or getattr(info, "kind", "") != "file":
            return
        self._identified_images.pop(path, None)
        self._identified_images[path] = (info.size, type_says_image(info.mime, info.engine))
        while len(self._identified_images) > self._IDENTIFIED_LIMIT:
            self._identified_images.pop(next(iter(self._identified_images)))

    def _content_says_disk_image(self, item, path: str) -> bool:
        """Whether the content of *item* (at *path*) says disk image, for
        Disk Image… in the menu - cheap on the GUI thread: what Identify
        found for this size of the file, else for a local regular file its
        first 4 KiB (core.disk_image.local_content_says_image). A remote
        file is never read here: opening a menu must not wait on the
        network. Nor a LocalFS subclass (an MTP device's FUSE mount may
        fetch the whole file on open) - plain LocalFS only."""
        if item.is_dir:
            return False
        known = self._identified_images.get(path)
        if known is not None and known[0] == item.size:
            return known[1]
        from core.disk_image import local_content_says_image
        from core.local_fs import LocalFS

        if type(self._backend) is not LocalFS:
            return False
        return local_content_says_image(path)

    def identify_folder(self, directory: str | None = None):
        """Open Identify Files in This Folder… on *directory* (default: the
        selected folder, else the folder shown - :meth:`terminal_directory`):
        every file in it identified by content in the background, through
        this pane's backend. Returns the window."""
        from ui.file_type_dialog import FolderFileTypeDialog

        dlg = FolderFileTypeDialog(self._backend, directory or self.terminal_directory(),
                                   parent=self)
        self.file_type_dialogs.append(dlg)
        dlg.destroyed.connect(
            lambda _obj=None, d=dlg: self.file_type_dialogs.remove(d)
            if d in self.file_type_dialogs
            else None
        )
        dlg.show()
        dlg.start()
        return dlg

    def view_media(self, selected_only: bool = False):
        """Ask for the media-view options, then open the media viewer on
        this folder (or on the selected files and folders). Returns the
        viewer window, or ``None`` when nothing was opened."""
        from core.security_mode import current_policy
        from ui.media_viewer import MediaViewOptionsDialog

        policy = current_policy()
        if not policy.allow_auto_preview:
            QMessageBox.warning(
                self,
                tr("View Media"),
                tr("The '{mode}' security mode blocks the media viewer.").format(mode=policy.name),
            )
            return None
        names = None
        if selected_only:
            names = {item.name for item in self.selected_file_items()}
            if not names:
                return None
        dialog = MediaViewOptionsDialog(
            self, selection=selected_only, defaults=FilePaneWidget._media_view_defaults
        )
        if dialog.exec() != MediaViewOptionsDialog.DialogCode.Accepted:
            return None
        options = dialog.options()
        FilePaneWidget._media_view_defaults = options
        return self.open_media_viewer(options, only_names=names)

    def open_media_viewer(self, options, only_names: set[str] | None = None):
        """Open the media viewer without asking (``options`` already chosen)."""
        from ui.media_viewer import MediaViewerDialog

        dialog = MediaViewerDialog(
            self._backend,
            self._current_path,
            options,
            only_names=only_names,
            include_hidden=bool(getattr(self._proxy, "show_hidden", False)),
            parent=self.window(),
            source_pane=self,
        )
        dialog.show()
        dialog.start()
        return dialog

    def _edit_selected(self) -> None:
        """Open selected file in editor (F4) — text or hex based on type."""
        items = self.selected_file_items()
        files = [i for i in items if not i.is_dir]
        if len(files) != 1:
            return
        item = files[0]
        full_path = self._safe_item_path(item)
        if full_path is None:
            return
        self._when_binary_known(full_path, item.name, lambda binary: (
            self._open_hex_editor(full_path) if binary else self._open_editor(full_path)))

    def _copy_to_target(self) -> None:
        """Copy selected items to the target pane (F5)."""
        selected = self.selected_items()
        if selected:
            self.transfer_requested.emit(selected)

    def _move_to_target(self) -> None:
        """Move selected items to the target pane (F6). The production
        countdown is the main window's (``_request_transfer``), which every
        move passes; asking here too would ask twice."""
        selected = self.selected_items()
        if selected:
            self.move_requested.emit(selected)

    # -- Cut / Paste (ui.cut_clipboard) -----------------------------------------

    def cut_selected(self) -> bool:
        """Cut (Ctrl+X): remember the selected entries for a Paste in any
        pane. Nothing is removed here - the move happens on Paste, and a
        cut that is never pasted leaves every entry where it is. False when
        nothing usable is selected (a pending cut then stays)."""
        from ui.cut_clipboard import cut_clipboard

        paths = self.selected_items()
        if not paths:
            return False
        cut_clipboard().cut(self, self._backend, self._current_path, paths)
        self._feedback(
            tr("Cut {count} item(s): Paste (Ctrl+V) in a folder moves them there").format(
                count=len(paths))
        )
        return True

    def can_paste(self) -> bool:
        """A Cut or Copy is pending and a window listens to do the transfer."""
        from ui.cut_clipboard import cut_clipboard

        return (cut_clipboard().pending is not None
                and self.receivers(self.paste_requested) > 0)

    def paste_cut(self) -> bool:
        """Paste (Ctrl+V): move the pending Cut - or copy the pending Copy -
        into this pane's folder (the main window checks, asks about name
        conflicts and queues the transfer)."""
        if not self.can_paste():
            return False
        self.paste_requested.emit()
        return True

    def _drop_own_cut(self) -> bool:
        """Forget a pending Cut of this pane; its entries stay where they are."""
        from ui.cut_clipboard import cut_clipboard

        return cut_clipboard().drop_source(self)

    def _apply_cut_marks(self) -> None:
        """Dim the entries of this folder that a pending Cut holds."""
        if self._shutting_down:
            return
        from ui.cut_clipboard import cut_clipboard

        self._model.set_cut_names(cut_clipboard().names_in(self._backend, self._current_path))

    def _production_ok(self, op_desc: str) -> bool:
        """The production tarpit for a destructive entry of this pane
        (see ui.production_gate): False when the user stopped it."""
        from ui.production_gate import confirm_production

        return confirm_production(self, self._backend, op_desc)

    def _select_all(self) -> None:
        """Select all items except '..' (Ctrl+A)."""
        sel = self._table.selectionModel()
        sel.blockSignals(True)
        self._table.selectAll()
        # Deselect the "." and ".." rows - each of them: both may be listed.
        # The proxy knows where they are (no look at every row).
        for row in self._proxy.nav_rows():
            sel.select(
                self._proxy.index(row, 0),
                sel.SelectionFlag.Deselect | sel.SelectionFlag.Rows,
            )
        sel.blockSignals(False)
        self.selection_changed.emit()

    def _toggle_select_and_move_down(self) -> None:
        """Toggle selection on current row and move cursor down (Space, MC-style)."""
        current = self._table.currentIndex()
        if not current.isValid():
            return
        source_idx = self._proxy.mapToSource(current)
        item = self._model.get_item(source_idx.row())
        if item and item.is_nav:
            # Don't toggle "." / "..", just move down
            pass
        else:
            sel = self._table.selectionModel()
            row_idx = self._proxy.index(current.row(), 0)
            if sel.isSelected(row_idx):
                sel.select(row_idx, sel.SelectionFlag.Deselect | sel.SelectionFlag.Rows)
            else:
                sel.select(row_idx, sel.SelectionFlag.Select | sel.SelectionFlag.Rows)
        # Move cursor down - without touching the marks: the view's
        # setCurrentIndex applies the ExtendedSelection command
        # (ClearAndSelect), which wiped every mark but the new row.
        next_row = current.row() + 1
        if next_row < self._proxy.rowCount():
            next_idx = self._proxy.index(next_row, current.column())
            self._table.selectionModel().setCurrentIndex(
                next_idx, QItemSelectionModel.SelectionFlag.NoUpdate
            )
            view = self._thumbs if self.view_mode == "thumbnails" else self._table
            view.scrollTo(next_idx)

    def _invert_selection(self) -> None:
        """Invert selection on all items except '..' (Ctrl+Shift+A).

        Same result as toggling row by row — a row counts as selected when
        its first cell is; it ends up fully deselected, every other row
        fully selected, and '..' keeps whatever it had — but applied as one
        selection: one select() per row made 20 000 rows take ~40 s.
        """
        proxy = self._proxy
        rows = proxy.rowCount()
        sel = self._table.selectionModel()
        current = sel.selection()
        selected = [False] * rows
        for rng in current:
            if rng.left() <= 0 <= rng.right():
                for r in range(rng.top(), rng.bottom() + 1):
                    selected[r] = True
        last_col = max(proxy.columnCount() - 1, 0)
        final = QItemSelection()
        dotdot_rows = []
        run_start = None
        nav_rows = set(proxy.nav_rows())
        for row in range(rows):
            take = not selected[row]
            if row in nav_rows:
                dotdot_rows.append(row)
                take = False
            if take and run_start is None:
                run_start = row
            elif not take and run_start is not None:
                final.select(proxy.index(run_start, 0), proxy.index(row - 1, last_col))
                run_start = None
        if run_start is not None:
            final.select(proxy.index(run_start, 0), proxy.index(rows - 1, last_col))
        for row in dotdot_rows:  # '..' keeps its cells exactly as they were
            for rng in current:
                if rng.top() <= row <= rng.bottom():
                    final.select(proxy.index(row, rng.left()), proxy.index(row, rng.right()))
        sel.blockSignals(True)
        try:
            sel.clearSelection()
            sel.select(final, sel.SelectionFlag.Select)
        finally:
            sel.blockSignals(False)
        self.selection_changed.emit()

    def _copy_path_text(self) -> None:
        """More ▸ Copy Path: the selected paths as text, one per line and
        control characters escaped - nothing marked for Paste."""
        paths = self.selected_items()
        if not paths:
            return
        lines = [_sanitize_clipboard_text(p) for p in paths]
        QApplication.clipboard().setText("\n".join(text for text, _had in lines))
        status = tr_n(len(paths), "Copied {n} path to the clipboard",
                      "Copied {n} paths to the clipboard")
        if any(had for _text, had in lines):
            status += " " + tr("(control characters escaped)")
        self._feedback(status)

    def _copy_paths_to_clipboard(self) -> None:
        """Copy selected file paths to clipboard (Ctrl+C).

        A remote filesystem is free to have files with newlines (or
        any other control char) in their names. Without sanitising,
        a later shell paste of ``/tmp/harmless\\n; rm -rf /`` would
        execute whatever came after the newline. We escape control
        characters to backslash-escapes so the clipboard stays a
        single visible line per path and the user gets a warning
        when anything non-trivial was re-encoded."""
        paths = self.selected_items()
        if not paths:
            return
        safe_lines: list[str] = []
        any_escaped = False
        for p in paths:
            sanitized, had_control = _sanitize_clipboard_text(p)
            if had_control:
                any_escaped = True
            safe_lines.append(sanitized)
        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(safe_lines))
        # The entries themselves too: Ctrl+V in a pane copies them there
        # (Ctrl+C then Ctrl+V did nothing). Read back - the stored text is
        # how a later paste tells that nothing else was copied meanwhile.
        from ui.cut_clipboard import cut_clipboard

        cut_clipboard().copy(self, self._backend, self._current_path, paths,
                             clipboard.text())
        status = tr_n(len(paths), "Copied {n} path to the clipboard",
                      "Copied {n} paths to the clipboard")
        status += " – " + tr("Paste (Ctrl+V) in a folder copies the files there")
        if any_escaped:
            status += " " + tr("(control characters escaped)")
            log.warning(
                "Clipboard copy: %d path(s) contained control characters — escaped before copy",
                sum(1 for p in paths if _sanitize_clipboard_text(p)[1]),
            )
        self._feedback(status)

    def _safe_item_path(self, item: FileItem, *, warn: bool = True) -> str | None:
        """Return the selected item's child path, rejecting hostile names."""
        from core.path_policy import BackendPathPolicy

        # safe_join, with the backend's policy made once per backend, not
        # once per name: a selection of 90,000 entries asked it 90,000 times.
        backend = self._backend
        held = getattr(self, "_path_policy_of", None)
        if held is None or held[0] is not backend:
            held = self._path_policy_of = (backend, BackendPathPolicy.for_backend(backend))
        try:
            return held[1].join(self._current_path, item.name)
        except ValueError as exc:
            log.warning("Unsafe backend item name %r: %s", item.name, exc)
            if warn:
                QMessageBox.warning(
                    self,
                    tr("Unsafe Item Name"),
                    as_written(tr("Skipping unsafe item name:\n{name}\n\n{error}").format(
                        name=item.name, error=exc)),
                )
            return None

    def selected_items(self) -> list[str]:
        """Return full paths of selected items."""
        return [path for path, _item in self._selected_entries()]

    def _selected_rows(self) -> list[int]:
        """The shown rows selected, as selectedRows() gives them - read off
        the selection's ranges. selectedRows() asks the model for the flags
        of every column of every row it checks: 0.4 s for 20 000 selected
        rows, on every copy, refresh and right-click. The table selects
        whole rows; a range that is not one (a cell selected by code) falls
        back to selectedRows()."""
        sel = self._table.selectionModel()
        last = self._proxy.columnCount() - 1
        ranges = list(sel.selection())
        if any(r.left() != 0 or r.right() != last for r in ranges):
            return [index.row() for index in sel.selectedRows(COL_NAME)]
        return list(dict.fromkeys(row for r in ranges for row in range(r.top(), r.bottom() + 1)))

    def _selected_source_items(self) -> list[FileItem]:
        """The listing items of the selected rows ("." and ".." included)."""
        get = self._model.get_item
        return [item for row in self._proxy.source_rows_of(self._selected_rows())
                if (item := get(row)) is not None]

    def _selected_entries(self) -> list[tuple[str, FileItem]]:
        """``(full path, listing item)`` of every selected row but "." and "..".

        A row whose name cannot be joined safely on this backend is left
        out, and the status line says so: a copy that silently misses a
        selected file looks complete."""
        entries = []
        left_out = []
        for item in self._selected_source_items():
            if not item.is_nav:
                path = self._safe_item_path(item, warn=False)
                if path is not None:
                    entries.append((path, item))
                else:
                    left_out.append(item.name)
        if left_out:
            self._feedback(
                tr("{count} selected item(s) left out: name not usable here ({names})").format(
                    count=len(left_out),
                    names=", ".join(repr(n) for n in left_out[:3]),
                )
            )
        return entries

    def _selection_by_name(self) -> tuple[set[str], str | None] | None:
        """The selected rows' names and the current row's name, or None
        when there is neither. The current row counts on its own: after
        Space (mark and move down) it is the next, unmarked row - a
        refresh dropped it and the next arrow key started at the top."""
        sel = self._table.selectionModel()
        names = {item.name for item in self._selected_source_items()}
        current = None
        index = sel.currentIndex()
        if index.isValid():
            current = self._model.get_item(self._proxy.mapToSource(index).row())
        current_name = current.name if current is not None else None
        if not names and current_name is None:
            return None
        return names, current_name

    def reveal_path(self, path: str) -> None:
        """Show the folder holding *path* with that entry selected and
        scrolled into view - loading the folder in the background first
        when the pane shows another one."""
        backend = self._backend
        folder = backend.parent(path)
        name = path[len(folder):].lstrip("/\\") if path.startswith(folder) else path
        if not name:
            return

        def select() -> None:
            note = self._make_visible(name)
            self._restore_selection({name}, name)
            index = self._table.currentIndex()
            if index.isValid():
                self._table.scrollTo(index)
            self._table.setFocus()
            if note:
                self.status_message(note)

        if folder == self._current_path and not self.is_loading:
            select()
            return

        def arrived(loaded: str, ok: bool) -> None:
            try:
                self.navigation_finished.disconnect(arrived)
            except (TypeError, RuntimeError):
                pass
            if ok and loaded == folder and backend is self._backend and not self._shutting_down:
                select()

        self.navigation_finished.connect(arrived)
        self.navigate_async(folder)

    def _make_visible(self, name: str) -> str:
        """Let the entry *name* of this folder be seen for a Reveal: the
        filter typed earlier is cleared, and hidden entries are shown in
        this folder (until the pane goes to another one) when the entry is
        hidden and they are not shown. Returns what was changed, for the
        status line ("" when nothing had to be).

        Before, the reveal selected nothing and said nothing: the entry was
        there, but filtered out."""
        proxy = self._proxy
        for row in range(self._model.rowCount()):
            item = self._model.get_item(row)
            if item is None or item.name != name:
                continue
            index = self._model.index(row, COL_NAME)
            if proxy.mapFromSource(index).isValid():
                return ""
            cleared = shown = False
            if self._filter_edit.text():
                self._filter_edit.clear()
                cleared = True
            if not proxy.mapFromSource(index).isValid() and item.is_hidden \
                    and not proxy.show_hidden:
                proxy.show_hidden = True
                self._reveal_hidden_in = self._current_path
                shown = True
            if cleared and shown:
                text = tr("Filter cleared and hidden entries shown in this folder to show {name}")
            elif cleared:
                text = tr("Filter cleared to show {name}")
            elif shown:
                text = tr("Hidden entries shown in this folder to show {name}")
            else:
                return ""
            return text.format(name=name)
        return tr("{name} is not in this folder").format(name=name)

    def _wait(self, fn, text: str):
        """*fn()* - backend calls an action needs the answer of before it
        goes on (encrypt, decrypt, a link's target) - off the GUI thread:
        the windows keep painting meanwhile (ui.off_gui)."""
        from ui.off_gui import run_off_gui

        return run_off_gui(fn, text=text, status=lambda shown: self._status.setText(
            shown or self._items_text()))

    def _items_text(self) -> str:
        """The status line's count: the entries, not the "." and ".." rows -
        and what the backend has to say about its state, if anything (a
        Git URL session: offline, or commits not pushed to origin)."""
        # The entries shown, not all listed: hidden ones (and those the
        # filter leaves out) are counted apart (UX review round 7).
        shown, hidden, filtered = self._proxy.entry_counts()
        if filtered:
            text = tr_n(shown + filtered, "{shown} of {n} item", "{shown} of {n} items",
                        shown=shown)
        else:
            text = tr_n(shown, "{n} item", "{n} items")
        if hidden:
            text += " " + tr_n(hidden, "({n} hidden)", "({n} hidden)")
        note_of = getattr(self._backend, "status_note", None)
        if callable(note_of):
            try:
                note = note_of()
            except Exception:  # noqa: BLE001 - a status line never breaks a listing
                note = ""
            if isinstance(note, str) and note:
                text = f"{text} \u00b7 {note}"
        self._count_text = text
        return text

    def _count_changed(self, *_args) -> None:
        """The rows shown changed (filter, Show Hidden Files): the count
        in the status line follows - unless a message stands there."""
        if not self._count_pending:
            self._count_pending = True
            QTimer.singleShot(0, self._refresh_count)

    def _refresh_count(self) -> None:
        self._count_pending = False
        if getattr(self, "_status", None) is None:
            return
        if self._status.text() == self._count_text:
            self._status.setText(self._items_text())

    def _list_views(self) -> list:
        """The table and, once made, the thumbnail view: both show the model."""
        views = [self._table]
        thumbs = getattr(self, "_thumbs", None)
        if thumbs is not None:
            views.append(thumbs)
        return views

    def _scroll_places(self) -> list[tuple[int, int]]:
        return [(v.verticalScrollBar().value(), v.horizontalScrollBar().value())
                for v in self._list_views()]

    def _keep_place(self, places, keep) -> None:
        """After the model was reset: a refresh (*places* given) puts each
        view back where it was scrolled and the selection back without
        Qt's auto-scroll to the current row; another folder starts at the
        top. Reported: scrolling up went to the top and then started at
        the bottom again - every refresh (the watcher, a transfer writing
        into the folder) jumped to the row last clicked."""
        views = self._list_views()
        for view in views:
            # The scroll ranges follow a reset only at the next layout: now,
            # so a value set below is not cut to the old list's range.
            view.executeDelayedItemsLayout()
        if keep:
            held = [(view, view.hasAutoScroll()) for view in views]
            for view, _on in held:
                view.setAutoScroll(False)
            try:
                self._restore_selection(*keep)
            finally:
                for view, on in held:
                    view.setAutoScroll(on)
        for index, view in enumerate(views):
            vertical, horizontal = places[index] if places and index < len(places) else (0, 0)
            view.verticalScrollBar().setValue(vertical)
            view.horizontalScrollBar().setValue(horizontal)

    def _restore_selection(self, names: set[str], current: str | None) -> None:
        """Select the rows named ``names`` in one change; ``current`` back as current.

        One range per run of adjacent rows: one per row made Qt merge 20 000
        ranges for a folder with everything selected (2 s on every refresh)."""
        proxy = self._proxy
        rows = []
        current_index = None
        # The listing's names as one list (the model keeps it for the
        # filter): no get_item call per row (100 ms per 100,000 entries).
        listed = self._model.row_cache().names
        wanted = names | {current} if current is not None else names
        for row in [r for r, name in enumerate(listed) if name in wanted]:
            item = self._model.get_item(row)
            if item is None or item.name not in wanted:
                continue
            index = proxy.mapFromSource(self._model.index(row, COL_NAME))
            if not index.isValid():  # filtered out (hidden files)
                continue
            if item.name == current:
                current_index = index
            if item.name in names:
                rows.append(index.row())
        sel = self._table.selectionModel()
        flags = QItemSelectionModel.SelectionFlag
        if not rows:
            # Nothing marked: the current row alone comes back - NoUpdate,
            # so it stays unmarked.
            if current_index is not None:
                sel.setCurrentIndex(current_index, flags.NoUpdate)
            return
        rows.sort()
        last = proxy.columnCount() - 1
        selection = QItemSelection()
        top = previous = rows[0]
        for row in rows[1:] + [None]:
            if row is not None and row == previous + 1:
                previous = row
                continue
            selection.select(proxy.index(top, 0), proxy.index(previous, last))
            if row is not None:
                top = previous = row
        sel.select(selection, flags.ClearAndSelect | flags.Rows)
        if current_index is not None:
            sel.setCurrentIndex(current_index, flags.NoUpdate)

    def selected_file_items(self) -> list[FileItem]:
        """Return FileItem objects for selected rows."""
        return [item for item in self._selected_source_items() if not item.is_nav]

    def set_show_hidden(self, show: bool) -> None:
        self._hidden_pref = show
        self._reveal_hidden_in = None
        self._proxy.show_hidden = show

    def set_hidden_style(self, highlight: bool, colour: str | None = None) -> None:
        """Hidden entries in italics and in *colour* (``#rrggbb``) or the
        theme's muted colour; off: drawn like every other entry."""
        self._model.highlight_hidden = highlight
        self._model.hidden_color = colour

    def set_proxy_info(self, text: str, tooltip: str = "") -> None:
        """Show the proxy route in the status bar; ``""`` hides it."""
        self._proxy_label.setText(text)
        self._proxy_label.setToolTip(tooltip)
        self._proxy_label.setVisible(bool(text))

    def set_backend(self, backend: FileBackend, path: str | None = None) -> None:
        """Switch to *backend* (a reconnect) and load *path*, else its home.

        The listing on screen belongs to the old connection and is dropped
        here: ``_current_path`` moves at once, and a name selected in the
        old listing would otherwise be joined onto the new folder by the
        next Delete / Rename. The watcher is bound to a backend as well and
        is stopped, so the next listing starts one on the new connection.
        """
        self._stop_watcher()
        self._drop_own_cut()  # its entries belong to the old connection
        self._backend = backend
        self._identified_images.clear()  # paths of the old connection
        self._current_path = backend.home()
        self._retire_stale_menus()
        self._history = []
        self._history_pos = 0
        self._model.set_items([])
        self._path_edit.setText(self._current_path)
        self.update_header_color()
        self.navigate_async(path or self._current_path)

    #: what protects the pane's connection now (core.conn_security.SecurityInfo)
    security_info = None

    def refresh_security(self) -> None:
        """Read the connection's protection again (negotiated values once the
        backend is connected) and show it; tell the window when it changed
        (the workspace tab shows the weakest of its panes)."""
        badge = getattr(self, "_security_badge", None)
        if badge is None:
            return
        from core import conn_security

        info = conn_security.of_backend(self._backend)
        badge.set_info(info)
        if info != self.security_info:
            self.security_info = info
            self.security_changed.emit()

    def get_session_type(self) -> str:
        """Return 'local', 'remote', or 'root' based on the backend type."""
        from core.local_fs import LocalFS

        if isinstance(self._backend, LocalFS):
            return "local"
        # Check for root user (SSH backends have _profile)
        if hasattr(self._backend, "_profile"):
            if getattr(self._backend._profile, "username", "") == "root":
                return "root"
        if hasattr(self._backend, "_username"):
            if self._backend._username == "root":
                return "root"
        return "remote"

    def update_header_color(self, theme: str | None = None) -> None:
        """Update header label color based on session type and current theme.

        ``None`` re-uses the last theme this pane was given, so a
        backend swap does not snap the header back to the light colours.
        """
        if theme is None:
            theme = getattr(self, "_header_theme", "default")
        self._header_theme = theme
        session_type = self.get_session_type()

        # Color schemes: {theme: {session_type: (bg_color, text_color)}}
        color_schemes = {
            "default": {
                "local": ("#3498db", "#ffffff"),  # Blue
                "remote": ("#27ae60", "#ffffff"),  # Green
                "root": ("#e74c3c", "#ffffff"),  # Red
            },
            "dark": {
                "local": ("#45475a", "#89b4fa"),  # Catppuccin blue
                "remote": ("#45475a", "#a6e3a1"),  # Catppuccin green
                "root": ("#5c2d2d", "#f38ba8"),  # Catppuccin red
            },
            "modern-light": {
                "local": ("#dbe3ff", "#2f4ac2"),
                "remote": ("#d3f2e0", "#17693b"),
                "root": ("#ffe0e0", "#a61e1e"),
            },
            "modern-dark": {
                "local": ("#26305a", "#9db3ff"),
                "remote": ("#1d3a2c", "#7fe3a6"),
                "root": ("#4a2226", "#ff9a9a"),
            },
            "hacker": {
                "local": ("#0a2a0a", "#00ff41"),  # Matrix green
                "remote": ("#0a0a2a", "#41ff00"),  # Lime
                "root": ("#2a0a0a", "#ff4141"),  # Red alert
            },
            "amber": {
                "local": ("#1a1000", "#ff8c00"),  # Amber
                "remote": ("#0a1a0a", "#ffaa00"),  # Gold
                "root": ("#2a0a0a", "#ff4500"),  # Orange-red
            },
        }

        scheme = color_schemes.get(theme, color_schemes["default"])
        bg, fg = scheme.get(session_type, scheme["local"])

        type_label = tr({"local": "LOCAL", "remote": "REMOTE", "root": "ROOT"}[session_type])
        self.refresh_security()
        name = backend_label(self._backend.name)
        # "Local [LOCAL]" said one thing twice: the badge only where it adds
        # something (a remote or root connection, or a renamed local one).
        badge = (f" <small>[{type_label}]</small>"
                 if type_label.casefold() != name.casefold() else "")
        self._header_label.setText(f"<b>{escape(name)}</b>{badge}")
        _set_style(
            self._header_label,
            f"QLabel {{ background-color: {bg}; color: {fg}; "
            f"padding: 2px 6px; border-radius: 3px; }}",
        )

    def set_pane_role(self, role: str, theme: str = "default") -> None:
        """Set the pane role: 'source', 'target', or '' (none).

        Updates the border frame color and role badge.
        """
        # Border colors per role
        border_colors = {
            "source": "#4a90d9",  # Blue
            "target": "#58a55c",  # Green
            "": "#555555",  # Gray
        }
        color = border_colors.get(role, border_colors[""])
        _set_style(
            self._border_frame,
            f"QFrame#axPaneBorder {{ border: 3px solid {color}; border-radius: 4px; }}",
        )

        # Role badge
        if role == "source":
            self._role_label.setText(tr("SOURCE"))
            _set_style(
                self._role_label,
                "QLabel { font-size: 10px; font-weight: bold; padding: 1px 6px; "
                "border-radius: 3px; background-color: #4a90d9; color: white; }",
            )
            self._role_label.show()
        elif role == "target":
            self._role_label.setText(tr("TARGET"))
            _set_style(
                self._role_label,
                "QLabel { font-size: 10px; font-weight: bold; padding: 1px 6px; "
                "border-radius: 3px; background-color: #58a55c; color: white; }",
            )
            self._role_label.show()
        else:
            self._role_label.hide()

    def _update_disk_usage(self) -> None:
        """Update disk usage display in status bar."""
        self._show_disk_usage(self._read_disk_usage(self._current_path))

    def _show_disk_usage(self, usage) -> None:
        """Render ``(total, used, free)`` (``None`` = unavailable)."""
        if not usage:
            self._disk_label.setText("")
            return
        total, used, free = usage
        if total <= 0:
            self._disk_label.setText("")
            return

        def _fmt(b: float) -> str:
            for unit in ("B", "KB", "MB", "GB", "TB"):
                if abs(b) < 1024:
                    return f"{format_decimal(b)} {unit}" if unit != "B" else f"{b} {unit}"
                b /= 1024
            return f"{format_decimal(b)} PB"

        pct = int((used / total) * 100) if total else 0
        # The short form when the footer is narrow (ui.elided_label).
        self._disk_label.set_texts(
            tr("Free: {free} / {total} ({pct}% used)").format(
                free=_fmt(free), total=_fmt(total), pct=pct),
            tr("Free: {free}").format(free=_fmt(free)),
        )

    # --- Filter ---

    def _on_filter_changed(self, text: str) -> None:
        # Key column and case sensitivity are set once in _setup_ui:
        # setting them here re-filtered every row a second time per key.
        # "tag:<name>" shows the files that carry that tag (core.tags).
        if text.lower().startswith("tag:"):
            from core import tags as T

            wanted = text[4:].strip().lower()
            name = next((t.name for t in T.store().tags() if t.name.lower() == wanted), None)
            self._proxy.setFilterFixedString("")
            self._proxy.set_tag_filter(
                (lambda item: name in self._tags_of_item(item)) if name else (lambda item: False))
            return
        if self._proxy._tag_filter is not None:
            self._proxy.set_tag_filter(None)
        self._proxy.setFilterFixedString(text)

    # --- Tags ---

    #: The connection profile this pane was opened from ("" for local and
    #: ad-hoc connections); the main window sets it. Tags remember it.
    profile_name = ""

    def _tags_of_item(self, item) -> list[str]:
        if item is None or item.is_nav:
            return []
        from core import tags as T

        return T.store().tags_of(self._backend.name, self._backend.join(self._current_path, item.name))

    def tag_colours_at(self, proxy_index) -> list[str]:
        """The colours of the tags of the row at *proxy_index* (the dots)."""
        from core import tags as T

        item = self._model.get_item(self._proxy.mapToSource(proxy_index).row())
        names = self._tags_of_item(item)
        if not names:
            return []
        store = T.store()
        return [c for c in (store.colour(n) for n in names) if c]

    def toggle_tag(self, name: str) -> None:
        """Tag every selected file with *name*, or - when all have it -
        take it off all of them."""
        from core import tags as T

        paths = self.selected_items()
        if not paths:
            return
        store = T.store()
        backend = self._backend.name
        # One write of tags.json for the whole selection (core.tags).
        if all(name in store.tags_of(backend, p) for p in paths):
            store.untag_many(backend, paths, name)
        else:
            store.tag_many(backend, self.profile_name, paths, name)
        self._tags_changed()

    def new_tag_for_selection(self) -> None:
        from core import tags as T
        from ui.tag_ui import ask_new_tag

        tag = ask_new_tag(self)
        if tag is None:
            return
        T.store().tag_many(self._backend.name, self.profile_name, self.selected_items(), tag.name)
        self._tags_changed()

    def _tags_follow_rename(self, old_path: str, new_path: str) -> None:
        """The tags of a renamed file - or of the files below a renamed
        folder - move to the new path (core.tags)."""
        from core import tags as T

        try:
            T.store().rename_path(self._backend.name, old_path, new_path)
        except OSError as exc:  # tags.json not writable: the rename itself stands
            log.warning("Tags could not follow %s -> %s: %s", old_path, new_path, exc)

    def _tags_changed(self) -> None:
        if self._proxy._tag_filter is not None:
            self._proxy.invalidateFilter()
        # A tagged name needs room for its dots (ui.tag_ui.dots_width):
        # measure the Name column again and refit it.
        self._content_widths_changed()
        self._table.viewport().update()

    # --- Bookmark ---

    def _add_bookmark(self) -> None:
        self.bookmark_requested.emit(self._current_path, self._backend.name)

    # --- Drag & Drop ---

    def _start_drag(self) -> None:
        """Called by _DragTableView.startDrag when user drags from the table."""
        entries = self._selected_entries()
        selected = [path for path, _item in entries]
        if not selected:
            log.debug("Drag start ignored: no selected items")
            return
        # Folders as the listing shows them; no stat on the GUI thread.
        dirs = [path for path, item in entries if item.is_dir]

        drag = QDrag(self._table)
        mime = QMimeData()
        from core.local_fs import LocalFS

        urls: list[QUrl] = []
        for path in selected:
            if isinstance(self._backend, LocalFS):
                urls.append(QUrl.fromLocalFile(path))
            else:
                url = QUrl()
                url.setScheme("sftp")
                url.setPath(path)
                urls.append(url)
        mime.setUrls(urls)
        mime.setData(TRANSFER_MIME_TYPE, self._encode_transfer_payload(selected, dirs))
        drag.setMimeData(mime)
        # What moves travels with the mouse; without a pixmap only the
        # cursor changes and nothing on screen shows the drag.
        pix = drag_pixmap([item.name for _path, item in entries], len(dirs))
        drag.setPixmap(pix)
        # The cursor tip at the picture's top-left corner: a hot spot
        # outside the picture is not portable (Windows builds a cursor).
        drag.setHotSpot(QPoint(0, 0))
        log.debug("Starting drag with %d item(s) from %s", len(selected), self._backend.name)
        # A plain drag moves; Ctrl copies (the drop side decides from the
        # modifiers, this is only what the cursor proposes first).
        result = drag.exec(
            Qt.DropAction.CopyAction | Qt.DropAction.MoveAction,
            Qt.DropAction.MoveAction,
        )
        log.debug("Drag finished with action %s", result)

    def dragEnterEvent(self, event, origin: QWidget | None = None) -> None:
        """*origin*: the child view whose coordinates *event* carries."""
        # Pane rearrangement drag
        if self._pane_drop.enter(event, origin):
            return
        # File transfer drag (from any pane, this one included: inside a
        # pane a drop onto a folder moves or copies into it)
        payload = self._decode_transfer_payload(event.mimeData())
        if payload:
            event.setDropAction(_drop_action(event))
            event.accept()
            return
        event.ignore()

    def _folder_at(self, pos: QPoint, view=None) -> str | None:
        """The folder a drop at viewport *pos* of *view* (the table unless
        given) goes into: a folder row, the parent for "..", else None (the
        pane's current folder applies)."""
        index = (view or self._table).indexAt(pos)
        if not index.isValid():
            return None
        item = self._model.get_item(self._proxy.mapToSource(index).row())
        if item is None:
            return None
        if item.name == "..":
            parent = self._backend.parent(self._current_path)
            return parent if parent and parent != self._current_path else None
        if item.name == "." and item.is_dir:
            return None  # this folder: the pane's own folder applies
        if not item.is_dir:
            return None
        return self._safe_item_path(item)

    def _drop_target(self, payload: dict, folder: str | None) -> str | None:
        """Where a drop of *payload* goes: the folder, "" for this pane's
        current folder, or None when the drop would do nothing."""
        paths = [str(p) for p in payload.get("paths") or []]
        same_pane = payload.get("source_pane_id") == str(id(self))
        if folder is None:
            return None if same_pane else ""
        # The paths are the source pane's: on another filesystem the same
        # path string is another folder. A payload that does not say keeps
        # the guard below.
        source_fs = payload.get("filesystem")
        if not same_pane and source_fs is not None and source_fs != filesystem_key(self._backend):
            return folder
        for path in paths:
            if self.is_within(folder, path):
                return None  # onto itself or into itself
        if same_pane and all(self._backend.parent(p) == folder for p in paths):
            return None  # already there
        return folder

    def is_within(self, folder: str, path: str) -> bool:
        """True when *folder* is *path* or lies below it, walked up with the
        backend's own parent() so every path syntax is handled."""
        current = folder
        for _ in range(256):
            if current == path:
                return True
            parent = self._backend.parent(current)
            if not parent or parent == current:
                return False
            current = parent
        return False

    def dragMoveEvent(
        self, event, folder: str | None = None, origin: QWidget | None = None
    ) -> None:
        # Pane rearrangement — show drop zone
        if self._pane_drop.move(event, origin):
            return
        # File transfer drag
        payload = self._decode_transfer_payload(event.mimeData())
        if not payload or self._drop_target(payload, folder) is None:
            event.ignore()
            return
        event.setDropAction(_drop_action(event))
        event.accept()

    def dragLeaveEvent(self, event) -> None:
        self._pane_drop.leave()
        super().dragLeaveEvent(event)

    def _show_drop_hint(self, pos: QPoint, folder: str | None, action) -> None:
        """Frame the row a drop at viewport *pos* goes into and name the
        folder beside the cursor (*folder* None: this pane's own folder)."""
        viewport = self._table.viewport()
        up = False
        if folder is not None:
            index = self._table.indexAt(pos)
            item = self._model.get_item(self._proxy.mapToSource(index).row())
            up = item is not None and item.name == ".."
            rect = self._table.visualRect(index)
            self._drop_row_marker.setGeometry(0, rect.top(), viewport.width(), rect.height())
            self._drop_row_marker.show()
            self._drop_row_marker.raise_()
        else:
            self._drop_row_marker.hide()
        verb = (
            tr("Copy to {folder}") if action == Qt.DropAction.CopyAction else tr("Move to {folder}")
        )
        text = verb.format(folder=folder if folder is not None else self._current_path)
        if up:
            text += "  " + tr("(.. = one folder up)")
        self._drop_hint.setText(text)
        self._drop_hint.adjustSize()
        size = self._drop_hint.size()
        # Above the cursor: the drag picture hangs below and to the right.
        x = min(pos.x() + 8, max(0, viewport.width() - size.width()))
        y = pos.y() - size.height() - 8
        if y < 0:
            y = min(pos.y() + 40, max(0, viewport.height() - size.height()))
        self._drop_hint.move(x, y)
        self._drop_hint.show()
        self._drop_hint.raise_()

    def _hide_drop_hint(self) -> None:
        self._drop_row_marker.hide()
        self._drop_hint.hide()

    def dropEvent(
        self, event, folder: str | None = None, origin: QWidget | None = None
    ) -> None:
        # Pane rearrangement drop
        pane_drop = self._pane_drop.drop(event, origin)
        if pane_drop is not None:
            source_id, zone = pane_drop
            # The window does the actual reparenting
            self.pane_drop_requested.emit(source_id, self, zone)
            log.info("Pane drop: zone=%s onto %s", zone, self._backend.name)
            return
        if event.mimeData().hasFormat(PANE_MIME_TYPE):
            return  # a drag of this pane itself, or no pane: ignored
        # File transfer drop
        payload = self._decode_transfer_payload(event.mimeData())
        if not payload:
            event.ignore()
            return

        paths = payload["paths"]
        source_pane_id = payload["source_pane_id"]
        target = self._drop_target(payload, folder)
        if target is None:
            event.ignore()
            return
        is_move = _drop_action(event) == Qt.DropAction.MoveAction

        if paths:
            self.drop_transfer_requested.emit(paths, self, source_pane_id, is_move, target)
            event.setDropAction(_drop_action(event))
            event.accept()
            action = "Move" if is_move else "Copy"
            log.info("Drop %s received: %d items", action, len(paths))
        else:
            event.ignore()

    def _encode_transfer_payload(self, paths: list[str], dirs: list[str] | None = None) -> bytes:
        """*dirs* names the dragged folders (from the listing, no stat):
        the bookmark sidebar bookmarks those and only those."""
        payload = {
            "paths": paths,
            "source_pane_id": str(id(self)),
            "dirs": list(dirs or []),
            "filesystem": filesystem_key(self._backend),
        }
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _decode_transfer_payload(mime: QMimeData | None) -> dict[str, object] | None:
        return decode_transfer_payload(mime)

    # --- Slots ---

    def _handle_extra_mouse_button(self, button, pos) -> bool:
        """Side buttons and wheel click. *pos* is in table-viewport
        coordinates. Returns True when the button was consumed."""
        if button == Qt.MouseButton.BackButton:
            self._go_back()
            return True
        if button == Qt.MouseButton.ForwardButton:
            self._go_forward()
            return True
        if button == Qt.MouseButton.MiddleButton:
            index = self._table.indexAt(pos)
            if index.isValid():
                self._on_double_click(index)
            return True
        return False

    def mousePressEvent(self, event) -> None:
        # Side buttons anywhere on the pane (path bar, status line, ...);
        # the table handles its own area. Everything else is unchanged.
        if event.button() in (Qt.MouseButton.BackButton, Qt.MouseButton.ForwardButton):
            self._handle_extra_mouse_button(event.button(), event.position().toPoint())
            event.accept()
            return
        super().mousePressEvent(event)

    def _go_up(self) -> None:
        parent = self._backend.parent(self._current_path)
        if parent != self._current_path:
            self.navigate_async(parent)

    def _go_home(self) -> None:
        self.navigate_async(self._backend.home())

    def _on_path_entered(self) -> None:
        path = self._path_edit.text().strip()
        if path:
            self.navigate_async(path)

    def _on_double_click(self, index: QModelIndex) -> None:
        source_idx = self._proxy.mapToSource(index)
        item = self._model.get_item(source_idx.row())
        if not item:
            return
        self._open_item(item)

    def _open_item(self, item) -> None:
        """Open *item* as a double-click or Enter does: a folder in this
        pane, a file in the viewer or editor it calls for."""
        if item.name == "..":
            self.navigate_async(self._backend.parent(self._current_path))
            return
        if item.name == "." and item.is_dir:
            return  # this folder: nothing to open
        full_path = self._safe_item_path(item)
        if full_path is None:
            return
        if item.is_dir:
            self.navigate_async(full_path)
        elif item.is_link:
            # Where it leads is read on a worker (readlink + stat: two round
            # trips to a server, which held the window).
            backend, folder = self._backend, self._current_path
            self._probe(tr("Opening {name}…").format(name=item.name),
                        lambda _c, _r: _link_is_dir(backend, folder, full_path),
                        lambda is_dir: self.navigate_async(full_path) if is_dir
                        else self._activate_file(item, full_path))
        else:
            self._activate_file(item, full_path)

    def _activate_file(self, item, full_path: str) -> None:
        """A double-click on a file: the viewer or editor it calls for."""
        # Supported archives open in the non-modal preview dock
        # (Task A4) BEFORE the binary/hex branch - otherwise a .zip
        # would fall through to the hex editor. Local-backend only;
        # the preview-dock owner extracts to the local filesystem.
        from core import archive as _ARCH
        from core import previews as _PV

        if _PV._is_local_backend(self._backend) and _ARCH.is_supported_archive(item.name):
            self._open_archive_preview(full_path)
            return
        # Route to the best viewer:
        #   images (local only) -> ImageViewerDialog
        #   PDFs                -> media viewer, that document alone
        #   binaries            -> hex
        #   text                -> text editor
        #   fallthrough         -> emit for other handlers
        if self._looks_like_image(item.name) and self._open_image_viewer(full_path):
            return
        if self._open_document_viewer(full_path, item.name):
            return
        self._when_binary_known(full_path, item.name,
                                lambda binary: self._open_by_kind(item, full_path, binary))

    def _open_by_kind(self, item, full_path: str, binary: bool) -> None:
        if binary:
            self._open_hex_editor(full_path)
        elif self._is_editable_file(item.name, item.size):
            self._open_editor(full_path)
        elif item.size > max_open_bytes():
            QMessageBox.information(
                self,
                tr("File Too Large"),
                as_written(tr("{name} is {size}; files up to {limit} are opened. Raise the limit "
                              "under Edit → Settings… → Files & Panes → Open Size Limit.").format(
                    name=item.name, size=item.size_human, limit=describe_limit())),
            )
        else:
            self.file_activated.emit(full_path)

    # Known binary extensions
    _BINARY_EXTENSIONS = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".tiff",
        ".mp3",
        ".mp4",
        ".avi",
        ".mkv",
        ".flac",
        ".wav",
        ".ogg",
        ".webm",
        ".zip",
        ".gz",
        ".bz2",
        ".xz",
        ".tar",
        ".7z",
        ".rar",
        ".zst",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".o",
        ".a",
        ".pyc",
        ".pyo",
        ".class",
        ".wasm",
        ".bin",
        ".dat",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".iso",
        ".img",
        ".dmg",
        ".deb",
        ".rpm",
    }

    # Known text extensions
    _TEXT_EXTENSIONS = {
        ".txt",
        ".md",
        ".py",
        ".js",
        ".ts",
        ".json",
        ".xml",
        ".html",
        ".css",
        ".csv",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".java",
        ".rs",
        ".go",
        ".rb",
        ".pl",
        ".lua",
        ".sql",
        ".log",
        ".env",
        ".gitignore",
        ".dockerfile",
        ".makefile",
        ".tsx",
        ".jsx",
        ".svelte",
        ".vue",
        ".scss",
        ".less",
        ".sass",
        ".php",
        ".swift",
        ".kt",
        ".scala",
        ".zig",
        ".nim",
        ".r",
        ".jl",
        ".ex",
        ".exs",
        ".erl",
        ".hs",
        ".ml",
        ".v",
        ".sv",
        ".vhd",
        ".tcl",
        ".cmake",
        ".service",
        ".timer",
        ".socket",
        ".desktop",
        ".rules",
    }

    # Known text filenames (no extension)
    _TEXT_FILENAMES = {
        "makefile",
        "dockerfile",
        "readme",
        "license",
        "changelog",
        "authors",
        "todo",
        "copying",
        "contributing",
        "cmakelists.txt",
    }

    # Binary magic bytes: (offset, signature). Derived from the signature
    # table core.file_type classifies with, so the two cannot drift apart.
    _BINARY_MAGIC = list(BINARY_SIGNATURES)

    def _is_binary_file(self, path: str, name: str) -> bool:
        """Detect if a file is binary using extension + magic bytes. Reads
        the first bytes through the backend when the name does not tell:
        the UI asks :meth:`_when_binary_known`, which reads off the GUI
        thread."""
        by_name = self._binary_by_name(name)
        if by_name is not None:
            return by_name
        return self._header_is_binary(_read_header(self._backend, path))

    def _binary_by_name(self, name: str) -> bool | None:
        """True / False when the extension says; None when only the
        content can."""
        lower = name.lower()
        for ext in self._BINARY_EXTENSIONS:
            if lower.endswith(ext):
                return True
        for ext in self._TEXT_EXTENSIONS:
            if lower.endswith(ext):
                return False
        return None

    def _header_is_binary(self, header: bytes) -> bool:
        """Magic bytes, or a NUL in the first bytes of the file."""
        if not header:
            return False
        for offset, magic in self._BINARY_MAGIC:
            if header[offset : offset + len(magic)] == magic:
                return True
        return b"\x00" in header

    def _when_binary_known(self, path: str, name: str, then) -> None:
        """*then(is_binary)*: at once when the name decides, else once the
        first bytes were read - on a worker. The read ran on the GUI thread
        at every double-click, F3 and F4 on a file without a known
        extension: one round trip to a server, the window held meanwhile."""
        by_name = self._binary_by_name(name)
        if by_name is not None:
            then(by_name)
            return
        backend = self._backend
        self._probe(tr("Opening {name}…").format(name=name),
                    lambda _cancelled, _report: _read_header(backend, path),
                    lambda header: then(self._header_is_binary(header)))

    def _probe(self, text: str, work, done) -> None:
        """A short read for the UI (what a file is, where a link leads) on a
        worker; *done(result)* on the GUI thread - unless the pane moved to
        another folder or connection meanwhile, or another probe replaced
        this one (a second double-click)."""
        if self._probe_job is None:
            self._probe_job = ScanJob(self, interval_ms=300, formatter=lambda _st: self._probe_text)
            self._probe_job.progress.connect(self._status.setText)
            self._probe_job.finished.connect(self._on_probe_finished)
        self._probe_text = text
        self._probe_then = (done, self._backend, self._current_path)
        self._probe_job.start(work, replace=True)

    def _on_probe_finished(self, kind: str, value, cancelled: bool) -> None:
        done, backend, folder = self._probe_then
        self._probe_then = (None, None, None)
        if self._status.text() == self._probe_text:
            self._status.setText(self._items_text())
        if cancelled or done is None or self._shutting_down:
            return
        if backend is not self._backend or folder != self._current_path:
            return  # the pane moved on: opening it now would surprise
        if kind == "error":
            log.warning("Could not read %s: %s", self._probe_text, value)
            return
        done(value)

    def _run_op(self, text: str, work, done, title: str, *, failed: str,
                exists: str | None = None) -> None:
        """A short change for the UI (New Folder, New File, Rename) on a
        worker: its backend calls held the window - an exists() and a
        mkdir() are two round trips to a server. *done(result)* on the GUI
        thread; an OSError is shown under *title* - *exists* for a
        FileExistsError, else *failed* with ``{error}``. One at a time per
        pane; dropped when the pane closes."""
        if self._op_job is None:
            self._op_job = ScanJob(self, interval_ms=300, formatter=lambda _st: self._op_text)
            self._op_job.progress.connect(self._status.setText)
            self._op_job.finished.connect(self._on_op_finished)
        elif self._op_then[0] is not None:
            self.status_message(tr("Another change is still running in this pane."))
            return
        self._op_text = text
        self._op_then = (done, title, failed, exists)
        # replace: a step started from the last step's done() finds that
        # job's thread still ending (its result is in already).
        self._op_job.start(work, replace=True)

    def _on_op_finished(self, kind: str, value, cancelled: bool) -> None:
        done, title, failed, exists = self._op_then
        self._op_then = (None, "", "", None)
        if self._status.text() == self._op_text:
            self._status.setText(self._items_text())
        if cancelled or done is None or self._shutting_down:
            return
        if kind == "error":
            if isinstance(value, FileExistsError) and exists:
                QMessageBox.warning(self, title, exists)
                return
            if not isinstance(value, OSError):
                raise value  # a bug, not the server's answer: the error dialog
            log.error("%s failed: %s", title, value)
            # replace, not format(): *failed* already holds file names, and
            # one with braces ("{draft}.txt") made format() raise KeyError.
            QMessageBox.warning(self, title, failed.replace("{error}", str(value)))
            return
        done(value)

    def _is_editable_file(self, name: str, size: int) -> bool:
        """Check if a file should be opened in the text/hex editor."""
        # One user-configurable limit (Settings > Files & Panes) for every viewer.
        if size > max_open_bytes():
            return False

        lower = name.lower()

        # Known text extensions
        for ext in self._TEXT_EXTENSIONS:
            if lower.endswith(ext):
                return True

        # Known text filenames
        if "." not in name and lower in self._TEXT_FILENAMES:
            return True

        # Unknown extension: binaries were routed to the hex editor before
        # we get here, so anything within the limit may open as text.
        return True

    def _open_editor(self, path: str, read_only: bool = False) -> None:
        """Edit *path*: a tab in the window's editor (non-modal; the window
        refreshes this pane after a save), or - in a pane without a main
        window - the single-file dialog."""
        opener = getattr(self.window(), "open_in_editor", None)
        if callable(opener):
            opener(self._backend, path, read_only=read_only)
            return
        from ui import viewer_window as VW
        from ui.text_editor import TextEditorDialog

        dialog = TextEditorDialog(
            self._backend, path, parent=VW.owner_window(self), read_only=read_only
        )
        if not dialog.loaded:  # it said why
            dialog.deleteLater()
            return
        dialog.saved.connect(self.refresh_after_change)
        VW.show_independent(dialog)

    def _open_hex_editor(self, path: str, read_only: bool = False) -> None:
        """*path* in a hex window of its own: non-modal (``exec()`` froze the
        editor and the main window until it closed), owned by the main
        window, the file read off the GUI thread; a save refreshes this
        pane."""
        from ui import viewer_window as VW
        from ui.hex_editor import HexEditorDialog

        dialog = HexEditorDialog(
            self._backend, path, parent=VW.owner_window(self), read_only=read_only,
            background=True,
        )
        dialog.saved.connect(self.refresh_after_change)
        VW.show_independent(dialog)

    def _link_points_to_directory(self, path: str) -> bool:
        return _link_is_dir(self._backend, self._current_path, path)

    def _build_context_menu(self) -> QMenu:
        """Assemble the right-click menu for the current selection.

        Split out from :meth:`_show_context_menu` so the menu's contents
        can be asserted without popping up a modal — ``menu.exec`` blocks
        until a human clicks. Loaded extensions add their entries last.
        """
        menu = self._build_base_context_menu()
        from ui import extension_host

        extension_host.add_context_actions(self, menu)
        # The entries without a letter of their own (Paste, Pack, Analyse,
        # More's and the submenus' entries, extensions') get a free one when
        # the menu opens, in either language (UX review round 8).
        from ui import mnemonics

        mnemonics.install(menu, now=False)
        self._track_menu(menu)
        return menu

    def _track_menu(self, menu: QMenu) -> None:
        """Remember the folder and connection *menu* was built for.

        Its entries captured the selection (and some the FileItem) of that
        folder; :meth:`_retire_stale_menus` disables them once the pane
        shows another one."""
        from PyQt6 import sip

        menus = [m for m in getattr(self, "_menus", []) if not sip.isdeleted(m[0])]
        menus.append((menu, self._backend, self._current_path))
        self._menus = menus

    def _retire_stale_menus(self) -> None:
        """Disable every entry of a menu built for another folder or connection.

        A folder load can finish while the right-click menu (or the menu
        bar's Actions menu, which shows the same actions) is open. Encrypt,
        Checksum and friends then joined the old item's name onto the new
        folder, and Rename/Delete read a selection the menu never showed."""
        from PyQt6 import sip

        keep = []
        for menu, backend, path in getattr(self, "_menus", []):
            if sip.isdeleted(menu):
                continue
            if backend is self._backend and path == self._current_path:
                keep.append((menu, backend, path))
                continue
            stack = [menu]
            while stack:
                for action in stack.pop().actions():
                    if action.menu() is not None:
                        stack.append(action.menu())
                    action.setEnabled(False)
        self._menus = keep

    def _build_base_context_menu(self) -> QMenu:
        """The pane's own right-click entries: one column of at most
        eighteen, the rarer ones in submenus. Open first (a folder opens in
        this pane, a file in its viewer, as Enter does), then the core file
        operations - copy, cut, paste and rename, copy / move to the target
        pane, trash and delete, new - then Properties, Analyse and More
        (Refresh, this folder, Copy Path, Links, Metadata, Tags, terminals,
        mounts, the agent, Send to Workspace). Each entry shows
        the icon its command has in the toolbar or a dock and the key the
        pane or the window reacts to (:data:`CONTEXT_COMMANDS`); the
        underlined letter (``&``) picks it while the menu is open, unique
        within each menu in English and German."""
        menu = QMenu(self)
        menu.setToolTipsVisible(True)
        selected = self.selected_file_items()
        files = [i for i in selected if not i.is_dir]
        dirs = [i for i in selected if i.is_dir]
        single = files[0] if len(files) == 1 else None
        single_path = self._safe_item_path(single, warn=False) if single is not None else None
        # A single file whose name cannot be joined safely gets none of the
        # entries that act on that name (open, rename, remove, checksum ...).
        hostile = single is not None and single_path is None

        def entry_in(target: QMenu):
            def entry(command: str, label: str, slot=None):
                action = decorate_command(target.addAction(label), command)
                if slot is not None:
                    action.triggered.connect(slot)
                return action
            return entry

        entry = entry_in(menu)

        def group(target: QMenu = menu) -> None:
            actions = target.actions()
            if actions and not actions[-1].isSeparator():
                target.addSeparator()

        def submenu(label: str) -> QMenu:
            sub = QMenu(label, menu)
            sub.setToolTipsVisible(True)
            return sub

        def attach(sub: QMenu, command: str | None = None,
                   target: QMenu = menu) -> QMenu | None:
            """Add *sub* to *target* when it has an entry; drop it otherwise."""
            while sub.actions() and sub.actions()[-1].isSeparator():
                sub.removeAction(sub.actions()[-1])
            if not sub.actions():
                sub.deleteLater()
                return None
            action = target.addMenu(sub)
            if command is not None:
                decorate_command(action, command)
            return sub

        # -- open: what Enter / a double-click does, then Open With ▸
        if len(selected) == 1 and not hostile and not selected[0].is_nav:
            item = selected[0]
            opener = entry("open", tr("&Open"), lambda _checked=False, i=item: self._open_item(i))
            bold = opener.font()
            bold.setBold(True)
            opener.setFont(bold)
        open_with = submenu(tr("Open &With"))
        with_entry = entry_in(open_with)
        archive = None
        if single_path is not None:
            with_entry("open-text", tr("Open as &Text"), lambda: self._open_editor(single_path))
            with_entry("open-hex", tr("Open as &Hex"), lambda: self._open_hex_editor(single_path))
            # "Open as root…" only for local backends with pkexec + the
            # helper binaries (cat/tee/stat/ls): no click into an error dialog.
            if self._elevated_io_available():
                with_entry("open-root", tr("Open as root…"),
                           lambda: self._open_as_root(single_path))
            archive = self._add_archive_actions(with_entry, single, single_path)
        # Only for a selection with something to view: a folder (its media
        # are collected) or an image, PDF or video - not for a README.md.
        if any(_may_hold_media(item) for item in selected):
            with_entry(
                "view-selected-media",
                tr("View Selected Media…"),
                lambda _checked=False: self.view_media(selected_only=True),
            )
        attach(open_with, "open-with")
        if archive is not None:
            extract = entry("extract", tr("E&xtract…"), lambda: self._extract_archive(archive))
            # Bold sets the one entry that writes to disk apart from the
            # read-only preview; its icon comes from the provider like every
            # other entry, so monochrome mode and the theme tint apply to it.
            bold = extract.font()
            bold.setBold(True)
            extract.setFont(bold)

        # -- clipboard / edit. Paste is offered on empty space too.
        if selected or self.can_paste():
            group()
        if selected:
            # Ctrl+C: Paste (Ctrl+V) in a folder copies the entries there;
            # other programs get their paths as text. More ▸ Copy Path puts
            # only the paths on the clipboard.
            copy = entry("copy", tr("&Copy"),
                         lambda _checked=False: self._copy_paths_to_clipboard())
            copy.setToolTip(tr("Copy the selected entries: Paste (Ctrl+V) in a folder copies "
                               "them there; other programs get their paths as text"))
            if not hostile:
                entry("cut", tr("Cu&t"), lambda _checked=False: self.cut_selected())
        if self.can_paste():
            paste = entry("paste", tr("Paste"), lambda _checked=False: self.paste_cut())
            from ui.cut_clipboard import cut_clipboard

            pending = cut_clipboard().pending
            paste.setToolTip(tr("Move the cut entries into this folder")
                             if pending is None or pending.move
                             else tr("Copy the copied entries into this folder"))
        if selected and not hostile:
            entry("rename", tr("&Rename"), self._rename_selected)
            if len(selected) > 1:
                entry("batch-rename", tr("Batch Rename…"), self._batch_rename)

        # -- transfer
        if selected:
            group()
            entry(
                "copy-to-target",
                tr("Copy to Tar&get Pane"),
                lambda: self.transfer_requested.emit(self.selected_items()),
            )
            entry(
                "move-to-target",
                tr("Mo&ve to Target Pane"),
                lambda _checked=False: self._move_to_target(),
            )
            decorate_command(menu.addMenu(self._build_pack_menu(selected, menu)), "pack")

        # -- remove: Del moves to the trash where the connection has one,
        # Shift+Del deletes permanently (Del too where there is no trash).
        if selected and not hostile:
            group()
            if self.can_trash():
                entry("trash", tr("Move to Tr&ash"), self._trash_selected)
                entry("delete", tr("&Delete Permanently"), self._delete_selected)
            else:
                delete = entry("delete", tr("&Delete Permanently"), self._delete_selected)
                delete.setShortcuts([QKeySequence("Del"), QKeySequence("Shift+Del")])
                delete.setToolTip(tr("This connection has no trash: Del deletes permanently, "
                                     "after a question"))

        # -- create in this folder
        group()
        entry("new-folder", tr("&New Folder"), self._create_folder)
        entry("new-file", tr("New &File…"), self._create_empty_file)

        # -- about the selection: Properties, then the submenus
        group()
        if selected:
            entry("properties", tr("Propert&ies…"), self._show_properties)
        attach(self._build_analyse_menu(submenu(tr("Anal&yse")), entry_in, selected, files,
                                        dirs, single, single_path, hostile), "analyse-menu")

        # -- More ▸ for the rest: this folder (Refresh first), the paths,
        # links, metadata and tags, terminals, mounts, the agent, Send to
        # Workspace. The top level stays one column at 1024x600 in English
        # and German, an archive selected and a Paste pending included
        # (review round 6, tests/test_context_menu_one_column.py).
        group()
        more = submenu(tr("&More"))
        more_entry = entry_in(more)
        # In the background, as Ctrl+R and the toolbar: refresh() lists the
        # folder on the GUI thread (scripts and tests want it that way).
        more_entry("refresh", tr("R&efresh"), lambda _checked=False: self.refresh_async())
        # One name, check and key with View → Thumbnail View (the menus
        # named it "View as Thumbnails" / "Thumbnail View"; UX review round 7).
        view_mode = more_entry("view-mode", tr("Thumb&nail View"),
                               lambda _checked=False: self.toggle_view_mode())
        view_mode.setCheckable(True)
        view_mode.setChecked(self.view_mode == "thumbnails")
        more_entry("media-view", tr("View Media…"), lambda _checked=False: self.view_media())
        # The name of View → Bookmarks → Bookmark This Folder (F8).
        more_entry("bookmark", tr("&Bookmark This Folder"), self._add_bookmark)
        more_entry("trash-browser", tr("Show Trash…"), self._show_trash_browser)
        group(more)
        # The paths alone, as text (Copy - Ctrl+C - marks the entries for
        # Paste as well), and the links: rarer than the top level's
        # entries, which fit one column at 1024x600 (review round 6).
        if selected:
            more_entry("copy-path", tr("Copy &Path"),
                       lambda _checked=False: self._copy_path_text())
        links = QMenu(tr("&Links"), more)
        links.setToolTipsVisible(True)
        link_entry = entry_in(links)
        if any(i.is_link for i in selected) and not hostile:
            link_entry("link-target", tr("Show Link Target"), self._show_link_target)
        if getattr(self._backend, "supports_symlinks", False):
            link_entry("new-symlink", tr("New Symlink…"), self._create_symlink)
        if getattr(self._backend, "supports_hardlinks", False):
            link_entry("new-hardlink", tr("New Hardlink…"), self._create_hardlink)
        link_entry("xlink", tr("Create XLink…"), self._create_xlink)
        attach(links, "links-menu", target=more)
        # Metadata acts on the selection, or on this folder when nothing is
        # selected - "remove all metadata" for a directory is one click.
        metadata = QMenu(tr("Me&tadata"), more)
        metadata.setToolTipsVisible(True)
        meta_entry = entry_in(metadata)
        for command, label, meta_action in (
            ("metadata", "Show Metadata…", "show"),
            ("metadata-remove", "Remove Metadata…", "remove"),
            ("metadata-export", "Export Metadata…", "export"),
        ):
            meta_entry(command, tr(label),
                       lambda _checked=False, a=meta_action: self.open_metadata(a))
        attach(metadata, "metadata-menu", target=more)
        # -- tags of the selection (nothing without one)
        from ui.tag_ui import add_tags_menu

        add_tags_menu(self, more)
        group(more)
        self._add_terminal_actions(more)
        self._add_fuse_actions(more, more_entry)
        if selected and not hostile:
            group(more)
            more_entry("permissions", tr("Per&missions…"), self._show_permissions)
        # -- protect (single file: passphrase prompt flow)
        if single_path is not None:
            if single.name.endswith(".axenc"):
                more_entry("decrypt", tr("Decrypt with passphrase…"),
                           lambda: self._decrypt_selected_file(single))
            else:
                more_entry("encrypt", tr("Encrypt with Passphrase…"),
                           lambda: self._encrypt_selected_file(single))
        # -- the agent
        group(more)
        self._add_agent_action(more)
        # -- the pane itself: Send to Workspace ▸, in a group of its own at
        # the end of More (none off a workspace) - as in the pane header's menu.
        from ui.workspaces import add_send_to_workspace_menu

        group(more)
        send = add_send_to_workspace_menu(self, more)
        if send is not None:
            decorate_command(send.menuAction(), "send-to-workspace")
        attach(more, "more-menu")
        while menu.actions() and menu.actions()[-1].isSeparator():
            menu.removeAction(menu.actions()[-1])
        return menu

    def _build_analyse_menu(self, sub: QMenu, entry_in, selected, files, dirs, single,
                            single_path, hostile: bool) -> QMenu:
        """Analyse ▸: file type, disk image, checksum, versions, size, sift,
        duplicates and Find in This Folder."""
        entry = entry_in(sub)
        if selected:
            identify = entry(
                "identify",
                tr("Identif&y File Type…"),
                lambda _checked=False: self.identify_file_type(),
            )
            identify.setToolTip(
                tr("Detect the real type from the content and compare it with the extension")
            )
        # The folder you stand in (or the selected one): offered on empty space too.
        folder_scan = entry(
            "identify-folder",
            tr("Identify Files in This Folder…"),
            lambda _checked=False: self.identify_folder(),
        )
        folder_scan.setToolTip(
            tr("Detect the real type of every file in this folder (or the selected one) "
               "from its content; disk images show their partitions")
        )
        if single_path is not None:
            from core.disk_image import looks_like_image

            if looks_like_image(single.name) or self._content_says_disk_image(
                    single, single_path):
                image = entry("disk-image", tr("Disk Image…"),
                              lambda _checked=False: self.show_disk_image())
                image.setToolTip(
                    tr("Partitions and file systems of the image; mount one read-only")
                )
            # Most backends return a native fingerprint cheaply (S3 ETag,
            # Drive md5Checksum, ssh sha256sum); the rest stream after a prompt.
            entry("checksum", tr("Show Checks&um…"), lambda: self._show_checksum(single))
            entry("versions", tr("Show Versions…"), lambda: self._show_versions(single))
        if dirs and not hostile:
            entry(
                "calculate-size",
                tr_n(len(dirs), "Calculate Si&ze ({n} folder)", "Calculate Si&ze ({n} folders)"),
                self._calculate_dir_size,
            )
        sub.addSeparator()
        self._add_sift_actions(entry, files, hostile)
        sub.addSeparator()
        # Acts on the folder you are standing in: offered with nothing selected.
        entry(
            # One name with View > Duplicate Finder… (the same window).
            "duplicates", tr("Dup&licate Finder…"), self.open_duplicates_requested.emit
        )
        if self.receivers(self.find_files_requested) > 0:
            find = entry(
                "find-files",
                tr("Find in This Folder…"),
                lambda _checked=False: self.find_files_requested.emit(self.terminal_directory()),
            )
            find.setToolTip(
                tr("Search this folder (or the selected one) by name, type, content and "
                   "inside archives")
            )
        # No doubled separators where a group stayed empty.
        previous_separator = True
        for action in list(sub.actions()):
            if action.isSeparator():
                if previous_separator:
                    sub.removeAction(action)
                previous_separator = True
            else:
                previous_separator = False
        return sub

    def _add_sift_actions(self, entry, files, hostile: bool) -> None:
        """Analyse with sift (the selected files) and Analyse Folder with sift
        (the selected folder, else the one shown), both in the window's
        Analysis dock - offered only where a window listens."""
        if self.receivers(self.analyse_requested) > 0 and not hostile:
            chosen = [(path, item) for item in files
                      if (path := self._safe_item_path(item, warn=False)) is not None]
            if chosen:
                action = entry("analyse-sift", tr("Analyse with sift"),
                               lambda _checked=False, c=chosen: self.analyse_requested.emit(c))
                action.setToolTip(
                    tr("Explain the file in the Analysis dock (sift); several files are "
                       "offered as one batch for the LLM")
                )
        if self.receivers(self.analyse_folder_requested) > 0:
            action = entry(
                "analyse-folder-sift",
                tr("Analyse Folder with sift"),
                lambda _checked=False: self.analyse_folder_requested.emit(
                    self.terminal_directory()),
            )
            action.setToolTip(
                tr("Offer the files of this folder (or the selected one) in the Analysis dock "
                   "(sift), as one batch for the LLM")
            )

    def _add_archive_actions(self, entry, item, path: str):
        """Preview Archive (in Open With ▸) for one local file whose name is
        a format :mod:`core.archive` extracts; returns *item* when it is
        one, so the caller offers Extract… at the top level. The safety
        caps and the zip-slip guard live there; the UI picks a unique
        target dir and drives a progress dialog."""
        from core import archive as _ARCH
        from core import previews as _PV

        if not (_PV._is_local_backend(self._backend) and _ARCH.is_supported_archive(item.name)):
            return None
        # The non-modal archive dock, nothing extracted to disk.
        entry(
            "preview-archive",
            tr("&Preview Archive"),
            lambda _checked=False, p=path: self._open_archive_preview(p),
        )
        return item

    def _add_fuse_actions(self, menu: QMenu, entry) -> None:
        """Mount as FUSE read-only / read-write, or Unmount - only when
        fusepy is importable. Two entries make the chosen mode explicit."""
        try:
            from core import fuse_mount as FM

            if not FM.is_available():
                return
            if getattr(self, "_fuse_handle", None) is not None:
                entry("fuse-unmount", tr("Unmount FUSE"), self._unmount_fuse)
            else:
                entry(
                    "fuse-ro",
                    tr("Mount as FUSE (read-only)…"),
                    lambda: self._mount_as_fuse(writeable=False),
                )
                entry(
                    "fuse-rw",
                    tr("Mount as FUSE (read-write)…"),
                    lambda: self._mount_as_fuse(writeable=True),
                )
        except Exception as exc:  # noqa: BLE001 — never let fuse break the menu
            log.debug("Skipping FUSE menu entry: %s", exc)

    def _add_terminal_actions(self, menu: QMenu) -> None:
        """Open Terminal Here (embedded dock) and, for local folders, Open
        External Terminal Here. Outside the selection block: on empty space
        they act on the folder shown."""
        from core import terminal_here as TH

        kind = TH.shell_kind(self._backend)
        menu.setToolTipsVisible(True)
        embedded = decorate_command(menu.addAction(tr("&Open Terminal Here")), "terminal")
        embedded.triggered.connect(lambda _checked=False: self.open_terminal_here())
        if not kind:
            embedded.setEnabled(False)
            embedded.setToolTip(TH.no_shell_reason(self._backend))
        elif self.receivers(self.open_terminal_requested) == 0:
            embedded.setEnabled(False)
            embedded.setToolTip(tr("No embedded terminal is available in this window."))
        elif kind == TH.SSH:
            embedded.setToolTip(tr("Open a shell on this SSH connection in the folder"))
        else:
            embedded.setToolTip(tr("Open a shell in the terminal dock in this folder"))
        if kind == TH.LOCAL:
            external = decorate_command(
                menu.addAction(tr("Open External Terminal Here")), "external-terminal"
            )
            external.setToolTip(tr("Start your terminal emulator ($TERMINAL) in this folder"))
            external.triggered.connect(lambda _checked=False: self.open_external_terminal_here())

    def _add_agent_action(self, menu: QMenu) -> None:
        """Send to Agent: the selection, or the folder on empty space; and
        New Agent Tab Here: start the agent in a new tab for this folder."""
        if self.receivers(self.send_to_agent_requested) == 0:
            return
        action = decorate_command(menu.addAction(tr("Send to Agent")), "send-to-agent")
        action.setToolTip(tr("Attach the selection (or this folder) to the Agent's current tab"))
        action.triggered.connect(lambda _checked=False: self.send_to_agent())
        if self.receivers(self.new_agent_tab_requested):
            start = menu.addAction(tr("New Agent Tab Here"))
            start.setToolTip(tr("Open the Agent with a new conversation in this folder"))
            start.triggered.connect(lambda _checked=False: self.new_agent_tab_here())

    def new_agent_tab_here(self) -> None:
        from core.local_fs import LocalFS

        local = isinstance(self._backend, LocalFS)
        self.new_agent_tab_requested.emit(self._current_path if local else "")

    def send_to_agent(self) -> None:
        paths = self.selected_items() or ([self._current_path] if self._current_path else [])
        if paths:
            self.send_to_agent_requested.emit(paths)

    def terminal_directory(self) -> str:
        """The folder Open Terminal Here acts on: a single selected folder,
        otherwise the folder shown (a selected file opens its parent)."""
        selected = self.selected_file_items()
        if len(selected) == 1 and selected[0].is_dir:
            path = self._safe_item_path(selected[0], warn=False)
            if path is not None:
                return path
        return self._current_path

    def _local_folder_or_warn(self, directory: str) -> str | None:
        import os

        if os.path.isdir(directory):
            return directory
        QMessageBox.warning(
            self,
            tr("Open Terminal Here"),
            tr("{path} is no longer a folder (deleted or unmounted?).").format(path=directory),
        )
        return None

    def open_terminal_here(self) -> None:
        """Ask the main window for an embedded shell in :meth:`terminal_directory`."""
        from core import terminal_here as TH

        directory = self.terminal_directory()
        kind = TH.shell_kind(self._backend)
        if kind == TH.LOCAL:
            if self._local_folder_or_warn(directory) is None:
                return
        elif kind == TH.SSH:
            try:
                TH.remote_cd_command(directory)
            except ValueError as exc:
                QMessageBox.warning(self, tr("Open Terminal Here"), str(exc))
                return
        else:
            QMessageBox.information(
                self, tr("Open Terminal Here"), TH.no_shell_reason(self._backend)
            )
            return
        self.open_terminal_requested.emit(directory)

    def open_external_terminal_here(self) -> None:
        """Start the user's terminal emulator in :meth:`terminal_directory`."""
        from core import terminal_here as TH

        directory = self._local_folder_or_warn(self.terminal_directory())
        if directory is None:
            return
        try:
            argv = TH.launch_external_terminal(directory)
        except TH.TerminalLaunchError as exc:
            QMessageBox.warning(self, tr("Open External Terminal Here"), str(exc))
            return
        log.info("Started external terminal %s in %s", argv[0], directory)

    def _show_context_menu(self, pos) -> None:
        # ``pos`` arrives in viewport-local coordinates per Qt's
        # QAbstractScrollArea contract, but user reports show the
        # menu landing in the wrong place on some window-manager /
        # Qt-version combos (likely a HiDPI scaling mismatch or a
        # viewport geometry quirk when the pane is split). Using the
        # current cursor's global position sidesteps the coordinate-
        # system conversion entirely — the menu opens where the
        # user actually clicked, every time.
        from PyQt6.QtGui import QCursor

        # Without a deleteLater every right click left the menu, its
        # submenus and ~70 actions on the pane for good - and the actions'
        # slots kept switched-off extensions' modules alive. Triggered
        # entries run inside exec(), so the menu is no longer needed after.
        menu = self._build_context_menu()
        try:
            menu.exec(QCursor.pos())
        finally:
            menu.deleteLater()

    # -- packing ------------------------------------------------------------
    _QUICK_PACK = (("zip", "Pack as ZIP"), ("tar.gz", "Pack as .tar.gz"),
                   ("tar.zst", "Pack as .tar.zst"), ("7z", "Pack as 7z"))
    _QUICK_COMPRESS = (("gz", "Compress as .gz"), ("zst", "Compress as .zst"),
                       ("xz", "Compress as .xz"), ("bz2", "Compress as .bz2"))

    def _build_pack_menu(self, selected, parent: QMenu) -> QMenu:
        """Pack submenu: one click per common format, single-file
        compression when one file is selected, and the options dialog."""
        from core import packer as PK

        menu = QMenu(tr("Pac&k"), parent)
        for fmt_id, label in self._QUICK_PACK:
            action = menu.addAction(tr(label))
            ok, reason = PK.FORMATS[fmt_id].available()
            action.setEnabled(ok)
            action.setToolTip(tr(reason) if reason else "")
            action.triggered.connect(lambda _checked=False, f=fmt_id: self.pack_selection(f))
        files = [i for i in selected if not i.is_dir and not i.is_nav]
        if len(selected) == 1 and len(files) == 1:
            menu.addSeparator()
            for fmt_id, label in self._QUICK_COMPRESS:
                action = menu.addAction(tr(label))
                ok, reason = PK.FORMATS[fmt_id].available()
                action.setEnabled(ok)
                action.setToolTip(tr(reason) if reason else "")
                action.triggered.connect(lambda _checked=False, f=fmt_id: self.pack_selection(f))
        menu.setToolTipsVisible(True)
        menu.addSeparator()
        options = menu.addAction(tr("Pack with Options…"))
        options.triggered.connect(lambda _checked=False: self.pack_selection(None))
        return menu

    def _feedback(self, text: str) -> None:
        """Show *text* in the pane's status line; when the line is too
        narrow for all of it, in the window's status bar as well (the
        pane line then shows it cut with "…", whole in its tooltip)."""
        self._status.setText(text)
        room = self._status_row.message_room()
        if self.isVisible() and self._status.fontMetrics().horizontalAdvance(text) > room:
            window = self.window()
            if window is not self and hasattr(window, "statusBar"):
                window.statusBar().showMessage(text, 8000)

    def status_message(self, text: str) -> None:
        """Show *text* in the pane's status line and the window's."""
        self._status.setText(text)
        window = self.window()
        if window is not self and hasattr(window, "statusBar"):
            window.statusBar().showMessage(text, 8000)

    @property
    def pack_running(self) -> bool:
        job = getattr(self, "_pack_job", None)
        return job is not None and job.running

    def pack_selection(self, fmt_id: str | None = None) -> bool:
        """Pack the selection into this folder - with *fmt_id*, or after
        asking with the options dialog. Runs in the background; the
        listing refreshes when the archive is in place. False when nothing
        started (nothing selected, dialog cancelled, a pack still running)."""
        from core import packer as PK
        from ui.scan_job import ScanJob

        if self.pack_running:
            self.status_message(tr("A pack is still running in this pane."))
            return False
        items = [i for i in self.selected_file_items() if not i.is_nav]
        if not items:
            return False
        names = [i.name for i in items]
        single = len(items) == 1 and not items[0].is_dir
        default = PK.default_name(names, self._current_path)
        if fmt_id is None:
            from ui.pack_dialog import PackDialog

            dialog = PackDialog(names, default, single_file=single, parent=self)
            try:
                if dialog.exec() != PackDialog.DialogCode.Accepted:
                    return False
                archive_name, options = dialog.result_values()
            finally:
                dialog.deleteLater()
        else:
            archive_name, options = default, PK.PackOptions(fmt=fmt_id)
        backend, folder = self._backend, self._current_path

        def work(cancelled, report):
            class _Cancel:
                is_set = staticmethod(cancelled)

            return PK.pack(
                backend, folder, names, archive_name, options,
                progress=lambda done, total, name: report(done, total, name),
                cancel=_Cancel(),
            )

        job = getattr(self, "_pack_job", None)
        if job is None:
            job = ScanJob(
                self,
                formatter=lambda st: tr("Packing… {scanned} of {total} – {path}").format(
                    scanned=st["scanned"], total=st["indexed"], path=st["path"]),
            )
            job.progress.connect(self.status_message)
            job.finished.connect(self._on_pack_finished)
            self._pack_job = job
        self.status_message(tr("Packing {what}…").format(what=default))
        return job.start(work)

    def _on_pack_finished(self, kind: str, value, cancelled: bool) -> None:
        from core import packer as PK

        if kind == "done":
            name = value.path.replace("\\", "/").rsplit("/", 1)[-1]
            text = tr_n(value.files, "Packed {n} file into {name}",
                        "Packed {n} files into {name}", name=name)
            if value.skipped:
                text += " " + tr_n(len(value.skipped), "({n} link skipped)",
                                   "({n} links skipped)")
            self.status_message(text)
            self.refresh_after_change(quiet=True)
            return
        if cancelled or isinstance(value, PK.PackCancelled):
            self.status_message(tr("Packing cancelled – nothing was written."))
            return
        QMessageBox.warning(self, tr("Pack"), f"{tr('The archive was not made:')}\n{value}")

    def _create_folder(self) -> None:
        from PyQt6.QtWidgets import QInputDialog

        # Taken before the dialog: a folder load finishing while it is open
        # moves _current_path (see _rename_selected).
        folder = self._current_path
        name, ok = QInputDialog.getText(self, tr("New Folder"), tr("Folder name:"))
        if not ok or not name:
            return
        if not _is_safe_leaf_name(name):
            QMessageBox.warning(
                self,
                tr("New Folder"),
                tr("Folder name must be a plain filename – no path "
                "separators, no '..', no NUL bytes."),
            )
            return
        backend = self._backend
        path = backend.join(folder, name)

        def work(_cancelled, _report):
            if backend.exists(path):
                raise FileExistsError(path)
            backend.mkdir(path)

        def done(_value):
            log.info("Created folder: %s", path)
            self.refresh_after_change()

        self._run_op(tr("Creating {name}…").format(name=name), work, done, tr("New Folder"),
                     exists=tr("Path already exists:\n{name}").format(name=name),
                     failed=tr("Could not create folder:\n{error}"))

    def _create_empty_file(self) -> None:
        """Create a zero-byte file at a user-supplied name.

        Uses the backend's own ``open_write`` rather than a
        filesystem-specific syscall; this means "New File" works on
        every backend that supports writes (SFTP, S3, Dropbox, …),
        not just LocalFS. An empty file is semantically unambiguous
        across backends — no MIME guessing, no attribute defaults
        that differ per protocol.
        """
        from PyQt6.QtWidgets import QInputDialog

        folder = self._current_path  # before the dialog; see _create_folder
        name, ok = QInputDialog.getText(self, tr("New File"), tr("File name:"))
        if not ok or not name:
            return
        if not _is_safe_leaf_name(name):
            QMessageBox.warning(
                self,
                tr("New File"),
                tr("File name must be a plain filename – no path separators, no '..', no NUL bytes."),
            )
            return
        backend = self._backend
        path = backend.join(folder, name)

        def work(_cancelled, _report):
            if backend.exists(path):
                raise FileExistsError(path)
            with backend.open_write(path) as fh:
                fh.write(b"")

        def done(_value):
            log.info("Created empty file: %s", path)
            self.refresh_after_change()

        self._run_op(tr("Creating {name}…").format(name=name), work, done, tr("New File"),
                     exists=tr("Path already exists:\n{name}").format(name=name),
                     failed=tr("Could not create file:\n{error}"))

    def _create_symlink(self) -> None:
        """Prompt for target + link name, then create a symlink.

        Target may be absolute or relative (dangling symlinks are a
        legitimate POSIX pattern and we don't second-guess). The link
        is created under the current directory using the user-supplied
        name. Backends flag support via ``supports_symlinks``; this
        action is hidden from the menu otherwise.
        """
        from PyQt6.QtWidgets import QInputDialog

        # Before the dialogs (see _create_folder): a relative target
        # resolves next to the link, so the folder decides what it means.
        folder = self._current_path
        target, ok = QInputDialog.getText(
            self,
            tr("New Symlink"),
            tr("Target (what the symlink points to):"),
        )
        if not ok or not target:
            return
        link_name, ok = QInputDialog.getText(
            self,
            tr("New Symlink"),
            tr("Link name (created in this folder):"),
        )
        if not ok or not link_name:
            return
        if not _is_safe_leaf_name(link_name):
            QMessageBox.warning(
                self,
                tr("New Symlink"),
                tr("Link name must be a plain filename – no path separators, no '..', no NUL bytes."),
            )
            return
        link_path = self._backend.join(folder, link_name)
        try:
            backend = self._backend
            self._wait(lambda: backend.symlink(target, link_path),
                       tr("Creating {name}…").format(name=link_name))
            log.info("Created symlink: %s → %s", link_path, target)
            self.refresh_after_change()
        except OSError as e:
            log.error("Failed to create symlink: %s", e)
            QMessageBox.warning(
                self,
                tr("New Symlink"),
                tr("Could not create symlink:\n{error}").format(error=describe(e)),
            )

    def _create_hardlink(self) -> None:
        """Prompt for target + link name, then create a hardlink.

        Both paths must live on the same filesystem — cross-device
        hardlinks raise OSError(EXDEV) which we surface verbatim so
        the user understands why. Backends flag support via
        ``supports_hardlinks``; this action is hidden from the menu
        otherwise.
        """
        from PyQt6.QtWidgets import QInputDialog

        folder = self._current_path  # before the dialogs; see _create_folder
        target, ok = QInputDialog.getText(
            self,
            tr("New Hardlink"),
            tr("Target (existing file to link to):"),
        )
        if not ok or not target:
            return
        link_name, ok = QInputDialog.getText(
            self,
            tr("New Hardlink"),
            tr("Link name (created in this folder):"),
        )
        if not ok or not link_name:
            return
        if not _is_safe_leaf_name(link_name):
            QMessageBox.warning(
                self,
                tr("New Hardlink"),
                tr("Link name must be a plain filename – no path separators, no '..', no NUL bytes."),
            )
            return
        link_path = self._backend.join(folder, link_name)
        try:
            backend = self._backend
            self._wait(lambda: backend.hardlink(target, link_path),
                       tr("Creating {name}…").format(name=link_name))
            log.info("Created hardlink: %s → %s", link_path, target)
            self.refresh_after_change()
        except OSError as e:
            log.error("Failed to create hardlink: %s", e)
            QMessageBox.warning(
                self,
                tr("New Hardlink"),
                tr("Could not create hardlink:\n{error}").format(error=describe(e)),
            )

    def _rename_selected(self) -> None:
        from PyQt6.QtWidgets import QInputDialog

        items = self.selected_file_items()
        if not items:
            return
        item = items[0]
        # Resolved before the dialog: a folder load finishing while it is
        # open moves _current_path, and the item belongs to this folder.
        old_path = self._safe_item_path(item)
        if old_path is None:
            return
        folder = self._current_path
        # The name without its extension is selected, as in other file
        # managers: typing replaces "report", ".pdf" stays.
        stem = len(item.name) if item.is_dir else rename_stem_length(item.name)
        QTimer.singleShot(0, lambda: _select_in_modal_line_edit(item.name, stem))
        new_name, ok = QInputDialog.getText(self, tr("Rename"), tr("New name:"), text=item.name)
        if not ok or not new_name or new_name == item.name:
            return
        if not _is_safe_leaf_name(new_name):
            QMessageBox.warning(
                self,
                tr("Rename"),
                tr("New name must be a plain filename – no path "
                "separators, no '..', no NUL bytes."),
            )
            return
        from core.server_ops import rename_target_taken, server_side_move

        backend = self._backend
        new_path = backend.join(folder, new_name)
        failed = f"Could not rename {item.name} to {new_name}:\n{{error}}"
        busy = tr("Renaming {name}…").format(name=item.name)

        def check(_cancelled, _report):
            # Case-aware: "Report.txt" for "report.txt" on a
            # case-insensitive backend finds the file itself.
            if rename_target_taken(backend, old_path, new_path):
                raise FileExistsError(new_path)

        def move(_cancelled, _report):
            server_side_move(backend, old_path, new_path)

        def moved(_value):
            log.info("Renamed %s -> %s", old_path, new_path)
            self._tags_follow_rename(old_path, new_path)
            self.refresh_after_change()

        def checked(_value):
            # The production question between the check and the move: on
            # the GUI thread, as every dialog.
            if not self._production_ok(tr("rename {path} to {name}").format(
                    path=old_path, name=new_name)):
                return
            self._run_op(busy, move, moved, tr("Rename"), failed=failed)

        self._run_op(busy, check, checked, tr("Rename"),
                     exists=tr("Target already exists:\n{name}").format(name=new_name),
                     failed=failed)

    def _batch_rename(self) -> None:
        from ui.batch_rename_dialog import BatchRenameDialog

        items = self.selected_file_items()
        if not items or not self._production_ok(
                tr_n(len(items), "rename {n} item", "rename {n} items")):
            return
        dialog = BatchRenameDialog(self._backend, self._current_path, items, parent=self)
        if dialog.exec():
            self.refresh_after_change()

    def can_trash(self) -> bool:
        """Whether Move to Trash works on this pane's connection."""
        from core.trash import supports_trash

        return supports_trash(self._backend)

    def _delete_key(self) -> None:
        """Del: Move to Trash where the connection has a trash, otherwise
        Delete Permanently (which asks, default No)."""
        if self.can_trash():
            self._trash_selected()
        else:
            self._delete_selected()

    def _delete_selected(self) -> None:
        """Delete the selection permanently, in the background.

        See :meth:`_start_removal`: the walk before the question and the
        removal itself run on a ScanJob, so the window stays live while a
        large folder (or a slow share) is deleted.
        """
        self._start_removal(trash=False)

    @property
    def removal_running(self) -> bool:
        """A Delete / Move to Trash of this pane is checking, asking or removing."""
        return bool(self._removal_ctx)

    def remove_paths(self, paths: list[str]) -> bool:
        """Delete *paths* (on this pane's backend) that a caller has already
        confirmed - the Compare window's Delete - without blocking.

        It is the removal phase of :meth:`_start_removal`: the paths are
        claimed against a parallel delete, the production gate asks, then
        the pane's status line shows the progress with Cancel, errors are
        reported per entry and the folder is reloaded at the end. Each path
        is removed on its own and non-recursively (a folder goes only when
        it is empty), deepest first, so a folder listed before the entries
        inside it goes after them. False when it did not start.
        """
        if not paths:
            return False
        if self._removal_ctx:
            QMessageBox.information(
                self,
                tr("Delete"),
                tr("A delete is still running in this pane; try again when it is done."),
            )
            return False
        backend = self._backend

        def depth(path: str) -> int:
            bare = path.rstrip("/\\")
            return bare.count("/") + bare.count("\\")

        ordered = sorted(dict.fromkeys(paths), key=depth, reverse=True)
        token, busy = _claim_removal(backend, ordered)
        if token is None:
            QMessageBox.warning(
                self,
                tr("Delete"),
                as_written(tr("Not started: these paths are already being deleted or moved "
                              "to the trash:\n{paths}").format(paths=_dialog_lines(busy[:10]))),
            )
            return False
        ctx = {
            "phase": "remove",
            "trash": False,
            "title": tr("Delete"),
            "backend": backend,
            "entries": [(path, path, False) for path in ordered],
            "unsafe": [],
            "names": "",
            "token": token,
        }
        self._removal_ctx = ctx
        if not self._production_ok(
                tr_n(len(ordered), "delete {n} item", "delete {n} items")):
            if not self._removal_dropped(ctx):
                self._end_removal(ctx)
            return False
        if self._removal_dropped(ctx):  # closed or reconnected meanwhile
            return False
        self._start_removal_phase(ctx)
        return True

    def _start_removal(self, *, trash: bool) -> None:
        """Delete (or move to the trash) the selected items without blocking.

        1. The paths are resolved now and claimed, so no second delete of
           them (from this pane or another) runs at the same time.
        2. ``preview_delete`` walks them on a worker thread: counts, and
           hidden entries inside selected folders. Cancel stops it and
           nothing is deleted.
        3. The question, then - for a folder holding hidden entries, or one
           the walk could not fully see - a second question with No as the
           default, then the production gate.
        4. The removal runs on the worker thread entry by entry; Cancel
           stops between entries. Errors are reported per entry, and the
           listing is reloaded at the end.
        """
        title = tr("Move to Trash") if trash else tr("Delete Permanently")
        if self._removal_ctx:
            self.status_message(tr("A delete is still running in this pane."))
            return
        items = self.selected_file_items()
        if not items:
            return
        from core.path_policy import safe_join

        entries: list[tuple[str, str, bool]] = []
        unsafe: list[str] = []
        for item in items:
            try:
                entries.append(
                    (
                        item.name,
                        safe_join(self._backend, self._current_path, item.name),
                        bool(item.is_dir),
                    )
                )
            except ValueError as exc:
                unsafe.append(f"{_shown_name(item.name)}: {exc}")
        if not entries:
            QMessageBox.warning(
                self,
                title,
                as_written(tr("No selected item has a name that can be used safely here:"
                              "\n{names}").format(names=_dialog_lines(unsafe[:10]))),
            )
            return
        backend = self._backend
        paths = [path for _name, path, _is_dir in entries]
        token, busy = _claim_removal(backend, paths)
        if token is None:
            QMessageBox.warning(
                self,
                title,
                as_written(tr("Not started: these paths are already being deleted or moved "
                              "to the trash:\n{paths}").format(paths=_dialog_lines(busy[:10]))),
            )
            return
        self._removal_ctx = {
            "phase": "check",
            "trash": trash,
            "title": title,
            "backend": backend,
            "entries": entries,
            "unsafe": unsafe,
            "names": _dialog_item_names(items),
            "token": token,
        }

        def work(cancelled, report):
            from core.destructive_preview import preview_delete

            return preview_delete(backend, paths, cancel=cancelled, progress=report,
                                  verb=tr("move to trash") if trash else tr("delete"))

        n = len(entries)
        self._show_removal_busy(
            tr_n(n, "Checking {n} item before moving it to the trash…",
                 "Checking {n} items before moving them to the trash…") if trash
            else tr_n(n, "Checking {n} item before the delete…",
                      "Checking {n} items before the delete…")
        )
        self._ensure_removal_job().start(work, replace=True)

    def _ensure_removal_job(self) -> ScanJob:
        if self._removal_job is None:
            self._removal_job = ScanJob(self, formatter=self._removal_progress_text)
            self._removal_job.progress.connect(self._status.setText)
            self._removal_job.finished.connect(self._on_removal_finished)
        return self._removal_job

    def _removal_progress_text(self, state: dict) -> str:
        ctx = self._removal_ctx
        where = _shorten_path(str(state.get("path", "")))
        if ctx.get("phase") == "remove":
            text = (tr("Moving to the trash… {done} of {total}") if ctx.get("trash")
                    else tr("Deleting… {done} of {total}"))
            return text.format(done=state["scanned"], total=state["indexed"]) + f" — {where}"
        return (
            tr("Checking before the delete… {folders} folders, {files} files").format(
                folders=state["scanned"], files=state["indexed"]
            )
            + f" — {where}"
        )

    def _show_removal_busy(self, text: str) -> None:
        self._status.setText(text)
        self._progress_bar.show()
        self._cancel_delete_btn.setEnabled(True)
        self._cancel_delete_btn.show()

    def _hide_removal_busy(self) -> None:
        self._cancel_delete_btn.hide()
        size_running = self._size_job is not None and self._size_job.running
        if not self.is_loading and not size_running:
            self._progress_bar.hide()

    def _cancel_removal(self) -> None:
        """Stop the running delete: the walk at once, a removal after the
        entry in progress (entries already removed stay removed)."""
        if not self._removal_ctx or self._removal_job is None:
            return
        self._removal_job.cancel()
        self._cancel_delete_btn.setEnabled(False)
        self._status.setText(tr("Cancelling – stopping at the next entry…"))

    def _end_removal(self, ctx: dict) -> None:
        _release_removal(ctx["token"])
        if self._removal_ctx is ctx:
            self._removal_ctx = {}

    def _on_removal_finished(self, kind: str, value, cancelled: bool) -> None:
        ctx = self._removal_ctx
        if not ctx or self._shutting_down:
            return
        self._hide_removal_busy()
        if ctx["phase"] == "check":
            self._on_removal_checked(ctx, kind, value, cancelled)
        else:
            self._on_removal_done(ctx, kind, value)

    def _removal_dropped(self, ctx: dict) -> bool:
        """True when the delete must not go on after a dialog: the pane is
        closing, or the connection changed under it (a reconnect)."""
        if self._shutting_down or self._removal_ctx is not ctx:
            _release_removal(ctx["token"])
            return True
        if self._backend is not ctx["backend"]:
            self._end_removal(ctx)
            self.status_message(
                tr("Nothing was moved to the trash: the connection changed meanwhile.")
                if ctx["trash"]
                else tr("Nothing was deleted: the connection changed meanwhile.")
            )
            return True
        return False

    def _on_removal_checked(self, ctx: dict, kind: str, value, cancelled: bool) -> None:
        trash, title = ctx["trash"], ctx["title"]
        preview = value if kind == "done" else None
        if kind == "error":
            log.debug("%s preview failed: %s", title, value)
        if cancelled or (preview is not None and preview.cancelled):
            self._end_removal(ctx)
            self.status_message(_removal_cancelled_text(trash))
            return
        if self._removal_dropped(ctx):
            return
        entries, unsafe = ctx["entries"], ctx["unsafe"]
        n = len(entries)
        preview_text = "\n\n" + removal_preview_text(preview) if preview is not None else ""
        if unsafe:
            preview_text += "\n\n" + tr_n(
                len(unsafe), "Skipped {n} item whose name cannot be used safely:",
                "Skipped {n} items whose names cannot be used safely:",
            ) + "\n" + "\n".join(unsafe[:5])
        if trash:
            question = tr_n(n, "Move {n} item to the trash?", "Move {n} items to the trash?")
        else:
            question = tr_n(n, "Delete {n} item permanently?", "Delete {n} items permanently?")
            question += " " + tr("This cannot be undone.")
        from ui.plain_text import as_written

        # A permanent delete defaults to No: Enter on a reflex keeps the files.
        reply = QMessageBox.question(
            self,
            title,
            as_written(f"{question}\n{ctx['names']}{preview_text}"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes if trash else QMessageBox.StandardButton.No,
        )
        if self._removal_dropped(ctx):
            return
        if reply != QMessageBox.StandardButton.Yes:
            self._end_removal(ctx)
            return
        if not self._hidden_entries_ok(ctx, preview):
            if not self._removal_dropped(ctx):
                self._end_removal(ctx)
                self.status_message(_removal_cancelled_text(trash))
            return
        if self._removal_dropped(ctx):
            return
        op = (
            tr_n(n, "move {n} item to the trash", "move {n} items to the trash")
            if trash
            else tr_n(n, "delete {n} item in {folder}", "delete {n} items in {folder}",
                      folder=self._current_path)
        )
        if not self._production_ok(op):
            if not self._removal_dropped(ctx):
                self._end_removal(ctx)
            return
        if self._removal_dropped(ctx):
            return
        self._start_removal_phase(ctx)

    def _hidden_entries_ok(self, ctx: dict, preview) -> bool:
        """Item 31: a selected folder holding hidden entries needs a second,
        explicit OK (default No). So does one the walk could not fully see:
        hidden entries cannot be ruled out there. Plain files, and a hidden
        entry selected by name, need none."""
        folders = [name for name, _path, is_dir in ctx["entries"] if is_dir]
        if not folders:
            return True
        if ctx["trash"]:
            # Asked once (UX review round 6): the trash keeps everything and
            # Undo / Show Trash… bring it back, and the first question has
            # counted the hidden entries already ("… of them 1 hidden").
            return True
        if preview is not None and not preview.hidden_count and not preview.incomplete:
            return True
        if preview is not None and preview.hidden_count:
            n = preview.hidden_count
            shown = preview.hidden[:5]
            if len(folders) == 1:
                intro = tr_n(n, "The folder {name} contains {n} hidden entry that a listing "
                             "without hidden files does not show:",
                             "The folder {name} contains {n} hidden entries that a listing "
                             "without hidden files does not show, for example:",
                             name=folders[0])
            else:
                intro = tr_n(n, "The selected folders contain {n} hidden entry that a listing "
                             "without hidden files does not show:",
                             "The selected folders contain {n} hidden entries that a listing "
                             "without hidden files does not show, for example:")
            lines = [
                intro,
                *(f"  {_shorten_path(p, 80)}" for p in shown),
            ]
            if n > len(shown):
                lines.append("  " + tr("… and {n} more").format(n=n - len(shown)))
            if preview.incomplete:
                lines.append(tr("The check did not see every entry; there may be more."))
        else:
            if preview is None:
                reason = tr("the check failed")
            elif preview.truncated:
                reason = tr("it stopped after {n} entries").format(n=preview.total_items)
            else:
                reason = tr_n(len(preview.warnings), "{n} entry could not be read",
                              "{n} entries could not be read")
            lines = [
                tr("The check could not look at every entry in the selected folders "
                   "({reason}), so hidden entries cannot be ruled out.").format(reason=reason)
            ]
        lines.append("")
        # No keeps everything - the whole delete, not only the hidden part.
        lines.append(tr("Delete them as well? No deletes nothing."))
        reply = QMessageBox.warning(
            self,
            tr("{title}: hidden entries").format(title=ctx["title"]),
            as_written(_dialog_lines(lines)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _start_removal_phase(self, ctx: dict) -> None:
        ctx["phase"] = "remove"
        backend, entries, trash, token = ctx["backend"], ctx["entries"], ctx["trash"], ctx["token"]

        options = ctx.get("options")

        def work(cancelled, report):
            try:
                return _run_removal(backend, entries, trash, cancelled, report, options)
            finally:
                _release_removal(token)

        n = len(entries)
        self._show_removal_busy(
            tr_n(n, "Moving {n} item to the trash…", "Moving {n} items to the trash…")
            if trash
            else tr_n(n, "Deleting {n} item…", "Deleting {n} items…")
        )
        self._ensure_removal_job().start(work, replace=True)

    def _on_removal_done(self, ctx: dict, kind: str, value) -> None:
        self._end_removal(ctx)
        trash, total = ctx["trash"], len(ctx["entries"])
        errors = list(ctx["unsafe"])
        questions = value.questions if kind == "done" else []
        if questions:
            # Asked below: neither done nor "kept" by a cancel.
            total -= len(questions)
            value.not_attempted -= len(questions)
        if kind == "done" and questions and not total and not errors:
            self._ask_removal_questions(ctx, questions)
            return
        if kind == "error":  # _run_removal catches per entry; this is a defect
            log.error("%s failed: %s", ctx["title"], value)
            errors.append(str(value))
            note = tr("{what} failed: {error}").format(what=ctx["title"], error=value)
        else:
            errors.extend(value.errors)
            done, kept = value.done, value.not_attempted
            if value.aborted:
                note = (
                    tr_n(total, "Move to Trash stopped after an unexpected error: "
                         "{done} of {n} item moved to the trash; {kept} kept.",
                         "Move to Trash stopped after an unexpected error: "
                         "{done} of {n} items moved to the trash; {kept} kept.",
                         done=done, kept=kept)
                    if trash else
                    tr_n(total, "Delete stopped after an unexpected error: "
                         "{done} of {n} item deleted; {kept} kept.",
                         "Delete stopped after an unexpected error: "
                         "{done} of {n} items deleted; {kept} kept.",
                         done=done, kept=kept)
                )
            elif value.partial is not None:
                part_name, part_count = value.partial
                note = tr_n(
                    total,
                    "Delete cancelled after {done} of {n} item; {name} was partly deleted "
                    "({inside} entries inside it removed, the rest is still there); {kept} kept.",
                    "Delete cancelled after {done} of {n} items; {name} was partly deleted "
                    "({inside} entries inside it removed, the rest is still there); {kept} kept.",
                    done=done, name=part_name, inside=part_count, kept=kept,
                )
            elif kept:
                note = (
                    tr_n(total, "Move to Trash cancelled after {done} of {n} item; {kept} kept.",
                         "Move to Trash cancelled after {done} of {n} items; {kept} kept.",
                         done=done, kept=kept)
                    if trash else
                    tr_n(total, "Delete cancelled after {done} of {n} item; {kept} kept.",
                         "Delete cancelled after {done} of {n} items; {kept} kept.",
                         done=done, kept=kept)
                )
            elif trash and done == total:
                # All of it: "1 of 1" read like a partial result (round 6).
                note = tr_n(total, "{n} item moved to the trash.",
                            "{n} items moved to the trash.")
            elif trash:
                note = tr_n(total, "Moved {done} of {n} item to the trash.",
                            "Moved {done} of {n} items to the trash.", done=done)
            elif done == total:
                note = tr_n(total, "{n} item deleted.", "{n} items deleted.")
            else:
                note = tr_n(total, "Deleted {done} of {n} item.", "Deleted {done} of {n} items.",
                            done=done)
        self._note_after_refresh(note)
        if errors:
            QMessageBox.warning(
                self,
                tr("Trash Errors") if trash else tr("Delete Errors"),
                as_written(tr_n(len(errors), "{n} item failed:", "{n} items failed:") + "\n"
                           + _dialog_lines(errors[:10])),
            )
        if questions:
            self._ask_removal_questions(ctx, questions)

    def _ask_removal_questions(self, ctx: dict, questions: list) -> None:
        """Ask about each entry the backend would not delete without a yes
        (:class:`core.backend.ConfirmationRequired`: what Yes does is in its
        explanation), default No; the ones answered Yes are deleted again
        with the backend's keyword for it. No deletes nothing and shows no
        error."""
        from ui.plain_text import as_written

        confirmed: list[tuple[str, str, bool]] = []
        options: dict[str, dict[str, bool]] = {}
        for name, path, is_dir, exc in questions:
            if self._shutting_down or self._backend is not ctx["backend"]:
                return
            reply = QMessageBox.question(
                self,
                ctx["title"],
                as_written(f"{exc.explanation}\n\n" + tr("Go ahead?")),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                confirmed.append((name, path, is_dir))
                options[path] = {exc.option: True}
            else:
                log.info("Delete of %s declined (%s)", path, exc.kind)
        if not confirmed or self._shutting_down or self._removal_ctx:
            return
        backend = ctx["backend"]
        if self._backend is not backend:
            self.status_message(tr("Nothing was deleted: the connection changed meanwhile."))
            return
        token, busy = _claim_removal(backend, [path for _n, path, _d in confirmed])
        if token is None:
            QMessageBox.warning(
                self,
                ctx["title"],
                as_written(tr("Not started: these paths are already being deleted or moved "
                              "to the trash:\n{paths}").format(paths=_dialog_lines(busy[:10]))),
            )
            return
        again = {
            "phase": "remove",
            "trash": False,
            "title": ctx["title"],
            "backend": backend,
            "entries": confirmed,
            "unsafe": [],
            "names": "",
            "token": token,
            "options": options,
        }
        self._removal_ctx = again
        self._start_removal_phase(again)

    def _note_after_refresh(self, text: str) -> None:
        """Show *text* and reload the folder; the reload's "N items" line
        would hide the result, so it is shown again once the listing is in."""
        self.status_message(text)
        folder = self._current_path
        self.refresh_after_change(quiet=True)
        if not self.is_loading:
            return

        def again(path: str, ok: bool) -> None:
            try:
                self.navigation_finished.disconnect(again)
            except (TypeError, RuntimeError):
                pass
            # Not over the listing of a folder the user went to meanwhile.
            if ok and path == folder and not self._shutting_down:
                self._status.setText(text)

        self.navigation_finished.connect(again)

    def _show_permissions(self) -> None:
        """Chmod-only editor. Kept as a separate entry point for callers
        that want just the mode; Alt+Enter goes to the full properties
        sheet, which embeds this same editor as its second tab."""
        from ui.permissions_dialog import PermissionsDialog

        items = self.selected_file_items()
        if not items:
            return
        item = items[0]
        path = self._safe_item_path(item)
        if path is None or not self._production_ok(
                tr("change permissions of {path}").format(path=path)):
            return
        dialog = PermissionsDialog(self._backend, path, item, parent=self)
        if dialog.exec():
            self.refresh_after_change()

    def _show_properties(self) -> None:
        """Properties for the selection.

        One entry gets the detailed sheet; several get a single summary
        rooted at the current directory. Passing only items[0] for a
        multi-selection — which is what this did — answers a question
        nobody asked after Ctrl+A.
        """
        from ui import viewer_window as VW
        from ui.properties_dialog import PropertiesDialog

        items = self.selected_file_items()
        if not items:
            return
        owner = VW.owner_window(self)
        if len(items) == 1:
            path = self._safe_item_path(items[0])
            if path is None:
                return
            dialog = PropertiesDialog(self._backend, path, items[0], parent=owner)
        else:
            dialog = PropertiesDialog(self._backend, self._current_path, items, parent=owner)
        # The permissions tab may have written a new mode: OK refreshes.
        dialog.accepted.connect(self.refresh_after_change)
        VW.show_independent(dialog)

    def _calculate_dir_size(self) -> None:
        """Total size of the selected folders, walked in the background.

        The walk (core.tree_size) runs on a ScanJob: the window stays live,
        the status line counts folders and files, Cancel stops it. When it
        is done the result is a sortable table (ui.dir_size_dialog), and
        each folder's size shows in this pane's Size column until the
        listing is reloaded.
        """
        from core.tree_size import tree_size

        items = self.selected_file_items()
        dirs = [i for i in items if i.is_dir]
        if not dirs:
            return
        # Resolved now: a folder load finishing during the walk moves
        # _current_path (see _rename_selected).
        targets = []
        for item in dirs:
            dir_path = self._safe_item_path(item)
            if dir_path is not None:
                targets.append((item.name, dir_path))
        if not targets:
            return
        if self._size_job is not None and self._size_job.running:
            self.status_message(tr("A size calculation is still running in this pane."))
            return
        backend = self._backend

        def work(cancelled, report):
            results, folders, files = [], 0, 0
            for name, path in targets:
                if cancelled():
                    break
                base_folders, base_files = folders, files
                r = tree_size(
                    backend,
                    path,
                    cancel=cancelled,
                    progress=lambda f, n, where: report(base_folders + f, base_files + n, where),
                )
                folders, files = folders + r.folders, files + r.files
                results.append((name, r))
            return results

        if self._size_job is None:
            self._size_job = ScanJob(
                self,
                formatter=lambda st: tr("Calculating size… {folders} folders, {files} files")
                .format(folders=st["scanned"], files=st["indexed"])
                + f" — {_shorten_path(st['path'])}",
            )
            self._size_job.progress.connect(self._status.setText)
            self._size_job.finished.connect(self._on_dir_size_finished)
        self._status.setText(tr("Calculating size…"))
        self._progress_bar.show()
        self._cancel_size_btn.show()
        # The listing the names belong to: a result that arrives after the
        # pane moved on must not label a same-named folder elsewhere.
        self._size_origin = (backend, self._current_path)
        self._size_job.start(work)

    def _cancel_dir_size(self) -> None:
        if self._size_job is not None:
            self._size_job.cancel()

    def _on_dir_size_finished(self, kind: str, value, cancelled: bool) -> None:
        self._cancel_size_btn.hide()
        if not self.is_loading:
            self._progress_bar.hide()
        if cancelled:
            self._status.setText(tr("Size calculation cancelled"))
            return
        self._status.setText(self._items_text())
        if kind == "error":
            QMessageBox.warning(self, tr("Folder Size"), tr("Could not calculate the size:\n{error}").format(error=value))
            return
        from ui.dir_size_dialog import DirSizeDialog, rows_from_results

        rows = rows_from_results(value)
        backend, folder = getattr(self, "_size_origin", (None, None))
        if backend is self._backend and folder == self._current_path:
            self._model.set_computed_sizes({r.name: (r.bytes, r.incomplete) for r in rows})
        old = getattr(self, "_size_dialog", None)
        if old is not None:
            old.close()
        dialog = DirSizeDialog(rows, folder or self._current_path, parent=self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.destroyed.connect(lambda _obj=None, d=dialog: self._forget_size_dialog(d))
        self._size_dialog = dialog
        dialog.show()

    def _forget_size_dialog(self, dialog) -> None:
        if getattr(self, "_size_dialog", None) is dialog:
            self._size_dialog = None

    # Known checksum-string prefixes that the backends return. Keeping
    # this as an explicit allowlist (rather than a "looks like
    # ``<word>:<hex>``" heuristic) avoids two failure modes:
    #   * a hex-only value that happens to contain a ":" being split
    #     in the wrong place
    #   * a backend later returning some new "<word>:<value>" format
    #     where the tail isn't a hex digest (would have been silently
    #     reinterpreted as the algorithm by the old code)
    # Order matters: longer prefixes (s3-etag) must come before any
    # shorter one they could overlap with.
    _CHECKSUM_PREFIXES = (
        "s3-etag",
        "etag",
        "dropbox",
        "quickxor",
        "md5",
        "sha1",
        "sha256",
        "sha512",
    )

    @classmethod
    def _split_checksum(cls, value: str) -> tuple[str, str]:
        """Return ``(algorithm, hex_value)`` for a string returned by
        ``backend.checksum``. Strings without a known prefix are
        treated as raw SHA-256 (the requested default algorithm)."""
        for prefix in cls._CHECKSUM_PREFIXES:
            head = prefix + ":"
            if value.startswith(head):
                return prefix, value[len(head) :]
        return "sha256", value

    def _show_checksum(self, item) -> None:
        """Fetch or compute a checksum for *item* and show it in a copy
        dialog - off the GUI thread. Backends with a native fingerprint
        answer ``backend.checksum`` (SFTP runs sha256sum on the server: a
        large file took minutes, the window frozen under a wait cursor);
        the rest answer ``""`` and SHA-256 is offered by reading the file,
        which ran on the GUI thread a megabyte at a time. Both run on a
        ScanJob now: the status line says how far it is, Cancel stops it."""
        full_path = self._safe_item_path(item)
        if full_path is None:
            return
        job = self._ensure_checksum_job()
        if job.running:
            self.status_message(tr("A checksum is still running in this pane."))
            return
        backend = self._backend
        # The backend with them: the stream hash after the question reads
        # through this one, not the one the pane shows by then.
        self._checksum_target = (item, full_path)
        self._checksum_backend = backend
        self._checksum_phase = "native"
        self._begin_checksum(tr("Checksum of {name}…").format(name=item.name))
        job.start(lambda _cancelled, _report: backend.checksum(full_path))

    def _ensure_checksum_job(self) -> ScanJob:
        if self._checksum_job is None:
            self._checksum_job = ScanJob(self, formatter=self._checksum_progress_text)
            self._checksum_job.progress.connect(self._status.setText)
            self._checksum_job.finished.connect(self._on_checksum_finished)
        return self._checksum_job

    def _checksum_progress_text(self, state: dict) -> str:
        item, _path = getattr(self, "_checksum_target", (None, ""))
        name = item.name if item is not None else ""
        if getattr(self, "_checksum_phase", "") != "stream":
            return tr("Checksum of {name}…").format(name=name)
        done, total = state.get("scanned", 0), state.get("indexed", 0)
        if total and total > 0:
            return tr("Hashing {name}… {done} of {total}").format(
                name=name, done=_human_size(done), total=_human_size(total))
        return tr("Hashing {name}… {done}").format(name=name, done=_human_size(done))

    def _begin_checksum(self, text: str) -> None:
        self._status.setText(text)
        self._progress_bar.show()
        self._cancel_checksum_btn.show()

    def _cancel_checksum(self) -> None:
        if self._checksum_job is not None:
            self._checksum_job.cancel()

    def _start_stream_checksum(self, item, full_path: str) -> None:
        """SHA-256 by reading the whole file through the backend it was asked on."""
        backend = self._checksum_backend
        total = item.size if item.size and item.size > 0 else 0
        self._checksum_phase = "stream"
        self._begin_checksum(tr("Hashing {name}…").format(name=item.name))
        # replace: the first job's thread may not have ended yet - it
        # finished its work and is reporting (its result is in already).
        self._ensure_checksum_job().start(
            lambda cancelled, report: _stream_sha256(backend, full_path, total, cancelled, report),
            replace=True)

    def _on_checksum_finished(self, kind: str, value, cancelled: bool) -> None:
        self._cancel_checksum_btn.hide()
        if not self.is_loading:
            self._progress_bar.hide()
        self._status.setText(self._items_text())
        if cancelled or (kind == "done" and value is None):
            self._status.setText(tr("Checksum cancelled"))
            return
        item, full_path = self._checksum_target
        stream = self._checksum_phase == "stream"
        if kind == "error":
            text = (tr("Failed to read file for hashing:\n{error}") if stream
                    else tr("Failed to compute checksum:\n{error}"))
            QMessageBox.warning(self, tr("Checksum"), text.format(error=value))
            return
        if stream:
            self._present_checksum(full_path, "sha256", value, "stream-read")
            return
        algo, digest = self._split_checksum(value) if value else ("", "")
        # A backend that returned a known prefix with an empty tail
        # (e.g. ``"md5:"``) is still "no native checksum" from the
        # user's perspective - on to the stream hash.
        if digest:
            self._present_checksum(full_path, algo, digest, "native")
            return
        from ui.plain_text import as_written

        # The name is the backend's: shown as written, never as markup.
        reply = QMessageBox.question(
            self,
            tr("Checksum"),
            as_written(tr("{name}: this backend has no native checksum.\n\n"
                          "Compute SHA-256 by reading the entire file?").format(name=item.name)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._start_stream_checksum(item, full_path)

    def _present_checksum(self, full_path: str, algo: str, value: str, source: str) -> None:
        from ui import viewer_window as VW
        from ui.checksum_dialog import ChecksumDialog

        VW.show_independent(
            ChecksumDialog(full_path, algo, value, source=source, parent=VW.owner_window(self))
        )

    # ------------------------------------------------------------------
    # Column header — show/hide + persist widths
    # ------------------------------------------------------------------
    def _apply_column_prefs(self) -> None:
        from ui import column_prefs as CP

        prefs = CP.load()
        # Defensive: if a hand-edited prefs file claims col 0 is
        # hidden, ignore it — the Name column must always be visible.
        if 0 in prefs.hidden:
            prefs.hidden.discard(0)
        # Cache so the resize / hide handlers can mutate-and-save
        # without re-reading the file every time.
        self._column_prefs = prefs
        header = self._table.horizontalHeader()
        n = self._model.columnCount()
        self._fitting = True
        try:
            self._restore_column_order(prefs.order)
            for col in range(n):
                width = prefs.widths.get(col)
                if col != 0 and width and width > 10:
                    header.resizeSection(col, int(width))
                self._table.setColumnHidden(col, col in prefs.hidden)
        finally:
            self._fitting = False
        self._fit_name_column()

    def _save_column_prefs(self) -> None:
        """Persist this pane's column prefs without losing changes
        another pane (in the same process) wrote concurrently.

        Uses ``column_prefs.update`` which holds a per-path lock for
        the entire load+modify+save cycle. The mutator merges *our*
        deltas onto the on-disk state so two panes saving at the
        same time don't clobber each other's widths."""
        from ui import column_prefs as CP

        local = getattr(self, "_column_prefs", None)
        if local is None:
            return
        try:
            merged = CP.update(self._merge_into_prefs)
            # Refresh our cached copy so subsequent mutations start
            # from the merged baseline.
            self._column_prefs = merged
        except OSError as exc:
            log.warning("Could not persist column prefs: %s", exc)

    def _merge_into_prefs(self, on_disk) -> None:
        """Apply our local widths/hidden onto the freshly-loaded
        on-disk prefs.

        widths: per-column merge — ``on_disk.widths.update(local)``
                preserves another pane's edit on column N when ours
                edited column M. This is the lost-update fix: without
                it, two panes resizing different columns concurrently
                would each clobber the other's change.

        hidden: last-writer-wins — replace ``on_disk.hidden`` with
                ours. Hidden is a per-user preference (same human
                drives both panes); merging would lock columns visible
                that the user explicitly hid in the latest pane.
        """
        local = getattr(self, "_column_prefs", None)
        if local is None:
            return
        on_disk.widths.update(local.widths)
        on_disk.hidden = set(local.hidden)
        on_disk.order = list(local.order)

    def _restore_column_order(self, order: list[int]) -> None:
        """Apply a saved visual order; anything that is not a permutation of
        the current columns (old file, hand edit) is ignored."""
        header = self._table.horizontalHeader()
        if sorted(order) != list(range(header.count())):
            return
        for visual, logical in enumerate(order):
            header.moveSection(header.visualIndex(logical), visual)

    def _on_section_moved(self, _logical: int, _old: int, _new: int) -> None:
        if self._fitting or getattr(self, "_column_prefs", None) is None:
            return
        header = self._table.horizontalHeader()
        self._column_prefs.order = [header.logicalIndex(v) for v in range(header.count())]
        self._save_column_prefs()

    def _visible_columns(self) -> list[int]:
        return [c for c in range(self._model.columnCount()) if not self._table.isColumnHidden(c)]

    def _content_widths_changed(self, *_args) -> None:
        """The listing (or its font) changed: forget the measured widths
        and refit once the burst of model signals is over."""
        self._content_widths = {}
        if not self._content_fit_pending:
            self._content_fit_pending = True
            QTimer.singleShot(0, self._deferred_content_fit)

    def _deferred_content_fit(self) -> None:
        self._content_fit_pending = False
        if getattr(self, "_table", None) is not None:
            self._fit_name_column()

    def _content_width(self, col: int) -> int:
        """Width column *col* needs for its longest text, icon and padding.

        Reads up to _MEASURE_ROWS rows, picks the _MEASURE_LONGEST longest
        texts and asks the view for their exact size - a proportional font
        makes the longest string not always the widest. Cached until the
        listing changes.
        """
        cached = self._content_widths.get(col)
        if cached is not None:
            return cached
        rows = min(self._proxy.rowCount(), _MEASURE_ROWS)
        # The texts straight from the items (what data() shows), not one
        # proxy + model round trip per row: ~30 ms per 5000 rows.
        items = self._model._items
        text_of = self._model.display_text
        lengths = []
        for row, source in enumerate(self._proxy.source_rows(rows)):
            text = text_of(items[source], col)
            lengths.append((len(text) if isinstance(text, str) else 0, row))
        lengths.sort(reverse=True)
        width = 0
        for _length, row in lengths[:_MEASURE_LONGEST]:
            width = max(width, self._table.sizeHintForIndex(self._proxy.index(row, col)).width())
        self._content_widths[col] = width
        return width

    def _preferred_width(self, col: int) -> int:
        """The width the user gave column *col*, else its default - at
        least its header label's width: a German "Eigentümer" is wider
        than the default and was clipped to "igentüme" (UX review round 6;
        a column that does not fit steps aside instead)."""
        prefs = getattr(self, "_column_prefs", None)
        stored = prefs.widths.get(col) if prefs is not None else None
        if stored and stored > 10:
            return int(stored)
        default = _DEFAULT_COLUMN_WIDTHS.get(col, 100)
        table = getattr(self, "_table", None)
        if table is None:
            return default
        return max(default, self._label_width(col))

    def _label_width(self, col: int) -> int:
        """Width the header label of *col* needs as drawn: the header's
        real (style sheet) font, its padding and room for a sort arrow.

        Not header.sectionSizeHint(): that is 0 for a hidden column,
        so a column that had stepped aside came back below its label - the
        German "Eigentümer" at 75 px drawn as "igentüme" (UX review
        round 7)."""
        from PyQt6.QtCore import QSize
        from PyQt6.QtWidgets import QStyle, QStyleOptionHeader

        header = self._table.horizontalHeader()
        opt = QStyleOptionHeader()
        opt.initFrom(header)
        opt.orientation = Qt.Orientation.Horizontal
        opt.section = col
        opt.text = str(self._model.headerData(col, Qt.Orientation.Horizontal) or "")
        opt.textAlignment = header.defaultAlignment()
        # Room for the arrow whichever column is sorted: sorting by a
        # column must not clip its label either. The same measure for a
        # shown and a hidden column, so a refresh does not make columns
        # jump.
        if header.isSortIndicatorShown():
            opt.sortIndicator = QStyleOptionHeader.SortIndicator.SortDown
        size = header.style().sizeFromContents(
            QStyle.ContentsType.CT_HeaderSection, opt, QSize(), header
        )
        return size.width()

    def _column_floor(self, col: int) -> int:
        """Narrowest *col* may get to make room for a name: its own content
        and its header label stay whole."""
        header = self._table.horizontalHeader()
        return max(header.minimumSectionSize(), self._content_width(col), self._label_width(col))

    def _user_visible_columns(self) -> list[int]:
        """The columns the user wants shown (the fitting may hide some)."""
        prefs = getattr(self, "_column_prefs", None)
        hidden = prefs.hidden if prefs is not None else set()
        return [c for c in range(self._model.columnCount()) if c not in hidden]

    def _name_floor(self, viewport: int) -> int:
        """Width Name gets before any other column is considered: what its
        content needs, at most the larger of 40 % of the pane and about 24
        characters - the other columns shrink or step aside for it."""
        chars = self._table.fontMetrics().horizontalAdvance("n" * 24)
        icon = self._table.iconSize().width() if self._table.iconSize().isValid() else 16
        # Never less than its header label: an empty folder (only "." and
        # "..") left Name a few pixels wide beside full-width columns
        # (UX review round 6).
        label = self._label_width(0)
        return max(label, min(self._content_width(0), max(viewport * 2 // 5, chars + icon + 24)))

    def _fit_widths(self, others: list[int], viewport: int, chosen: set[int]) -> dict[int, int]:
        """Widths of *others*: their preferred ones, minus the slack a name
        that does not fit takes (each gives up at most what its own content
        does not use, in proportion to that slack)."""
        widths = {c: self._preferred_width(c) for c in others}
        missing = self._content_width(0) - (viewport - sum(widths.values()))
        if missing <= 0 or not others:
            return widths
        slack = {
            c: 0 if c in chosen else max(0, widths[c] - self._column_floor(c)) for c in others
        }
        total = sum(slack.values())
        take = min(missing, total)
        if take > 0:
            given = {c: take * slack[c] // total for c in others}
            rest = take - sum(given.values())
            for c in sorted(others, key=lambda c: slack[c] - given[c], reverse=True):
                if rest <= 0:
                    break
                if given[c] < slack[c]:
                    given[c] += 1
                    rest -= 1
            for c in others:
                widths[c] -= given[c]
        return widths

    def _fit_name_column(self) -> None:
        """Lay the columns out across the viewport, Name first.

        Every other visible column gets its preferred width while the name
        fits in what is left. A name that does not fit takes the slack of
        the others first. If Name still has less than its floor
        (_name_floor) the rightmost columns step aside - hidden for now,
        not in the prefs, back as soon as the pane is wide enough; ones
        the user never resized go first. A width the user dragged is no
        slack: taking it made every drag snap back while a long name did
        not fit. None of this is a user choice, so nothing here writes
        column prefs.
        """
        if self._fitting or getattr(self, "_table", None) is None:
            return
        header = self._table.horizontalHeader()
        viewport = self._table.viewport().width()
        if viewport <= 0 or self._table.isColumnHidden(0):
            return
        others = [c for c in self._user_visible_columns() if c != 0]
        chosen = set(getattr(self._column_prefs, "widths", {}) or {})
        step_aside: set[int] = set()
        # Hidden, the viewport has no real width yet: nothing to make room in.
        if self._table.isVisible():
            widths = self._fit_widths(others, viewport, chosen)
            floor = self._name_floor(viewport)
            while others and viewport - sum(widths.values()) < floor:
                by_position = sorted(others, key=header.visualIndex, reverse=True)
                victim = next((c for c in by_position if c not in chosen), by_position[0])
                others.remove(victim)
                step_aside.add(victim)
                widths = self._fit_widths(others, viewport, chosen)
        else:
            step_aside = self._fit_hidden & set(others)
            others = [c for c in others if c not in step_aside]
            widths = {c: self._preferred_width(c) for c in others}
        target = max(header.minimumSectionSize(), viewport - sum(widths.values()))
        self._fitting = True
        try:
            for c in range(1, self._model.columnCount()):
                user_visible = c in others or c in step_aside
                if user_visible and self._table.isColumnHidden(c) != (c in step_aside):
                    self._table.setColumnHidden(c, c in step_aside)
            self._fit_hidden = step_aside
            for c in others:
                if header.sectionSize(c) != widths[c]:
                    header.resizeSection(c, widths[c])
            if header.sectionSize(0) != target:
                header.resizeSection(0, target)
        finally:
            self._fitting = False

    def _next_visible_after_name(self) -> int | None:
        header = self._table.horizontalHeader()
        for visual in range(header.visualIndex(0) + 1, header.count()):
            logical = header.logicalIndex(visual)
            if not self._table.isColumnHidden(logical):
                return logical
        return None

    def _name_divider_dragged(self, old: int, new: int) -> None:
        """The user dragged the divider right of Name: the neighbour pays
        (or receives) the difference so the columns keep filling the pane."""
        header = self._table.horizontalHeader()
        neighbour = self._next_visible_after_name()
        if neighbour is not None and new != old:
            width = max(header.minimumSectionSize(), header.sectionSize(neighbour) - (new - old))
            self._fitting = True
            try:
                header.resizeSection(neighbour, width)
            finally:
                self._fitting = False
            self._column_prefs.widths[neighbour] = int(width)
            self._save_column_prefs()
        self._fit_name_column()

    def _on_section_resized(self, idx: int, old: int, new: int) -> None:
        if self._fitting or getattr(self, "_column_prefs", None) is None:
            return
        # Name's width is derived from the others; the drag handler below
        # turns a drag on its divider into a move of the neighbour's.
        if idx == 0:
            self._name_divider_dragged(old, new)
            return
        # Tiny / negative widths happen during programmatic moves —
        # ignore them so we don't persist garbage.
        if new >= 10:
            self._column_prefs.widths[int(idx)] = int(new)
            self._save_column_prefs()
        self._fit_name_column()

    def _show_header_menu(self, pos) -> None:
        """Right-click on the header opens a checkbox list of columns
        — checked = visible. Toggling a column hides/shows it and
        persists the change. The Name column (0) is pinned visible
        because hiding it leaves the pane unusable."""
        from PyQt6.QtGui import QCursor

        if getattr(self, "_column_prefs", None) is None:
            return
        n = self._model.columnCount()
        menu = QMenu(self)
        for col in range(n):
            label = (
                self._model.headerData(
                    col,
                    Qt.Orientation.Horizontal,
                    Qt.ItemDataRole.DisplayRole,
                )
                or tr("Column {n}").format(n=col)
            )
            action = menu.addAction(str(label))
            action.setCheckable(True)
            action.setChecked(col not in self._column_prefs.hidden)
            if col == 0:
                # Pinning: never let the user hide the Name column.
                action.setEnabled(False)
            else:
                action.toggled.connect(lambda visible, c=col: self._toggle_column(c, visible))
        try:
            menu.exec(QCursor.pos())
        finally:
            menu.deleteLater()

    def _toggle_column(self, col: int, visible: bool) -> None:
        if getattr(self, "_column_prefs", None) is None:
            return
        # Pin: the Name column is the row identity; hiding it
        # leaves the pane unusable. The right-click menu disables
        # the action for col=0, but a programmatic call (test, future
        # API, restored prefs file edited by hand) would still get
        # through without this guard.
        if col == 0 and not visible:
            return
        self._table.setColumnHidden(col, not visible)
        if visible:
            self._column_prefs.hidden.discard(col)
        else:
            self._column_prefs.hidden.add(col)
        self._save_column_prefs()
        self._fit_name_column()

    # ------------------------------------------------------------------
    # FUSE mount integration (Phase 6a)
    # ------------------------------------------------------------------
    def _mount_as_fuse(self, writeable: bool = False) -> None:
        """Pop a directory chooser and start a FUSE mount of the
        current backend at the chosen empty mount point.

        Read-only by default; ``writeable=True`` enables the
        create/write/unlink/mkdir/rename callbacks. The wiring adds
        two menu entries (read-only + writeable) so the user sees
        the mode they're picking up front rather than a hidden
        toggle buried in a dialog."""
        from PyQt6.QtWidgets import QFileDialog

        from core import fuse_mount as FM
        from ui.off_gui import run_off_gui

        existing = getattr(self, "_fuse_handle", None)
        if existing is not None and getattr(existing, "is_alive", lambda: True)():
            QMessageBox.information(
                self,
                "FUSE",
                tr("This pane already has a FUSE mount at {path}.").format(
                    path=existing.mount_point),
            )
            return
        # A handle whose loop has ended serves nothing: no reason to refuse.
        self._fuse_handle = None
        mount_point = QFileDialog.getExistingDirectory(
            self,
            tr("Pick an empty mount point"),
        )
        if not mount_point:
            return
        try:
            handle = FM.mount(
                self._backend,
                mount_point,
                root=self._current_path,
                writeable=writeable,
            )
            # mount() returns once its loop thread started; libfuse may
            # still refuse the mount a moment later (no /dev/fuse, a busy
            # or non-empty folder). Report "Mounted" only for a real one.
            mounted = run_off_gui(lambda: handle.wait_until_mounted(FUSE_MOUNT_WAIT_S))
        except Exception as exc:  # noqa: BLE001 — surface to user
            QMessageBox.critical(
                self,
                "FUSE",
                tr("Could not mount at {path}:\n{reason}").format(
                    path=mount_point, reason=describe(exc, mount_point)),
            )
            return
        if not mounted:
            error = getattr(handle, "error", None)
            if handle.is_alive():  # neither up nor failed: give up on it
                try:
                    run_off_gui(handle.unmount)
                except Exception as exc:  # noqa: BLE001 — the report below says enough
                    log.debug("FUSE: unmount of a mount that never came up: %s", exc)
                if handle.is_alive():
                    self._fuse_handle = handle  # still running: keep it unmountable
                reason = tr("The mount did not come up within {n} seconds.").format(
                    n=FUSE_MOUNT_WAIT_S)
            elif error is None or isinstance(error, RuntimeError):
                # fusepy raises RuntimeError(status) for every refusal.
                reason = tr("FUSE refused the mount. Check that the fuse kernel module "
                            "is loaded (/dev/fuse), and that the folder is empty and "
                            "not in use.")
            else:
                reason = describe(error, mount_point)
            QMessageBox.critical(
                self,
                "FUSE",
                tr("Could not mount at {path}:\n{reason}").format(
                    path=mount_point, reason=reason),
            )
            return
        self._fuse_handle = handle
        mode = tr("read-write") if writeable else tr("read-only")
        QMessageBox.information(
            self,
            "FUSE",
            tr("Mounted {path} ({mode}) at {mount_point}.").format(
                path=self._current_path, mode=mode, mount_point=mount_point),
        )

    def _unmount_fuse(self) -> None:
        handle = getattr(self, "_fuse_handle", None)
        if handle is None:
            return
        from ui.off_gui import run_off_gui

        try:
            # fusermount -u, umount and the serving thread's end: up to
            # about 15 s, off the GUI thread.
            run_off_gui(handle.unmount)
        except Exception as exc:  # noqa: BLE001
            # Still mounted (busy) or still served: keep the handle, so
            # Unmount FUSE stays in the menu for another try.
            QMessageBox.warning(
                self,
                "FUSE",
                tr("{path} is still mounted:\n{reason}").format(
                    path=handle.mount_point, reason=describe(exc, handle.mount_point)),
            )
            return
        self._fuse_handle = None
        QMessageBox.information(
            self,
            "FUSE",
            tr("Unmounted {path}.").format(path=handle.mount_point),
        )

    def _create_xlink(self) -> None:
        """Pop the create-xlink dialog and write a new ``.axlink``
        pointer file in the current directory."""
        from core import xlink as XL
        from ui.create_xlink_dialog import CreateXlinkDialog

        folder = self._current_path  # before the dialog; see _create_folder
        dlg = CreateXlinkDialog(parent=self)
        if not dlg.exec():
            return
        name = dlg.name()
        url = dlg.target_url()
        display = dlg.display_name()
        if not _is_safe_leaf_name(name):
            QMessageBox.warning(
                self,
                tr("Create XLink"),
                tr("Link name must be a plain filename – no path separators, no '..', no NUL bytes."),
            )
            return
        target_path = self._backend.join(folder, name)
        leaf = name if XL.is_xlink_path(name) else name + XL.LINK_SUFFIX
        try:
            # create_xlink replaces what is there (atomic_write); like New
            # Folder and New File, an existing name is refused, not overwritten.
            backend = self._backend

            def create() -> str | None:
                # Off the GUI thread (ui.off_gui): an exists() and an atomic
                # write are round trips to a server.
                if backend.exists(backend.join(folder, leaf)):
                    return None
                return XL.create_xlink(backend, target_path, url, display_name=display)

            final = self._wait(create, tr("Creating {name}…").format(name=leaf))
            if final is None:
                QMessageBox.warning(self, tr("Create XLink"),
                                    as_written(tr("Path already exists:\n{name}").format(name=leaf)))
                return
            log.info("Created xlink %s → %s", final, redact_url(url))
        except (OSError, ValueError) as exc:
            QMessageBox.critical(
                self,
                tr("Create XLink"),
                tr("Could not create xlink:\n{error}").format(error=describe(exc)),
            )
            return
        self.refresh_after_change()

    def _show_versions(self, item) -> None:
        """Open the snapshot/versions browser for a single file."""
        from ui.snapshot_browser_dialog import SnapshotBrowserDialog

        full_path = self._safe_item_path(item)
        if full_path is None:
            return
        dlg = SnapshotBrowserDialog(self._backend, full_path, parent=self)
        dlg.finished.connect(lambda _code: self.refresh_after_change())
        dlg.open()

    def _elevated_io_available(self) -> bool:
        """True when the menu entry "Open as root…" should be shown:
        backend is local AND pkexec + helper binaries are on PATH."""
        try:
            from core import elevated_io as E

            return E._is_local_backend(self._backend) and E.is_pkexec_available()
        except Exception as exc:  # noqa: BLE001 - no menu entry rather than a broken menu
            log.debug("Open as root… left out: %s", exc)
            return False

    def _open_as_root(self, full_path: str) -> None:
        """Read *full_path* via pkexec and pop a read-only viewer.

        The polkit prompt is handled by the system agent (a separate
        process); during the prompt our subprocess.run blocks the GUI
        thread for up to ELEVATED_TIMEOUT_SECS. That's a known wart of
        the synchronous first cut — acceptable because the user just
        triggered this action and is expecting an auth dialog.
        """
        from core import elevated_io as E
        from ui.elevated_viewer import ElevatedViewerDialog

        try:
            from ui.off_gui import run_off_gui

            # pkexec waits for the polkit prompt: off the GUI thread, the
            # window painting meanwhile.
            backend = self._backend
            data = run_off_gui(lambda: E.elevated_read(backend, full_path),
                               text=tr("Waiting for the administrator password…"),
                               status=lambda shown: self._status.setText(
                                   shown or self._items_text()))
        except E.ElevatedCancelled:
            log.info("Open-as-root cancelled by user: %s", full_path)
            return
        except E.ElevatedNotAvailable as exc:
            QMessageBox.information(
                self,
                tr("Open as root"),
                tr("Cannot elevate access:\n{error}").format(error=exc),
            )
            return
        except E.ElevatedOutputTooLarge as exc:
            QMessageBox.warning(
                self,
                tr("Open as root"),
                tr("File is too large to read into memory:\n{error}").format(error=exc),
            )
            return
        except (E.ElevatedIOError, ValueError) as exc:
            QMessageBox.critical(
                self,
                tr("Open as root"),
                tr("Elevated read failed:\n{error}").format(error=exc),
            )
            return
        from ui import viewer_window as VW

        VW.show_independent(ElevatedViewerDialog(full_path, data, parent=VW.owner_window(self)))

    def _trash_selected(self) -> None:
        """Move selected items to ``core.trash`` for the current backend.

        Trash lives at ``<backend.home()>/.axross-trash`` by default,
        so the entry survives restart and can be restored through
        "Show Trash…". Runs like Delete (see :meth:`_start_removal`): in
        the background, with the same second question for folders that
        hold hidden entries. Per-item OSError is collected and reported
        at the end; one bad item doesn't abort the rest.
        """
        self._start_removal(trash=True)

    def _show_trash_browser(self) -> None:
        """Open a dialog listing ``core.trash`` entries for the current
        backend. User can restore or permanently delete from there."""
        from ui.trash_browser import TrashBrowserDialog

        dlg = TrashBrowserDialog(self._backend, parent=self)
        dlg.finished.connect(lambda _code: self.refresh_after_change())
        dlg.open()

    def _open_archive_preview(self, path: str) -> None:
        """Open *path* in the main window's non-modal archive preview
        dock (Task A4).

        The pane is a reusable widget with no stored MainWindow
        reference — we reach the owning window via ``self.window()``
        (Qt returns the top-level ancestor, the MainWindow). Guard on
        the ``open_archive_pane`` attribute so a pane hosted outside a
        MainWindow (tests, an embedded harness) degrades to a no-op +
        log line rather than crashing."""
        win = self.window()
        opener = getattr(win, "open_archive_pane", None)
        if opener is None:
            log.warning("Archive preview unavailable: no main window for %s", path)
            return
        opener(path)

    def _extract_archive(self, item) -> None:
        """Extract the archive at *item* into a same-named sibling
        folder (extension stripped). On collision (``foo/`` already
        exists) the target auto-suffixes to ``foo-1/``, ``foo-2/``, …
        so repeated extracts of the same archive don't clobber.

        Runs on a QThread with a QProgressDialog; cancel aborts the
        worker and removes the partially-populated target directory
        (cleanup lives in :func:`core.archive.extract` — we just
        raise ExtractCancelled from the progress callback and let
        the library roll back).

        Local-backend-only: the caller gates the menu entry on
        ``_is_local_backend``. Remote-backend archives would need a
        download-then-extract flow which is intentionally out of
        scope for V1 — use "Copy to Target Pane" + extract locally.
        """
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QProgressDialog

        from core import archive as ARCH

        src_path = self._safe_item_path(item)
        if src_path is None:
            return
        parent_dir = self._backend.parent(src_path)
        base = ARCH.strip_archive_extension(item.name)
        try:
            target_dir = ARCH.auto_suffix_dir(parent_dir, base)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Extract Archive"),
                tr("Cannot pick a target folder:\n{error}").format(error=exc),
            )
            return

        from ui.plain_text import as_written

        progress = QProgressDialog(
            as_written(tr("Extracting {name} → {target}…").format(
                name=item.name, target=Path(target_dir).name)),
            tr("Cancel"),
            0,
            0,
            self,
        )
        progress.setWindowTitle(tr("Extract Archive"))
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(250)
        progress.setValue(0)

        # Shared state between the worker and the dialog poller.
        done_event = threading.Event()
        # Pre-seed with something the types in the pipeline accept.
        state: dict = {"ok": False, "count": 0, "error": None, "current": 0, "total": 0, "name": ""}
        # The worker reads this, never the dialog: a widget is the GUI
        # thread's alone (wasCanceled() from the worker was a data race).
        cancelled = threading.Event()
        progress.canceled.connect(cancelled.set)

        def _progress_cb(done: int, total: int, name: str) -> None:
            state["current"] = done
            state["total"] = total
            state["name"] = name
            if cancelled.is_set():
                raise ARCH.ExtractCancelled(
                    "user cancelled via progress dialog",
                )

        def _worker() -> None:
            try:
                state["count"] = ARCH.extract(
                    src_path,
                    target_dir,
                    progress=_progress_cb,
                )
                state["ok"] = True
            except ARCH.ExtractCancelled:
                state["error"] = "cancelled"
            except ARCH.UnsafeArchive as exc:
                state["error"] = f"refused as unsafe: {exc}"
            except Exception as exc:  # noqa: BLE001
                state["error"] = f"extraction failed: {exc}"
            finally:
                done_event.set()

        t = threading.Thread(
            target=_worker,
            daemon=True,
            name=f"extract:{item.name}",
        )
        t.start()

        # Pump the Qt event loop while the worker runs so the
        # progress dialog stays responsive. ``done_event.wait(short)``
        # parks us cheaply when the worker is busy AND gives the
        # event loop a chance to fire the Cancel button.
        while not done_event.is_set():
            QApplication.processEvents()
            if progress.wasCanceled():  # here, on the GUI thread: Esc, the X, Cancel
                cancelled.set()
            done_event.wait(0.05)
        # Drain any pending UI events so the final progress update
        # lands before we close the dialog.
        QApplication.processEvents()
        progress.close()

        if state["ok"]:
            log.info(
                "Extracted %s → %s (%d files)",
                src_path,
                target_dir,
                state["count"],
            )
            self.refresh_after_change()
            text = tr_n(
                int(state["count"]),
                "Extracted {n} file to\n{target}",
                "Extracted {n} files to\n{target}",
                target=target_dir,
            )
            # Links are never extracted: say which, here and in the status line.
            note = skipped_links_note(state["count"])
            if note:
                self.status_message(note)
                text += "\n\n" + note
            QMessageBox.information(self, tr("Extract Archive"), as_written(text))
            return
        if state["error"] == "cancelled":
            log.info("Extraction cancelled: %s", src_path)
            return
        QMessageBox.warning(
            self,
            tr("Extract Archive"),
            # the archive's name and the error come from outside: as written
            as_written(tr("Could not extract {name}:\n{error}").format(
                name=item.name, error=state["error"])),
        )

    def _encrypt_selected_file(self, item) -> None:
        """Encrypt *item* in place (writes ``<name>.axenc`` next to it).

        Prompts for a passphrase twice (confirm) via QInputDialog, then
        reads the source, encrypts via core.encrypted_overlay, writes
        the resulting ``.axenc``. Does NOT delete the plaintext — user
        decides when they're comfortable.
        """
        from PyQt6.QtWidgets import QInputDialog, QLineEdit

        from core import encrypted_overlay as E

        # Resolved before the passphrase prompts; see _rename_selected.
        src_path = self._safe_item_path(item)
        if src_path is None:
            return
        from ui.plain_text import as_written

        pw, ok = QInputDialog.getText(
            self,
            tr("Encrypt File"),
            as_written(tr("Passphrase for '{name}':").format(name=item.name)),
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pw:
            return
        pw_confirm, ok = QInputDialog.getText(
            self,
            tr("Encrypt File"),
            tr("Repeat passphrase:"),
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        if pw != pw_confirm:
            QMessageBox.warning(
                self,
                tr("Encrypt File"),
                tr("Passphrases do not match."),
            )
            return

        try:
            # Same question Decrypt asks: an existing ciphertext may be
            # the only copy of an older version, under another passphrase.
            existing = E._ensure_enc_suffix(src_path)
            backend = self._backend
            if self._wait(lambda: backend.exists(existing), tr("Checking {name}…").format(
                    name=existing.rsplit('/', 1)[-1])):
                from ui.plain_text import as_written

                reply = QMessageBox.question(
                    self,
                    tr("Overwrite?"),
                    as_written(tr("'{name}' already exists. Overwrite?").format(
                        name=existing.rsplit('/', 1)[-1])),
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
            def encrypt() -> str:
                # Read, key derivation (scrypt: deliberately slow) and write.
                with backend.open_read(src_path) as fh:
                    data = fh.read(E.MAX_ENCRYPTED_SIZE + 1)  # more is refused anyway
                return E.write_encrypted(backend, src_path, data, pw)

            dst_path = self._wait(encrypt, tr("Encrypting {name}…").format(name=item.name))
            log.info("Encrypted %s -> %s", src_path, dst_path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                tr("Encrypt Failed"),
                tr("Could not encrypt file:\n{error}").format(error=describe(exc)),
            )
            return
        from ui.plain_text import as_written

        QMessageBox.information(
            self,
            tr("Encrypted"),
            as_written(f"{item.name} → {dst_path.rsplit('/', 1)[-1]}\n\n"
                       + tr("Original plaintext is still in place – delete it manually "
                            "when you've verified the encrypted copy decrypts cleanly.")),
        )
        self.refresh_after_change()

    def _decrypt_selected_file(self, item) -> None:
        """Decrypt a ``.axenc`` file in place (writes the original
        filename minus the ``.axenc`` suffix)."""
        from PyQt6.QtWidgets import QInputDialog, QLineEdit

        from core import encrypted_overlay as E

        # Resolved before the passphrase prompt; see _rename_selected.
        src_path = self._safe_item_path(item)
        if src_path is None:
            return
        dst_name = item.name[: -len(E.ENC_SUFFIX)] or item.name + ".decrypted"
        dst_path = self._backend.join(self._current_path, dst_name)
        from ui.plain_text import as_written

        pw, ok = QInputDialog.getText(
            self,
            tr("Decrypt File"),
            as_written(tr("Passphrase for '{name}':").format(name=item.name)),
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pw:
            return
        backend = self._backend
        try:
            plain = self._wait(lambda: E.read_encrypted(backend, src_path, pw),
                               tr("Decrypting {name}…").format(name=item.name))
        except E.InvalidCiphertext as exc:
            QMessageBox.warning(
                self,
                tr("Decrypt Failed"),
                tr("Wrong passphrase or corrupted file:\n{error}").format(error=exc),
            )
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                tr("Decrypt Failed"),
                tr("Could not decrypt file:\n{error}").format(error=describe(exc)),
            )
            return

        try:
            if self._wait(lambda: backend.exists(dst_path),
                          tr("Checking {name}…").format(name=dst_name)):
                from ui.plain_text import as_written

                reply = QMessageBox.question(
                    self,
                    tr("Overwrite?"),
                    as_written(tr("'{name}' already exists. Overwrite?").format(name=dst_name)),
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
            from core.atomic_io import atomic_write

            self._wait(lambda: atomic_write(backend, dst_path, plain),
                       tr("Writing {name}…").format(name=dst_name))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                tr("Decrypt Failed"),
                tr("Could not write plaintext:\n{error}").format(error=describe(exc)),
            )
            return
        log.info("Decrypted %s -> %s", src_path, dst_path)
        self.refresh_after_change()

    def _show_link_target(self) -> None:
        items = self.selected_file_items()
        links = [i for i in items if i.is_link]
        if not links:
            return

        named = [(item, self._safe_item_path(item, warn=False)) for item in links]
        backend = self._backend

        def targets() -> list[str]:
            parts = []
            for item, path in named:
                if path is None:
                    parts.append(f"{item.name} -> (unsafe name)")
                    continue
                try:
                    parts.append(f"{item.name} -> {backend.readlink(path)}")
                except OSError as e:
                    parts.append(f"{item.name} -> (error: {e})")
            return parts

        msg_parts = self._wait(targets, tr("Reading link targets…"))

        QMessageBox.information(self, tr("Symlink Targets"), "\n".join(msg_parts))

    def focusInEvent(self, event) -> None:
        super().focusInEvent(event)
        self.pane_focused.emit()

    def enterEvent(self, event) -> None:
        super().enterEvent(event)
        from core import pane_activation as PA

        delay = PA.activation_delay_ms()
        if delay is not None and not getattr(self, "_shutting_down", False):
            self._hover_timer.start(delay)

    def leaveEvent(self, event) -> None:
        super().leaveEvent(event)
        self._hover_timer.stop()

    def _activate_by_hover(self) -> None:
        """The mouse rested here: become the active pane. Keyboard focus
        follows only from another pane's file list - typing in a text field
        must not land in a pane the mouse merely crossed."""
        self.pane_focused.emit()
        focused = QApplication.focusWidget()
        if focused is None or self.isAncestorOf(focused):
            return
        if not isinstance(focused, QAbstractItemView) and not isinstance(
            focused.parent(), QAbstractItemView
        ):
            return
        owner = focused.parent()
        while owner is not None and not isinstance(owner, FilePaneWidget):
            owner = owner.parent()
        if owner is not None:
            view = self._thumbs if self.view_mode == "thumbnails" else self._table
            view.setFocus()

    def _key_views(self) -> tuple:
        views = (self._table, self._table.viewport())
        thumbs = getattr(self, "_thumbs", None)
        if thumbs is not None:
            views += (thumbs, thumbs.viewport())
        return views

    # -- view mode: details table or thumbnails ---------------------------
    VIEW_MODES = ("details", "thumbnails")

    @property
    def view_mode(self) -> str:
        thumbs = getattr(self, "_thumbs", None)
        return "thumbnails" if thumbs is not None and not thumbs.isHidden() else "details"

    @property
    def thumbnail_view(self):
        """The thumbnail face of this pane, made on first use."""
        if getattr(self, "_thumbs", None) is None:
            from ui.thumbnail_view import ThumbnailView

            thumbs = ThumbnailView(self)
            thumbs.hide()
            layout = self._table.parentWidget().layout()
            layout.insertWidget(layout.indexOf(self._table) + 1, thumbs, 1)
            for widget in (thumbs, thumbs.viewport()):
                widget.installEventFilter(self)
            self._thumbs = thumbs
        return self._thumbs

    def set_view_mode(self, mode: str) -> None:
        """Show the folder as the details table or as thumbnails. The
        selection is shared, so it stays as it is."""
        if mode not in self.VIEW_MODES:
            raise ValueError(f"unknown view mode {mode!r}")
        if mode == self.view_mode:
            return
        had_focus = self._table.hasFocus() or (
            getattr(self, "_thumbs", None) is not None and self._thumbs.hasFocus()
        )
        if mode == "thumbnails":
            thumbs = self.thumbnail_view
            self._table.hide()
            thumbs.show()
            shown = thumbs
        else:
            self._thumbs.hide()
            self._table.show()
            shown = self._table
        current = self._table.selectionModel().currentIndex()
        if current.isValid():
            shown.scrollTo(current)
        if had_focus:
            shown.setFocus()
        self.view_mode_changed.emit(mode)

    def toggle_view_mode(self) -> None:
        self.set_view_mode("details" if self.view_mode == "thumbnails" else "thumbnails")

    def _escape_in_list(self) -> None:
        """Esc in the file list undoes one thing, the most transient first:
        a running load is stopped; else an active filter is cleared (it
        hides entries, so the selection may be partly out of sight); else
        the selection is cleared; else a pending Cut of this pane is dropped
        (its entries stay where they are)."""
        if self.is_loading:
            self.cancel_navigation()
        elif self._filter_edit.text():
            self._filter_edit.clear()
        elif self._table.selectionModel().hasSelection():
            self._table.clearSelection()
        else:
            self._drop_own_cut()

    def _escape_in_path(self) -> None:
        """Esc in the path bar: drop what was typed (the bar shows the
        current folder again) and go back to the list."""
        self._path_edit.setText(self._current_path)
        view = self._thumbs if self.view_mode == "thumbnails" else self._table
        view.setFocus(Qt.FocusReason.ShortcutFocusReason)

    def _escape_in_filter(self) -> None:
        """Esc in the filter line: clear the filter and go back to the list
        (the thumbnails in that view)."""
        self._filter_edit.clear()
        view = self._thumbs if self.view_mode == "thumbnails" else self._table
        view.setFocus(Qt.FocusReason.ShortcutFocusReason)

    def eventFilter(self, watched, event) -> bool:
        if event.type() in (QEvent.Type.FocusIn, QEvent.Type.MouseButtonPress):
            self.pane_focused.emit()

        if (
            event.type() == QEvent.Type.KeyPress
            and watched is self._filter_edit
            and event.key() == Qt.Key.Key_Escape
            and event.modifiers() == Qt.KeyboardModifier.NoModifier
        ):
            self._escape_in_filter()
            return True

        if (
            event.type() == QEvent.Type.KeyPress
            and watched in (self._path_edit, self._filter_edit)
            and event.modifiers() in (Qt.KeyboardModifier.NoModifier,
                                      Qt.KeyboardModifier.ControlModifier)
        ):
            # Esc in the path bar went nowhere, and Ctrl+L / Ctrl+F only
            # worked from the list (UX review round 9): Esc puts the
            # current folder back and returns to the list; either key
            # moves between the two lines.
            key, ctrl = event.key(), event.modifiers() == Qt.KeyboardModifier.ControlModifier
            if key == Qt.Key.Key_Escape and not ctrl and watched is self._path_edit:
                self._escape_in_path()
                return True
            if key == Qt.Key.Key_L and ctrl:
                self._path_edit.setFocus(Qt.FocusReason.ShortcutFocusReason)
                self._path_edit.selectAll()
                return True
            if key == Qt.Key.Key_F and ctrl:
                self._filter_edit.setFocus(Qt.FocusReason.ShortcutFocusReason)
                self._filter_edit.selectAll()
                return True

        # Keyboard shortcuts when the table (or its viewport) has focus
        if event.type() == QEvent.Type.KeyPress and watched in self._key_views():
            key = event.key()
            mods = event.modifiers()
            ctrl = mods == Qt.KeyboardModifier.ControlModifier
            ctrl_shift = mods == (
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier
            )
            alt = mods == Qt.KeyboardModifier.AltModifier
            no_mods = mods == Qt.KeyboardModifier.NoModifier

            # --- Alt+Enter → properties (must be before bare Enter) ---
            # Used to open the chmod editor alone, which is why the app
            # looked like it had no properties view; that editor is now
            # the second tab of the properties sheet.
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and alt:
                self._show_properties()
                return True

            # --- File operations ---
            # F8 is the window's "Bookmark This Folder" shortcut, not delete.
            # Del moves to the trash (a permanent delete where the connection
            # has none); Shift+Del deletes permanently, after a question
            # whose default is No.
            if key == Qt.Key.Key_Delete and no_mods:
                self._delete_key()
                return True
            if key == Qt.Key.Key_Delete and mods == Qt.KeyboardModifier.ShiftModifier:
                self._delete_selected()
                return True
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and no_mods:
                rows = self._selected_rows()
                if len(rows) == 1:
                    self._on_double_click(self._proxy.index(rows[0], COL_NAME))
                return True
            if key == Qt.Key.Key_F2 and no_mods:
                self._rename_selected()
                return True
            if key == Qt.Key.Key_F3 and no_mods:
                self._view_selected()
                return True
            if key == Qt.Key.Key_F4 and no_mods:
                self._edit_selected()
                return True
            if key == Qt.Key.Key_F5 and no_mods:
                self._copy_to_target()
                return True
            if key == Qt.Key.Key_F6 and no_mods:
                self._move_to_target()
                return True
            if key == Qt.Key.Key_F7 and no_mods:
                self._create_folder()
                return True
            if key == Qt.Key.Key_F9 and no_mods:
                self._rename_selected()
                return True
            if key == Qt.Key.Key_F10 and no_mods:
                idx = self._table.currentIndex()
                if idx.isValid():
                    pos = self._table.visualRect(idx).bottomLeft()
                else:
                    vp = self._table.viewport()
                    pos = QPoint(vp.width() // 2, vp.height() // 2)
                self._show_context_menu(pos)
                return True

            # --- Navigation ---
            if key == Qt.Key.Key_R and ctrl:
                self.refresh_async()
                return True
            if key == Qt.Key.Key_Backspace and no_mods:
                self._go_up()
                return True
            if key == Qt.Key.Key_Left and alt:
                self._go_back()
                return True
            if key == Qt.Key.Key_Right and alt:
                self._go_forward()
                return True

            # --- Selection ---
            if key == Qt.Key.Key_Escape and no_mods:
                self._escape_in_list()
                return True
            if key == Qt.Key.Key_A and ctrl_shift:
                self._invert_selection()
                return True
            if key == Qt.Key.Key_A and ctrl:
                self._select_all()
                return True
            if key == Qt.Key.Key_Space and no_mods:
                self._toggle_select_and_move_down()
                return True

            # --- Misc ---
            # Ctrl+H is not a pane key: View > Show Hidden Files owns it and
            # switches every pane at once (a pane-only toggle drifted from
            # the menu check and from the other panes).
            if key == Qt.Key.Key_F and ctrl:
                self._filter_edit.setFocus()
                self._filter_edit.selectAll()
                return True
            if key == Qt.Key.Key_L and ctrl:
                self._path_edit.setFocus()
                self._path_edit.selectAll()
                return True
            if key == Qt.Key.Key_D and ctrl:
                self._add_bookmark()
                return True
            if key == Qt.Key.Key_B and ctrl:
                self.open_bookmarks_requested.emit()
                return True
            if key == Qt.Key.Key_C and ctrl:
                if self.selected_items():
                    self._copy_paths_to_clipboard()
                    return True
                return False  # let Ctrl+C propagate if nothing selected
            if key == Qt.Key.Key_X and ctrl:
                self.cut_selected()
                return True
            if key == Qt.Key.Key_V and ctrl:
                self.paste_cut()
                return True

            # --- Pane cycling ---
            if key == Qt.Key.Key_Tab and no_mods:
                self.cycle_pane_requested.emit(True)
                return True
            if key == Qt.Key.Key_Backtab:  # Shift+Tab
                self.cycle_pane_requested.emit(False)
                return True

        return super().eventFilter(watched, event)
