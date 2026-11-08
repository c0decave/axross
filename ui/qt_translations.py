"""Qt's own button texts (OK, Cancel, Apply, Yes, No...) from axross's catalogue.

Qt names the standard buttons of every QDialogButtonBox and QMessageBox
through ``QCoreApplication.translate("QPlatformTheme", ...)``, and the keys
of a shortcut in a menu through ``translate("QShortcut", "Ctrl")``. Its own
``.qm`` catalogues are not shipped (see core.i18n), so without this a
German dialog said "Cancel" under German labels. This translator answers
those few contexts from the active JSON catalogue and leaves every other
text to Qt.
"""

from __future__ import annotations

from PyQt6.QtCore import QTranslator

from core import i18n

#: The Qt contexts whose texts the catalogue carries.
CONTEXTS = frozenset({"QPlatformTheme", "QDialogButtonBox", "QMessageBox",
                      # A tab's close button ("Close Tab"), a shortcut editor's
                      # placeholder ("Press shortcut").
                      "QTabBar", "CloseButton", "QKeySequenceEdit"})


def _key_name(name: str) -> str | None:
    """A key or modifier name of QKeySequence's native text ("Ctrl",
    "Shift", "Del") as the keyboard of the interface language prints it
    (core.i18n.tr_keys: "Strg", "Umschalt", "Entf"), so the shortcuts the
    menus show match the rest of the German window. None for a name the
    table does not have ("Media Play"): Qt keeps its own."""
    if not name.isascii() or not name.isalpha():
        return None
    translated = i18n.tr_keys(name)
    return translated if translated != name else None


class CatalogueTranslator(QTranslator):
    """Qt's standard button texts through :func:`core.i18n.tr`."""

    def translate(self, context, source_text, disambiguation=None, n=-1):  # noqa: N802 - Qt API
        if context == "QShortcut" and source_text:
            return _key_name(source_text)
        if context not in CONTEXTS or not source_text:
            # None is Qt's null string, "not translated here": Qt then
            # shows its source text. "" would be an empty label.
            return None
        return i18n.tr(source_text)

    def isEmpty(self) -> bool:  # noqa: N802 - Qt API
        return False


def install_qt_translator(app) -> CatalogueTranslator | None:
    """Install the translator on *app* when the interface is not English.

    The translator is kept on the application so it lives as long as it.
    """
    if i18n.active().language == i18n.DEFAULT_LANGUAGE:
        return None
    translator = CatalogueTranslator(app)
    app.installTranslator(translator)
    app._ax_qt_translator = translator  # noqa: SLF001 - keep it alive
    return translator
