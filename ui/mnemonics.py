"""Mnemonics for the menu entries that have none.

Sixteen submenus of the menu bar had entries without an underlined letter -
Layout Preset, Theme, Panels, Bookmarks, More, Analyse, the presets of New
Agent Tab from Profile, the Workspace list, the Extensions entries, ... - so
the keyboard could open them but not pick an entry (UX review round 7). Most
of them are built at run time (workspaces, extensions, presets) and all are
translated, so the letter is chosen here, when the menu opens: the first
letter of a word not yet used in that menu, else any free letter, in
whatever language the text is. A menu's own letters stay as they are.
"""

from __future__ import annotations

import re

from PyQt6.QtWidgets import QMenu

_MNEMONIC = re.compile(r"&([^&\s])")
#: Marks a menu whose aboutToShow is hooked already.
_HOOKED = "axMnemonicsHooked"


def mnemonic_of(text: str) -> str | None:
    """The mnemonic letter of *text* (lower case), or None. "&&" is a
    literal ampersand, not a mnemonic."""
    match = _MNEMONIC.search(text.replace("&&", "\0\0"))
    return match.group(1).lower() if match else None


def with_mnemonic(text: str, taken: set[str]) -> str:
    """*text* with "&" before a letter not in *taken*: a word's first
    letter if one is free, else any free letter or digit. Unchanged when
    every letter is taken. Text after a tab (a shown shortcut) is left out."""
    label, tab, rest = text.partition("\t")
    plain = label.replace("&&", "\0\0")
    starts = [m.start() for m in re.finditer(r"(?<![^\W_])[^\W_]", plain)]
    anywhere = [i for i, ch in enumerate(plain) if ch.isalnum()]
    for i in starts + anywhere:
        letter = plain[i].lower()
        if letter not in taken:
            return label[:i] + "&" + label[i:] + tab + rest
    return text


def assign(menu: QMenu) -> None:
    """Give every entry of *menu* without a mnemonic a free one."""
    actions = [a for a in menu.actions()
               if not a.isSeparator() and a.text() and a.isVisible()]
    taken = {m for a in actions if (m := mnemonic_of(a.text())) is not None}
    for action in actions:
        text = action.text()
        if mnemonic_of(text) is not None:
            continue
        new = with_mnemonic(text, taken)
        if new != text:
            taken.add(mnemonic_of(new))
            action.setText(new)


def install(menu: QMenu, *, now: bool = True) -> None:
    """Assign mnemonics in *menu* and its submenus each time it opens -
    after the menu's own aboutToShow, which may rebuild its entries. With
    *now* false only then: a popup menu built for one exec() (the pane's
    right-click menu, Quick Connect) keeps its labels as built until it
    is shown."""
    if menu.property(_HOOKED):
        return
    menu.setProperty(_HOOKED, True)

    def on_show() -> None:
        assign(menu)
        for action in menu.actions():
            sub = action.menu()
            if sub is not None:
                install(sub)

    menu.aboutToShow.connect(on_show)
    if now:
        on_show()


__all__ = ["assign", "install", "mnemonic_of", "with_mnemonic"]
