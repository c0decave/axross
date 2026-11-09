"""Walk a QMenu with its submenus.

The file pane's right-click menu keeps its rarer entries in submenus (Open
With, Analyse, Links, More, ...; review round 5): a test that looks for an
entry asks the whole tree, not only the top level.
"""

from __future__ import annotations


def all_actions(menu) -> list:
    """The actions of *menu* and of every submenu in it, depth first."""
    found = []
    for action in menu.actions():
        found.append(action)
        if action.menu() is not None:
            found += all_actions(action.menu())
    return found


__all__ = ["all_actions"]
