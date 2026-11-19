"""What an approval of the agent says about a call besides its arguments
(core.agent.approval_args): where a write really goes. Words for people,
in the interface language."""

from __future__ import annotations

from core.i18n import tr


def link_note(path: str, target: str) -> str:
    """*path* leads to *target* (a symlink on the way): the call changes that."""
    return tr("{path} is a link: the call changes {target}.").format(path=path, target=target)
