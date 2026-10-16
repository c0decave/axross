"""Backend sessions handed to scripts can be closed and used in ``with``.

The scripting docs showed ``with axross.open("alpha-ssh") as b:`` while
no backend class had ``__enter__``/``__exit__`` - the statement raised
TypeError before the body ran - and LocalFS, SSHSession, SCPSession and
WinRMSession had no ``close()`` at all. ``core.backend.SessionLifecycle``
gives every registered session class both; leaving a ``with`` block also
gives back the ConnectionManager reference a script took through
``axross.open`` / ``axross.open_url``, so the health monitor stops
probing a session the script has closed.
"""

from __future__ import annotations

import importlib
import inspect
import re

import pytest

from core import backend_registry
from core import scripting as axross
from core.backend import SessionLifecycle
from core.conn_health import get_manager


def _registered() -> list:
    backend_registry.init_registry()
    return sorted(backend_registry.all_backends(), key=lambda b: b.protocol_id)


@pytest.mark.parametrize("info", _registered(), ids=lambda b: b.protocol_id)
def test_happy_every_registered_session_class_supports_close_and_with(info) -> None:
    try:
        cls = getattr(importlib.import_module(info.module), info.class_name)
    except ImportError as exc:  # optional SDK missing in this environment
        pytest.skip(f"{info.module} not importable here: {exc}")
    assert issubclass(cls, SessionLifecycle), cls
    for member in ("close", "__enter__", "__exit__"):
        assert callable(getattr(cls, member, None)), (cls, member)


def test_happy_localfs_works_as_a_context_manager() -> None:
    with axross.localfs() as fs:
        assert fs.exists(fs.home())
    fs.close()  # LocalFS holds nothing; a second close is harmless


def test_happy_leaving_the_block_closes_a_ramfs_session() -> None:
    with axross.ramfs() as ram:
        axross.write_text(ram, "/note.txt", "kept until close")
        assert ram.exists("/note.txt")
    # RamFS discards every byte on close.
    assert not ram.exists("/note.txt")


def test_sad_an_exception_in_the_block_propagates_and_still_closes() -> None:
    with pytest.raises(ZeroDivisionError):
        with axross.ramfs() as ram:
            axross.write_text(ram, "/note.txt", "x")
            1 / 0  # noqa: B018
    assert not ram.exists("/note.txt")


def test_edge_with_on_a_managed_session_gives_back_its_reference() -> None:
    # open_url("ramfs://") goes through ConnectionManager, which enrols
    # the session with the health monitor; leaving the block must unenrol.
    with axross.open_url("ramfs://lifecycle") as ram:
        key = ram._axross_profile_key
        assert get_manager().get(key) is not None
    assert get_manager().get(key) is None


def test_edge_closing_twice_is_harmless() -> None:
    ram = axross.open_url("ramfs://twice")
    with ram:
        pass
    with ram:  # the reference is gone; the second exit only closes again
        pass
    ram.close()


def test_edge_close_falls_back_to_disconnect() -> None:
    class OnlyDisconnect(SessionLifecycle):
        def __init__(self) -> None:
            self.calls = 0

        def disconnect(self) -> None:
            self.calls += 1

    session = OnlyDisconnect()
    with session as same:
        assert same is session
    assert session.calls == 1
    session.close()
    assert session.calls == 2


def test_edge_no_docstring_names_a_scripting_function_that_does_not_exist() -> None:
    # exec()'s docstring pointed at ``axross.show()``, which never existed.
    dangling = set()
    texts = {"<module>": axross.__doc__ or ""}
    texts.update({n: inspect.getdoc(getattr(axross, n)) or "" for n in axross.__all__})
    for owner, text in texts.items():
        for ref in re.findall(r"axross\.([A-Za-z_]\w*)", text):
            if not hasattr(axross, ref):
                dangling.add((owner, ref))
    assert dangling == set()
