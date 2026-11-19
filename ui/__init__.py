"""The widgets of the axross window.

Importing the package installs core.qt_exit's exit handler and
ui.markup_guard's rich-text guard. The exit handler: every process
that builds axross widgets (the app, the test children) deletes the Qt
objects Python still owns before PyQt's own exit walk does, outside it.

Each is installed as soon as its part of Qt is there: at once when it is
imported already, else right after the import of PyQt6.QtCore (the
handler) and of PyQt6.QtGui or PyQt6.QtWidgets (the guard) - before any
widget can be made. A process of the package that never starts Qt
(``axross-markdown --term``, ``--html``, ``--help``) imports none of it:
it ran on a machine without Qt's libraries.
"""

import sys

from core.qt_exit import install_orderly_qt_exit
from ui import markup_guard as _markup_guard  # (no Qt at its import: its install imports it)

#: The guard wraps classes of these (any of them imported: installed).
_GUARDED = ("PyQt6.QtGui", "PyQt6.QtWidgets")


def _install_guard() -> None:
    # No label, tooltip, message box or text view of any process that builds
    # axross widgets can make Qt read a file a hostile name points it to
    # (<img src="/dev/zero"> aborted the process) - see ui.markup_guard.
    _markup_guard.install()


class _AfterImport:
    """A finder that runs the installs right after the module of Qt they
    need is imported (its loader's exec_module), then goes."""

    def find_spec(self, name, path=None, target=None):
        if name != "PyQt6.QtCore" and name not in _GUARDED:
            return None
        spec = None
        for finder in sys.meta_path:  # (whoever finds it - a frozen program's own finder too)
            if finder is self or not hasattr(finder, "find_spec"):
                continue
            spec = finder.find_spec(name, path, target)
            if spec is not None:
                break
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return spec
        spec.loader = _Loader(spec.loader, name)
        return spec


#: Imports of Qt's modules under way (one imports the others in its own):
#: the installs run when the outermost is done - inside it, a module half
#: made could not be imported again.
_UNDER_WAY: list = []
_IMPORTED: set = set()


class _Loader:
    """*loader* of the Qt module *name*: the installs after it (_after)."""

    def __init__(self, loader, name: str):
        self._loader = loader
        self._name = name

    def create_module(self, spec):
        _UNDER_WAY.append(self._name)
        try:
            return self._loader.create_module(spec)
        except BaseException:
            _UNDER_WAY.pop()
            raise

    def exec_module(self, module):
        try:
            self._loader.exec_module(module)
        finally:
            _UNDER_WAY.pop()
        _IMPORTED.add(self._name)
        if not _UNDER_WAY:
            _after()

    def __getattr__(self, name):
        return getattr(self._loader, name)


_HOOK = _AfterImport()


def _after() -> None:
    """Qt's modules imported (_IMPORTED): what needs them installed."""
    install_orderly_qt_exit()  # (any of them imports QtCore: the handler first, as before)
    if _IMPORTED & set(_GUARDED):
        _install_guard()
    if _done():
        _unhook()


def _done() -> bool:
    return "PyQt6.QtCore" in sys.modules and any(name in sys.modules for name in _GUARDED)


def _unhook() -> None:
    if _HOOK in sys.meta_path:
        sys.meta_path.remove(_HOOK)


if "PyQt6.QtCore" in sys.modules:
    install_orderly_qt_exit()
if any(name in sys.modules for name in _GUARDED):
    _install_guard()
if not ("PyQt6.QtCore" in sys.modules and any(name in sys.modules for name in _GUARDED)):
    sys.meta_path.insert(0, _HOOK)
