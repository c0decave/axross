"""The widgets of the axross window.

Importing the package installs core.qt_exit's exit handler and
ui.markup_guard's rich-text guard. The exit handler: every process
that builds axross widgets (the app, the test children) deletes the Qt
objects Python still owns before PyQt's own exit walk does, outside it.
"""

from core.qt_exit import install_orderly_qt_exit

install_orderly_qt_exit()

# No label, tooltip, message box or text view of any process that builds
# axross widgets can make Qt read a file a hostile name points it to
# (<img src="/dev/zero"> aborted the process) - see ui.markup_guard.
from ui.markup_guard import install as _install_markup_guard  # noqa: E402

_install_markup_guard()
