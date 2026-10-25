"""The widgets of the axross window.

Importing the package installs core.qt_exit's exit handler: every process
that builds axross widgets (the app, the test children) deletes the Qt
objects Python still owns before PyQt's own exit walk does, outside it.
"""

from core.qt_exit import install_orderly_qt_exit

install_orderly_qt_exit()
