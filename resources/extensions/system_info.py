"""System Information: everything about the hardware axross runs on, in a
window of its own.

*Extensions → System Information…* (or *Tools → System Information…*)
opens it: an overview dashboard with rings for CPU, memory, swap, disk
and battery, temperatures on a colour scale and sparklines of the live
CPU and memory use, then a page per area - CPU, Memory, Storage, Graphics
& Displays, Network, Audio, USB & Peripherals, PCI, Battery & Power,
Sensors, System & OS, Virtualisation - with a search across all of them,
Copy Section / Copy All, Save Report… (text or JSON) and JSON Export (a
file, everything or the page shown to the clipboard). Serial numbers,
MAC and IP addresses and UUIDs stay hidden until *Show identifiers* is
ticked, in the window and in every copy.

The gathering (core/system_info.py) reads /proc and /sys without root and
starts no program; the window is ui/system_info_window.py.
"""

from __future__ import annotations

from PyQt6 import sip

EXTENSION = {
    "name": "System Information",
    "version": "1.0",
    "description": "A window with everything about this computer's hardware - CPU, memory, "
    "disks, graphics and displays, network, sound, USB, PCI, battery, sensors, firmware, OS "
    "and virtualisation - as a dashboard with live gauges and a page per area; search, copy "
    "and save a report with serial numbers and addresses hidden.",
    "author": "axross",
}

#: The open window (one at a time), or None.
_WINDOW = None


def show_window(parent=None):
    """Open the System Information window, or bring the open one to the front."""
    global _WINDOW
    if _WINDOW is not None and not sip.isdeleted(_WINDOW):
        if _WINDOW.isMinimized():
            _WINDOW.showNormal()
        _WINDOW.show()
        _WINDOW.raise_()
        _WINDOW.activateWindow()
        return _WINDOW
    from ui.system_info_window import open_window

    _WINDOW = open_window(parent)
    return _WINDOW


def activate(api):
    window = getattr(api, "window", None)
    from core.i18n import tr

    api.add_menu_action(tr("System Information…"), lambda: show_window(window), icon="system-info")


def deactivate(api):
    global _WINDOW
    window, _WINDOW = _WINDOW, None
    if window is not None and not sip.isdeleted(window):
        window.close()
