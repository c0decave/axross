"""Who made a Bluetooth device: the vendor of its address, the company of
its BLE manufacturer data.

* :func:`company_name` - a BLE advertisement's manufacturer data starts
  with a 16-bit Bluetooth SIG company identifier: the full list
  (core/bluetooth_companies.py, ~3300 companies), with the short names of
  core.bluetooth.COMPANY_NAMES for the common ones ("Apple", not
  "Apple, Inc.").
* :func:`address_vendor` - a *public* device address starts with the IEEE
  OUI of its maker: Wireshark's table, from the ``manuf`` package
  (axross[mac]) or a Wireshark install. A random address (BLE privacy,
  ``AddressType`` "random") and a locally administered one carry no maker.
  The table (~45 000 lines) is read on a worker thread the first time it
  is asked for, pausing every few hundred lines so the GUI thread keeps
  the GIL; until then the answer is "" and :func:`notifier` says
  ``loaded`` when it is ready (the panel then fills its Vendor column).
"""

from __future__ import annotations

import logging
import os
import threading
import time

from PyQt6.QtCore import QObject, pyqtSignal

log = logging.getLogger(__name__)


class _Notifier(QObject):
    #: the OUI table is ready (emitted from the worker thread: queued to the GUI)
    loaded = pyqtSignal()


_notifier: _Notifier | None = None
_lock = threading.Lock()
#: nibbles of the prefix (6: an OUI, 7: MA-M /28, 9: MA-S /36) -> {hex prefix: name}
_table: dict[int, dict[str, str]] = {}
#: "" before the first ask, "loading", "ready", "missing" (no table), "failed"
_state = ""
#: Lines read between two pauses that let the GUI thread run (the GIL).
_LINES_PER_PAUSE = 1000
#: Wireshark's own copy, when the manuf package is not installed.
SYSTEM_TABLES = ("/usr/share/wireshark/manuf", "/usr/local/share/wireshark/manuf")


def notifier() -> _Notifier:
    global _notifier
    if _notifier is None:
        _notifier = _Notifier()
    return _notifier


def company_name(company: int) -> str:
    """The company behind a manufacturer-data key, "" when unassigned."""
    from core.bluetooth import COMPANY_NAMES
    from core.bluetooth_companies import COMPANY_IDENTIFIERS

    return COMPANY_NAMES.get(company) or COMPANY_IDENTIFIERS.get(company, "")


def is_public(address: str, address_type: str = "public") -> bool:
    """True for an address its maker's OUI starts: a public one that is not
    locally administered (bit 1 of the first byte)."""
    if (address_type or "public") != "public":
        return False
    try:
        first = int(str(address)[:2], 16)
    except ValueError:
        return False
    return len(str(address)) == 17 and not first & 0x02


def table_file() -> str | None:
    """Wireshark's OUI table: the manuf package's copy, else the system's."""
    import importlib.util

    try:
        spec = importlib.util.find_spec("manuf")
    except (ImportError, ValueError):
        spec = None
    candidates = []
    if spec is not None and spec.submodule_search_locations:
        candidates += [os.path.join(p, "manuf") for p in spec.submodule_search_locations]
    candidates += SYSTEM_TABLES
    return next((c for c in candidates if os.path.isfile(c)), None)


def parse_table(lines) -> dict[int, dict[str, str]]:
    """Wireshark's manuf lines -> {nibbles: {hex prefix: short name}}:
    ``00:01:95<TAB>SenaTech<TAB>Sena Technologies, Inc.`` and the smaller
    blocks ``00:55:DA:10:00:00/28<TAB>KoolPOS<TAB>...``."""
    table: dict[int, dict[str, str]] = {6: {}, 7: {}, 9: {}}
    for n, line in enumerate(lines):
        if n % _LINES_PER_PAUSE == 0:
            time.sleep(0)  # the GUI thread gets the GIL now and then
        if not line or line[0] in "#\n":
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 2 or not parts[1]:
            continue
        key, _sep, bits = parts[0].partition("/")
        digits = key.replace(":", "").replace("-", "").upper()
        nibbles = {"": 6, "24": 6, "28": 7, "36": 9}.get(bits)
        if nibbles is None or len(digits) < nibbles:
            continue
        table[nibbles][digits[:nibbles]] = parts[1].strip()
    return table


def _load() -> None:
    global _table, _state
    path = table_file()
    if path is None:
        with _lock:
            _state = "missing"
        log.info("Bluetooth vendors: no OUI table (axross[mac] or Wireshark's manuf)")
        return
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            table = parse_table(handle)
    except Exception:  # noqa: BLE001 - a broken table is no vendor, not a crash
        log.exception("reading the OUI table %s failed", path)
        with _lock:
            _state = "failed"
        return
    with _lock:
        _table = table
        _state = "ready"
    notifier().loaded.emit()


def oui_state() -> str:
    return _state


def preload() -> None:
    """Start reading the OUI table in the background (once)."""
    global _state
    notifier()  # made on the GUI thread, before the worker emits through it
    with _lock:
        if _state:
            return
        _state = "loading"
    threading.Thread(target=_load, name="bt-oui", daemon=True).start()


def address_vendor(address: str, address_type: str = "public") -> str:
    """The maker of a public address ("SenaTech"), "" for a random or
    locally administered one, while the table loads, or without one."""
    if not is_public(address, address_type):
        return ""
    if _state != "ready":
        preload()
        return ""
    digits = str(address).replace(":", "").upper()
    for nibbles in (9, 7, 6):  # the smallest block first: it is the more exact one
        name = _table.get(nibbles, {}).get(digits[:nibbles])
        if name:
            return name
    return ""


def _reset_for_tests(state: str = "", table: dict | None = None) -> None:
    global _state, _table
    with _lock:
        _state, _table = state, dict(table or {})


__all__ = ["address_vendor", "company_name", "is_public", "notifier", "oui_state", "preload"]
