"""What hardware axross runs on: CPU, memory, storage, graphics, network,
sound, USB, PCI, battery, sensors, firmware, the OS and whether it is a
virtual machine or a container - gathered without root and without Qt.

Linux is read from files only (``/proc``, ``/sys``, ``/etc/os-release``,
``pci.ids``/``usb.ids``); no program is started, nothing asks for a
password. Windows and macOS get what :mod:`platform`, :mod:`os` and the
optional ``psutil`` (bundled in axross-full only) tell.

Every source is a *probe* of its own: probes run in parallel worker
threads, each with a deadline, and a probe that fails, hangs or finds its
files missing gives a section that says ``not available: <why>`` - one
broken source never costs the others. Files are read with a size cap, a
file the user may not read (``/sys/class/dmi/id/product_serial`` is
root-only) is skipped quietly.

The report is plain, JSON-serialisable data::

    {"schema": 1, "generated": "...", "sections": [
        {"key": "cpu", "title": "CPU", "available": True, "reason": "",
         "fields": [{"label": "Model", "value": "...", "ident": False}, ...],
         "tables": [{"title": "Caches", "columns": [...], "rows": [[...]],
                     "ident_columns": [], "parents": None}, ...],
         "data": {...}}, ...]}

``fields`` and ``tables`` are the human view (units already applied),
``data`` the raw numbers for the charts and the JSON export. Serial numbers,
MAC addresses, UUIDs and IP addresses are *identifiers*: :func:`redact`
hides them, and :func:`export_text` / :func:`export_json` do so unless asked
otherwise, because such reports get pasted in public.

:class:`LiveSampler` reads the few cheap values the window shows live: CPU
use per core from ``/proc/stat`` deltas, memory and swap, temperatures and
network throughput.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import logging
import math
import os
import platform
import queue
import re
import socket
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA = 1
#: Seconds one probe may take before its section is "timed out".
PROBE_TIMEOUT = 4.0
#: Seconds the usage of one mounted file system may take (a dead NFS mount).
USAGE_TIMEOUT = 2.0
#: Bytes read from an ordinary /proc or /sys file.
READ_LIMIT = 64 * 1024
#: Bytes read from /proc/cpuinfo (a 256-thread machine writes ~1 MiB).
CPUINFO_LIMIT = 4 * 1024 * 1024
#: Bytes read from pci.ids / usb.ids (about 1.5 MiB each today).
IDS_LIMIT = 8 * 1024 * 1024
#: Entries looked at in one directory (a /sys/bus/usb with thousands of
#: hubs is not a real machine).
DIR_LIMIT = 4096
#: What an identifier reads as while identifiers are hidden.
HIDDEN = "‹hidden›"

PCI_IDS = ("usr/share/hwdata/pci.ids", "usr/share/misc/pci.ids", "usr/share/pci.ids")
USB_IDS = ("usr/share/hwdata/usb.ids", "usr/share/misc/usb.ids", "usr/share/usb.ids")

Report = dict[str, Any]
Section = dict[str, Any]


# --------------------------------------------------------------------------- units


def human_bytes(n: float | int | None) -> str:
    """1536 -> "1.5 KiB": binary units with one decimal, bytes as a whole number."""
    if n is None:
        return "?"
    value = float(n)
    if value < 1024:
        return f"{int(value)} B"
    for unit in ("KiB", "MiB", "GiB", "TiB", "PiB"):
        value /= 1024
        if value < 1024 or unit == "PiB":
            return f"{value:.1f} {unit}"
    return f"{value:.1f} PiB"  # pragma: no cover - the loop returns


def human_mhz(mhz: float | int | None) -> str:
    """3400 -> "3.40 GHz", 800 -> "800 MHz"."""
    if mhz is None:
        return "?"
    if mhz >= 1000:
        return f"{mhz / 1000:.2f} GHz"
    return f"{mhz:.0f} MHz"


def human_duration(seconds: float | None) -> str:
    """93784 -> "1 d 2 h 3 min"."""
    if seconds is None or seconds < 0:
        return "?"
    minutes = int(seconds // 60)
    days, minutes = divmod(minutes, 24 * 60)
    hours, minutes = divmod(minutes, 60)
    parts = []
    if days:
        parts.append(f"{days} d")
    if hours or days:
        parts.append(f"{hours} h")
    parts.append(f"{minutes} min")
    return " ".join(parts)


def human_rate(bytes_per_s: float | None) -> str:
    if bytes_per_s is None:
        return "?"
    return f"{human_bytes(bytes_per_s)}/s"


def celsius(value: float | None) -> str:
    return "?" if value is None else f"{value:.1f} °C"


def percent(value: float | None) -> str:
    return "?" if value is None else f"{value:.0f} %"


# --------------------------------------------------------------------------- report parts


def field(label: str, value: Any, ident: bool = False) -> dict | None:
    """One label/value row; ``None`` when there is no value to show."""
    if value is None or value == "" or value == []:
        return None
    return {"label": label, "value": str(value), "ident": bool(ident)}


def table(title: str, columns: list[str], rows: list[list[Any]], *,
          ident_columns: tuple[int, ...] = (), parents: list[int | None] | None = None) -> dict:
    """A table; *parents* (one entry per row, the index of the parent row or
    None) makes it a tree."""
    return {
        "title": title,
        "columns": list(columns),
        "rows": [["" if c is None else str(c) for c in row] for row in rows],
        "ident_columns": list(ident_columns),
        "parents": list(parents) if parents is not None else None,
    }


def make_section(key: str, title: str, fields: list | tuple = (), tables: list | tuple = (),
                 data: dict | None = None) -> Section:
    return {
        "key": key,
        "title": title,
        "available": True,
        "reason": "",
        "fields": [f for f in fields if f],
        "tables": [t for t in tables if t and t["rows"]],
        "data": data or {},
    }


def unavailable(key: str, title: str, reason: str) -> Section:
    section = make_section(key, title)
    section["available"] = False
    section["reason"] = reason
    return section


class NotAvailable(Exception):
    """A probe found nothing to report; the message says why."""


# --------------------------------------------------------------------------- privacy

#: Keys in ``data`` whose values are identifiers.
IDENT_KEYS = frozenset({
    "serial", "uuid", "mac", "address", "addresses", "ipv4", "ipv6", "gateway",
    "dns", "product_serial", "board_serial", "chassis_serial", "product_uuid", "hostname",
})
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_UUID_RE = re.compile(
    r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")


#: A folder named after a volume's short serial: the desktop mounts an
#: unlabelled FAT stick at /run/media/alice/1A2B-3C4D, an NTFS one under its
#: 16-digit volume serial.
_VOLUME_ID_PATH_RE = re.compile(
    r"(?<=/)(?:[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}|[0-9A-Fa-f]{16})(?=/|\s|$)")

#: A network interface named after its MAC (systemd: enx00e04c680a1b).
_MAC_NAME_RE = re.compile(r"\b(en|wl|ww)x[0-9A-Fa-f]{12}\b")
#: The server of a network mount's source at the start of a value:
#: ``//server/share`` (SMB), ``[user@]server:/path`` (NFS, sshfs),
#: ``user@server:`` (sshfs, any path) - not a URL (``https://``). Only the
#: safety net for text nobody marked: a mount's own source is hidden
#: whole (:func:`mount_source_shown`).
_MOUNT_SOURCE_RE = re.compile(
    r"^(?://[^/\s]+(?=/)|[^\s@/:]+@(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):"
    r"|(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):(?=/(?!/)))")
#: Mount sources that name no device and no server.
_PSEUDO_SOURCES = frozenset({"tmpfs", "overlay", "none", "rootfs", "devtmpfs"})
#: A Windows drive (``C:`` or ``C:\``), as psutil names a local one.
_DRIVE_RE = re.compile(r"[A-Za-z]:\\?")


def _hide_mount_source(match: re.Match) -> str:
    return f"//{HIDDEN}" if match.group(0).startswith("//") else f"{HIDDEN}:"


def mount_source_shown(device: str, fstype: str) -> bool:
    """Whether a mount's source *device* may stay in a report with
    identifiers hidden: only a local block device (``/dev/…``, a Windows
    drive) or a pseudo source (``tmpfs``). Anything else - and every
    source of a network file system - names a server, an account or a
    share in a form of its own (``alice@nas:``, ``https://…/files/alice``,
    ``remote:path``, ``10.0.0.1:6789:/``), so it is hidden whole."""
    if fstype in NETWORK_FS:
        return False
    return (device.startswith("/dev/") or device in _PSEUDO_SOURCES
            or _DRIVE_RE.fullmatch(device) is not None)


def _hidden_sources(sections: list[Section]) -> frozenset[str]:
    """The mount sources in *sections* (``data["filesystems"]``) that are
    identifiers: wherever else the report shows one - the File systems
    table, a reason, a field - it is hidden too."""
    out = set()
    for section in sections:
        for f in (section.get("data") or {}).get("filesystems") or ():
            if not isinstance(f, dict):
                continue
            device = str(f.get("device") or "")
            if device and not mount_source_shown(device, str(f.get("fstype") or "")):
                out.add(device)
    return frozenset(out)


def _hide_sources(text: str, sources: frozenset[str]) -> str:
    if text in sources:
        return HIDDEN
    # Inside a longer text only a source long enough not to hit ordinary
    # words is replaced.
    for source in sources:
        if len(source) >= 4 and source in text:
            text = text.replace(source, HIDDEN)
    return text


def scrub_text(text: str) -> str:
    """MAC addresses (also inside an interface name), UUIDs and the server
    of a network mount source in *text* hidden - the safety net for an
    identifier in a field nobody marked (a USB product string)."""
    text = _MOUNT_SOURCE_RE.sub(_hide_mount_source, text)
    text = _MAC_NAME_RE.sub(lambda m: f"{m.group(1)}x{HIDDEN}", text)
    text = _UUID_RE.sub(HIDDEN, _MAC_RE.sub(HIDDEN, text))
    return _VOLUME_ID_PATH_RE.sub(HIDDEN, text)


def _redact_value(value: Any) -> Any:
    if isinstance(value, list):
        return [HIDDEN if v not in (None, "") else v for v in value]
    if value in (None, ""):
        return value
    return HIDDEN


def _redact_data(value: Any, sources: frozenset[str] = frozenset()) -> Any:
    if isinstance(value, dict):
        return {k: (_redact_value(v) if k in IDENT_KEYS else _redact_data(v, sources))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_data(v, sources) for v in value]
    if isinstance(value, str):
        return scrub_text(_hide_sources(value, sources))
    return value


def redact_section(section: Section, sources: frozenset[str] | None = None) -> Section:
    """A copy of *section* with its identifiers hidden; *sources* are the
    mount sources to hide (by default those the section itself lists)."""
    if sources is None:
        sources = _hidden_sources([section])
    out = copy.deepcopy(section)
    for f in out.get("fields", []):
        if f.get("ident") and f.get("value"):
            f["value"] = HIDDEN
        else:
            f["value"] = scrub_text(_hide_sources(str(f.get("value", "")), sources))
    for t in out.get("tables", []):
        idents = set(t.get("ident_columns", []))
        for row in t.get("rows", []):
            for i, cell in enumerate(row):
                if i in idents and cell:
                    row[i] = HIDDEN
                else:
                    row[i] = scrub_text(_hide_sources(cell, sources))
    out["data"] = _redact_data(out.get("data", {}), sources)
    out["reason"] = scrub_text(_hide_sources(out.get("reason", ""), sources))
    return out


def redact(report: Report) -> Report:
    """A copy of *report* with every identifier replaced by :data:`HIDDEN`."""
    out = {k: copy.deepcopy(v) for k, v in report.items() if k != "sections"}
    sources = _hidden_sources(report.get("sections", []))
    out["sections"] = [redact_section(s, sources) for s in report.get("sections", [])]
    out["identifiers"] = "hidden"
    return out


# --------------------------------------------------------------------------- export


def _column_text(columns: list[str], rows: list[list[str]], indent: str,
                 depths: list[int] | None = None) -> list[str]:
    cells = [list(columns)] + [list(r) for r in rows]
    if depths:
        for i, depth in enumerate(depths, start=1):
            cells[i][0] = "  " * depth + cells[i][0]
    widths = [max(len(row[i]) if i < len(row) else 0 for row in cells)
              for i in range(len(columns))]
    lines = []
    for n, row in enumerate(cells):
        text = "  ".join((row[i] if i < len(row) else "").ljust(widths[i])
                         for i in range(len(columns)))
        lines.append(indent + text.rstrip())
        if n == 0:
            lines.append(indent + "  ".join("-" * w for w in widths))
    return lines


def tree_depths(parents: list[int | None]) -> list[int]:
    """The depth of every row of a tree table (cycles are cut)."""
    depths = []
    for i in range(len(parents)):
        depth, node, seen = 0, parents[i], {i}
        while node is not None and 0 <= node < len(parents) and node not in seen:
            seen.add(node)
            depth += 1
            node = parents[node]
        depths.append(depth)
    return depths


def section_text(section: Section) -> str:
    """One section as plain text: its fields, then its tables."""
    title = section.get("title", section.get("key", ""))
    lines = [title, "=" * len(title)]
    if not section.get("available", True):
        lines.append(f"  not available: {section.get('reason', '')}")
        return "\n".join(lines)
    fields = section.get("fields", [])
    width = max((len(f["label"]) for f in fields), default=0)
    for f in fields:
        lines.append(f"  {f['label'].ljust(width)}  {f['value']}")
    for t in section.get("tables", []):
        lines.append("")
        lines.append(f"  {t['title']}")
        parents = t.get("parents")
        depths = tree_depths(parents) if parents else None
        lines.extend(_column_text(t["columns"], t["rows"], "  ", depths))
    return "\n".join(lines)


def export_text(report: Report, *, show_identifiers: bool = False,
                keys: list[str] | None = None) -> str:
    """The report (or the sections *keys*) as plain text; identifiers hidden
    unless *show_identifiers*."""
    shown = report if show_identifiers else redact(report)
    sections = [s for s in shown.get("sections", []) if keys is None or s["key"] in keys]
    head = [
        "System Information (axross)",
        f"Generated: {shown.get('generated', '?')}",
        "Identifiers (serial numbers, MAC/IP addresses, UUIDs, computer name, "
        "network mount sources): "
        + ("shown" if show_identifiers else "hidden"),
    ]
    return "\n".join(head) + "\n\n" + "\n\n".join(section_text(s) for s in sections) + "\n"


def export_json(report: Report, *, show_identifiers: bool = False,
                keys: list[str] | None = None) -> str:
    """The report (or the sections *keys*) as JSON - every field, table and
    the raw ``data`` of each section; identifiers hidden unless
    *show_identifiers* (hidden across the whole report first, so a mount
    source named in another section stays hidden in the part exported)."""
    shown = report if show_identifiers else redact(report)
    if show_identifiers:
        shown = dict(shown, identifiers="shown")
    if keys is not None:
        shown = dict(shown, sections=[s for s in shown.get("sections", []) if s["key"] in keys])
    return json.dumps(shown, indent=2, ensure_ascii=False, default=str) + "\n"


# --------------------------------------------------------------------------- small parsers


def parse_key_values(text: str, sep: str = ":") -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, found, value = line.partition(sep)
        if found:
            out.setdefault(key.strip(), value.strip())
    return out


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, found, value = line.strip().partition("=")
        if not found or key.startswith("#"):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def parse_meminfo(text: str) -> dict[str, int]:
    """/proc/meminfo in bytes ("kB" lines times 1024, counts as they are)."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        key, found, rest = line.partition(":")
        if not found:
            continue
        parts = rest.split()
        if not parts:
            continue
        try:
            value = int(parts[0])
        except ValueError:
            continue
        if len(parts) > 1 and parts[1].lower() == "kb":
            value *= 1024
        out[key.strip()] = value
    return out


def parse_cpuinfo(text: str) -> list[dict[str, str]]:
    """One dict per block of /proc/cpuinfo (a block without ``processor``
    is the trailer ARM machines write: kept as it is)."""
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        key, found, value = line.partition(":")
        if found:
            current.setdefault(key.strip(), value.strip())
    if current:
        blocks.append(current)
    return blocks


def parse_cpu_list(text: str | None) -> list[int]:
    """"0-3,8,10-11" -> [0, 1, 2, 3, 8, 10, 11]; garbage -> what parses."""
    out: list[int] = []
    for part in (text or "").strip().split(","):
        part = part.strip()
        if not part:
            continue
        lo, dash, hi = part.partition("-")
        try:
            if dash:
                a, b = int(lo), int(hi)
                if 0 <= a <= b and b - a < 65536:
                    out.extend(range(a, b + 1))
            else:
                out.append(int(lo))
        except ValueError:
            continue
    return out


def parse_size_text(text: str | None) -> int | None:
    """Cache sizes as sysfs writes them: "48K", "1280K", "30720K", "2M"."""
    if not text:
        return None
    match = re.fullmatch(r"\s*(\d+)\s*([KMG]?)B?\s*", text, flags=re.I)
    if not match:
        return None
    value = int(match.group(1))
    return value * {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}[match.group(2).upper()]


def parse_proc_stat(text: str) -> dict[str, tuple[int, int]]:
    """``{"cpu": (busy, total), "cpu0": ...}`` jiffies from /proc/stat.

    busy = user + nice + system + irq + softirq + steal; idle = idle +
    iowait; guest time is already counted in user and nice."""
    out: dict[str, tuple[int, int]] = {}
    for line in text.splitlines():
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        try:
            values = [int(v) for v in parts[1:11]]
        except ValueError:
            continue
        if len(values) < 4:
            continue
        values += [0] * (8 - len(values))
        user, nice, system, idle, iowait, irq, softirq, steal = values[:8]
        busy = user + nice + system + irq + softirq + steal
        out[parts[0]] = (busy, busy + idle + iowait)
    return out


def cpu_percent(before: tuple[int, int] | None, after: tuple[int, int] | None) -> float | None:
    """Busy share between two ``(busy, total)`` samples, 0-100; ``None``
    when there is no earlier sample or no time passed (or the counters went
    back: a CPU went offline and came back)."""
    if before is None or after is None:
        return None
    d_total = after[1] - before[1]
    d_busy = after[0] - before[0]
    if d_total <= 0 or d_busy < 0:
        return None
    return max(0.0, min(100.0, 100.0 * d_busy / d_total))


def parse_mounts(text: str) -> list[tuple[str, str, str, str]]:
    """``(device, mount point, fstype, options)`` of a /proc/mounts text."""
    def unescape(s: str) -> str:
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)

    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        out.append((unescape(parts[0]), unescape(parts[1]), parts[2], parts[3]))
    return out


def lookup_ids(text_lines, vendors: set[str], pairs: set[tuple[str, str]]
               ) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    """Names from a pci.ids / usb.ids listing for the *vendors* and the
    ``(vendor, device)`` *pairs* asked for (lower-case hex)."""
    vendor_names: dict[str, str] = {}
    device_names: dict[tuple[str, str], str] = {}
    current: str | None = None
    for line in text_lines:
        if not line or line.startswith("#"):
            continue
        if line.startswith("C ") or line.startswith("AT ") or line.startswith("HID "):
            break  # the class lists after the vendors
        if line.startswith("\t\t"):
            continue  # subsystems
        if line.startswith("\t"):
            if current is None:
                continue
            ident, _sp, name = line.strip().partition(" ")
            key = (current, ident.lower())
            if key in pairs:
                device_names[key] = name.strip()
            continue
        ident, _sp, name = line.partition(" ")
        ident = ident.lower()
        if len(ident) == 4 and ident in vendors:
            current = ident
            vendor_names[ident] = name.strip()
        else:
            current = None
    return vendor_names, device_names


# --------------------------------------------------------------------------- tables of names

CHASSIS_TYPES = {
    1: "Other", 2: "Unknown", 3: "Desktop", 4: "Low-profile desktop", 5: "Pizza box",
    6: "Mini tower", 7: "Tower", 8: "Portable", 9: "Laptop", 10: "Notebook",
    11: "Hand-held", 12: "Docking station", 13: "All-in-one", 14: "Sub-notebook",
    15: "Space-saving", 16: "Lunch box", 17: "Server", 18: "Expansion chassis",
    19: "Sub-chassis", 20: "Bus expansion chassis", 21: "Peripheral chassis",
    22: "RAID chassis", 23: "Rack mount", 24: "Sealed-case PC", 25: "Multi-system",
    26: "Compact PCI", 27: "Advanced TCA", 28: "Blade", 29: "Blade enclosure",
    30: "Tablet", 31: "Convertible", 32: "Detachable", 33: "IoT gateway",
    34: "Embedded PC", 35: "Mini PC", 36: "Stick PC",
}
LAPTOP_CHASSIS = {8, 9, 10, 11, 14, 30, 31, 32}
SERVER_CHASSIS = {17, 23, 25, 28, 29}

#: Placeholders firmware vendors leave in DMI fields.
DMI_JUNK = {
    "", "to be filled by o.e.m.", "default string", "system product name",
    "system manufacturer", "system version", "not applicable", "not specified", "none",
    "0123456789", "o.e.m.", "oem", "x.x", "type1productconfigid", "invalid", "n/a",
    "base board product name", "base board version", "chassis version", "123456789",
}

PCI_CLASSES = {
    0x0000: "Unclassified device", 0x0100: "SCSI storage controller",
    0x0101: "IDE interface", 0x0104: "RAID bus controller", 0x0105: "ATA controller",
    0x0106: "SATA controller", 0x0107: "Serial Attached SCSI controller",
    0x0108: "Non-Volatile memory controller", 0x0180: "Mass storage controller",
    0x0200: "Ethernet controller", 0x0280: "Network controller",
    0x0300: "VGA compatible controller", 0x0302: "3D controller",
    0x0380: "Display controller", 0x0400: "Multimedia video controller",
    0x0401: "Multimedia audio controller", 0x0403: "Audio device",
    0x0480: "Multimedia controller", 0x0500: "RAM memory", 0x0580: "Memory controller",
    0x0600: "Host bridge", 0x0601: "ISA bridge", 0x0604: "PCI bridge",
    0x0680: "Bridge", 0x0700: "Serial controller", 0x0780: "Communication controller",
    0x0805: "SD Host controller", 0x0806: "IOMMU", 0x0880: "System peripheral",
    0x0c03: "USB controller", 0x0c05: "SMBus", 0x0c80: "Serial bus controller",
    0x0d11: "Bluetooth", 0x0d80: "Wireless controller", 0x1080: "Encryption controller",
    0x1180: "Signal processing controller", 0x1200: "Processing accelerators",
    0x0b40: "Co-processor", 0x1300: "Non-essential instrumentation",
}
PCI_TOP_CLASSES = {
    0x00: "Unclassified", 0x01: "Mass storage controller", 0x02: "Network controller",
    0x03: "Display controller", 0x04: "Multimedia controller", 0x05: "Memory controller",
    0x06: "Bridge", 0x07: "Communication controller", 0x08: "Generic system peripheral",
    0x09: "Input device controller", 0x0a: "Docking station", 0x0b: "Processor",
    0x0c: "Serial bus controller", 0x0d: "Wireless controller",
    0x0e: "Intelligent controller", 0x0f: "Satellite communications controller",
    0x10: "Encryption controller", 0x11: "Signal processing controller",
    0x12: "Processing accelerators", 0x13: "Non-essential instrumentation",
    0x40: "Coprocessor",
}
PCI_VENDORS = {
    "8086": "Intel", "1022": "AMD", "1002": "AMD/ATI", "10de": "NVIDIA",
    "10ec": "Realtek", "14e4": "Broadcom", "168c": "Qualcomm Atheros", "17cb": "Qualcomm",
    "144d": "Samsung", "15b7": "SanDisk/WD", "1c5c": "SK hynix", "1987": "Phison",
    "126f": "Silicon Motion", "1b4b": "Marvell", "1b21": "ASMedia", "1af4": "Red Hat (virtio)",
    "15ad": "VMware", "80ee": "VirtualBox", "1234": "QEMU", "1b36": "Red Hat (QEMU)",
    "1414": "Microsoft", "106b": "Apple", "14c3": "MediaTek", "1912": "Renesas",
    "1217": "O2 Micro", "1180": "Ricoh", "1d6a": "Aquantia", "8087": "Intel",
}

USB_CLASSES = {
    0x01: "Audio", 0x02: "Communications", 0x03: "HID (keyboard, mouse …)", 0x05: "Physical",
    0x06: "Imaging", 0x07: "Printer", 0x08: "Mass storage", 0x09: "Hub", 0x0A: "CDC data",
    0x0B: "Smart card", 0x0D: "Content security", 0x0E: "Video", 0x0F: "Personal healthcare",
    0x10: "Audio/Video", 0x11: "Billboard", 0x12: "USB-C bridge", 0xDC: "Diagnostic",
    0xE0: "Wireless (Bluetooth)", 0xEF: "Miscellaneous", 0xFE: "Application specific",
    0xFF: "Vendor specific",
}
INPUT_BUSES = {
    "0000": "",
    "0001": "PCI", "0003": "USB", "0005": "Bluetooth", "0006": "Virtual", "0010": "ISA",
    "0011": "PS/2", "0018": "I²C", "0019": "Platform", "001c": "Platform",
    "001e": "SPI",
}

#: (group, label, any of these cpuinfo flags).
CPU_FEATURES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Vector", "SSE2", ("sse2",)),
    ("Vector", "SSE4.2", ("sse4_2",)),
    ("Vector", "AVX", ("avx",)),
    ("Vector", "AVX2", ("avx2",)),
    ("Vector", "FMA3", ("fma",)),
    ("Vector", "AVX-512", ("avx512f",)),
    ("Vector", "AVX-VNNI", ("avx_vnni", "avx512_vnni")),
    ("Vector", "AMX", ("amx_tile",)),
    ("Vector", "NEON / ASIMD", ("neon", "asimd")),
    ("Vector", "SVE", ("sve",)),
    ("Crypto", "AES-NI", ("aes",)),
    ("Crypto", "SHA", ("sha_ni", "sha2", "sha1")),
    ("Crypto", "CLMUL", ("pclmulqdq", "pmull")),
    ("Crypto", "RDRAND", ("rdrand",)),
    ("Crypto", "RDSEED", ("rdseed",)),
    ("Virtualisation", "VT-x", ("vmx",)),
    ("Virtualisation", "AMD-V", ("svm",)),
    ("Virtualisation", "Runs under a hypervisor", ("hypervisor",)),
    ("Security", "NX", ("nx",)),
    ("Security", "SMEP", ("smep",)),
    ("Security", "SMAP", ("smap",)),
    ("Security", "CET-IBT", ("ibt",)),
    ("Security", "CET shadow stack", ("user_shstk", "shstk")),
    ("Security", "SGX", ("sgx",)),
    ("Security", "SEV", ("sev",)),
    ("Power", "Invariant TSC", ("nonstop_tsc",)),
    ("Power", "HWP (Speed Shift)", ("hwp",)),
)

#: DMI text -> hypervisor name, checked against vendor and product.
HYPERVISOR_DMI = (
    ("qemu", "QEMU"), ("kvm", "KVM"), ("vmware", "VMware"), ("innotek", "VirtualBox"),
    ("virtualbox", "VirtualBox"), ("xen", "Xen"), ("parallels", "Parallels"),
    ("bochs", "Bochs"), ("bhyve", "bhyve"), ("amazon ec2", "Amazon EC2"),
    ("google compute engine", "Google Compute Engine"), ("openstack", "OpenStack"),
    ("apple virtualization", "Apple Virtualization"), ("cloud hypervisor", "Cloud Hypervisor"),
)

_PCI_ADDR = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
_USB_DEV = re.compile(r"^(usb\d+|\d+-\d+(\.\d+)*)$")

LOCAL_FS = frozenset({
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "ntfs", "ntfs3",
    "fuseblk", "vfat", "exfat", "msdos", "apfs", "hfs", "hfsplus", "iso9660", "udf", "bcachefs",
    "overlay",
})
#: File systems whose mount source names a server, a share or an account
#: (hidden whole in a report with identifiers hidden).
NETWORK_FS = frozenset({
    "cifs", "smb3", "smb2", "smbfs", "nfs", "nfs3", "nfs4", "fuse.sshfs", "sshfs", "9p",
    "virtiofs", "ceph", "fuse.ceph", "fuse.ceph-fuse", "glusterfs", "fuse.glusterfs",
    "fuse.rclone", "rclone", "vboxsf", "davfs", "fuse.davfs", "fuse.davfs2", "fuse.s3fs",
    "fuse.gcsfuse", "fuse.curlftpfs", "afs", "lustre", "beegfs",
})


# --------------------------------------------------------------------------- the gatherer


class SystemInfo:
    """Gathers the report. Every path is looked up below *root*, so tests
    hand it a fake ``/proc`` and ``/sys`` in a temporary folder.

    *system* is ``platform.system()`` ("Linux", "Windows", "Darwin") unless
    given. *usage(path) -> (total, used, free)* measures a mounted file
    system. psutil (optional) is used only for the real machine
    (``root == "/"``) and only where it adds something.
    """

    def __init__(self, root: str | os.PathLike = "/", *, env: dict[str, str] | None = None,
                 system: str | None = None, hostname: str | None = None,
                 usage: Callable[[str], tuple[int, int, int]] | None = None,
                 timeout: float = PROBE_TIMEOUT, use_psutil: bool = True,
                 addresses: Callable[[], dict[str, list[dict]]] | None = None) -> None:
        self.root = Path(root)
        self.real = str(self.root) == os.sep or str(root) in ("/", "")
        self.env = dict(os.environ if env is None else env)
        self.system = system or platform.system()
        self.hostname = hostname
        self._usage = usage
        self.timeout = timeout
        self.use_psutil = use_psutil and self.real
        self._addresses = addresses
        self._lock = threading.Lock()
        self._cache: dict[str, Any] = {}

    # -- file access ----------
    def path(self, rel: str) -> Path:
        return self.root / rel.lstrip("/")

    def read(self, rel: str | Path, limit: int = READ_LIMIT) -> str | None:
        """The text of a file below the root (at most *limit* bytes), stripped;
        ``None`` when it is missing or unreadable."""
        path = rel if isinstance(rel, Path) else self.path(rel)
        try:
            with open(path, "rb") as fh:
                raw = fh.read(limit)
        except (OSError, ValueError):
            return None
        return raw.decode("utf-8", errors="replace").replace("\x00", "").strip()

    def read_bytes(self, rel: str | Path, limit: int = READ_LIMIT) -> bytes:
        path = rel if isinstance(rel, Path) else self.path(rel)
        try:
            with open(path, "rb") as fh:
                return fh.read(limit)
        except (OSError, ValueError):
            return b""

    def read_int(self, rel: str | Path) -> int | None:
        text = self.read(rel, 256)
        if text is None:
            return None
        try:
            return int(text.split()[0], 0) if text.startswith("0x") else int(text.split()[0])
        except (ValueError, IndexError):
            return None

    def listdir(self, rel: str | Path) -> list[str]:
        path = rel if isinstance(rel, Path) else self.path(rel)
        try:
            with os.scandir(path) as it:
                names = []
                for entry in it:
                    names.append(entry.name)
                    if len(names) >= DIR_LIMIT:
                        break
        except (OSError, ValueError):
            return []
        return sorted(names, key=_natural)

    def count_entries(self, rel: str, pattern: str, limit: int = 1 << 20) -> int:
        """How many names in *rel* match *pattern* - not cut at DIR_LIMIT
        like ``listdir`` (a 1 TiB machine has 8192 memory blocks of 128 MiB)."""
        count = 0
        try:
            with os.scandir(self.path(rel)) as it:
                for n, entry in enumerate(it):
                    if n >= limit:
                        break
                    if re.fullmatch(pattern, entry.name):
                        count += 1
        except (OSError, ValueError):
            return 0
        return count

    def link_name(self, path: Path) -> str:
        """The last part of where a symlink (``driver``) points; "" if none."""
        try:
            return os.path.basename(os.readlink(path))
        except (OSError, ValueError):
            return ""

    def exists(self, rel: str) -> bool:
        try:
            return self.path(rel).exists()
        except OSError:
            return False

    def _cached(self, key: str, make: Callable[[], Any]) -> Any:
        with self._lock:
            if key not in self._cache:
                self._cache[key] = make()
            return self._cache[key]

    def _psutil(self):
        if not self.use_psutil:
            return None
        try:
            import psutil  # type: ignore[import-not-found] - optional, bundled in axross-full
        except ImportError:
            return None
        return psutil

    @property
    def linux(self) -> bool:
        return self.system == "Linux"

    # -- running the probes ----------
    def probes(self) -> list[tuple[str, str, Callable[[], Section]]]:
        return [
            ("machine", "Machine & Firmware", self.probe_machine),
            ("os", "Operating System", self.probe_os),
            ("cpu", "CPU", self.probe_cpu),
            ("memory", "Memory", self.probe_memory),
            ("storage", "Storage", self.probe_storage),
            ("graphics", "Graphics & Displays", self.probe_graphics),
            ("network", "Network", self.probe_network),
            ("bluetooth", "Bluetooth & Radios", self.probe_bluetooth),
            ("audio", "Audio", self.probe_audio),
            ("usb", "USB Devices", self.probe_usb),
            ("input", "Input Devices", self.probe_input),
            ("pci", "PCI Devices", self.probe_pci),
            ("battery", "Battery & Power", self.probe_battery),
            ("sensors", "Sensors", self.probe_sensors),
            ("virtualization", "Virtualisation & Containers", self.probe_virtualization),
        ]

    def run_probe(self, key: str, title: str, probe: Callable[[], Section]) -> Section:
        started = time.monotonic()
        try:
            section = probe()
        except NotAvailable as exc:
            section = unavailable(key, title, str(exc) or "nothing found")
        except Exception as exc:  # noqa: BLE001 - one source, shown with its reason
            log.debug("System information probe %s failed", key, exc_info=True)
            section = unavailable(key, title, f"{type(exc).__name__}: {exc}")
        if not isinstance(section, dict):
            section = unavailable(key, title, "the probe returned nothing")
        section["key"], section["title"] = key, title
        section["ms"] = round((time.monotonic() - started) * 1000, 1)
        return section

    def gather(self, progress: Callable[[int, int, str], None] | None = None,
               cancel: Callable[[], bool] | None = None,
               only: list[str] | None = None) -> Report:
        """Run every probe (or those in *only*) in parallel; each gets
        :attr:`timeout` seconds. *progress(done, total, title)* is called from
        this thread after each one; *cancel()* true stops waiting."""
        started = time.monotonic()
        probes = [p for p in self.probes() if only is None or p[0] in only]
        results: queue.Queue = queue.Queue()

        def run(index: int, key: str, title: str, probe) -> None:
            results.put((index, self.run_probe(key, title, probe)))

        for index, (key, title, probe) in enumerate(probes):
            threading.Thread(target=run, args=(index, key, title, probe), daemon=True,
                             name=f"axross-sysinfo-{key}").start()
        sections: dict[int, Section] = {}
        deadline = started + self.timeout
        while len(sections) < len(probes):
            if cancel is not None and cancel():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                index, section = results.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            sections[index] = section
            if progress is not None:
                progress(len(sections), len(probes), section["title"])
        out = []
        for index, (key, title, _probe) in enumerate(probes):
            section = sections.get(index)
            if section is None:
                section = unavailable(key, title, f"timed out after {self.timeout:g} s")
                section["ms"] = round(self.timeout * 1000)
            out.append(section)
        return {
            "schema": SCHEMA,
            "generated": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "platform": self.system,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "sections": out,
        }

    # -- shared reads ----------
    def cpuinfo(self) -> list[dict[str, str]]:
        return self._cached("cpuinfo", lambda: parse_cpuinfo(
            self.read("proc/cpuinfo", CPUINFO_LIMIT) or ""))

    def cpu_flags(self) -> set[str]:
        for block in self.cpuinfo():
            flags = block.get("flags") or block.get("Features")
            if flags:
                return set(flags.split())
        return set()

    def dmi(self) -> dict[str, str]:
        def load() -> dict[str, str]:
            out = {}
            base = self.path("sys/class/dmi/id")
            for name in self.listdir(base):
                path = base / name
                if not path.is_file():
                    continue
                value = self.read(path, 4096)
                if value is None:
                    continue  # root-only (serials, UUID): skipped quietly
                if value.strip().lower() in DMI_JUNK:
                    continue
                out[name] = value.strip()
            return out
        return self._cached("dmi", load)

    def pci_devices(self) -> list[dict[str, Any]]:
        return self._cached("pci", self._load_pci)

    def _load_pci(self) -> list[dict[str, Any]]:
        base = self.path("sys/bus/pci/devices")
        devices = []
        for name in self.listdir(base):
            path = base / name
            cls = self.read(path / "class", 64) or ""
            try:
                code = int(cls, 16)
            except ValueError:
                code = None
            vendor = (self.read(path / "vendor", 64) or "").lower().removeprefix("0x")
            device = (self.read(path / "device", 64) or "").lower().removeprefix("0x")
            parent = None
            try:
                real = os.path.realpath(path)
                up = os.path.basename(os.path.dirname(real))
                if _PCI_ADDR.fullmatch(up):
                    parent = up
            except (OSError, ValueError):
                pass
            devices.append({
                "address": name,
                "class_code": code,
                "class": _pci_class(code),
                "vendor_id": vendor,
                "device_id": device,
                "subsystem_vendor": (self.read(path / "subsystem_vendor", 64) or "")
                .lower().removeprefix("0x"),
                "subsystem_device": (self.read(path / "subsystem_device", 64) or "")
                .lower().removeprefix("0x"),
                "revision": (self.read(path / "revision", 64) or "").lower().removeprefix("0x"),
                "driver": self.link_name(path / "driver"),
                "parent": parent,
                "boot_vga": self.read(path / "boot_vga", 8) == "1",
                "vram": self.read_int(path / "mem_info_vram_total"),
                "path": str(path),
            })
        devices.sort(key=lambda d: d["address"])  # fixed-width hex: plain order is bus order
        names = self.id_names(PCI_IDS, {d["vendor_id"] for d in devices},
                              {(d["vendor_id"], d["device_id"]) for d in devices})
        for d in devices:
            vendor_name = names[0].get(d["vendor_id"]) or PCI_VENDORS.get(d["vendor_id"], "")
            device_name = names[1].get((d["vendor_id"], d["device_id"]), "")
            d["vendor"] = vendor_name or (f"[{d['vendor_id']}]" if d["vendor_id"] else "")
            d["name"] = device_name or f"Device {d['vendor_id']}:{d['device_id']}"
        return devices

    def id_names(self, candidates: tuple[str, ...], vendors: set[str],
                 pairs: set[tuple[str, str]]) -> tuple[dict, dict]:
        """Names from the first pci.ids / usb.ids found below the root."""
        for rel in candidates:
            path = self.path(rel)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines = _capped_lines(fh, IDS_LIMIT)
                    return lookup_ids(lines, vendors, pairs)
            except OSError:
                continue
        return {}, {}

    # -- machine ----------
    def probe_machine(self) -> Section:
        dmi = self.dmi() if self.linux else {}
        model_dt = (self.read("sys/firmware/devicetree/base/model")
                    or self.read("proc/device-tree/model")) if self.linux else None
        data: dict[str, Any] = {}
        if not dmi and not model_dt and self.linux:
            if not self.exists("sys"):
                raise NotAvailable("/sys is not mounted (a sandbox or container)")
        vendor = dmi.get("sys_vendor") or dmi.get("board_vendor") or ""
        product = dmi.get("product_name") or model_dt or ""
        version = dmi.get("product_version", "")
        if not self.linux:
            uname = platform.uname()
            product = product or uname.machine
            vendor = vendor or ""
            if self.system == "Darwin":
                vendor = "Apple"
                product = _mac_model() or product
        friendly = product
        if (re.fullmatch(r"[0-9A-Z]{6,}", product or "") and re.search(r"\d", product)
                and " " in version):
            friendly = version  # Lenovo: product_name is the machine type, the name is here
        chassis_code = _int_or_none(dmi.get("chassis_type"))
        chassis = CHASSIS_TYPES.get(chassis_code, "") if chassis_code else ""
        if chassis_code in LAPTOP_CHASSIS:
            form = "laptop"
        elif chassis_code in SERVER_CHASSIS:
            form = "server"
        elif chassis_code:
            form = "desktop"
        else:
            form = ""
        firmware = ""
        secure_boot = None
        if self.linux:
            if self.exists("sys/firmware/efi"):
                firmware = "UEFI"
                secure_boot = self._secure_boot()
            elif dmi:
                firmware = "BIOS (legacy)"
        data.update({
            "vendor": vendor, "vendor_short": short_vendor(vendor), "product": product,
            "model": friendly, "version": version,
            "family": dmi.get("product_family", ""), "sku": dmi.get("product_sku", ""),
            "chassis": chassis, "form": form,
            "board_vendor": dmi.get("board_vendor", ""), "board_name": dmi.get("board_name", ""),
            "board_version": dmi.get("board_version", ""),
            "bios_vendor": dmi.get("bios_vendor", ""), "bios_version": dmi.get("bios_version", ""),
            "bios_date": dmi.get("bios_date", ""), "bios_release": dmi.get("bios_release", ""),
            "firmware": firmware, "secure_boot": secure_boot,
            "product_serial": dmi.get("product_serial", ""),
            "board_serial": dmi.get("board_serial", ""),
            "chassis_serial": dmi.get("chassis_serial", ""),
            "product_uuid": dmi.get("product_uuid", ""),
        })
        if not any(data[k] for k in ("vendor", "product", "board_name", "bios_vendor")):
            raise NotAvailable("the firmware tables (DMI) name no vendor or model")
        board = " ".join(x for x in (data["board_vendor"], data["board_name"],
                                     data["board_version"]) if x)
        bios = " ".join(x for x in (data["bios_vendor"], data["bios_version"]) if x)
        if data["bios_date"]:
            bios += f" ({data['bios_date']})"
        fields = [
            field("Manufacturer", vendor),
            field("Model", friendly),
            field("Product code", product if product != friendly else None),
            field("Version", version if version != friendly else None),
            field("Family", data["family"] if data["family"] != friendly else None),
            field("SKU", data["sku"]),
            field("Chassis", chassis),
            field("Mainboard", board),
            field("BIOS / firmware", bios.strip()),
            field("Firmware type", firmware),
            field("Secure Boot", {True: "on", False: "off"}.get(secure_boot)),
            field("Serial number", data["product_serial"], ident=True),
            field("Board serial", data["board_serial"], ident=True),
            field("Chassis serial", data["chassis_serial"], ident=True),
            field("UUID", data["product_uuid"], ident=True),
        ]
        return make_section("machine", "Machine & Firmware", fields, data=data)

    def _secure_boot(self) -> bool | None:
        base = self.path("sys/firmware/efi/efivars")
        for name in self.listdir(base):
            if name.startswith("SecureBoot-"):
                raw = self.read_bytes(base / name, 16)
                if len(raw) >= 5:
                    return raw[4] == 1
        return None

    # -- operating system ----------
    def probe_os(self) -> Section:
        osr = parse_os_release(self.read("etc/os-release") or self.read("usr/lib/os-release")
                               or "")
        hostname = self.hostname or socket.gethostname()
        if self.linux:
            name = osr.get("PRETTY_NAME") or osr.get("NAME") or "Linux"
            kernel = self.read("proc/sys/kernel/osrelease") or platform.release()
            kversion = self.read("proc/sys/kernel/version") or ""
        else:
            name = {"Darwin": f"macOS {platform.mac_ver()[0]}".strip(),
                    "Windows": f"Windows {platform.release()} ({platform.version()})"}.get(
                        self.system, platform.platform())
            kernel, kversion = platform.release(), platform.version()
        uptime = None
        up = self.read("proc/uptime", 256) if self.linux else None
        if up:
            try:
                uptime = float(up.split()[0])
            except (ValueError, IndexError):
                uptime = None
        if uptime is None and (ps := self._psutil()) is not None:
            try:
                uptime = time.time() - ps.boot_time()
            except Exception:  # noqa: BLE001 - optional source
                uptime = None
        load = None
        processes = None
        text = self.read("proc/loadavg", 256) if self.linux else None
        if text:
            parts = text.split()
            try:
                load = [float(x) for x in parts[:3]]
                processes = int(parts[3].split("/")[1])
            except (ValueError, IndexError):
                pass
        elif hasattr(os, "getloadavg") and self.real:
            try:
                load = list(os.getloadavg())
            except OSError:
                load = None
        env = self.env
        desktop = env.get("XDG_CURRENT_DESKTOP") or env.get("DESKTOP_SESSION") or ""
        session = env.get("XDG_SESSION_TYPE") or (
            "wayland" if env.get("WAYLAND_DISPLAY") else "x11" if env.get("DISPLAY") else "")
        init = self.read("proc/1/comm", 256) if self.linux else None
        tz = self._timezone()
        versions = _versions()
        data = {
            "hostname": hostname, "name": name, "id": osr.get("ID", ""),
            "version": osr.get("VERSION", osr.get("VERSION_ID", "")),
            "kernel": kernel, "kernel_version": kversion, "arch": platform.machine(),
            "uptime_s": uptime, "load": load, "processes": processes,
            "desktop": desktop, "session": session, "init": init or "",
            "timezone": tz, "locale": env.get("LANG", ""), **versions,
        }
        fields = [
            field("Computer name", hostname, ident=True),
            field("Operating system", name),
            field("Kernel", f"{kernel}" + (f"  ({kversion})" if kversion else "")),
            field("Architecture", data["arch"]),
            field("Uptime", human_duration(uptime) if uptime is not None else None),
            field("Load (1, 5, 15 min)", ", ".join(f"{x:.2f}" for x in load) if load else None),
            field("Processes", processes),
            field("Desktop", desktop),
            field("Session", session),
            field("Init system", init),
            field("Time zone", tz),
            field("Locale", data["locale"]),
            field("Python", versions["python"]),
            field("Qt / PyQt", versions.get("qt")),
            field("axross", versions["axross"]),
        ]
        return make_section("os", "Operating System", fields, data=data)

    def _timezone(self) -> str:
        tz = self.read("etc/timezone", 256)
        if tz:
            return tz
        try:
            target = os.readlink(self.path("etc/localtime"))
            if "zoneinfo/" in target:
                return target.split("zoneinfo/", 1)[1]
        except (OSError, ValueError):
            pass
        return time.strftime("%Z") if self.real else ""

    # -- CPU ----------
    def probe_cpu(self) -> Section:
        blocks = self.cpuinfo() if self.linux else []
        procs = [b for b in blocks if "processor" in b]
        first = procs[0] if procs else (blocks[0] if blocks else {})
        trailer = next((b for b in blocks if "processor" not in b), {})
        model = (first.get("model name") or first.get("Processor") or first.get("cpu model")
                 or trailer.get("Model") or trailer.get("Hardware") or "")
        if not model and not self.linux:
            model = platform.processor() or ""
            if self.system == "Darwin":
                model = _sysctl_string("machdep.cpu.brand_string") or model
        vendor = first.get("vendor_id") or first.get("CPU implementer") or ""
        base = self.path("sys/devices/system/cpu")
        cpu_dirs = [n for n in self.listdir(base) if re.fullmatch(r"cpu\d+", n)]
        online = parse_cpu_list(self.read(base / "online", 4096))
        threads = len(online) or len(procs) or len(cpu_dirs) or (os.cpu_count() if self.real
                                                                 else 0) or 0
        if not model and not threads:
            raise NotAvailable("/proc/cpuinfo and /sys/devices/system/cpu are not readable")
        cores_set: set[tuple[int, int]] = set()
        sockets: set[int] = set()
        p_cores = set(parse_cpu_list(self.read("sys/devices/cpu_core/cpus", 4096)))
        e_cores = set(parse_cpu_list(self.read("sys/devices/cpu_atom/cpus", 4096)))
        per_cpu = []
        for name in cpu_dirs:
            n = int(name[3:])
            d = base / name
            core = self.read_int(d / "topology/core_id")
            pkg = self.read_int(d / "topology/physical_package_id")
            if core is not None:
                cores_set.add((pkg or 0, core))
            if pkg is not None:
                sockets.add(pkg)
            cur = self.read_int(d / "cpufreq/scaling_cur_freq")
            fmin = self.read_int(d / "cpufreq/cpuinfo_min_freq")
            fmax = self.read_int(d / "cpufreq/cpuinfo_max_freq")
            kind = "P-core" if n in p_cores else "E-core" if n in e_cores else ""
            per_cpu.append({
                "cpu": n, "core": core, "socket": pkg, "type": kind,
                "cur_mhz": cur / 1000 if cur else None,
                "min_mhz": fmin / 1000 if fmin else None,
                "max_mhz": fmax / 1000 if fmax else None,
                "governor": self.read(d / "cpufreq/scaling_governor", 256) or "",
            })
        if not per_cpu and procs:
            for b in procs:
                try:
                    mhz = float(b.get("cpu MHz", ""))
                except ValueError:
                    mhz = None
                per_cpu.append({"cpu": _int_or_none(b.get("processor")),
                                "core": _int_or_none(b.get("core id")),
                                "socket": _int_or_none(b.get("physical id")), "type": "",
                                "cur_mhz": mhz, "min_mhz": None, "max_mhz": None,
                                "governor": ""})
                if b.get("core id") is not None:
                    cores_set.add((_int_or_none(b.get("physical id")) or 0,
                                   _int_or_none(b.get("core id")) or 0))
                if b.get("physical id") is not None:
                    sockets.add(_int_or_none(b.get("physical id")) or 0)
        cores = len(cores_set) or _int_or_none(first.get("cpu cores")) or None
        psutil = self._psutil()
        if psutil is not None and not self.linux:
            try:
                cores = cores or psutil.cpu_count(logical=False)
                freq = psutil.cpu_freq()
                if freq and not per_cpu:
                    per_cpu.append({"cpu": 0, "core": None, "socket": None, "type": "",
                                    "cur_mhz": freq.current, "min_mhz": freq.min or None,
                                    "max_mhz": freq.max or None, "governor": ""})
            except Exception:  # noqa: BLE001 - optional source
                pass
        max_mhz = max((c["max_mhz"] for c in per_cpu if c["max_mhz"]), default=None)
        min_mhz = min((c["min_mhz"] for c in per_cpu if c["min_mhz"]), default=None)
        curs = [c["cur_mhz"] for c in per_cpu if c["cur_mhz"]]
        avg_mhz = sum(curs) / len(curs) if curs else None
        flags = self.cpu_flags()
        features = [{"group": g, "name": label, "present": any(f in flags for f in names)}
                    for g, label, names in CPU_FEATURES]
        if flags:
            # Only what this architecture can have: no "NEON" on x86.
            x86 = "sse2" in flags or "fpu" in flags
            arm = "asimd" in flags or "neon" in flags or "fp" in flags
            features = [f for f in features if f["present"] or not (
                (x86 and f["name"] in ("NEON / ASIMD", "SVE"))
                or (arm and f["name"] not in ("NEON / ASIMD", "SVE", "AES-NI", "SHA", "CLMUL")))]
        else:
            features = []
        caches = self._caches(base, cpu_dirs)
        vulns = []
        vdir = base / "vulnerabilities"
        for name in self.listdir(vdir):
            status = self.read(vdir / name, 1024)
            if status is not None:
                vulns.append((name.replace("_", " "), status))
        governors = sorted({c["governor"] for c in per_cpu if c["governor"]})
        driver = self.read(base / "cpu0/cpufreq/scaling_driver", 256) or ""
        family = first.get("cpu family", "")
        data = {
            "model": model, "vendor": vendor, "threads": threads, "cores": cores,
            "sockets": len(sockets) or (1 if threads else None),
            "p_cores": sorted(p_cores), "e_cores": sorted(e_cores),
            "family": family, "model_id": first.get("model", ""),
            "stepping": first.get("stepping", ""), "microcode": first.get("microcode", ""),
            "min_mhz": min_mhz, "max_mhz": max_mhz, "avg_mhz": avg_mhz,
            "per_cpu": per_cpu, "features": features, "flags": sorted(flags),
            "caches": caches, "vulnerabilities": [{"name": n, "status": s} for n, s in vulns],
            "governors": governors, "driver": driver, "bogomips": first.get("bogomips", ""),
            "address_sizes": first.get("address sizes", ""),
        }
        hybrid = ""
        if p_cores or e_cores:
            hybrid = f"{len(p_cores)} P-core threads, {len(e_cores)} E-core threads"
        cache_totals: dict[str, int] = {}
        for c in caches:
            name = f"L{c['level']}{c['type_short']}"
            cache_totals[name] = cache_totals.get(name, 0) + c["total"]
        cache_text = ", ".join(f"{k} {human_bytes(v)}" for k, v in cache_totals.items() if v)
        ident = " ".join(x for x in (
            f"family {family}" if family else "", f"model {first.get('model')}"
            if first.get("model") else "", f"stepping {first.get('stepping')}"
            if first.get("stepping") else "") if x)
        fields = [
            field("Model", model),
            field("Vendor", vendor),
            field("Sockets", data["sockets"]),
            field("Cores", cores),
            field("Threads", threads),
            field("Hybrid layout", hybrid),
            field("Frequency range", f"{human_mhz(min_mhz)} – {human_mhz(max_mhz)}"
                  if min_mhz and max_mhz else None),
            field("Average current frequency", human_mhz(avg_mhz) if avg_mhz else None),
            field("Frequency driver / governor", " / ".join(
                x for x in (driver, ", ".join(governors)) if x)),
            field("Caches", cache_text),
            field("Identification", ident),
            field("Microcode", data["microcode"]),
            field("Address sizes", data["address_sizes"]),
            field("Instruction set flags", f"{len(flags)} flags" if flags else None),
        ]
        tables = [
            table("Logical CPUs", ["CPU", "Core", "Socket", "Type", "Current", "Min", "Max",
                                   "Governor"],
                  [[c["cpu"], c["core"], c["socket"], c["type"],
                    human_mhz(c["cur_mhz"]) if c["cur_mhz"] else "",
                    human_mhz(c["min_mhz"]) if c["min_mhz"] else "",
                    human_mhz(c["max_mhz"]) if c["max_mhz"] else "", c["governor"]]
                   for c in per_cpu]),
            table("Caches", ["Level", "Type", "Size each", "Instances", "Total", "Shared by"],
                  [[f"L{c['level']}", c["type"], human_bytes(c["size"]), c["instances"],
                    human_bytes(c["total"]), f"{c['shared_by']} CPUs" if c["shared_by"] else ""]
                   for c in caches]),
            table("Security vulnerabilities (kernel's view)", ["Issue", "Status"],
                  [[n, s] for n, s in vulns]),
        ]
        return make_section("cpu", "CPU", fields, tables, data)

    def _caches(self, base: Path, cpu_dirs: list[str]) -> list[dict]:
        seen: set[tuple] = set()
        groups: dict[tuple, dict] = {}
        for name in cpu_dirs[:1024]:
            cdir = base / name / "cache"
            for index in self.listdir(cdir):
                if not index.startswith("index"):
                    continue
                d = cdir / index
                level = self.read_int(d / "level")
                ctype = self.read(d / "type", 64) or ""
                size = parse_size_text(self.read(d / "size", 64))
                shared = self.read(d / "shared_cpu_list", 4096) or name[3:]
                if level is None or size is None:
                    continue
                instance = (level, ctype, shared)
                if instance in seen:
                    continue
                seen.add(instance)
                key = (level, ctype, size)
                group = groups.setdefault(key, {
                    "level": level, "type": ctype,
                    "type_short": {"Data": "d", "Instruction": "i"}.get(ctype, ""),
                    "size": size, "instances": 0, "total": 0,
                    "shared_by": len(parse_cpu_list(shared))})
                group["instances"] += 1
                group["total"] += size
        return sorted(groups.values(), key=lambda g: (g["level"], g["type"], g["size"]))

    # -- memory ----------
    def probe_memory(self) -> Section:
        info = parse_meminfo(self.read("proc/meminfo") or "") if self.linux else {}
        if not info.get("MemTotal"):
            ps = self._psutil()
            if ps is not None:
                vm, sw = ps.virtual_memory(), ps.swap_memory()
                info = {"MemTotal": vm.total, "MemAvailable": vm.available, "MemFree": vm.free,
                        "SwapTotal": sw.total, "SwapFree": sw.free}
            elif self.real and hasattr(os, "sysconf"):
                try:
                    info = {"MemTotal": os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")}
                except (ValueError, OSError):
                    info = {}
        total = info.get("MemTotal")
        if not total:
            raise NotAvailable("/proc/meminfo is missing or names no MemTotal")
        available = info.get("MemAvailable", info.get("MemFree"))
        used = total - available if available is not None else None
        cache = (info.get("Cached", 0) + info.get("SReclaimable", 0) + info.get("Buffers", 0)
                 if "Cached" in info else None)
        swap_total = info.get("SwapTotal", 0)
        swap_free = info.get("SwapFree", 0)
        swap_used = swap_total - swap_free if swap_total else 0
        block = self.read("sys/devices/system/memory/block_size_bytes", 64)
        installed = None
        if block:
            try:
                size = int(block, 16)
                count = self.count_entries("sys/devices/system/memory", r"memory\d+")
                installed = size * count if count else None
            except ValueError:
                installed = None
            # Fewer blocks than the kernel's total: a count cut short (or
            # hot-unplugged blocks) - not the installed amount.
            if installed is not None and installed < info.get("MemTotal", 0):
                installed = None
        swaps = []
        for line in (self.read("proc/swaps") or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                try:
                    swaps.append({"name": parts[0], "type": parts[1], "size": int(parts[2]) * 1024,
                                  "used": int(parts[3]) * 1024, "priority": parts[4]})
                except ValueError:
                    continue
        data = {
            "total": total, "available": available, "used": used,
            "free": info.get("MemFree"), "cache": cache, "buffers": info.get("Buffers"),
            "shared": info.get("Shmem"), "dirty": info.get("Dirty"),
            "swap_total": swap_total, "swap_used": swap_used, "swap_free": swap_free,
            "installed": installed, "hugepages": info.get("HugePages_Total"),
            "hugepage_size": info.get("Hugepagesize"), "committed": info.get("Committed_AS"),
            "commit_limit": info.get("CommitLimit"), "swaps": swaps,
        }
        pct = 100.0 * used / total if used is not None else None
        fields = [
            field("Total (usable)", human_bytes(total)),
            field("Installed (memory blocks)", human_bytes(installed)
                  if installed and installed >= total else None),
            field("In use", f"{human_bytes(used)}  ({percent(pct)})" if used is not None else None),
            field("Available", human_bytes(available) if available is not None else None),
            field("Cache and buffers", human_bytes(cache) if cache is not None else None),
            field("Shared (tmpfs, shm)", human_bytes(info["Shmem"]) if "Shmem" in info else None),
            field("Swap", f"{human_bytes(swap_used)} used of {human_bytes(swap_total)}"
                  if swap_total else "none"),
            field("Committed", f"{human_bytes(info['Committed_AS'])} of "
                  f"{human_bytes(info['CommitLimit'])} limit"
                  if "Committed_AS" in info and "CommitLimit" in info else None),
            field("Huge pages", f"{info['HugePages_Total']} × {human_bytes(info['Hugepagesize'])}"
                  if info.get("HugePages_Total") and info.get("Hugepagesize") else None),
        ]
        tables = [table("Swap areas", ["Name", "Type", "Size", "Used", "Priority"],
                        [[s["name"], s["type"], human_bytes(s["size"]), human_bytes(s["used"]),
                          s["priority"]] for s in swaps])]
        return make_section("memory", "Memory", fields, tables, data)

    # -- storage ----------
    def _mounts(self) -> list[tuple[str, str, str, str]]:
        return parse_mounts(self.read("proc/self/mounts", 1024 * 1024)
                            or self.read("proc/mounts", 1024 * 1024) or "")

    def probe_storage(self) -> Section:
        if not self.linux:
            return self._storage_fallback()
        mounts = self._mounts()
        base = self.path("sys/block")
        dm_names = {}
        for name in self.listdir(base):
            if name.startswith("dm-"):
                mapped = self.read(base / name / "dm/name", 256)
                if mapped:
                    dm_names[f"/dev/mapper/{mapped}"] = name
        dev_mounts: dict[str, list[str]] = {}
        for device, mount, _fs, _opts in mounts:
            name = dm_names.get(device) or (device[5:] if device.startswith("/dev/") else "")
            if name:
                dev_mounts.setdefault(name, []).append(mount)
        disks = []
        for name in self.listdir(base):
            if name.startswith(("loop", "ram", "zram", "fd")):
                continue
            # eMMC boot / RPMB areas are parts of the chip, not disks.
            if re.fullmatch(r"mmcblk\d+(boot\d+|rpmb)", name):
                continue
            d = base / name
            sectors = self.read_int(d / "size")
            if not sectors:
                continue
            dev = d / "device"
            try:
                real = os.path.realpath(d)
            except (OSError, ValueError):
                real = ""
            rotational = self.read(d / "queue/rotational", 8)
            removable = self.read(d / "removable", 8) == "1"
            model = (self.read(dev / "model", 256) or self.read(dev / "name", 256) or "").strip()
            vendor = (self.read(dev / "vendor", 256) or "").strip()
            transport = _transport(name, real, self.read(dev / "type", 64) or "")
            kind = _disk_kind(name, transport, rotational, removable)
            parts = []
            for pname in self.listdir(d):
                pdir = d / pname
                if not (pdir / "partition").exists():
                    continue
                psize = (self.read_int(pdir / "size") or 0) * 512
                parts.append({"name": pname, "size": psize,
                              "start": (self.read_int(pdir / "start") or 0) * 512,
                              "mounts": dev_mounts.get(pname, [])})
            parts.sort(key=lambda p: p["start"])
            sched = self.read(d / "queue/scheduler", 256) or ""
            m = re.search(r"\[([^\]]+)\]", sched)
            disks.append({
                "name": name, "model": model, "vendor": vendor if vendor.lower() != "ata" else "",
                "size": sectors * 512, "kind": kind, "transport": transport,
                "rotational": rotational == "1", "removable": removable,
                "serial": (self.read(dev / "serial", 256) or "").strip(),
                "firmware": (self.read(dev / "firmware_rev", 256) or self.read(dev / "rev", 256)
                             or "").strip(),
                "scheduler": m.group(1) if m else sched,
                "logical_block": self.read_int(d / "queue/logical_block_size"),
                "physical_block": self.read_int(d / "queue/physical_block_size"),
                "mapped": self.read(d / "dm/name", 256) or "",
                "mounts": dev_mounts.get(name, []), "partitions": parts,
            })
        filesystems = self._filesystems(mounts)
        usage_of = {f["mount"]: f for f in filesystems}
        for disk in disks:
            for part in disk["partitions"]:
                part["usage"] = [usage_of[m] for m in part["mounts"] if m in usage_of][:1]
            disk["usage"] = [usage_of[m] for m in disk["mounts"] if m in usage_of][:1]
        if not disks and not filesystems:
            raise NotAvailable("neither /sys/block nor /proc/mounts lists a disk")
        total = sum(d["size"] for d in disks if d["kind"] not in ("Virtual (device mapper)",
                                                                   "Software RAID"))
        fields = [
            field("Disks", len([d for d in disks if not d["name"].startswith(("dm-", "md"))])),
            field("Total capacity", human_bytes(total) if total else None),
            field("Mounted file systems", len(filesystems)),
        ]
        rows, ident_rows = [], []
        for d in disks:
            rows.append([d["name"], " ".join(x for x in (d["vendor"], d["model"]) if x)
                         or d["mapped"], d["kind"], human_bytes(d["size"]),
                         ", ".join(p["name"] for p in d["partitions"]) or "-",
                         ", ".join(d["mounts"] + [m for p in d["partitions"] for m in p["mounts"]]),
                         d["firmware"], d["serial"]])
            ident_rows.append(d["serial"])
        fs_rows = [[f["mount"], f["device"], f["fstype"], human_bytes(f["total"]),
                    human_bytes(f["used"]), human_bytes(f["free"]),
                    percent(f["percent"]) if f["percent"] is not None else f["error"]]
                   for f in filesystems]
        tables = [
            table("Disks", ["Device", "Model", "Type", "Size", "Partitions", "Mounted at",
                            "Firmware", "Serial"], rows, ident_columns=(7,)),
            table("File systems", ["Mount point", "Device", "Type", "Size", "Used", "Free",
                                   "Use"], fs_rows),
        ]
        return make_section("storage", "Storage", fields, tables,
                            {"disks": disks, "filesystems": filesystems})

    def _filesystems(self, mounts) -> list[dict]:
        chosen = []
        seen_devices = set()
        for device, mount, fstype, _opts in mounts:
            if fstype in NETWORK_FS or device.startswith("//"):
                kind = "network"
            elif fstype in LOCAL_FS and (device.startswith("/dev/") or mount == "/"):
                kind = "local"
            elif fstype == "tmpfs" and mount in ("/tmp",):
                kind = "memory"
            else:
                continue
            if kind == "local" and device in seen_devices:
                continue
            seen_devices.add(device)
            chosen.append({"mount": mount, "device": device, "fstype": fstype, "kind": kind,
                           "total": None, "used": None, "free": None, "percent": None,
                           "error": ""})
        return measure_usage(chosen[:256], self._usage or _default_usage)

    def _storage_fallback(self) -> Section:
        ps = self._psutil()
        mounts: list[tuple[str, str, str, str]] = []
        if ps is not None:
            try:
                mounts = [(p.device, p.mountpoint, p.fstype or "local", "")
                          for p in ps.disk_partitions(all=False)]
            except Exception:  # noqa: BLE001 - optional source
                mounts = []
        if not mounts and self.real:
            if self.system == "Windows":
                mounts = [(f"{c}:\\", f"{c}:\\", "", "") for c in "CDEFGH"
                          if os.path.exists(f"{c}:\\")]
            else:
                mounts = [("/", "/", "", "")]
        fs = [{"mount": m, "device": d, "fstype": t, "kind": "local", "total": None,
               "used": None, "free": None, "percent": None, "error": ""}
              for d, m, t, _o in mounts]
        fs = measure_usage(fs, self._usage or _default_usage)
        if not fs:
            raise NotAvailable(f"no disk list on {self.system} without psutil")
        rows = [[f["mount"], f["device"], f["fstype"], human_bytes(f["total"]),
                 human_bytes(f["used"]), human_bytes(f["free"]),
                 percent(f["percent"]) if f["percent"] is not None else f["error"]] for f in fs]
        return make_section("storage", "Storage", [field("Mounted file systems", len(fs))],
                            [table("File systems", ["Mount point", "Device", "Type", "Size",
                                                    "Used", "Free", "Use"], rows)],
                            {"disks": [], "filesystems": fs})

    # -- graphics ----------
    def probe_graphics(self) -> Section:
        gpus = [d for d in self.pci_devices() if d["class_code"] is not None
                and d["class_code"] >> 16 == 0x03]
        drm = self.path("sys/class/drm")
        displays = []
        cards = []
        for name in self.listdir(drm):
            d = drm / name
            if re.fullmatch(r"card\d+", name):
                cards.append({"name": name, "driver": self.link_name(d / "device/driver")})
                continue
            match = re.fullmatch(r"card(\d+)-(.+)", name)
            if not match:
                continue
            status = self.read(d / "status", 64) or "unknown"
            modes = [m for m in (self.read(d / "modes", 64 * 1024) or "").splitlines() if m]
            edid = parse_edid(self.read_bytes(d / "edid", 32 * 1024))
            connector = match.group(2)
            displays.append({
                "connector": connector, "card": f"card{match.group(1)}", "status": status,
                "enabled": self.read(d / "enabled", 64) == "enabled",
                "internal": connector.startswith(("eDP", "LVDS", "DSI")),
                "modes": _dedupe(modes)[:64], "preferred": modes[0] if modes else "",
                **edid,
            })
        displays.sort(key=lambda d: (d["status"] != "connected", not d["internal"],
                                     _natural(d["connector"])))
        if not gpus and not displays and not cards:
            if not self.linux:
                raise NotAvailable(f"no graphics source on {self.system} (Qt's screen list "
                                   "is below)")
            raise NotAvailable("no display controller on the PCI bus and no /sys/class/drm")
        gpu_rows = []
        for g in gpus:
            gpu_rows.append([g["vendor"], g["name"], g["class"], g["driver"] or "-",
                             human_bytes(g["vram"]) if g["vram"] else "",
                             "yes" if g["boot_vga"] else "", g["address"]])
        if not gpus:
            for c in cards:
                gpu_rows.append(["", c["name"], "DRM device", c["driver"] or "-", "", "", ""])
        connected = [d for d in displays if d["status"] == "connected"]
        disp_rows = [[d["connector"], d["status"], d.get("monitor") or "",
                      d.get("resolution") or d["preferred"],
                      f"{d['refresh']:.0f} Hz" if d.get("refresh") else "",
                      f"{d['diagonal_in']:.1f}\"" if d.get("diagonal_in") else "",
                      len(d["modes"]) or ""] for d in displays]
        fields = [
            field("Graphics", "; ".join(f"{g['vendor']} {g['name']}".strip() for g in gpus)),
            field("Drivers", ", ".join(_dedupe([g["driver"] for g in gpus if g["driver"]]
                                               + [c["driver"] for c in cards if c["driver"]]))),
            field("Connected displays", len(connected) if displays else None),
        ]
        tables = [
            table("Graphics adapters", ["Vendor", "Model", "Class", "Driver", "Video memory",
                                        "Primary", "PCI address"], gpu_rows),
            table("Display outputs", ["Output", "Status", "Monitor", "Resolution", "Refresh",
                                      "Size", "Modes"], disp_rows),
        ]
        for d in displays:
            d.pop("serial", None)
        return make_section("graphics", "Graphics & Displays", fields, tables,
                            {"gpus": gpus, "displays": displays, "cards": cards})

    # -- network ----------
    def probe_network(self) -> Section:
        if not self.linux:
            return self._network_fallback()
        base = self.path("sys/class/net")
        names = self.listdir(base)
        if not names:
            raise NotAvailable("/sys/class/net is empty or missing")
        addresses = self._interface_addresses()
        wifi = _parse_proc_wireless(self.read("proc/net/wireless") or "")
        interfaces = []
        for name in names:
            d = base / name
            try:
                real = os.path.realpath(d)
            except (OSError, ValueError):
                real = ""
            arptype = self.read_int(d / "type")
            wireless = (d / "wireless").exists() or (d / "phy80211").exists()
            virtual = "/devices/virtual/" in real
            kind = _net_kind(name, arptype, wireless, virtual, (d / "bridge").exists(),
                             (d / "tun_flags").exists())
            speed = self.read_int(d / "speed")
            interfaces.append({
                "name": name, "kind": kind, "state": self.read(d / "operstate", 64) or "unknown",
                "mac": self.read(d / "address", 64) or "", "mtu": self.read_int(d / "mtu"),
                "speed_mbps": speed if speed and speed > 0 else None,
                "duplex": self.read(d / "duplex", 64) or "",
                "driver": self.link_name(d / "device/driver"),
                "rx_bytes": self.read_int(d / "statistics/rx_bytes"),
                "tx_bytes": self.read_int(d / "statistics/tx_bytes"),
                "addresses": [a["address"] for a in addresses.get(name, [])],
                "signal_dbm": wifi.get(name, {}).get("level"),
                "link_quality": wifi.get(name, {}).get("quality"),
            })
        gateway, gw_iface = _default_route(self.read("proc/net/route") or "")
        dns = [line.split()[1] for line in (self.read("etc/resolv.conf") or "").splitlines()
               if line.startswith("nameserver") and len(line.split()) > 1]
        up = [i for i in interfaces if i["state"] == "up" and i["kind"] != "Loopback"]
        fields = [
            field("Interfaces", f"{len(interfaces)} ({len(up)} up)"),
            field("Default route via", gw_iface),
            field("Gateway", gateway, ident=True),
            field("DNS servers", ", ".join(dns), ident=True),
        ]
        rows = [[i["name"], i["kind"], i["state"],
                 f"{i['speed_mbps']} Mb/s" if i["speed_mbps"] else "",
                 f"{i['signal_dbm']} dBm" if i["signal_dbm"] is not None else "",
                 i["driver"], i["mtu"] or "", human_bytes(i["rx_bytes"]) if i["rx_bytes"] is
                 not None else "", human_bytes(i["tx_bytes"]) if i["tx_bytes"] is not None else "",
                 i["mac"], ", ".join(i["addresses"])] for i in interfaces]
        tables = [table("Interfaces", ["Name", "Type", "State", "Speed", "Signal", "Driver", "MTU",
                                       "Received", "Sent", "MAC address", "IP addresses"],
                        rows, ident_columns=(9, 10))]
        return make_section("network", "Network", fields, tables, {
            "interfaces": interfaces, "gateway": gateway, "default_interface": gw_iface,
            "dns": dns})

    def _interface_addresses(self) -> dict[str, list[dict]]:
        if self._addresses is not None:
            return self._addresses()
        out: dict[str, list[dict]] = {}
        ps = self._psutil()
        if ps is not None:
            try:
                for name, addrs in ps.net_if_addrs().items():
                    for a in addrs:
                        if a.family in (socket.AF_INET, socket.AF_INET6):
                            out.setdefault(name, []).append(
                                {"address": a.address.split("%")[0],
                                 "family": "ipv4" if a.family == socket.AF_INET else "ipv6"})
                return out
            except Exception:  # noqa: BLE001 - optional source
                out = {}
        for line in (self.read("proc/net/if_inet6") or "").splitlines():
            parts = line.split()
            if len(parts) >= 6 and len(parts[0]) == 32:
                addr = ":".join(parts[0][i:i + 4] for i in range(0, 32, 4))
                try:
                    addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(parts[0]))
                except (OSError, ValueError):
                    pass
                out.setdefault(parts[5], []).append({"address": addr, "family": "ipv6"})
        if self.real and self.linux:
            for name in self.listdir("sys/class/net"):
                addr = _ipv4_of(name)
                if addr:
                    out.setdefault(name, []).insert(0, {"address": addr, "family": "ipv4"})
        return out

    def _network_fallback(self) -> Section:
        ps = self._psutil()
        if ps is None:
            raise NotAvailable(f"interfaces on {self.system} need psutil (axross-full)")
        stats = ps.net_if_stats()
        addrs = ps.net_if_addrs()
        rows, interfaces = [], []
        for name, st in sorted(stats.items()):
            mac = next((a.address for a in addrs.get(name, ())
                        if a.family not in (socket.AF_INET, socket.AF_INET6)), "")
            ips = [a.address for a in addrs.get(name, ())
                   if a.family in (socket.AF_INET, socket.AF_INET6)]
            interfaces.append({"name": name, "state": "up" if st.isup else "down",
                               "speed_mbps": st.speed or None, "mtu": st.mtu, "mac": mac,
                               "addresses": ips, "kind": ""})
            rows.append([name, "", "up" if st.isup else "down",
                         f"{st.speed} Mb/s" if st.speed else "", "", "", st.mtu, "", "",
                         mac, ", ".join(ips)])
        return make_section(
            "network", "Network", [field("Interfaces", len(rows))],
            [table("Interfaces", ["Name", "Type", "State", "Speed", "Signal", "Driver", "MTU",
                                  "Received", "Sent", "MAC address", "IP addresses"], rows,
                   ident_columns=(9, 10))], {"interfaces": interfaces})

    def probe_bluetooth(self) -> Section:
        if not self.linux:
            raise NotAvailable(f"no Bluetooth source on {self.system}")
        adapters = []
        base = self.path("sys/class/bluetooth")
        for name in self.listdir(base):
            if not re.fullmatch(r"hci\d+", name):
                continue
            d = base / name
            adapters.append({"name": name, "driver": self.link_name(d / "device/driver"),
                             "address": self.read(d / "address", 64) or "",
                             "bus": "USB" if "/usb" in os.path.realpath(d) else ""})
        radios = []
        rbase = self.path("sys/class/rfkill")
        for name in self.listdir(rbase):
            d = rbase / name
            radios.append({"name": self.read(d / "name", 256) or name,
                           "type": self.read(d / "type", 64) or "",
                           "soft_blocked": self.read(d / "soft", 8) == "1",
                           "hard_blocked": self.read(d / "hard", 8) == "1"})
        if not adapters and not radios:
            raise NotAvailable("no Bluetooth adapter and no radio switch (rfkill) found")
        fields = [field("Bluetooth adapters", len(adapters) or "none")]
        tables = [
            table("Bluetooth adapters", ["Adapter", "Driver", "Bus", "Address"],
                  [[a["name"], a["driver"], a["bus"], a["address"]] for a in adapters],
                  ident_columns=(3,)),
            table("Radio switches (rfkill)", ["Radio", "Type", "Switched off in software",
                                              "Switched off by hardware"],
                  [[r["name"], r["type"], "yes" if r["soft_blocked"] else "no",
                    "yes" if r["hard_blocked"] else "no"] for r in radios]),
        ]
        return make_section("bluetooth", "Bluetooth & Radios", fields, tables,
                            {"adapters": adapters, "radios": radios})

    # -- audio ----------
    def probe_audio(self) -> Section:
        if not self.linux:
            raise NotAvailable(f"no ALSA (/proc/asound) on {self.system}")
        text = self.read("proc/asound/cards")
        if text is None:
            raise NotAvailable("/proc/asound/cards is missing (no ALSA sound driver loaded)")
        cards = parse_asound_cards(text)
        for card in cards:
            cdir = self.path(f"proc/asound/card{card['index']}")
            codecs = []
            for name in self.listdir(cdir):
                if name.startswith("codec#"):
                    first = (self.read(cdir / name, 4096) or "").splitlines()[:1]
                    if first and first[0].startswith("Codec:"):
                        codecs.append(first[0].split(":", 1)[1].strip())
            card["codecs"] = codecs
        pcms = []
        for line in (self.read("proc/asound/pcm") or "").splitlines():
            parts = [p.strip() for p in line.split(":")]
            if len(parts) >= 3:
                caps = ", ".join(p.split()[0] for p in parts[3:] if p)
                pcms.append({"id": parts[0], "name": parts[1], "caps": caps})
        if not cards:
            raise NotAvailable("ALSA lists no sound card")
        audio_pci = [d for d in self.pci_devices() if d["class_code"] is not None
                     and d["class_code"] >> 16 == 0x04]
        fields = [field("Sound cards", len(cards)),
                  field("Codecs", ", ".join(_dedupe([c for k in cards for c in k["codecs"]]))),
                  field("Audio controllers", "; ".join(f"{d['vendor']} {d['name']}"
                                                      for d in audio_pci))]
        tables = [
            table("Sound cards", ["#", "ID", "Driver", "Name", "Codec"],
                  [[c["index"], c["id"], c["driver"], c["long_name"] or c["name"],
                    ", ".join(c["codecs"])] for c in cards]),
            table("PCM devices", ["Device", "Name", "Can"],
                  [[p["id"], p["name"], p["caps"]] for p in pcms]),
        ]
        return make_section("audio", "Audio", fields, tables, {"cards": cards, "pcms": pcms})

    # -- USB ----------
    def probe_usb(self) -> Section:
        if not self.linux:
            raise NotAvailable(f"no USB device list on {self.system}")
        base = self.path("sys/bus/usb/devices")
        if not self.path("sys/bus/usb").exists():
            raise NotAvailable("/sys/bus/usb is missing (no USB controller, or /sys not mounted)")
        devices = []
        for name in self.listdir(base):
            if not _USB_DEV.fullmatch(name):
                continue
            d = base / name
            vid = (self.read(d / "idVendor", 16) or "").lower()
            if not vid:
                continue
            pid = (self.read(d / "idProduct", 16) or "").lower()
            classes, drivers = [], []
            prefix = f"{name[3:]}-0:" if name.startswith("usb") else f"{name}:"
            for sub in self.listdir(d):
                if sub.startswith(prefix):
                    c = self.read(d / sub / "bInterfaceClass", 16)
                    if c:
                        try:
                            classes.append(USB_CLASSES.get(int(c, 16), f"class {c}"))
                        except ValueError:
                            pass
                    drv = self.link_name(d / sub / "driver")
                    if drv:
                        drivers.append(drv)
            dev_class = self.read(d / "bDeviceClass", 16) or "00"
            try:
                dc = int(dev_class, 16)
            except ValueError:
                dc = 0
            if dc and dc not in (0xEF, 0xFF):
                classes.insert(0, USB_CLASSES.get(dc, f"class {dev_class}"))
            speed = self.read(d / "speed", 32)
            devices.append({
                "name": name, "vendor_id": vid, "product_id": pid,
                "manufacturer": self.read(d / "manufacturer", 256) or "",
                "product": self.read(d / "product", 256) or "",
                "serial": self.read(d / "serial", 256) or "",
                "speed": _usb_speed(speed), "version": (self.read(d / "version", 32) or "").strip(),
                "classes": _dedupe(classes), "drivers": _dedupe(drivers),
                "max_power": self.read(d / "bMaxPower", 32) or "",
                "bus": self.read_int(d / "busnum"), "dev": self.read_int(d / "devnum"),
                "parent": _usb_parent(name), "hub": dc == 0x09,
            })
        if not devices:
            raise NotAvailable("no USB device in /sys/bus/usb/devices")
        missing = {(d["vendor_id"], d["product_id"]) for d in devices
                   if not d["product"] or not d["manufacturer"]}
        if missing:
            vnames, dnames = self.id_names(USB_IDS, {v for v, _p in missing}, missing)
            for d in devices:
                d["manufacturer"] = d["manufacturer"] or vnames.get(d["vendor_id"], "")
                d["product"] = d["product"] or dnames.get((d["vendor_id"], d["product_id"]), "")
        order = _tree_order([d["name"] for d in devices], [d["parent"] for d in devices])
        devices = [devices[i] for i in order]
        index = {d["name"]: i for i, d in enumerate(devices)}
        parents = [index.get(d["parent"]) for d in devices]
        rows = []
        for d in devices:
            if d["name"].startswith("usb"):
                label = f"USB bus {d['bus'] or d['name'][3:]} ({d['speed'].split(' (')[0]})"
            else:
                label = d["product"] or "USB device"
            rows.append([label, d["manufacturer"], f"{d['vendor_id']}:{d['product_id']}",
                         ", ".join(d["classes"]), d["speed"], ", ".join(d["drivers"]),
                         d["name"], d["serial"]])
        real = [d for d in devices if not d["hub"]]
        fields = [field("Devices", f"{len(real)} (and {len(devices) - len(real)} hubs)")]
        return make_section("usb", "USB Devices", fields, [
            table("USB devices", ["Device", "Manufacturer", "ID", "Kind", "Speed", "Drivers",
                                  "Port", "Serial"], rows, ident_columns=(7,), parents=parents)],
            {"devices": devices})

    def probe_input(self) -> Section:
        if not self.linux:
            raise NotAvailable(f"no input device list on {self.system}")
        text = self.read("proc/bus/input/devices", 1024 * 1024)
        if text is None:
            raise NotAvailable("/proc/bus/input/devices is not readable")
        devices = parse_input_devices(text)
        if not devices:
            raise NotAvailable("the kernel lists no input device")
        counts: dict[str, int] = {}
        for d in devices:
            counts[d["kind"]] = counts.get(d["kind"], 0) + 1
        fields = [field("Input devices", ", ".join(f"{n} {k.lower()}{'' if n == 1 else 's'}"
                                                   for k, n in sorted(counts.items())))]
        return make_section("input", "Input Devices", fields, [
            table("Input devices", ["Name", "Kind", "Bus", "ID", "Handlers"],
                  [[d["name"], d["kind"], d["bus"], d["id"], d["handlers"]] for d in devices])],
            {"devices": devices})

    # -- PCI ----------
    def probe_pci(self) -> Section:
        if not self.linux:
            raise NotAvailable(f"no PCI device list on {self.system}")
        devices = self.pci_devices()
        if not devices:
            raise NotAvailable("/sys/bus/pci/devices is empty or missing (no PCI bus, or "
                               "/sys not mounted)")
        order = _tree_order([d["address"] for d in devices], [d["parent"] for d in devices])
        devices = [devices[i] for i in order]
        index = {d["address"]: i for i, d in enumerate(devices)}
        parents = [index.get(d["parent"]) for d in devices]
        rows = [[d["name"], d["vendor"], d["class"], d["driver"],
                 f"{d['vendor_id']}:{d['device_id']}", d["revision"], d["address"]]
                for d in devices]
        by_class: dict[str, int] = {}
        for d in devices:
            top = PCI_TOP_CLASSES.get((d["class_code"] or 0) >> 16, "Other")
            by_class[top] = by_class.get(top, 0) + 1
        fields = [field("PCI devices", len(devices)),
                  field("By kind", ", ".join(f"{n} × {k}" for k, n in sorted(
                      by_class.items(), key=lambda kv: -kv[1])))]
        for d in devices:
            d.pop("path", None)
        return make_section("pci", "PCI Devices", fields, [
            table("PCI devices", ["Device", "Vendor", "Class", "Driver", "ID", "Rev.", "Address"],
                  rows, parents=parents)], {"devices": devices})

    # -- battery ----------
    def probe_battery(self) -> Section:
        if not self.linux:
            return self._battery_fallback()
        base = self.path("sys/class/power_supply")
        if not base.exists():
            raise NotAvailable("/sys/class/power_supply is missing")
        batteries, adapters = [], []
        for name in self.listdir(base):
            d = base / name
            kind = self.read(d / "type", 64) or ""
            if kind == "Battery":
                batteries.append(self._battery(name, d))
            elif kind in ("Mains", "USB", "UPS", "Wireless"):
                adapters.append({"name": name, "type": kind,
                                 "online": self.read(d / "online", 8) == "1"})
        on_ac = any(a["online"] for a in adapters) if adapters else None
        fields = [field("Power source", {True: "AC adapter", False: "battery"}.get(on_ac)),
                  field("Batteries", len(batteries) or "none (a desktop, or not reported)")]
        system_bats = [b for b in batteries if b["scope"] != "Device"]
        for b in system_bats:
            pre = f"{b['name']}: " if len(system_bats) > 1 else "Battery "
            fields += [
                field(f"{pre}charge", percent(b["capacity"]) if b["capacity"] is not None
                      else b.get("capacity_level")),
                field(f"{pre}status", b["status"]),
                field(f"{pre}health", f"{b['health']:.0f} % of design capacity"
                      if b["health"] is not None else None),
                field(f"{pre}capacity now / design",
                      f"{b['full_wh']:.1f} Wh / {b['design_wh']:.1f} Wh"
                      if b["full_wh"] and b["design_wh"] else None),
                field(f"{pre}charge cycles", b["cycles"]),
                field(f"{pre}power draw", f"{b['power_w']:.1f} W" if b["power_w"]
                      else None),
                field(f"{pre}time left", b["time_text"]),
                field(f"{pre}charge limit", f"{b['charge_limit']} %"
                      if b["charge_limit"] else None),
                field(f"{pre}model", " ".join(x for x in (
                    b["manufacturer"], b["model"], b["technology"]) if x)),
                field(f"{pre}serial number", b["serial"], ident=True),
            ]
        tables = [table("Power supplies", ["Name", "Type", "State"],
                        [[a["name"], a["type"], "online" if a["online"] else "offline"]
                         for a in adapters]
                        + [[b["name"], "Battery" + (" (device)" if b["scope"] == "Device" else ""),
                            f"{b['status']}, {percent(b['capacity'])}"] for b in batteries])]
        return make_section("battery", "Battery & Power", fields, tables,
                            {"batteries": batteries, "adapters": adapters, "on_ac": on_ac})

    def _battery(self, name: str, d: Path) -> dict:
        def num(attr):
            return self.read_int(d / attr)

        voltage = num("voltage_min_design") or num("voltage_now")
        energy_now, full, design = num("energy_now"), num("energy_full"), num("energy_full_design")
        if full is None and num("charge_full") is not None and voltage:
            # µAh × µV / 1e6 = µWh
            energy_now = (num("charge_now") or 0) * voltage // 10**6
            full = num("charge_full") * voltage // 10**6
            design = (num("charge_full_design") or 0) * voltage // 10**6 or None
        power = num("power_now")
        if power is None and num("current_now") is not None and num("voltage_now"):
            power = num("current_now") * num("voltage_now") // 10**6
        if power is not None:
            # Negative while discharging on some drivers (bq27xxx, sbs).
            power = abs(power)
        capacity = num("capacity")
        if capacity is None and energy_now is not None and full:
            capacity = round(100 * energy_now / full)
        if capacity is not None:
            capacity = max(0, min(100, capacity))
        health = 100.0 * full / design if full and design else None
        status = self.read(d / "status", 64) or "Unknown"
        hours = None
        if power and power > 0 and energy_now is not None:
            if status == "Discharging":
                hours = energy_now / power
            elif status == "Charging" and full:
                hours = max(0, full - energy_now) / power
        time_text = None
        if hours is not None and hours < 100:
            time_text = (f"{human_duration(hours * 3600)} "
                         f"{'until empty' if status == 'Discharging' else 'until full'}")
        return {
            "name": name, "status": status, "capacity": capacity,
            "capacity_level": self.read(d / "capacity_level", 64) or "",
            "scope": self.read(d / "scope", 64) or "System",
            "health": health, "cycles": num("cycle_count") or None,
            "full_wh": full / 1e6 if full else None, "design_wh": design / 1e6 if design else None,
            "now_wh": energy_now / 1e6 if energy_now is not None else None,
            "power_w": abs(power) / 1e6 if power else None, "hours": hours,
            "time_text": time_text, "technology": self.read(d / "technology", 64) or "",
            "manufacturer": self.read(d / "manufacturer", 256) or "",
            "model": self.read(d / "model_name", 256) or "",
            "serial": self.read(d / "serial_number", 256) or "",
            "charge_limit": num("charge_control_end_threshold"),
        }

    def _battery_fallback(self) -> Section:
        ps = self._psutil()
        if ps is None:
            raise NotAvailable(f"the battery on {self.system} needs psutil (axross-full)")
        bat = ps.sensors_battery() if hasattr(ps, "sensors_battery") else None
        if bat is None:
            return make_section("battery", "Battery & Power", [field("Batteries", "none")],
                                data={"batteries": [], "adapters": [], "on_ac": None})
        status = "Charging" if bat.power_plugged else "Discharging"
        b = {"name": "BAT", "status": status, "capacity": round(bat.percent), "health": None,
             "cycles": None, "scope": "System", "power_w": None, "time_text": None,
             "full_wh": None, "design_wh": None}
        return make_section("battery", "Battery & Power", [
            field("Power source", "AC adapter" if bat.power_plugged else "battery"),
            field("BAT: charge", percent(bat.percent)), field("BAT: status", status)],
            data={"batteries": [b], "adapters": [], "on_ac": bool(bat.power_plugged)})

    # -- sensors ----------
    def temperature_sources(self) -> list[dict]:
        """Every temperature input: ``{"chip", "label", "path", "high", "crit"}``."""
        out = []
        base = self.path("sys/class/hwmon")
        for name in self.listdir(base):
            d = base / name
            chip = self.read(d / "name", 256) or name
            found = False   # this chip's, not any chip's so far
            for folder in (d, d / "device"):
                for entry in self.listdir(folder):
                    m = re.fullmatch(r"temp(\d+)_input", entry)
                    if not m:
                        continue
                    n = m.group(1)
                    label = self.read(folder / f"temp{n}_label", 256) or f"temp{n}"
                    high = self.read_int(folder / f"temp{n}_max")
                    crit = self.read_int(folder / f"temp{n}_crit")
                    out.append({"chip": chip, "label": label, "path": str(folder / entry),
                                "high": high / 1000 if high and 0 < high < 200000 else None,
                                "crit": crit / 1000 if crit and 0 < crit < 200000 else None,
                                "source": "hwmon"})
                    found = True
                if found:
                    break
        tbase = self.path("sys/class/thermal")
        for name in self.listdir(tbase):
            if not name.startswith("thermal_zone"):
                continue
            d = tbase / name
            crit = None
            for i in range(16):
                if self.read(d / f"trip_point_{i}_type", 64) == "critical":
                    value = self.read_int(d / f"trip_point_{i}_temp")
                    crit = value / 1000 if value and 0 < value < 200000 else None
                    break
                if not (d / f"trip_point_{i}_type").exists():
                    break
            out.append({"chip": "thermal zone", "label": self.read(d / "type", 256) or name,
                        "path": str(d / "temp"), "high": None, "crit": crit,
                        "source": "thermal"})
        return out

    def probe_sensors(self) -> Section:
        temps = []
        fans, volts = [], []
        if self.linux:
            for src in self.temperature_sources():
                value = read_millis(src["path"])
                if value is None:
                    continue
                temps.append({**src, "celsius": value})
            base = self.path("sys/class/hwmon")
            for name in self.listdir(base):
                d = base / name
                chip = self.read(d / "name", 256) or name
                for entry in self.listdir(d):
                    m = re.fullmatch(r"(fan|in)(\d+)_input", entry)
                    if not m:
                        continue
                    value = self.read_int(d / entry)
                    if value is None:
                        continue
                    label = self.read(d / f"{m.group(1)}{m.group(2)}_label", 256) or \
                        f"{m.group(1)}{m.group(2)}"
                    if m.group(1) == "fan":
                        fans.append({"chip": chip, "label": label, "rpm": value})
                    else:
                        volts.append({"chip": chip, "label": label, "volts": value / 1000})
        else:
            ps = self._psutil()
            if ps is not None and hasattr(ps, "sensors_temperatures"):
                try:
                    for chip, entries in ps.sensors_temperatures().items():
                        for e in entries:
                            temps.append({"chip": chip, "label": e.label or chip, "path": "",
                                          "celsius": e.current, "high": e.high, "crit": e.critical,
                                          "source": "psutil"})
                except Exception:  # noqa: BLE001 - optional source
                    pass
        for t in temps:
            t.pop("path", None)
        if not temps and not fans and not volts:
            raise NotAvailable("no temperature, fan or voltage sensor is exposed"
                               + (" (/sys/class/hwmon and /sys/class/thermal are empty)"
                                  if self.linux else f" on {self.system}"))
        hottest = max((t["celsius"] for t in temps), default=None)
        fields = [field("Temperature sensors", len(temps)),
                  field("Hottest", celsius(hottest) if hottest is not None else None),
                  field("Fans", ", ".join(f"{f['label']} {f['rpm']} rpm" for f in fans))]
        tables = [
            table("Temperatures", ["Chip", "Sensor", "Now", "High", "Critical"],
                  [[t["chip"], t["label"], celsius(t["celsius"]),
                    celsius(t["high"]) if t["high"] else "",
                    celsius(t["crit"]) if t["crit"] else ""] for t in temps]),
            table("Fans", ["Chip", "Fan", "Speed"],
                  [[f["chip"], f["label"], f"{f['rpm']} rpm"] for f in fans]),
            table("Voltages", ["Chip", "Rail", "Voltage"],
                  [[v["chip"], v["label"], f"{v['volts']:.3f} V"] for v in volts]),
        ]
        return make_section("sensors", "Sensors", fields, tables,
                            {"temperatures": temps, "fans": fans, "voltages": volts})

    # -- virtualisation ----------
    def probe_virtualization(self) -> Section:
        evidence: list[str] = []
        vm = ""
        if self.linux:
            if "hypervisor" in self.cpu_flags():
                evidence.append("the CPU reports a hypervisor (cpuinfo flag \"hypervisor\")")
                vm = vm or "hypervisor not named"
            hyp = self.read("sys/hypervisor/type", 64)
            if hyp:
                evidence.append(f"/sys/hypervisor/type says {hyp!r}")
                vm = hyp.capitalize()
            dmi = self.dmi()
            text = " ".join(dmi.get(k, "") for k in ("sys_vendor", "product_name", "board_vendor",
                                                     "bios_vendor", "chassis_vendor")).lower()
            for needle, name in HYPERVISOR_DMI:
                if needle in text:
                    evidence.append(f"the firmware (DMI) names {name}")
                    vm = name
                    break
            if "microsoft corporation" in text and "virtual machine" in text:
                evidence.append("the firmware (DMI) names Hyper-V")
                vm = "Hyper-V"
            osrel = (self.read("proc/sys/kernel/osrelease", 256) or "").lower()
            if "microsoft" in osrel or "wsl" in osrel:
                evidence.append("the kernel is Microsoft's WSL kernel")
                vm = "WSL 2 (Hyper-V)"
        containers: list[str] = []
        if self.linux:
            checks = (
                (".dockerenv", "Docker", "/.dockerenv exists"),
                ("run/.containerenv", "Podman", "/run/.containerenv exists"),
                (".flatpak-info", "Flatpak", "/.flatpak-info exists"),
                ("run/firejail", "Firejail sandbox", "/run/firejail exists"),
                ("proc/vz", "OpenVZ", "/proc/vz exists"),
            )
            for rel, name, why in checks:
                if self.exists(rel) and not (rel == "proc/vz" and self.exists("proc/bc")):
                    containers.append(name)
                    evidence.append(why)
            marker = self.read("run/systemd/container", 256)
            if marker:
                containers.append(marker)
                evidence.append(f"systemd says container {marker!r}")
            cgroup = (self.read("proc/1/cgroup") or "").lower()
            for needle, name in (("docker", "Docker"), ("kubepods", "Kubernetes"),
                                 ("libpod", "Podman"), ("lxc", "LXC")):
                if needle in cgroup:
                    containers.append(name)
                    evidence.append(f"the init process's control group names {needle}")
            if self.env.get("container"):
                containers.append(self.env["container"])
                evidence.append(f"the environment says container={self.env['container']!r}")
            if self.env.get("SNAP"):
                containers.append("Snap")
                evidence.append("running from a Snap package")
        containers = _dedupe(containers)
        if vm and containers:
            verdict = f"Container ({', '.join(containers)}) in a virtual machine ({vm})"
        elif vm:
            verdict = f"Virtual machine ({vm})"
        elif containers:
            verdict = f"Container ({', '.join(containers)})"
        elif self.linux:
            verdict = "Bare metal (no sign of a virtual machine or container)"
        else:
            raise NotAvailable(f"no detection on {self.system}")
        checked = (["the CPU's hypervisor flag", "/sys/hypervisor", "the firmware's vendor "
                    "and model (DMI)", "a WSL kernel", "/.dockerenv, /run/.containerenv, "
                    "/.flatpak-info, /run/firejail, /proc/vz", "systemd's container marker",
                    "the init process's control groups", "the environment (container, SNAP)"]
                   if self.linux else [])
        kind = ("vm+container" if vm and containers else "vm" if vm else
                "container" if containers else "bare")
        fields = [field("Verdict", verdict),
                  field("Hypervisor", vm),
                  field("Container / sandbox", ", ".join(containers)),
                  field("CPU virtualisation support", ", ".join(
                      n for f, n in (("vmx", "Intel VT-x"), ("svm", "AMD-V"))
                      if f in self.cpu_flags()) or ("none reported" if self.linux else None))]
        return make_section("virtualization", "Virtualisation & Containers", fields, [
            table("Evidence", ["What was found"], [[e] for e in evidence])],
            {"kind": kind, "hypervisor": vm, "containers": containers, "verdict": verdict,
             "evidence": evidence, "checked": checked})


# --------------------------------------------------------------------------- helpers


_VENDOR_SHORT = (
    ("lenovo", "Lenovo"), ("asustek", "ASUS"), ("dell", "Dell"), ("hewlett", "HP"),
    ("hp", "HP"), ("micro-star", "MSI"), ("gigabyte", "Gigabyte"), ("acer", "Acer"),
    ("apple", "Apple"), ("microsoft", "Microsoft"), ("framework", "Framework"),
    ("samsung", "Samsung"), ("toshiba", "Toshiba"), ("fujitsu", "Fujitsu"),
    ("intel", "Intel"), ("supermicro", "Supermicro"), ("asrock", "ASRock"),
    ("tuxedo", "TUXEDO"), ("system76", "System76"), ("razer", "Razer"),
    ("innotek", "innotek (VirtualBox)"), ("qemu", "QEMU"),
)


def short_vendor(vendor: str) -> str:
    """"LENOVO" -> "Lenovo", "ASUSTeK COMPUTER INC." -> "ASUS"; others as given."""
    low = (vendor or "").lower()
    for needle, name in _VENDOR_SHORT:
        if low.startswith(needle):
            return name
    return vendor


def _natural(name: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", name)]


def _capped_lines(fh, limit: int):
    read = 0
    for line in fh:
        read += len(line)
        if read > limit:
            return
        yield line.rstrip("\n")


def _int_or_none(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _dedupe(items) -> list:
    out = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out


def _pci_class(code: int | None) -> str:
    if code is None:
        return "Unknown"
    return PCI_CLASSES.get(code >> 8) or PCI_TOP_CLASSES.get(code >> 16, f"Class {code:06x}")


def _transport(name: str, real: str, dev_type: str) -> str:
    if name.startswith("nvme"):
        return "NVMe"
    if "/usb" in real:
        return "USB"
    if name.startswith("mmcblk"):
        return "SD" if dev_type == "SD" else "eMMC" if dev_type == "MMC" else "MMC"
    if name.startswith("sr"):
        return "Optical"
    if name.startswith("vd"):
        return "virtio"
    if name.startswith("xvd"):
        return "Xen"
    if name.startswith("dm-"):
        return "Device mapper"
    if name.startswith("md"):
        return "RAID"
    if name.startswith(("sd", "hd")):
        return "SATA/SCSI"
    return ""


def _disk_kind(name: str, transport: str, rotational: str | None, removable: bool) -> str:
    if transport == "NVMe":
        return "NVMe SSD"
    if transport == "Optical":
        return "Optical drive"
    if transport in ("SD", "eMMC", "MMC"):
        return "SD card" if transport == "SD" else "eMMC"
    if transport in ("virtio", "Xen"):
        return "Virtual disk"
    if transport == "Device mapper":
        return "Virtual (device mapper)"
    if transport == "RAID":
        return "Software RAID"
    if transport == "USB":
        return "USB drive"
    if rotational == "1":
        return "Hard disk (HDD)"
    if rotational == "0":
        return "SSD"
    return "Disk"


def _default_usage(path: str) -> tuple[int, int, int]:
    from core import posix_compat

    return posix_compat.disk_usage(path)


#: Mount -> the thread still blocked measuring it (a dead network mount):
#: not measured again while it hangs - every Refresh left one more thread.
_HANGING: dict[str, threading.Thread] = {}
_HANGING_LOCK = threading.Lock()


def measure_usage(filesystems: list[dict], usage: Callable[[str], tuple[int, int, int]],
                  timeout: float = USAGE_TIMEOUT) -> list[dict]:
    """Size, used and free of every file system, each on its own thread: one
    that does not answer within *timeout* (a dead network mount) is unknown
    with that reason, the others are not held up. A mount whose earlier
    measuring thread still hangs is not measured again."""
    results: dict[int, tuple] = {}

    def probe(i: int, mount: str) -> None:
        try:
            results[i] = ("ok", usage(mount))
        except Exception as exc:  # noqa: BLE001 - one file system, shown with its reason
            results[i] = ("error", str(exc) or type(exc).__name__)

    threads = []
    for i, fs in enumerate(filesystems):
        with _HANGING_LOCK:
            hanging = _HANGING.get(fs["mount"])
            if hanging is not None and hanging.is_alive():
                results[i] = ("error", "still not answering")
                continue
            _HANGING.pop(fs["mount"], None)
            t = threading.Thread(target=probe, args=(i, fs["mount"]), daemon=True,
                                 name="axross-sysinfo-usage")
            t.start()
        threads.append((fs["mount"], t))
    deadline = time.monotonic() + timeout
    for _mount, t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    with _HANGING_LOCK:
        for mount, t in threads:
            if t.is_alive():
                _HANGING[mount] = t
    out = []
    for i, fs in enumerate(filesystems):
        fs = dict(fs)
        state, value = results.get(i, ("error", f"timed out after {timeout:g} s"))
        if state == "ok":
            try:
                total, used, free = (int(v) for v in value)
                fs.update(total=total, used=used, free=free,
                          percent=100.0 * used / (used + free) if used + free > 0 else None)
            except (TypeError, ValueError):
                fs["error"] = "unreadable size"
        else:
            fs["error"] = value
        out.append(fs)
    return out


def parse_edid(raw: bytes) -> dict:
    """Monitor name, maker, size and preferred mode from an EDID block."""
    if len(raw) < 128 or raw[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
        return {}
    out: dict[str, Any] = {}
    m = (raw[8] << 8) | raw[9]
    maker = "".join(chr(((m >> s) & 0x1F) + 64) for s in (10, 5, 0))
    if maker.isalpha():
        out["maker"] = maker
    w_cm, h_cm = raw[21], raw[22]
    if w_cm and h_cm:
        out["width_cm"], out["height_cm"] = w_cm, h_cm
        out["diagonal_in"] = round(math.hypot(w_cm, h_cm) / 2.54, 1)
    for off in (54, 72, 90, 108):
        block = raw[off:off + 18]
        if block[0] or block[1]:
            if "resolution" in out:
                continue
            clock = (block[0] | block[1] << 8) * 10_000
            h_active = block[2] | (block[4] & 0xF0) << 4
            h_blank = block[3] | (block[4] & 0x0F) << 8
            v_active = block[5] | (block[7] & 0xF0) << 4
            v_blank = block[6] | (block[7] & 0x0F) << 8
            if h_active and v_active:
                out["resolution"] = f"{h_active}x{v_active}"
                out["width_px"], out["height_px"] = h_active, v_active
                total = (h_active + h_blank) * (v_active + v_blank)
                if total:
                    out["refresh"] = round(clock / total, 2)
            continue
        tag = block[3]
        text = block[5:18].split(b"\n")[0].decode("cp437", errors="replace").strip()
        if tag == 0xFC and text:
            out["monitor"] = text
        elif tag == 0xFF and text:
            out["serial"] = text
    return out


def parse_asound_cards(text: str) -> list[dict]:
    cards = []
    head = re.compile(r"^\s*(\d+)\s+\[([^\]]*)\]:\s*(.*?)\s+-\s+(.*)$")
    for line in text.splitlines():
        m = head.match(line)
        if m:
            cards.append({"index": int(m.group(1)), "id": m.group(2).strip(),
                          "driver": m.group(3).strip(), "name": m.group(4).strip(),
                          "long_name": ""})
        elif cards and line.strip() and not cards[-1]["long_name"]:
            cards[-1]["long_name"] = re.sub(r"\s+at\s+0x[0-9a-f]+.*$", "", line.strip(),
                                            flags=re.I)
    return cards


def parse_input_devices(text: str) -> list[dict]:
    devices = []
    for block in re.split(r"\n\s*\n", text.strip()):
        info: dict[str, str] = {}
        for line in block.splitlines():
            tag, _sep, rest = line.partition(": ")
            if tag == "I":
                info.update(parse_key_values(rest.replace(" ", "\n"), "="))
            elif tag == "N":
                info["name"] = rest.partition("=")[2].strip().strip('"')
            elif tag == "P":
                info["phys"] = rest.partition("=")[2].strip()
            elif tag == "H":
                info["handlers"] = rest.partition("=")[2].strip()
            elif tag == "B" and rest.startswith("EV="):
                info["ev"] = rest[3:].strip()
        if not info.get("name"):
            continue
        handlers = info.get("handlers", "")
        devices.append({
            "name": info["name"], "kind": _input_kind(info["name"], handlers, info.get("ev", "")),
            "bus": INPUT_BUSES.get(info.get("Bus", "").lower(), info.get("Bus", "")),
            "id": f"{info.get('Vendor', '')}:{info.get('Product', '')}".strip(":"),
            "handlers": " ".join(h for h in handlers.split() if not h.startswith("event")),
        })
    return devices


def _input_kind(name: str, handlers: str, ev: str) -> str:
    low = name.lower()
    hs = handlers.split()
    if "touchpad" in low or "trackpad" in low:
        return "Touchpad"
    if "touchscreen" in low or "touch screen" in low:
        return "Touchscreen"
    if any(h.startswith("js") for h in hs):
        return "Game controller"
    if "mouse" in low or any(h.startswith("mouse") for h in hs):
        return "Mouse / pointer"
    if "button" in low or "switch" in low:
        return "Button / switch"
    if "video bus" in low or "camera" in low or "webcam" in low:
        return "Media keys"
    if any(w in low for w in ("headphone", "mic", "speaker", "line out", "hdmi/dp", "jack")):
        return "Audio jack"
    if "kbd" in hs and ("keyboard" in low or ev in ("120013", "12001f")):
        return "Keyboard"
    if "kbd" in hs:
        return "Keys"
    return "Other"


def _usb_speed(text: str | None) -> str:
    speeds = {"1.5": "Low (1.5 Mb/s)", "12": "Full (12 Mb/s)", "480": "High (480 Mb/s)",
              "5000": "SuperSpeed (5 Gb/s)", "10000": "SuperSpeed+ (10 Gb/s)",
              "20000": "SuperSpeed+ (20 Gb/s)", "40000": "USB4 (40 Gb/s)"}
    return speeds.get((text or "").strip(), f"{text} Mb/s" if text else "")


def _usb_parent(name: str) -> str | None:
    if name.startswith("usb"):
        return None
    if "." in name:
        return name.rsplit(".", 1)[0]
    bus = name.split("-", 1)[0]
    return f"usb{bus}"


def _tree_order(names: list[str], parents: list[str | None]) -> list[int]:
    """Indices in depth-first order: every child right below its parent."""
    index = {n: i for i, n in enumerate(names)}
    children: dict[int | None, list[int]] = {}
    for i, p in enumerate(parents):
        key = index.get(p) if p is not None else None
        if key == i:
            key = None
        children.setdefault(key, []).append(i)
    out: list[int] = []
    seen: set[int] = set()

    def walk(node: int | None) -> None:
        stack = list(reversed(children.get(node, [])))
        while stack:
            i = stack.pop()
            if i in seen:
                continue
            seen.add(i)
            out.append(i)
            stack.extend(reversed(children.get(i, [])))

    walk(None)
    for i in range(len(names)):  # cycles: whatever is left
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _net_kind(name: str, arptype: int | None, wireless: bool, virtual: bool, bridge: bool,
              tun: bool) -> str:
    if arptype == 772 or name == "lo":
        return "Loopback"
    if wireless:
        return "Wi-Fi"
    if bridge:
        return "Bridge"
    if tun or arptype in (65534, 768, 769, 776, 778):
        return "Tunnel / VPN"
    if name.startswith(("wwan", "wwp")):
        return "Mobile broadband"
    if virtual:
        return "Virtual"
    if arptype == 1:
        return "Ethernet"
    return "Other"


def _parse_proc_wireless(text: str) -> dict[str, dict]:
    out = {}
    for line in text.splitlines()[2:]:
        name, _sep, rest = line.partition(":")
        parts = rest.split()
        if len(parts) >= 3:
            try:
                out[name.strip()] = {"quality": float(parts[1].rstrip(".")),
                                     "level": int(float(parts[2].rstrip(".")))}
            except ValueError:
                continue
    return out


def _default_route(text: str) -> tuple[str, str]:
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "00000000":
            try:
                gw = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
            except (OSError, ValueError):
                gw = ""
            return gw, parts[0]
    return "", ""


def _ipv4_of(name: str) -> str:
    """The IPv4 address of interface *name* (Linux ioctl, no root)."""
    try:
        import fcntl
        import struct
    except ImportError:
        return ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            packed = struct.pack("256s", name[:15].encode())
            res = fcntl.ioctl(s.fileno(), 0x8915, packed)  # SIOCGIFADDR
            return socket.inet_ntoa(res[20:24])
    except (OSError, ValueError):
        return ""


def read_millis(path: str) -> float | None:
    """A sysfs milli-unit value (m°C) as units; ``None`` if unreadable."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(64)
        value = int(raw.strip() or b"x") / 1000
    except (OSError, ValueError):
        return None
    if not -100 < value < 250:
        return None
    return value


def _versions() -> dict[str, str]:
    out = {"python": f"{platform.python_implementation()} {platform.python_version()}"}
    try:
        from axross._version import __version__

        out["axross"] = __version__
    except Exception:  # noqa: BLE001 - a version is a nicety
        out["axross"] = "?"
    qt = sys.modules.get("PyQt6.QtCore")
    if qt is not None:
        out["qt"] = f"Qt {qt.QT_VERSION_STR}, PyQt {qt.PYQT_VERSION_STR}"
    return out


def _sysctl_string(name: str) -> str:
    """A sysctl string on macOS through libc (no program started)."""
    try:
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        size = ctypes.c_size_t(0)
        if libc.sysctlbyname(name.encode(), None, ctypes.byref(size), None, 0) != 0:
            return ""
        buf = ctypes.create_string_buffer(size.value)
        if libc.sysctlbyname(name.encode(), buf, ctypes.byref(size), None, 0) != 0:
            return ""
        return buf.value.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - optional source
        return ""


def _mac_model() -> str:
    return _sysctl_string("hw.model")


# --------------------------------------------------------------------------- live values


class LiveSampler:
    """The values the window shows live, from cheap reads: CPU use (total
    and per CPU, from /proc/stat deltas), memory and swap, temperatures and
    network throughput. Call :meth:`sample` every second or so from a
    worker thread; the first call has no CPU use yet (``None``)."""

    def __init__(self, root: str | os.PathLike = "/", *, system: str | None = None,
                 use_psutil: bool = True, clock: Callable[[], float] = time.monotonic,
                 max_temperatures: int = 64) -> None:
        self.info = SystemInfo(root, system=system, use_psutil=use_psutil)
        self._clock = clock
        self._prev_cpu: dict[str, tuple[int, int]] = {}
        self._prev_net: dict[str, tuple[int, int]] = {}
        self._prev_time: float | None = None
        self._temps: list[dict] | None = None
        self._max_temps = max_temperatures

    def _temperature_sources(self) -> list[dict]:
        if self._temps is None:
            # drivetemp wakes sleeping disks for every read: not live.
            self._temps = [t for t in self.info.temperature_sources()
                           if t["chip"] != "drivetemp"][: self._max_temps]
        return self._temps

    def sample(self) -> dict:
        now = self._clock()
        info = self.info
        out: dict[str, Any] = {"time": now, "cpu": None, "per_cpu": [], "cpu_ids": [],
                               "memory": None, "swap": None, "temperatures": [], "net": {}}
        if info.linux:
            stat = parse_proc_stat(info.read("proc/stat", 256 * 1024) or "")
            if stat:
                out["cpu"] = cpu_percent(self._prev_cpu.get("cpu"), stat.get("cpu"))
                cpus = sorted((k for k in stat if k != "cpu"), key=lambda k: int(k[3:] or 0))
                out["per_cpu"] = [cpu_percent(self._prev_cpu.get(k), stat[k]) for k in cpus]
                # Only the online CPUs are in /proc/stat: their numbers, so
                # a bar is named (and typed P/E) by its CPU, not its place.
                out["cpu_ids"] = [int(k[3:] or 0) for k in cpus]
                self._prev_cpu = stat
            mem = parse_meminfo(info.read("proc/meminfo") or "")
            if mem.get("MemTotal"):
                avail = mem.get("MemAvailable", mem.get("MemFree", 0))
                out["memory"] = {"total": mem["MemTotal"], "used": mem["MemTotal"] - avail,
                                 "available": avail, "free": mem.get("MemFree")}
                st = mem.get("SwapTotal", 0)
                out["swap"] = {"total": st, "used": st - mem.get("SwapFree", 0) if st else 0}
            for src in self._temperature_sources():
                value = read_millis(src["path"])
                if value is not None:
                    out["temperatures"].append({"chip": src["chip"], "label": src["label"],
                                                "celsius": value, "high": src["high"],
                                                "crit": src["crit"]})
            dt = now - self._prev_time if self._prev_time is not None else None
            net_now = {}
            for name in info.listdir("sys/class/net"):
                if name == "lo":
                    continue
                rx = info.read_int(f"sys/class/net/{name}/statistics/rx_bytes")
                tx = info.read_int(f"sys/class/net/{name}/statistics/tx_bytes")
                if rx is None or tx is None:
                    continue
                net_now[name] = (rx, tx)
                prev = self._prev_net.get(name)
                if prev and dt and dt > 0 and rx >= prev[0] and tx >= prev[1]:
                    out["net"][name] = {"rx": (rx - prev[0]) / dt, "tx": (tx - prev[1]) / dt}
            self._prev_net = net_now
        else:
            ps = info._psutil()
            if ps is not None:
                try:
                    out["per_cpu"] = list(ps.cpu_percent(percpu=True))
                    out["cpu_ids"] = list(range(len(out["per_cpu"])))
                    out["cpu"] = (sum(out["per_cpu"]) / len(out["per_cpu"])
                                  if out["per_cpu"] else None)
                    vm, sw = ps.virtual_memory(), ps.swap_memory()
                    out["memory"] = {"total": vm.total, "used": vm.total - vm.available,
                                     "available": vm.available}
                    out["swap"] = {"total": sw.total, "used": sw.used}
                except Exception:  # noqa: BLE001 - optional source
                    pass
        self._prev_time = now
        return out


def gather(root: str | os.PathLike = "/", **kwargs) -> Report:
    """The whole report for *root* (see :class:`SystemInfo`)."""
    return SystemInfo(root, **kwargs).gather()


__all__ = [
    "HIDDEN", "LiveSampler", "SystemInfo", "cpu_percent", "export_json", "export_text",
    "gather", "human_bytes", "human_duration", "human_mhz", "parse_cpuinfo", "parse_edid",
    "parse_meminfo", "parse_proc_stat", "redact", "section_text",
]
