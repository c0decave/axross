"""When were which Bluetooth devices in range - the presence log.

The request: a scanner with a presence log and data export - "when are my
devices reachable". This is the widget-free half (the dialog is
ui/bluetooth_presence.py):

* A **session** is one stretch of time a device was in range: from the
  first advertisement or signal reading (BluezClient.device_heard) to the
  last one. A device not heard for :data:`ABSENT_AFTER` seconds has left;
  its session ends at the time it was last heard, not when that was
  noticed. A connected device is in range while it stays connected (a
  connected Classic device does not advertise). Sessions are kept per
  address, so a device BlueZ forgets (an unpaired one ~30 s after it was
  last seen) and finds again continues the same session.
* **Listening** periods: when an adapter was discovering at all (our scan
  or another program's). Outside them nobody looked, so "not in range"
  means "not known" there - the export says which.
* :meth:`PresenceLog.set_monitoring` keeps a scan of ours running (again
  after the adapter was off, or after BlueZ ended it) for a log over hours.
* The log is a JSON-lines file (``$XDG_DATA_HOME/axross/bluetooth-presence.jsonl``,
  0600), one finished session or listening period per line, kept
  :data:`KEEP_DAYS` days and at most :data:`MAX_RECORDS` lines.
* :func:`summaries`, :func:`export_csv`, :func:`export_json` - per device:
  first and last seen, time in range, sessions; the sessions themselves.

Phones and many BLE devices change their random address every few
minutes (privacy): unpaired, each address is a device of its own here. A
bonded device is reported by BlueZ under its identity address and keeps it.
"""

from __future__ import annotations

import csv
import json
import logging
import math
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from core import bluetooth as BT
from core.i18n import tr

log = logging.getLogger(__name__)

#: Seconds without a sign of a device before it counts as gone.
ABSENT_AFTER = 120.0
#: How often open sessions are checked for devices that left (ms).
SWEEP_MS = 5_000
#: Days a finished session is kept.
KEEP_DAYS = 90
#: Lines the log file keeps at most (oldest go first).
MAX_RECORDS = 50_000
#: Seconds before monitoring tries to scan again after BlueZ refused.
MONITOR_RETRY_MS = 30_000
FILE_NAME = "bluetooth-presence.jsonl"
FILE_VARIABLE = "AXROSS_BT_PRESENCE"


def default_path() -> Path:
    from core.secure_storage import data_file_path

    return data_file_path(FILE_NAME, FILE_VARIABLE)


@dataclass
class Session:
    """One stretch of time a device was in range."""

    address: str
    start: float
    end: float
    name: str = ""
    vendor: str = ""
    kind: str = ""
    radio: str = ""
    paired: bool = False
    #: the device was connected during the session
    connected: bool = False
    rssi_min: int | None = None
    rssi_max: int | None = None
    rssi_sum: int = 0
    samples: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)

    @property
    def rssi_avg(self) -> float | None:
        return self.rssi_sum / self.samples if self.samples else None

    def note_rssi(self, rssi: int | None) -> None:
        if rssi is None:
            return
        self.rssi_min = rssi if self.rssi_min is None else min(self.rssi_min, rssi)
        self.rssi_max = rssi if self.rssi_max is None else max(self.rssi_max, rssi)
        self.rssi_sum += rssi
        self.samples += 1

    def record(self) -> dict:
        return {"t": "session", **asdict(self)}

    @classmethod
    def from_record(cls, raw: dict) -> Session | None:
        try:
            start, end = float(raw["start"]), float(raw["end"])
            address = str(raw["address"]).upper()
        except (KeyError, TypeError, ValueError):
            return None
        if not _is_address(address) or not (math.isfinite(start) and math.isfinite(end)) \
                or end < start or start < 0 or end > 32503680000:  # before year 3000
            return None

        def opt_int(key):
            value = raw.get(key)
            return value if isinstance(value, int) and not isinstance(value, bool) else None

        return cls(address=address, start=start, end=end,
                   name=BT.device_text(raw.get("name", "")),
                   vendor=str(raw.get("vendor", ""))[:200], kind=str(raw.get("kind", ""))[:60],
                   radio=str(raw.get("radio", ""))[:20], paired=bool(raw.get("paired")),
                   connected=bool(raw.get("connected")), rssi_min=opt_int("rssi_min"),
                   rssi_max=opt_int("rssi_max"), rssi_sum=opt_int("rssi_sum") or 0,
                   samples=max(0, opt_int("samples") or 0))


def _is_address(text: str) -> bool:
    parts = text.split(":")
    return len(parts) == 6 and all(len(p) == 2 and all(c in "0123456789ABCDEF" for c in p)
                                   for p in parts)


@dataclass
class Listening:
    """A stretch of time an adapter was discovering."""

    start: float
    end: float

    def record(self) -> dict:
        return {"t": "listen", "start": self.start, "end": self.end}


@dataclass
class Summary:
    """One device over a period."""

    address: str
    name: str
    vendor: str
    kind: str
    radio: str
    paired: bool
    first: float
    last: float
    #: seconds in range within the period
    present: float
    sessions: int
    present_now: bool
    rssi_avg: float | None = None
    #: (start, end) of each session within the period, oldest first
    spans: list = field(default_factory=list)


def _clip(start: float, end: float, since: float | None, until: float | None):
    lo = start if since is None else max(start, since)
    hi = end if until is None else min(end, until)
    return (lo, hi) if hi >= lo else None


def summaries(sessions: Iterable[Session], *, since: float | None = None,
              until: float | None = None, present: Iterable[str] = ()) -> list[Summary]:
    """Per device, the sessions overlapping [since, until], newest last
    seen first. *present*: the addresses in range now."""
    now_in = {a.upper() for a in present}
    out: dict[str, Summary] = {}
    weights: dict[str, int] = {}
    for s in sorted(sessions, key=lambda s: s.start):
        span = _clip(s.start, s.end, since, until)
        if span is None:
            continue
        sm = out.get(s.address)
        if sm is None:
            sm = out[s.address] = Summary(
                address=s.address, name=s.name, vendor=s.vendor, kind=s.kind, radio=s.radio,
                paired=s.paired, first=span[0], last=span[1], present=0.0, sessions=0,
                present_now=s.address in now_in)
            weights[s.address] = 0
        sm.present += span[1] - span[0]
        sm.sessions += 1
        sm.spans.append(span)
        sm.first, sm.last = min(sm.first, span[0]), max(sm.last, span[1])
        # the newest session names the device
        sm.name = s.name or sm.name
        sm.vendor = s.vendor or sm.vendor
        sm.kind = s.kind or sm.kind
        sm.radio = s.radio or sm.radio
        sm.paired = sm.paired or s.paired
        if s.samples:
            total = (sm.rssi_avg or 0.0) * weights[s.address] + s.rssi_sum
            weights[s.address] += s.samples
            sm.rssi_avg = total / weights[s.address]
    return sorted(out.values(), key=lambda sm: -sm.last)


def iso(t: float) -> str:
    """A time as local ISO 8601 with its offset (2026-11-04T10:15:00+01:00)."""
    return datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")


CSV_FIELDS = ("address", "name", "vendor", "kind", "radio", "paired", "connected", "start",
              "end", "duration_s", "rssi_min", "rssi_avg", "rssi_max")


def _session_row(s: Session) -> dict:
    return {"address": s.address, "name": s.name, "vendor": s.vendor, "kind": s.kind,
            "radio": s.radio, "paired": s.paired, "connected": s.connected,
            "start": iso(s.start), "end": iso(s.end), "duration_s": round(s.duration),
            "rssi_min": s.rssi_min, "rssi_avg": None if s.rssi_avg is None
            else round(s.rssi_avg, 1), "rssi_max": s.rssi_max}


def _safe_cell(value):
    """A cell a spreadsheet will not run: a device chose its name, and
    "=HYPERLINK(...)" in a CSV is a formula to Excel and LibreOffice."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _write_private(path: Path, write: Callable) -> None:
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            write(handle)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def export_csv(path, sessions: Iterable[Session]) -> int:
    """The sessions as CSV, oldest first; the number written."""
    rows = [_session_row(s) for s in sorted(sessions, key=lambda s: s.start)]

    def write(handle) -> None:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _safe_cell(v) for k, v in row.items()})

    _write_private(Path(path), write)
    return len(rows)


def export_json(path, sessions: Iterable[Session], *, listening: Iterable[Listening] = (),
                since: float | None = None, until: float | None = None,
                present: Iterable[str] = ()) -> int:
    """The devices (summaries), the sessions and the listening periods as
    one JSON document; the number of sessions written."""
    sessions = sorted(sessions, key=lambda s: s.start)
    doc = {
        "generated": iso(time.time()),
        "since": iso(since) if since is not None else None,
        "until": iso(until) if until is not None else None,
        "note": "Outside the listening periods nobody scanned: absent there means unknown.",
        "listening": [{"start": iso(p.start), "end": iso(p.end)} for p in listening],
        "devices": [{"address": sm.address, "name": sm.name, "vendor": sm.vendor,
                     "kind": sm.kind, "radio": sm.radio, "paired": sm.paired,
                     "first_seen": iso(sm.first), "last_seen": iso(sm.last),
                     "present_s": round(sm.present), "sessions": sm.sessions,
                     "present_now": sm.present_now,
                     "rssi_avg": None if sm.rssi_avg is None else round(sm.rssi_avg, 1)}
                    for sm in summaries(sessions, since=since, until=until, present=present)],
        "sessions": [_session_row(s) for s in sessions],
    }
    _write_private(Path(path), lambda handle: json.dump(doc, handle, indent=1,
                                                        ensure_ascii=False))
    return len(sessions)


def duration_text(seconds: float) -> str:
    """"45 s", "12 min", "3 h 05 min", "2 d 4 h"."""
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return tr("{n} s").format(n=seconds)
    minutes = seconds // 60
    if minutes < 60:
        return tr("{n} min").format(n=minutes)
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return tr("{h} h {m:02d} min").format(h=hours, m=minutes)
    days, hours = divmod(hours, 24)
    return tr("{d} d {h} h").format(d=days, h=hours)


class PresenceLog(QObject):
    """The sessions of every device the client hears, kept in a file."""

    #: sessions or listening changed (at most about once a second)
    changed = pyqtSignal()
    #: monitoring switched on or off
    monitoring_changed = pyqtSignal(bool)

    def __init__(self, client: BT.BluezClient, *, path: Path | None = None,
                 absent_after: float = ABSENT_AFTER, keep_days: float = KEEP_DAYS,
                 max_records: int = MAX_RECORDS, sweep_ms: int = SWEEP_MS,
                 retry_ms: int = MONITOR_RETRY_MS, clock: Callable[[], float] = time.time,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.client = client
        #: None: kept in memory only (tests, or no file wanted)
        self.path = Path(path) if path is not None else None
        self.absent_after = absent_after
        self.keep_days = keep_days
        self.max_records = max_records
        self._clock = clock
        #: address -> the session running now
        self._open: dict[str, Session] = {}
        #: address -> its device path (the last one BlueZ used)
        self._paths: dict[str, str] = {}
        self._closed: list[Session] = []
        self._listening: list[Listening] = []
        #: start of the listening period running now, or None
        self._listen_start: float | None = None
        self._monitor: str | None = None
        self._started = False
        self.write_error = ""
        self._sweep = QTimer(self)
        self._sweep.setInterval(sweep_ms)
        self._sweep.timeout.connect(self.sweep)
        self._emit_timer = QTimer(self)
        self._emit_timer.setSingleShot(True)
        self._emit_timer.setInterval(1000)
        self._emit_timer.timeout.connect(self.changed.emit)
        self._retry = QTimer(self)
        self._retry.setSingleShot(True)
        self._retry.setInterval(retry_ms)
        self._retry.timeout.connect(self._keep_scanning)

    # -- start and stop ----------------------------------------------------------------------

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._load()
        self.client.device_heard.connect(self._heard)
        self.client.device_updated.connect(self._updated)
        self.client.adapters_changed.connect(self._adapters_changed)
        self.client.operation_finished.connect(self._finished)
        self._adapters_changed()
        self._sweep.start()

    def stop(self) -> None:
        """Close what runs (a session ends when its device was last heard)."""
        if not self._started:
            return
        self._started = False
        self._sweep.stop()
        self._retry.stop()
        self._emit_timer.stop()
        for signal, slot in ((self.client.device_heard, self._heard),
                             (self.client.device_updated, self._updated),
                             (self.client.adapters_changed, self._adapters_changed),
                             (self.client.operation_finished, self._finished)):
            try:
                signal.disconnect(slot)
            except (TypeError, RuntimeError):
                pass
        self._monitor = None
        records = [s for s in self._open.values()]
        self._open.clear()
        self._closed.extend(records)
        out = [s.record() for s in records]
        if self._listen_start is not None:
            period = Listening(self._listen_start, self._clock())
            self._listen_start = None
            self._listening.append(period)
            out.append(period.record())
        self._append(out)

    # -- reading -----------------------------------------------------------------------------

    def sessions(self, since: float | None = None, until: float | None = None) -> list[Session]:
        """Finished and running sessions overlapping [since, until], oldest
        first (a running one ends at its device's last sign)."""
        out = [s for s in (*self._closed, *self._open.values())
               if _clip(s.start, s.end, since, until) is not None]
        return sorted(out, key=lambda s: s.start)

    def listening(self, since: float | None = None,
                  until: float | None = None) -> list[Listening]:
        periods = list(self._listening)
        if self._listen_start is not None:
            periods.append(Listening(self._listen_start, self._clock()))
        return [p for p in periods if _clip(p.start, p.end, since, until) is not None]

    def present(self) -> set[str]:
        """The addresses in range now."""
        return set(self._open)

    def summaries(self, since: float | None = None, until: float | None = None) -> list[Summary]:
        return summaries(self.sessions(since, until), since=since, until=until,
                         present=self._open)

    @property
    def monitoring(self) -> str | None:
        """The adapter monitoring keeps scanning on, or None."""
        return self._monitor

    # -- monitoring --------------------------------------------------------------------------

    def set_monitoring(self, adapter: str | None) -> None:
        """Keep our scan running on *adapter* (None: stop keeping it; a scan
        of ours that runs then is stopped too)."""
        old = self._monitor
        if adapter == old:
            return
        self._monitor = adapter
        self._retry.stop()
        if old is not None and adapter is None and self.client.scanning(old):
            self.client.stop_discovery(old)
        self.monitoring_changed.emit(adapter is not None)
        self._keep_scanning()

    def _keep_scanning(self) -> None:
        adapter = self._monitor
        if adapter is None or not self._started:
            return
        info = self.client.adapter(adapter)
        if info is None or not info.powered:
            return  # adapters_changed calls again when it is back
        if self.client.scanning(adapter) or self.client.busy(adapter) is not None:
            return
        self.client.start_discovery(adapter)

    def _finished(self, path: str, op: str, error: str) -> None:
        if path != self._monitor:
            return
        if op == "scan" and error:
            log.info("Bluetooth presence: scanning again in %d s (%s)",
                     self._retry.interval() // 1000, error)
            self._retry.start()
        elif op in ("power", "stop-scan") and not error:
            QTimer.singleShot(0, self._keep_scanning)

    # -- what the client says ----------------------------------------------------------------

    def _adapters_changed(self) -> None:
        listening = any(a.discovering for a in self.client.adapters())
        now = self._clock()
        if listening and self._listen_start is None:
            self._listen_start = now
            self._changed()
        elif not listening and self._listen_start is not None:
            period = Listening(self._listen_start, now)
            self._listen_start = None
            self._listening.append(period)
            self._append([period.record()])
            self._changed()
        if self._monitor is not None and not self._retry.isActive():
            self._keep_scanning()

    def _heard(self, path: str) -> None:
        device = self.client.device(path)
        if device is None or not device.address:
            return
        self._note(device, self._clock())

    def _updated(self, path: str) -> None:
        device = self.client.device(path)
        if device is not None and device.connected:
            self._note(device, self._clock())

    def _note(self, device: BT.Device, now: float) -> None:
        address = device.address.upper()
        self._paths[address] = device.path
        session = self._open.get(address)
        if session is None:
            session = self._open[address] = Session(address=address, start=now, end=now)
            self._changed()
        session.end = max(session.end, now)
        session.note_rssi(device.rssi)
        if device.named:
            session.name = device.display_name
        session.vendor = device.vendor or session.vendor
        session.kind = device.kind if device.kind != "Device" else (session.kind or "Device")
        session.radio = device.bearer or session.radio
        session.paired = session.paired or device.paired
        session.connected = session.connected or device.connected

    def sweep(self) -> None:
        """End the sessions of devices not heard for :attr:`absent_after`."""
        now = self._clock()
        done = []
        for address, session in list(self._open.items()):
            device = self.client.device(self._paths.get(address, ""))
            if device is not None and device.connected:
                session.end = now
                continue
            if now - session.end >= self.absent_after:
                done.append(self._open.pop(address))
        if done:
            self._closed.extend(done)
            self._append([s.record() for s in done])
            self._changed()

    def clear(self) -> None:
        """Forget every finished session and listening period (the file too);
        what runs now goes on."""
        self._closed.clear()
        self._listening.clear()
        if self.path is not None:
            try:
                self.path.unlink(missing_ok=True)
                self.write_error = ""
            except OSError as exc:
                self.write_error = str(exc)
        self._changed()

    def _changed(self) -> None:
        if not self._emit_timer.isActive():
            self._emit_timer.start()

    # -- the file ----------------------------------------------------------------------------

    def _load(self) -> None:
        if self.path is None:
            return
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            return
        except OSError as exc:
            log.warning("the Bluetooth presence log %s cannot be read: %s", self.path, exc)
            return
        oldest = self._clock() - self.keep_days * 86400
        kept = 0
        for line in lines[-self.max_records:]:
            try:
                raw = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if not isinstance(raw, dict):
                continue
            if raw.get("t") == "listen":
                try:
                    period = Listening(float(raw["start"]), float(raw["end"]))
                except (KeyError, TypeError, ValueError):
                    continue
                if period.end >= oldest and period.end >= period.start \
                        and math.isfinite(period.start) and math.isfinite(period.end):
                    self._listening.append(period)
                    kept += 1
            elif raw.get("t") == "session":
                session = Session.from_record(raw)
                if session is not None and session.end >= oldest:
                    self._closed.append(session)
                    kept += 1
        if kept < len(lines):
            self._rewrite()

    def _rewrite(self) -> None:
        records = [*(p.record() for p in self._listening), *(s.record() for s in self._closed)]
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            _write_private(self.path, lambda h: h.writelines(json.dumps(r) + "\n"
                                                             for r in records))
            self.write_error = ""
        except OSError as exc:
            self.write_error = str(exc)
            log.warning("the Bluetooth presence log %s cannot be written: %s", self.path, exc)

    def _append(self, records: list[dict]) -> None:
        if self.path is None or not records:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.writelines(json.dumps(r) + "\n" for r in records)
            self.write_error = ""
        except OSError as exc:
            self.write_error = str(exc)
            log.warning("the Bluetooth presence log %s cannot be written: %s", self.path, exc)
            return
        # over the limit by a tenth: cut back to nine tenths in one rewrite - not
        # a rewrite of the whole file at every new line once it is full
        total = len(self._closed) + len(self._listening)
        if total > self.max_records + max(1, self.max_records // 10):
            overflow = total - (self.max_records - self.max_records // 10)
            self._closed.sort(key=lambda s: s.end)
            del self._closed[:min(overflow, len(self._closed))]
            self._listening.sort(key=lambda p: p.end)
            excess = len(self._closed) + len(self._listening) - self.max_records
            if excess > 0:
                del self._listening[:excess]
            self._rewrite()


__all__ = ["ABSENT_AFTER", "CSV_FIELDS", "Listening", "PresenceLog", "Session", "Summary",
           "default_path", "duration_text", "export_csv", "export_json", "iso", "summaries"]
