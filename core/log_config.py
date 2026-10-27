"""Logging for axross: what is logged, where it goes, and no flooding.

``~/.config/axross/logging.json`` (0600, Edit > Settings… > Logging)::

    {
      "version": 1,
      "level": "INFO",                 # the overall level: DEBUG, INFO, WARNING, ERROR
      "areas": {"protocols.smb": "DEBUG", "third_party": "WARNING"},
      "file_max_mib": 5,               # the log file rolls over at this size, 1-100
      "file_backups": 3,               # rotated files kept, 1-20
      "terminal": false,               # also write to stderr
      "collapse_repeats": true,        # identical records within the window: one line
      "repeat_window": 10              # seconds, 1-300
    }

**Levels.** An area (core.log_areas) takes "inherit", a level, or "off". An
area left at "inherit" has its parent area's level, a top-level area the
overall level; third-party libraries default to WARNING. :func:`apply` sets
the level on every logger name an area lists - explicitly, so a package
logger's level (``core``) never leaks into a module of another area - and the
root logger to the overall level. A record goes from its logger to the root
handlers whatever the root's level, so a DEBUG area is logged while the rest
stays at INFO, and a quiet area's records are not even created (the logger's
``isEnabledFor`` is false). The handlers have no level of their own.

**--debug / --verbose** set a floor for the run (:func:`configure`): every
axross area is at least DEBUG (INFO), the terminal is on. Third-party
libraries keep their saved level - ``--debug`` would otherwise write every
SSH packet paramiko sees. A Settings save during the run keeps the floor.

**Repeated records.** :class:`RepeatCollapseFilter` sits on each handler: a
record identical to one written less than *repeat_window* seconds ago (same
logger, level, message and exception) is counted, not written.
The count comes out as one line, "Last message repeated K more times in T s:
<message>", before the next record of that kind after the window, when any
record arrives after the window, at a Settings change and at exit. A burst
of a timer firing every 10 ms is two lines per window, not a hundred per
second.
"""

from __future__ import annotations

import atexit
import json
import logging
import logging.handlers
import os
import sys
import threading
import time
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from core import log_areas as LA

log = logging.getLogger(__name__)

MIB = 1024 * 1024
LEVELS: tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR")
AREA_CHOICES: tuple[str, ...] = ("inherit", *LEVELS, "off")
#: Above CRITICAL: a logger at this level writes nothing.
OFF = logging.CRITICAL + 50
FILE_MIB_RANGE = (1, 100)
#: At least one: RotatingFileHandler with backupCount 0 never rolls over and
#: the file would grow without end.
BACKUPS_RANGE = (1, 20)
WINDOW_RANGE = (1, 300)
#: Distinct records the collapse filter remembers per handler.
MAX_REPEAT_KEYS = 512

FILE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
TERMINAL_FORMAT = "[%(levelname)s] %(name)s: %(message)s"


def settings_file() -> Path:
    return Path.home() / ".config" / "axross" / "logging.json"


def level_number(name: str) -> int:
    return OFF if name == "off" else logging.getLevelName(name)


def _int_in(value, bounds: tuple[int, int]) -> bool:
    return type(value) is int and bounds[0] <= value <= bounds[1]


_VALIDATORS: dict[str, Callable[[object], bool]] = {
    "level": lambda v: v in LEVELS,
    "file_max_mib": lambda v: _int_in(v, FILE_MIB_RANGE),
    "file_backups": lambda v: _int_in(v, BACKUPS_RANGE),
    "terminal": lambda v: type(v) is bool,
    "collapse_repeats": lambda v: type(v) is bool,
    "repeat_window": lambda v: _int_in(v, WINDOW_RANGE),
}


@dataclass
class LogSettings:
    level: str = "INFO"
    #: area id -> choice, only where it differs from the area's default.
    areas: dict[str, str] = field(default_factory=dict)
    file_max_mib: int = 5
    file_backups: int = 3
    terminal: bool = False
    collapse_repeats: bool = True
    repeat_window: int = 10

    def set(self, name: str, value) -> None:
        if name not in _VALIDATORS:
            raise KeyError(name)
        if not _VALIDATORS[name](value):
            raise ValueError(f"invalid value for the logging setting {name}: {value!r}")
        setattr(self, name, value)

    def area_choice(self, area_id: str) -> str:
        return self.areas.get(area_id, LA.AREAS_BY_ID[area_id].default)

    def set_area(self, area_id: str, choice: str) -> None:
        area = LA.AREAS_BY_ID[area_id]  # KeyError for an unknown area
        if choice not in AREA_CHOICES:
            raise ValueError(f"invalid level for the logging area {area_id}: {choice!r}")
        if choice == area.default:
            self.areas.pop(area_id, None)
        else:
            self.areas[area_id] = choice

    @classmethod
    def from_dict(cls, data) -> LogSettings:
        out = cls()
        if not isinstance(data, dict):
            return out
        for name in _VALIDATORS:
            if name in data:
                try:
                    out.set(name, data[name])
                except ValueError:
                    log.warning("Logging settings: ignored the invalid %s %r", name, data[name])
        areas = data.get("areas")
        if isinstance(areas, dict):
            for area_id, choice in areas.items():
                try:
                    out.set_area(area_id, choice)
                except (KeyError, ValueError, TypeError):
                    log.warning("Logging settings: ignored the area %r = %r", area_id, choice)
        return out

    def to_dict(self) -> dict:
        return {"version": 1, "level": self.level, "areas": dict(sorted(self.areas.items())),
                "file_max_mib": self.file_max_mib, "file_backups": self.file_backups,
                "terminal": self.terminal, "collapse_repeats": self.collapse_repeats,
                "repeat_window": self.repeat_window}

    def copy(self) -> LogSettings:
        return LogSettings.from_dict(self.to_dict())

    @classmethod
    def load(cls, path: Path | None = None) -> LogSettings:
        target = Path(path or settings_file())
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.warning("Logging settings %s unreadable, using the defaults: %s", target, exc)
            return cls()
        return cls.from_dict(raw)

    def save(self, path: Path | None = None) -> None:
        target = Path(path or settings_file())
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)


# ---------------------------------------------------------------------------
# Levels
# ---------------------------------------------------------------------------


def effective_levels(settings: LogSettings, floor: int | None = None) -> dict[str, int]:
    """area id -> the level its loggers get. *floor* (--debug / --verbose)
    lowers every axross area to at most that level; third-party areas keep
    theirs."""
    overall = level_number(settings.level)
    if floor is not None:
        overall = min(overall, floor)
    out: dict[str, int] = {}
    for area in LA.AREAS:  # parents first: a child reads its parent's result
        choice = settings.area_choice(area.id)
        if choice == "inherit":
            level = out[area.parent] if area.parent else overall
        else:
            level = level_number(choice)
        if floor is not None and not LA.is_third_party(area.id):
            level = min(level, floor)
        out[area.id] = level
    return out


# ---------------------------------------------------------------------------
# Repeated records
# ---------------------------------------------------------------------------


@dataclass
class _Seen:
    first: float
    last: float
    count: int
    name: str
    levelno: int
    pathname: str
    lineno: int
    message: str


class RepeatCollapseFilter(logging.Filter):
    """Write a record once per *window* seconds; count the identical ones in
    between and report the count as one line (see the module docstring).

    The summary goes straight to *handler* - only the handler this filter
    sits on writes it."""

    def __init__(self, handler: logging.Handler, *, window: float = 10, enabled: bool = True,
                 clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__()
        self._handler_ref = weakref.ref(handler)
        self.window = float(window)
        self.enabled = enabled
        self._clock = clock
        self._lock = threading.Lock()
        self._seen: dict[tuple, _Seen] = {}
        self._next_sweep = 0.0

    @staticmethod
    def _key(record: logging.LogRecord) -> tuple:
        """Never raises: an exception here would reach the caller's log call,
        past the handler's handleError - a record whose arguments do not fit
        its message is keyed by its raw parts and left to the handler."""
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - the handler reports it as usual
            message = f"{record.msg!r} % {record.args!r}"
        exc = record.exc_info
        exc_key = None
        if exc and exc[0] is not None:
            try:
                exc_key = (exc[0].__name__, str(exc[1]))
            except Exception:  # noqa: BLE001 - an exception whose str() fails
                exc_key = (exc[0].__name__, None)
        return (record.name, record.levelno, message, exc_key)

    def _summary(self, seen: _Seen) -> logging.LogRecord:
        record = logging.LogRecord(
            seen.name, seen.levelno, seen.pathname, seen.lineno,
            "Last message repeated %d more times in %.1f s: %s",
            (seen.count, seen.last - seen.first, seen.message[:300]), None)
        record._axross_repeat_summary = True  # type: ignore[attr-defined]
        return record

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "_axross_repeat_summary", False) or not self.enabled:
            return True
        key = self._key(record)
        now = self._clock()
        due: list[logging.LogRecord] = []
        with self._lock:
            seen = self._seen.get(key)
            if seen is not None and now - seen.first < self.window:
                seen.count += 1
                seen.last = now
                return False
            if seen is not None:
                del self._seen[key]  # re-inserted at the end: the newest
                if seen.count:
                    due.append(self._summary(seen))
            if now >= self._next_sweep:
                self._next_sweep = now + self.window
                for old_key, old in list(self._seen.items()):
                    if now - old.first >= self.window:
                        del self._seen[old_key]
                        if old.count:
                            due.append(self._summary(old))
            while len(self._seen) >= MAX_REPEAT_KEYS:
                oldest = next(iter(self._seen))
                old = self._seen.pop(oldest)
                if old.count:
                    due.append(self._summary(old))
            self._seen[key] = _Seen(now, now, 0, record.name, record.levelno, record.pathname,
                                    record.lineno, key[2])
        self._emit(due)
        return True

    def _emit(self, records: list[logging.LogRecord]) -> None:
        handler = self._handler_ref()
        if handler is None:
            return
        for summary in records:
            handler.handle(summary)

    def flush(self) -> None:
        """Write the counts not written yet and forget every record."""
        with self._lock:
            due = [self._summary(s) for s in self._seen.values() if s.count]
            self._seen.clear()
        self._emit(due)


# ---------------------------------------------------------------------------
# Handlers and applying
# ---------------------------------------------------------------------------

_state_lock = threading.RLock()
_current: LogSettings | None = None
_floor: int | None = None
_terminal_forced = False
_log_file: Path | None = None
#: Logger names whose level apply() set - teardown() gives them NOTSET back.
_touched: set[str] = set()
_filters: weakref.WeakSet[RepeatCollapseFilter] = weakref.WeakSet()
_atexit_registered = False


def _ours(role: str) -> logging.Handler | None:
    for handler in logging.getLogger().handlers:
        if getattr(handler, "_axross_role", None) == role:
            return handler
    return None


def file_handler() -> logging.handlers.RotatingFileHandler | None:
    return _ours("file")  # type: ignore[return-value]


def terminal_handler() -> logging.Handler | None:
    return _ours("terminal")


def run_floor() -> int | None:
    """The level --debug (DEBUG) or --verbose (INFO) set for this run, or None."""
    return _floor


def current() -> LogSettings | None:
    """The settings applied last, or None before the first apply."""
    return _current.copy() if _current is not None else None


def attach_filters(handler: logging.Handler) -> RepeatCollapseFilter:
    """Give *handler* (the Log dock's, say) the collapse of repeated records,
    following the settings applied now and later."""
    for existing in handler.filters:
        if isinstance(existing, RepeatCollapseFilter):
            return existing
    settings = _current or LogSettings()
    filt = RepeatCollapseFilter(handler, window=settings.repeat_window,
                                enabled=settings.collapse_repeats)
    handler.addFilter(filt)
    _filters.add(filt)
    return filt


def flush_repeats() -> None:
    for filt in list(_filters):
        filt.flush()


def _make_file_handler(path: Path, settings: LogSettings) -> logging.Handler:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    # Created private before the handler opens it: a umask of 0 never
    # leaves the log readable by others, not even for a moment.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=settings.file_max_mib * MIB, backupCount=settings.file_backups,
        encoding="utf-8")
    handler.setFormatter(logging.Formatter(FILE_FORMAT))
    handler._axross_handler = True  # type: ignore[attr-defined]
    handler._axross_role = "file"  # type: ignore[attr-defined]
    return handler


def _make_terminal_handler() -> logging.Handler:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(TERMINAL_FORMAT))
    handler._axross_handler = True  # type: ignore[attr-defined]
    handler._axross_role = "terminal"  # type: ignore[attr-defined]
    return handler


def _remove_handler(handler: logging.Handler) -> None:
    for filt in handler.filters:
        if isinstance(filt, RepeatCollapseFilter):
            filt.flush()
    logging.getLogger().removeHandler(handler)
    handler.close()


def configure(log_file: Path, *, debug: bool = False, verbose: bool = False,
              settings: LogSettings | None = None) -> LogSettings:
    """At the start: the log file, the terminal with --debug / --verbose or
    when the settings ask for it, the levels. *settings* None reads the saved
    ones. Calling it again replaces the handlers it made before."""
    global _floor, _terminal_forced, _log_file, _atexit_registered
    root = logging.getLogger()
    with _state_lock:
        for handler in list(root.handlers):
            if getattr(handler, "_axross_handler", False):
                _remove_handler(handler)
        _floor = logging.DEBUG if debug else (logging.INFO if verbose else None)
        _terminal_forced = debug or verbose
        _log_file = Path(log_file)
        # The file first, with the defaults: a warning about an unreadable
        # store then lands in it rather than on stderr.
        file_h = _make_file_handler(_log_file, settings or LogSettings())
        attach_filters(file_h)
        root.addHandler(file_h)
        if settings is None:
            settings = LogSettings.load()
        apply(settings)
        if not _atexit_registered:
            # Registered after logging's own shutdown hook: atexit runs it first.
            atexit.register(flush_repeats)
            _atexit_registered = True
    return settings


def _known_names() -> set[str]:
    """Logger names of the patterns' families that exist now: the loggers
    made so far plus the modules of the packages (made before their import,
    so a module imported later finds its level waiting)."""
    names = {n for n in logging.Logger.manager.loggerDict if isinstance(n, str)}
    try:
        import pkgutil

        import core

        names.update(f"core.{m.name}" for m in pkgutil.iter_modules(core.__path__))
    except Exception as exc:  # noqa: BLE001 - a frozen build may not list modules
        log.debug("Listing the core modules for logging failed: %s", exc)
    return names


def _set_levels(levels: dict[str, int]) -> None:
    for area in LA.AREAS:
        for name in area.loggers:
            logging.getLogger(name).setLevel(levels[area.id])
            _touched.add(name)
    if any(area.patterns for area in LA.AREAS):
        for name in _known_names():
            hits = LA.explicit_areas(name)
            if hits and name not in LA._EXACT and LA.AREAS_BY_ID[hits[0]].patterns:
                logging.getLogger(name).setLevel(levels[hits[0]])
                _touched.add(name)


def apply(settings: LogSettings) -> None:
    """Make *settings* the running configuration - levels, handlers, the
    collapse - without a restart. The --debug / --verbose floor of the run
    stays."""
    global _current
    with _state_lock:
        _current = settings.copy()
        levels = effective_levels(settings, _floor)
        overall = level_number(settings.level)
        if _floor is not None:
            overall = min(overall, _floor)
        root = logging.getLogger()
        root.setLevel(overall)
        _set_levels(levels)

        file_h = file_handler()
        if isinstance(file_h, logging.handlers.RotatingFileHandler):
            file_h.maxBytes = settings.file_max_mib * MIB
            file_h.backupCount = settings.file_backups
        want_terminal = settings.terminal or _terminal_forced
        term = terminal_handler()
        if want_terminal and term is None and _log_file is not None:
            term = _make_terminal_handler()
            attach_filters(term)
            root.addHandler(term)
        elif not want_terminal and term is not None:
            _remove_handler(term)

        for filt in list(_filters):
            if filt.enabled and not settings.collapse_repeats:
                filt.flush()
            filt.enabled = settings.collapse_repeats
            filt.window = float(settings.repeat_window)
    if log.isEnabledFor(logging.INFO):
        changed = {a: c for a, c in sorted(settings.areas.items())}
        log.info("Logging: overall %s%s, areas %s, file %d MiB x %d, terminal %s, "
                 "repeats %s", settings.level,
                 f" (run floor {logging.getLevelName(_floor)})" if _floor is not None else "",
                 changed or "at their defaults", settings.file_max_mib, settings.file_backups,
                 "on" if want_terminal else "off",
                 f"collapsed within {settings.repeat_window} s"
                 if settings.collapse_repeats else "not collapsed")


def refresh() -> None:
    """Give loggers made since the last apply (an extension just loaded) the
    level of their area."""
    with _state_lock:
        if _current is not None:
            _set_levels(effective_levels(_current, _floor))


def prepare_logger(name: str) -> None:
    """Set the level of the logger *name* from its area before the code that
    uses it runs (ui.extension_host, before an extension's module). Nothing
    before the first apply, nothing for a name outside every area."""
    with _state_lock:
        if _current is None:
            return
        area_id = LA.area_of(name)
        if area_id is None:
            return
        logging.getLogger(name).setLevel(effective_levels(_current, _floor)[area_id])
        _touched.add(name)


def teardown() -> None:
    """Undo configure() and apply(): our handlers removed, every logger level
    we set back to NOTSET. For tests and a clean exit."""
    global _current, _floor, _terminal_forced, _log_file
    with _state_lock:
        root = logging.getLogger()
        for handler in list(root.handlers):
            if getattr(handler, "_axross_handler", False):
                _remove_handler(handler)
        for name in _touched:
            logging.getLogger(name).setLevel(logging.NOTSET)
        _touched.clear()
        _current = None
        _floor = None
        _terminal_forced = False
        _log_file = None


__all__ = ["AREA_CHOICES", "BACKUPS_RANGE", "FILE_MIB_RANGE", "LEVELS", "MAX_REPEAT_KEYS", "MIB",
           "OFF", "WINDOW_RANGE", "LogSettings", "RepeatCollapseFilter", "apply",
           "attach_filters", "configure", "current", "effective_levels", "file_handler",
           "flush_repeats", "level_number", "prepare_logger", "refresh", "run_floor",
           "settings_file", "teardown", "terminal_handler"]
