"""The Analysis (sift) settings: how the Analysis dock runs sift, one JSON file.

``~/.config/axross/analysis.json`` (0600)::

    {
      "version": 1,
      "auto_analyse": true,       # explain every selected file without an LLM
      "llm_profile": "",          # the LLM profile of "Analyse with LLM";
                                  # "" = the active profile (LLM Profiles)
      "max_bytes": 25000000,      # sift reads at most this much of a file; a
                                  # remote file larger than this is not copied
      "time_budget": 60.0,        # seconds sift may spend on one file
      "vision": true,             # send images to a vision-capable model
      "context_tokens": 0,        # the model's context; 0 = what the server says
      "tags": 0,                  # tags asked for per file (LLM mode)
      "categories": [],           # the categories a file may be put in
      "cache": true               # keep sift's results in the cache folder
    }

The defaults are sift's own (``sift.config.Config``); tests/test_analysis_
settings.py holds them to it. Every value is checked by sift's own rules -
``sift.config.check_value``, ``sift.config.MAX_TAGS``,
``sift.categories.check_categories`` - so a value sift would refuse is
refused here with sift's words. Two bounds are axross's: the time budget may
not be 0 (sift's "no limit"), because the parent's wall-clock kill is derived
from it (core.analysis_worker), and max_bytes stays below half the worker's
address space.

sift's results are kept in :func:`cache_dir` (``$XDG_CACHE_HOME/axross/sift``,
0700); the worker child gets it as ``AXROSS_SIFT_CACHE``. :func:`clear_cache`
removes sift's entries there and nothing else (``sift.cache.SummaryCache.clear``).

A file that cannot be read completely (not JSON, not an object, an invalid
value) gives the defaults for what is missing; a later save first keeps the
file as ``analysis.json.unreadable-<time>-<hex>`` (core.secure_storage).
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from core.analysis_worker import ADDRESS_SPACE_LIMIT, DEFAULT_TIME_BUDGET
from core.file_analysis import MAX_REMOTE_BYTES
from core.secure_storage import keep_unreadable_copy, write_secret_file

log = logging.getLogger(__name__)

#: Seconds sift may spend on one file. Not 0 (sift's "no limit"): the
#: parent's wall-clock bound is time_budget + a margin.
TIME_BUDGET_RANGE = (1.0, 3600.0)
#: The most bytes sift may read of one file: half the worker child's
#: address space, so the read and what sift builds from it both fit.
MAX_BYTES_CEILING = ADDRESS_SPACE_LIMIT // 2
#: context_tokens' "ask the server" (sift.config._RANGES' unset value).
CONTEXT_FROM_SERVER = 0
#: The ranges when sift cannot be imported (axross-slim): the page is off
#: then, but a stored value is still checked. Held to sift's in the tests.
_FALLBACK_LIMITS = {"max_bytes": (1, MAX_BYTES_CEILING), "context_tokens": (256, None),
                    "tags": (0, 32)}


def _sift_config():
    try:
        from sift import config
    except ImportError:
        return None
    return config


def limits() -> dict[str, tuple]:
    """name -> (lowest, highest or None) of the numeric settings, from
    sift's own validation where sift is there."""
    config = _sift_config()
    out = dict(_FALLBACK_LIMITS)
    if config is not None:
        ranges = getattr(config, "_RANGES", {})
        if "max_bytes" in ranges:
            out["max_bytes"] = (ranges["max_bytes"][0], MAX_BYTES_CEILING)
        if "context_tokens" in ranges:
            out["context_tokens"] = (ranges["context_tokens"][0], ranges["context_tokens"][1])
        out["tags"] = (0, int(getattr(config, "MAX_TAGS", out["tags"][1])))
    out["time_budget"] = TIME_BUDGET_RANGE
    return out


def _whole(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _sift_says(key: str, value) -> str:
    """sift's refusal of *value* for *key*, or ""."""
    config = _sift_config()
    if config is None:
        return ""
    try:
        config.check_value(key, value)
    except config.ConfigError as exc:
        # Without " (set with --flag)": the command line's way to set it.
        return re.sub(r" \(set with [^)]*\)$", "", str(exc))
    return ""


def _check_max_bytes(value) -> str:
    if not _whole(value):
        return f"max_bytes must be a whole number, got {value!r}"
    low, high = limits()["max_bytes"]
    if value < low or value > high:
        return _sift_says("max_bytes", value) or f"max_bytes must be {low}–{high}, got {value}"
    return _sift_says("max_bytes", value)


def _check_time_budget(value) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return f"time_budget must be a number, got {value!r}"
    low, high = TIME_BUDGET_RANGE
    if not low <= value <= high:
        return f"time_budget must be {low:g}–{high:g} seconds, got {value:g}"
    return ""


def _check_context(value) -> str:
    if not _whole(value):
        return f"context_tokens must be a whole number, got {value!r}"
    if value == CONTEXT_FROM_SERVER:
        return ""
    low, _high = limits()["context_tokens"]
    if value < low:
        return (_sift_says("context_tokens", value)
                or f"context_tokens must be at least {low}, got {value}")
    return _sift_says("context_tokens", value)


def _check_tags(value) -> str:
    low, high = limits()["tags"]
    if not _whole(value) or not low <= value <= high:
        return f"tags must be a whole number from {low} to {high}, got {value!r}"
    return ""


def _check_categories(value) -> str:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        return f"categories must be a list of names, got {value!r}"
    try:
        from sift.categories import check_categories
    except ImportError:
        return ""
    try:
        check_categories(value)
    except ValueError as exc:
        return str(exc)
    return ""


def _bool(name: str):
    return lambda v: "" if isinstance(v, bool) else f"{name} must be true or false, got {v!r}"


#: name -> checker (returns why a value is refused, "" when it is fine). The
#: order is the settings page's.
FIELDS = {
    "auto_analyse": _bool("auto_analyse"),
    "llm_profile": lambda v: "" if isinstance(v, str) else f"llm_profile must be a name, got {v!r}",
    "max_bytes": _check_max_bytes,
    "time_budget": _check_time_budget,
    "vision": _bool("vision"),
    "context_tokens": _check_context,
    "tags": _check_tags,
    "categories": _check_categories,
    "cache": _bool("cache"),
}


def problem(name: str, value) -> str:
    """Why *value* cannot be the setting *name* ("" when it can)."""
    if name not in FIELDS:
        raise KeyError(name)
    return FIELDS[name](value)


def settings_file() -> Path:
    return Path.home() / ".config" / "axross" / "analysis.json"


def cache_dir() -> Path:
    """Where sift's results are kept: ``$XDG_CACHE_HOME/axross/sift`` (an
    absolute XDG_CACHE_HOME only, as the spec says), else ``~/.cache``."""
    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(base) if base and os.path.isabs(base) else Path.home() / ".cache"
    return root / "axross" / "sift"


def clear_cache(directory: str | os.PathLike | None = None) -> int:
    """Remove sift's entries from the cache folder; the number removed (0
    without sift). Files that are not sift's stay (SummaryCache.clear)."""
    try:
        from sift.cache import SummaryCache
    except ImportError:
        return 0
    return SummaryCache(directory=Path(directory) if directory else cache_dir()).clear()


def sift_status() -> tuple[bool, str]:
    """(sift can be imported, its version)."""
    try:
        import sift
    except ImportError:
        return False, ""
    return True, str(getattr(sift, "__version__", ""))


@dataclass
class AnalysisSettings:
    auto_analyse: bool = True
    llm_profile: str = ""
    max_bytes: int = MAX_REMOTE_BYTES
    time_budget: float = DEFAULT_TIME_BUDGET
    vision: bool = True
    context_tokens: int = CONTEXT_FROM_SERVER
    tags: int = 0
    categories: list = field(default_factory=list)
    cache: bool = True
    #: True when load() could not take in the whole file; save() keeps a
    #: copy of that file first.
    file_not_fully_loaded: bool = field(default=False, repr=False, compare=False)

    def get(self, name: str):
        if name not in FIELDS:
            raise KeyError(name)
        value = getattr(self, name)
        return list(value) if isinstance(value, list) else value

    def set(self, name: str, value) -> None:
        why = problem(name, value)
        if why:
            raise ValueError(f"invalid value for the analysis setting {name}: {why}")
        if name == "time_budget":
            value = float(value)
        elif name == "categories":
            value = list(value)
        setattr(self, name, value)

    def run_options(self) -> dict:
        """What core.file_analysis hands to the worker for one file."""
        return {
            "time_budget": float(self.time_budget),
            "max_bytes": self.max_bytes,
            "vision": self.vision,
            "context_tokens": self.context_tokens,
            "tags": self.tags,
            "categories": list(self.categories),
            "cache": self.cache,
        }

    @classmethod
    def from_dict(cls, data) -> AnalysisSettings:
        out = cls()
        if not isinstance(data, dict):
            out.file_not_fully_loaded = True
            return out
        for f in fields(cls):
            if f.name in FIELDS and f.name in data:
                try:
                    out.set(f.name, data[f.name])
                except ValueError as exc:
                    log.warning("Analysis settings: %s", exc)
                    out.file_not_fully_loaded = True  # the default stands in
        return out

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("file_not_fully_loaded", None)
        return {"version": 1, **data}

    @classmethod
    def load(cls, path: Path | None = None) -> AnalysisSettings:
        path = Path(path or settings_file())
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.warning("Analysis settings: cannot read %s (%s), using the defaults", path, exc)
            out = cls()
            out.file_not_fully_loaded = True
            return out
        return cls.from_dict(raw)

    def save(self, path: Path | None = None) -> None:
        path = Path(path or settings_file())
        if self.file_not_fully_loaded and path.exists() and not keep_unreadable_copy(path):
            raise OSError(f"Not saving: the unreadable {path} could not be kept as a copy")
        write_secret_file(str(path), json.dumps(self.to_dict(), indent=2) + "\n")
        self.file_not_fully_loaded = False


__all__ = ["CONTEXT_FROM_SERVER", "FIELDS", "MAX_BYTES_CEILING", "TIME_BUDGET_RANGE",
           "AnalysisSettings", "cache_dir", "clear_cache", "limits", "problem",
           "settings_file", "sift_status"]
