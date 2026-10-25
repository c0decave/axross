"""Public package facade for axross scripting helpers.

The names of core.scripting are loaded on first use: ``import axross`` for
the version (main.py, the crash log) does not import the whole scripting
API, and ``import axross; axross.<name>`` or ``from axross import <name>``
gives the same objects as before.
"""

from __future__ import annotations

from axross._version import __version__ as _source_version

__version__ = _source_version


def _scripting():
    from core import scripting

    return scripting


def __getattr__(name: str):
    if name == "__all__":
        return [*_scripting().__all__, "__version__"]
    scripting = _scripting()
    if name in scripting.__all__:
        value = getattr(scripting, name)
        globals()[name] = value  # looked up once
        return value
    raise AttributeError(f"module 'axross' has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({*globals(), *_scripting().__all__})
