"""Public package facade for axross scripting helpers."""

from __future__ import annotations

from axross._version import __version__ as _source_version
from core import scripting as _scripting

__version__ = _source_version

for _name in _scripting.__all__:
    globals()[_name] = getattr(_scripting, _name)

__all__ = [*_scripting.__all__, "__version__"]
