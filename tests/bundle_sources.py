"""The bundle-build sources under build/, which an sdist cannot carry.

setuptools prunes its build_base, ``build/``, from every sdist, so the
PyInstaller spec, the hashed bundle lock and the voice source offer exist in
a checkout only. A test of the bundle build reads them through here: from an
unpacked sdist it skips (module or test) instead of failing at collection.
"""
from __future__ import annotations

from pathlib import Path

import pytest

BUILD_DIR = Path(__file__).resolve().parent.parent / "build"
REASON = "build/ is not in an sdist (setuptools prunes its build_base); run from a checkout"


def have_bundle_sources() -> bool:
    return (BUILD_DIR / "axross.spec").is_file() and (BUILD_DIR / "requirements-bundle.txt").is_file()


def require_bundle_sources() -> None:
    """Skip the calling test module when build/ is not there."""
    if not have_bundle_sources():
        pytest.skip(REASON, allow_module_level=True)


def read(name: str) -> str:
    """build/<name> as text, or "" when build/ is not there (the tests that
    use it skip through :func:`require_bundle_sources` or ``skipif``)."""
    path = BUILD_DIR / name
    return path.read_text(encoding="utf-8") if path.is_file() else ""
