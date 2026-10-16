"""PyInstaller EXE options per operating system, for build/axross.spec.

Linux keeps what the spec always used. Windows has no strip tool and UPX
corrupts Qt DLLs; macOS code signatures break when a bundled library is
stripped, and a windowed one-file build is deprecated there, so the macOS
binary is a plain console executable.
"""

from __future__ import annotations


def exe_options(platform: str) -> dict:
    """``strip``, ``upx``, ``upx_exclude`` and ``console`` for ``EXE()``."""
    if platform.startswith("linux"):
        return {
            "strip": True,
            "upx": True,  # shrinks the binary ~30-40 %, harmless on ELF
            "upx_exclude": ["libQt6*.so*", "libicu*.so*"],  # Qt plugins break under UPX
            "console": False,
        }
    if platform == "win32":
        return {"strip": False, "upx": False, "upx_exclude": [], "console": False}
    if platform == "darwin":
        return {"strip": False, "upx": False, "upx_exclude": [], "console": True}
    raise ValueError(f"no bundle options for platform {platform!r}")
