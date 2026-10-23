"""A hanging NVIDIA driver, for tests: a process started through
:func:`command` sees ``/proc/driver/nvidia/version`` and a ``libcuda.so.1``
whose ``cuInit`` never returns.

Reported: axross-full showed no window on a laptop with the NVIDIA driver.
The native stack (eu-stack) of the stuck process:

    QAudioDecoder::QAudioDecoder -> QPlatformMediaIntegration::instance()
    -> (Qt's FFmpeg plugin) -> av_hwdevice_ctx_create -> cuInit -> wait4

Qt's FFmpeg backend tries every hardware decoder when its integration is
created; it tries CUDA only where ``/proc/driver/nvidia/version`` exists and
``libnvcuvid.so`` loads. This module builds both stand-ins - a private mount
namespace (``unshare -rm``) puts a tmpfs over ``/proc/driver``, and two stub
libraries come first in ``LD_LIBRARY_PATH``. FFmpeg resolves every CUDA
entry point before it calls cuInit, so the stub exports all names the
bundled libavutil asks for (read from its strings).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_CU_NAME = re.compile(rb"\bcu[A-Z][A-Za-z0-9_]{2,60}\b")


def libavutil_paths() -> list[Path]:
    """The libavutil copies Qt Multimedia's FFmpeg plugin may load."""
    try:
        import PyQt6
    except ImportError:
        return []
    lib = Path(PyQt6.__file__).resolve().parent / "Qt6" / "lib"
    return sorted(lib.glob("libavutil.so*"))


def cuda_names(libavutil: Path) -> list[str]:
    """Every CUDA driver function name inside *libavutil*'s strings."""
    data = libavutil.read_bytes()
    return sorted({m.decode() for m in _CU_NAME.findall(data)} | {"cuInit"})


def available() -> str:
    """"" when a hanging driver can be built here, else why not."""
    if not shutil.which("gcc"):
        return "no gcc"
    if not shutil.which("unshare"):
        return "no unshare"
    if not libavutil_paths():
        return "no libavutil next to PyQt6's Qt"
    probe = subprocess.run(["unshare", "-rm", "true"], capture_output=True, timeout=30)
    if probe.returncode != 0:
        return "no user namespaces: " + probe.stderr.decode(errors="replace").strip()
    return ""


def build(directory: Path, libavutil: Path | None = None) -> Path:
    """Write and compile the stubs into *directory*/lib; return that lib dir."""
    libavutil = libavutil or libavutil_paths()[0]
    lib = directory / "lib"
    lib.mkdir(parents=True, exist_ok=True)
    lines = [
        "#include <unistd.h>",
        "int cuInit(unsigned int flags) { (void)flags; for (;;) pause(); return 0; }",
    ]
    lines += [f"int {name}(void) {{ return 999; }}" for name in cuda_names(libavutil)
              if name != "cuInit"]
    (directory / "cuda.c").write_text("\n".join(lines) + "\n")
    (directory / "nvcuvid.c").write_text("int nvcuvid_stub(void) { return 0; }\n")
    for source, name in (("cuda.c", "libcuda.so.1"), ("nvcuvid.c", "libnvcuvid.so.1")):
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(lib / name),
                        str(directory / source)], check=True, capture_output=True, timeout=120)
    (lib / "libcuda.so").symlink_to("libcuda.so.1")
    (lib / "libnvcuvid.so").symlink_to("libnvcuvid.so.1")
    return lib


def command(lib: Path, argv: list[str]) -> list[str]:
    """*argv* run where the hanging driver is installed (see the module)."""
    script = (
        "mount -t tmpfs tmpfs /proc/driver && mkdir -p /proc/driver/nvidia && "
        "echo 'NVRM version: NVIDIA UNIX x86_64 Kernel Module  580.00 (stub)' "
        "> /proc/driver/nvidia/version && "
        f"exec env LD_LIBRARY_PATH={lib} \"$@\""
    )
    return ["unshare", "-rm", "bash", "-c", script, "_", *argv]
