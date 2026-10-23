"""The built binary against THIS host: host programs it starts and host
libraries loaded into it must work as they do without axross.

The build gates (scripts/bundle_smoke.py --system-libs) check the rules:
nothing bundled the host must own, no symbol version past the oldest
supported system, no child sees the unpacked folder. This test checks the
outcome on a real, current host - where the failures were found:

- ``bash -c true`` died with "symbol lookup error ... rl_trim_arg_from_keyseq"
  (the bundle's readline), ``ffprobe`` with "libstdc++.so.6: version
  GLIBCXX_3.4.32 not found" (the bundle's libstdc++);
- an OpenGL context aborted with "Could not initialize GLX": Mesa's
  libgallium needs GLIBCXX_3.4.30, the bundle carried 3.4.29.

Every check has a control: the same program, library or GL context
without axross (host Python). Only what works there must work in the binary.

Opt-in, it needs a built binary: ``AXROSS_FROZEN_BINARY=dist/axross-full``
(or -slim). Part of every release check.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import elf_needs as E  # noqa: E402

BINARY = os.environ.get("AXROSS_FROZEN_BINARY", "")
pytestmark = [
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux one-file bundle"),
    pytest.mark.skipif(not BINARY, reason="set AXROSS_FROZEN_BINARY to a built axross-full/slim"),
]

#: Host programs a user's axross starts (terminal, tools, viewers) or that
#: stand for a class of them: a shell, a C++ program, a Qt-free CLI.
PROGRAMS = (
    ["bash", "-c", "true"], ["sh", "-c", "true"], ["ffprobe", "-version"], ["gpg", "--version"],
    ["git", "--version"], ["ssh", "-V"], ["rsync", "--version"], ["python3", "-c", "pass"],
    ["xdg-mime", "--version"], ["qemu-img", "--version"], ["restic", "version"],
    ["file", "--version"], ["lsblk", "--version"],
)

#: Where host libraries come from that get loaded INTO a process: GL and
#: Vulkan drivers, audio plugins, JACK. (Host GIO modules are not loaded:
#: libgio is not in the bundle, bundle_options.DROPPED.)
PLUGIN_GLOBS = (
    "/usr/lib/libgallium*.so", "/usr/lib*/dri/*.so", "/usr/lib/x86_64-linux-gnu/dri/*.so",
    "/usr/lib*/libjack.so.*", "/usr/lib/x86_64-linux-gnu/libjack.so.*",
    "/usr/lib*/alsa-lib/*.so", "/usr/lib/x86_64-linux-gnu/alsa-lib/*.so",
    "/usr/lib*/libvulkan_*.so", "/usr/lib/x86_64-linux-gnu/libvulkan_*.so",
    "/usr/lib*/libGLX_mesa.so.*", "/usr/lib*/libEGL_mesa.so.*",
    "/usr/lib/x86_64-linux-gnu/libGLX_mesa.so.*", "/usr/lib/x86_64-linux-gnu/libEGL_mesa.so.*",
)

_PROBE = r'''
import ctypes, json, os, subprocess, sys
from pathlib import Path
cfg = json.loads(Path(os.environ["PROBE_CFG"]).read_text())
out = {"programs": {}, "libraries": {}, "gl": None}
for argv in cfg["programs"]:
    r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    out["programs"][" ".join(argv)] = [r.returncode, (r.stderr.strip().splitlines() or [""])[0][:200]]
for path in cfg["libraries"]:
    try:
        import _ctypes  # the raw dlopen: PyInstaller's CDLL wrapper hides dlerror()
        _ctypes.dlopen(path, os.RTLD_NOW | os.RTLD_LOCAL)  # every symbol, at once
        out["libraries"][path] = "ok"
    except OSError as exc:
        out["libraries"][path] = str(exc)[:200]
if cfg.get("gl"):
    from PyQt6.QtGui import QGuiApplication, QOpenGLContext, QOffscreenSurface
    app = QGuiApplication.instance() or QGuiApplication(["probe"])
    ctx = QOpenGLContext(); made = ctx.create()
    surf = QOffscreenSurface(); surf.create()
    out["gl"] = [bool(made), bool(made and ctx.makeCurrent(surf))]
Path(os.environ["PROBE_OUT"]).write_text(json.dumps(out))
'''


def _installed(argv) -> bool:
    return shutil.which(argv[0]) is not None


def _host_plugins() -> list[str]:
    found = []
    for pattern in PLUGIN_GLOBS:
        for path in sorted(glob.glob(pattern)):
            if os.path.isfile(path) and E.needed(os.path.realpath(path)) is not None:
                found.append(os.path.realpath(path))
    # One per distinct file is plenty; Mesa ships dozens of copies of one driver.
    seen, unique = set(), []
    for p in found:
        key = os.stat(p).st_ino
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique[:120]


def _run_probe(command: list[str], cfg: dict, tmp: Path, **env) -> dict:
    cfg_file, out_file = tmp / "cfg.json", tmp / "out.json"
    cfg_file.write_text(json.dumps(cfg))
    out_file.unlink(missing_ok=True)
    home = tmp / "home"
    home.mkdir(exist_ok=True)
    full_env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "QT_QPA_PLATFORM": "offscreen", "PROBE_CFG": str(cfg_file),
                "PROBE_OUT": str(out_file), "XDG_CONFIG_HOME": str(home / ".config"),
                "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring", **env}
    # The host control's Python finds PyQt6 where this test's Python does.
    for name in ("PYTHONUSERBASE", "PYTHONPATH", "VIRTUAL_ENV"):
        if name in os.environ:
            full_env[name] = os.environ[name]
    r = subprocess.run(command, capture_output=True, text=True, timeout=600, env=full_env)
    if not out_file.exists():
        return {"failed": f"{tmp.name} probe wrote nothing (rc {r.returncode}): {r.stderr[-1200:]}"}
    return json.loads(out_file.read_text())


@pytest.fixture(scope="module")
def probe_file():
    tmp = Path(tempfile.mkdtemp(prefix="axross-host-e2e-"))
    script = tmp / "probe.py"
    script.write_text(_PROBE)
    yield tmp, script
    shutil.rmtree(tmp, ignore_errors=True)


def _both(probe_file, cfg: dict, **env) -> tuple[dict, dict]:
    tmp, script = probe_file
    (tmp / "host").mkdir(exist_ok=True)
    (tmp / "frozen").mkdir(exist_ok=True)
    host = _run_probe([sys.executable, str(script)], cfg, tmp / "host", **env)
    if "failed" in host:
        pytest.skip(f"the control without axross failed: {host['failed']}")
    frozen = _run_probe([os.path.abspath(BINARY), "--script", str(script)], cfg, tmp / "frozen",
                        **env)
    assert "failed" not in frozen, frozen.get("failed")
    return host, frozen


def test_host_programs_started_from_the_binary_work(probe_file):
    programs = [a for a in PROGRAMS if _installed(a)]
    assert programs, "not even a shell found"
    host, frozen = _both(probe_file, {"programs": programs, "libraries": []})
    broken = {cmd: frozen["programs"][cmd] for cmd, (rc, _e) in host["programs"].items()
              if rc == 0 and frozen["programs"][cmd][0] != 0}
    assert not broken, f"work on the host, fail from {BINARY}: {broken}"


def test_host_plugin_libraries_load_into_the_binary(probe_file):
    libraries = _host_plugins()
    if not libraries:
        pytest.skip("no host plugin library found on this machine")
    host, frozen = _both(probe_file, {"programs": [], "libraries": libraries})
    broken = {p: frozen["libraries"][p] for p, res in host["libraries"].items()
              if res == "ok" and frozen["libraries"][p] != "ok"}
    assert not broken, f"load on the host, fail in {BINARY}: {broken}"


def test_an_opengl_context_works_in_the_binary(probe_file):
    xvfb = shutil.which("Xvfb")
    if not xvfb:
        pytest.skip("Xvfb not installed")
    display = ":%d" % (150 + os.getpid() % 50)
    server = subprocess.Popen([xvfb, display, "-noreset", "-screen", "0", "800x600x24"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        host, frozen = _both(probe_file, {"programs": [], "libraries": [], "gl": True},
                             QT_QPA_PLATFORM="xcb", DISPLAY=display)
    finally:
        server.terminate()
        server.wait(timeout=10)
    if host["gl"] != [True, True]:
        pytest.skip(f"no OpenGL on this host's Xvfb either: {host['gl']}")
    assert frozen["gl"] == [True, True], f"OpenGL in {BINARY}: {frozen['gl']}"
