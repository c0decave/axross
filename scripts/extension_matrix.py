"""Start axross with each bundled extension on, alone and all together.

Usage: python scripts/extension_matrix.py [--hanging-gpu] (--source | DIST_DIR)

Reported: axross-full showed no window on a laptop with the NVIDIA driver.
The Media Player extension created its audio engine while the main window
was being built, and Qt Multimedia's FFmpeg backend hung in the NVIDIA
driver's cuInit. Every unit test of the extension injects a fake engine,
and no smoke run switched an extension on - so no test ever started the
real app with it.

Each start here runs in its own HOME with ``extensions.json`` switching the
extensions on and ``AXROSS_SMOKE_GUI_MS=0``, so axross quits once the main
window is up. A start passes when the window line comes, the process exits
0 within the timeout, the log says every switched-on extension loaded and
no extension failed.

``--source`` starts ``main.py`` of this tree with the running Python;
DIST_DIR starts ``axross-full`` (else ``axross-slim``) found there.
``--hanging-gpu`` makes every start see an NVIDIA driver whose cuInit never
returns (tests/hanging_gpu_driver.py; Linux with gcc and user namespaces)
and runs only the start with all extensions on - once as shipped and once
with axross's GPU-probe switch off (``AXROSS_MULTIMEDIA_GPU_PROBE=1``), where
only the multimedia probe in a child keeps the window coming.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "resources" / "extensions"
WINDOW_LINE = "gui smoke: window shown on "
#: A start that has not quit by then counts as hung. A healthy start takes
#: about 2 s on an idle machine; the margin is for loaded CI hosts.
TIMEOUT = 90
ALL = "all"
#: Seconds a hung start gets between SIGTERM and SIGKILL.
KILL_GRACE = 10


@dataclass
class StartResult:
    ids: list[str]
    returncode: int | None = None  # None: killed after the timeout
    window: bool = False
    loaded: set[str] = field(default_factory=set)
    failed: dict[str, str] = field(default_factory=dict)
    output: str = ""
    log: str = ""

    def problems(self) -> list[str]:
        label = ",".join(self.ids) or "no extension"
        tail = self.output[-1500:]
        if self.returncode is None:
            return [f"{label}: no exit within the timeout (hung); window shown: "
                    f"{self.window}; output: {tail}"]
        found = []
        if self.returncode != 0 or not self.window:
            found.append(f"{label}: exit {self.returncode}, window shown: {self.window}: {tail}")
        for ext_id, text in sorted(self.failed.items()):
            found.append(f"{label}: {ext_id} failed: {text}")
        for ext_id in self.ids:
            if ext_id not in self.loaded and ext_id not in self.failed:
                found.append(f"{label}: {ext_id} was switched on but did not load")
        return found


def bundled_ids(folder: Path = BUNDLED) -> list[str]:
    """The ids of the bundled extensions, from the files themselves."""
    ids = []
    for entry in sorted(folder.iterdir()):
        name = entry.name
        if name.startswith((".", "_")):
            continue
        if entry.is_file() and name.endswith(".py"):
            ids.append(f"bundled:{name[:-3]}")
        elif entry.is_dir() and (entry / "__init__.py").is_file():
            ids.append(f"bundled:{name}")
    return ids


def find_binary(dist: Path) -> Path:
    suffix = ".exe" if sys.platform == "win32" else ""
    for name in ("axross-full", "axross-slim"):
        exe = dist / f"{name}{suffix}"
        if exe.is_file():
            return exe
    raise FileNotFoundError(f"no axross-full or axross-slim in {dist}")


def _env(home: Path, extra: dict | None) -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("AXROSS_", "QT_FFMPEG_")) and k not in ("DISPLAY", "WAYLAND_DISPLAY")}
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        APPDATA=str(home / "AppData" / "Roaming"),
        LOCALAPPDATA=str(home / "AppData" / "Local"),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_DATA_HOME=str(home / ".local" / "share"),
        XDG_CACHE_HOME=str(home / ".cache"),
        XDG_STATE_HOME=str(home / ".local" / "state"),
        # A one-file binary unpacks itself here and removes that only on a
        # normal exit; inside the start's folder a killed start leaves nothing.
        TMPDIR=str(home.parent / "tmp"),
        QT_QPA_PLATFORM="offscreen",
        PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
        AXROSS_SMOKE_GUI_MS="0",
    )
    env.update(extra or {})
    return env


#: ui.extension_host's line for a loaded extension; the activation time
#: after the id is optional (older versions do not write it).
_LOADED = re.compile(r"ui\.extension_host: Extension loaded: .* \((\S+)\)(?: in [0-9.]+ s)?$")


def _parse_log(text: str, result: StartResult) -> None:
    for line in text.splitlines():
        loaded = _LOADED.search(line)
        if loaded:
            result.loaded.add(loaded.group(1))
        elif "ui.extension_host: Extension " in line and " failed: " in line:
            head, _, text_ = line.partition(" failed: ")
            result.failed[head.rsplit(" ", 1)[1]] = text_


def start(argv: list[str], ids: list[str], *, timeout: float = TIMEOUT,
          wrap=None, user_extensions: dict[str, str] | None = None,
          extra_env: dict | None = None) -> StartResult:
    """Start *argv* once with *ids* switched on; *wrap* turns the command
    into the one to run (the hanging driver), *user_extensions* maps a
    module name to the source of a user extension placed in the HOME."""
    result = StartResult(ids=list(ids))
    with tempfile.TemporaryDirectory(prefix="axross-matrix-") as tmp:
        home = Path(tmp) / "home"
        config = home / ".config" / "axross"
        config.mkdir(parents=True)
        (Path(tmp) / "tmp").mkdir()
        (config / "extensions.json").write_text(json.dumps({"enabled": list(ids)}),
                                                encoding="utf-8")
        for name, source in (user_extensions or {}).items():
            (config / "extensions").mkdir(exist_ok=True)
            (config / "extensions" / f"{name}.py").write_text(source, encoding="utf-8")
        command = wrap(argv) if wrap else argv
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors="replace", env=_env(home, extra_env),
                                cwd=tmp, start_new_session=True)
        try:
            result.output, _ = proc.communicate(timeout=timeout)
            result.returncode = proc.returncode
        except subprocess.TimeoutExpired:
            result.output = _stop(proc)
        result.window = WINDOW_LINE in result.output
        log = home / ".local" / "state" / "axross" / "logs" / "axross.log"
        try:
            result.log = log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result.log = ""
        _parse_log(result.log, result)
    return result


def _stop(proc: subprocess.Popen) -> str:
    """End a hung start: SIGTERM first (a one-file binary's parent then
    removes what it unpacked), SIGKILL after a grace period. The output."""
    for sig, grace in ((signal.SIGTERM, KILL_GRACE), (signal.SIGKILL, None)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        try:
            return proc.communicate(timeout=grace)[0]
        except subprocess.TimeoutExpired:
            continue
    return ""


def plan(ids: list[str], *, hanging_gpu: bool) -> list[list[str]]:
    """The starts to make: each extension alone, then all of them; under the
    hanging driver only all of them (a hang of any one shows there)."""
    if hanging_gpu:
        return [list(ids)]
    return [[i] for i in ids] + [list(ids)]


def hanging_gpu_wrap(workdir: Path):
    """The command wrapper of tests/hanging_gpu_driver.py, built in *workdir*."""
    sys.path.insert(0, str(ROOT))
    from tests import hanging_gpu_driver as HGD

    reason = HGD.available()
    if reason:
        raise RuntimeError(f"no hanging GPU driver here: {reason}")
    lib = HGD.build(workdir)
    return lambda argv: HGD.command(lib, argv)


def variants(*, hanging_gpu: bool) -> list[tuple[str, dict]]:
    """The environments each start runs in. Under the hanging driver also
    one with axross's own GPU-probe switch off (core.multimedia_env), so
    Qt really calls cuInit: then only the multimedia probe in a child
    (core.multimedia_probe) keeps the window coming."""
    if not hanging_gpu:
        return [("", {})]
    return [("", {}), (" (GPU probe on)", {"AXROSS_MULTIMEDIA_GPU_PROBE": "1"})]


def run(argv: list[str], ids: list[str], *, hanging_gpu: bool = False,
        timeout: float = TIMEOUT) -> list[str]:
    """Problems found over the whole matrix; empty when every start passed."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="axross-matrix-gpu-") as gpu:
        wrap = hanging_gpu_wrap(Path(gpu)) if hanging_gpu else None
        for suffix, extra in variants(hanging_gpu=hanging_gpu):
            for combo in plan(ids, hanging_gpu=hanging_gpu):
                result = start(argv, combo, timeout=timeout, wrap=wrap, extra_env=extra)
                found = [p + suffix for p in result.problems()]
                label = (ALL if len(combo) > 1 else combo[0]) + suffix
                print(f"{'FAIL' if found else 'ok  '} {label}", flush=True)
                problems += found
    return problems


def main(args: list[str]) -> int:
    hanging_gpu = "--hanging-gpu" in args
    rest = [a for a in args if a != "--hanging-gpu"]
    if len(rest) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    if rest[0] == "--source":
        argv = [sys.executable, str(ROOT / "main.py")]
    else:
        try:
            argv = [str(find_binary(Path(rest[0])))]
        except FileNotFoundError as exc:
            print(f"matrix failed: {exc}", file=sys.stderr)
            return 2
    try:
        problems = run(argv, bundled_ids(), hanging_gpu=hanging_gpu)
    except RuntimeError as exc:
        print(f"matrix failed: {exc}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"matrix failed: {p}")
    if problems:
        return 1
    print("matrix ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
