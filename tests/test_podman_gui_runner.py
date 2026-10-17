"""scripts/axross-podman.sh runs axross (GUI, MCP, a local LLM) in podman.

The script picks the display the host offers (a Wayland socket, else an
X11 socket with a cookie of its own), keeps the container's home on the
host, and can start a llama.cpp server beside axross in one pod with an
LLM profile pointing at it. A fake ``podman`` on PATH records every call,
so the decisions are checked without a container engine.
"""

from __future__ import annotations

import json
import os
import shlex
import socket
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "axross-podman.sh"

FAKE_PODMAN = """#!/bin/sh
printf '%s\\n' "$*" >> "$PODMAN_LOG"
case "$1" in
  logs) printf '%b' "${FAKE_LLM_LOG-load_model: loading\\nllama_server: model loaded\\nllama_server: listening on http://127.0.0.1:8080\\n}" ;;
  container) [ "${FAKE_LLM_DEAD:-0}" = 1 ] && exit 1 ;;
esac
exit 0
"""
FAKE_XAUTH = """#!/bin/sh
# xauth nlist :N  -> one cookie line;  xauth -f FILE nmerge -  -> write FILE
case "$1" in
  nlist) echo "0100 0004 74657374 0001 37 0012 4d49542d4d414749432d434f4f4b49452d31 0010 00112233445566778899aabbccddeeff" ;;
  -f) cat > "$2" ;;
esac
"""


def _socket(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(path))
    s.close()


@pytest.fixture
def env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("podman", FAKE_PODMAN), ("xauth", FAKE_XAUTH)):
        f = bin_dir / name
        f.write_text(body)
        f.chmod(0o755)
    runtime = tmp_path / "run"
    runtime.mkdir(mode=0o700)
    return {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(tmp_path / "home"),
        "XDG_RUNTIME_DIR": str(runtime),
        "XDG_DATA_HOME": str(tmp_path / "data-home"),
        "PODMAN_LOG": str(tmp_path / "podman.log"),
        "AXROSS_X11_DIR": str(tmp_path / "x11"),
    }


def _run(env, *args, expect=0):
    proc = subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True,
                          timeout=30, cwd=ROOT)
    assert proc.returncode == expect, proc.stderr + proc.stdout
    log = Path(env["PODMAN_LOG"])
    calls = [shlex.split(line) for line in log.read_text().splitlines()] if log.exists() else []
    return proc, calls


def _run_call(calls):
    return next(c for c in calls if c[0] == "run" and "axross-gui-llm" not in c)


def _pairs(call, flag):
    return [call[i + 1] for i, a in enumerate(call) if a == flag]


def _home(env) -> Path:
    return Path(env["XDG_DATA_HOME"]) / "axross-podman" / "home"


# --- happy ------------------------------------------------------------------


def test_happy_wayland_is_used_when_its_socket_is_there(env):
    _socket(Path(env["XDG_RUNTIME_DIR"]) / "wayland-1")
    env["WAYLAND_DISPLAY"] = "wayland-1"
    env["DISPLAY"] = ":7"
    _, calls = _run(env, "gui")
    call = _run_call(calls)
    assert f"{env['XDG_RUNTIME_DIR']}/wayland-1:/run/wayland/wayland-0" in _pairs(call, "-v")
    envs = _pairs(call, "-e")
    assert "WAYLAND_DISPLAY=/run/wayland/wayland-0" in envs and "QT_QPA_PLATFORM=wayland" in envs
    assert not any(e.startswith("DISPLAY=") for e in envs)
    assert "--userns=keep-id" in call and "--cap-drop=ALL" in call
    assert call[-1] == "localhost/axross-gui:latest"


def test_happy_x11_gets_its_socket_and_a_cookie_of_its_own(env):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env["DISPLAY"] = ":7"
    _, calls = _run(env, "gui")
    call = _run_call(calls)
    mounts = _pairs(call, "-v")
    assert f"{env['AXROSS_X11_DIR']}/X7:/tmp/.X11-unix/X7" in mounts
    cookie = next(m.split(":")[0] for m in mounts if m.endswith(":/tmp/.Xauthority:ro"))
    assert Path(cookie).read_text().startswith("ffff")  # any-host family, so the container's hostname matches
    assert stat.S_IMODE(Path(cookie).stat().st_mode) == 0o600
    envs = _pairs(call, "-e")
    assert {"DISPLAY=:7", "QT_QPA_PLATFORM=xcb", "XAUTHORITY=/tmp/.Xauthority"} <= set(envs)


def test_happy_a_local_model_runs_beside_axross_sharing_its_network(env, tmp_path):
    # No pod: a pod's infra container did not start on podman 6.1 / runc 1.5.2
    # ("invalid rootfs"); axross joins the model container's user and network
    # namespaces instead, so 127.0.0.1:8080 is the model's server.
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env["DISPLAY"] = ":7"
    model = tmp_path / "qwen2.5-7b-instruct-q4_k_m.gguf"
    model.write_bytes(b"GGUF")
    _, calls = _run(env, "gui", "--llm-model", str(model))
    assert not any(c[:1] == ["pod"] for c in calls)
    llm = next(c for c in calls if c[0] == "run" and "axross-gui-llm" in c)
    assert "--userns=keep-id" in llm and f"{model}:/models/{model.name}:ro" in _pairs(llm, "-v")
    assert ["-m", f"/models/{model.name}"] == llm[llm.index("-m"):llm.index("-m") + 2] and "--jinja" in llm
    app = _run_call(calls)
    assert _pairs(app, "--network") == ["container:axross-gui-llm"]
    assert _pairs(app, "--userns") == ["container:axross-gui-llm"] and "--userns=keep-id" not in app
    assert _pairs(app, "--user") == [f"{os.getuid()}:{os.getgid()}"]
    assert ["rm", "-f", "axross-gui-llm"] in [c[:3] for c in calls]  # cleaned up afterwards
    profiles = json.loads((_home(env) / ".config" / "axross" / "llm.json").read_text())
    (profile,) = profiles["profiles"]
    assert profile["endpoint"] == "http://127.0.0.1:8080/v1" and profiles["active"] == profile["name"]


def test_happy_mcp_mode_is_a_stdio_server_without_a_display(env):
    _, calls = _run(env, "mcp", "--", "--mcp-tools", "remote,agent")
    call = _run_call(calls)
    assert "-i" in call and not any("X11" in m or "wayland" in m for m in _pairs(call, "-v"))
    assert call[-4:] == ["localhost/axross-gui:latest", "--mcp-server", "--mcp-tools", "remote,agent"]


def test_happy_build_uses_the_gui_dockerfile(env):
    _, calls = _run(env, "build")
    (call,) = calls
    assert call[:1] == ["build"] and _pairs(call, "-f") == ["Dockerfile.gui"]
    assert "localhost/axross-gui:latest" in _pairs(call, "-t")


# --- sad --------------------------------------------------------------------


def test_sad_no_display_at_all(env):
    proc, calls = _run(env, "gui", expect=2)
    assert "no Wayland or X11 display" in proc.stderr and calls == []


def test_sad_a_missing_model_file(env):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env["DISPLAY"] = ":7"
    proc, calls = _run(env, "gui", "--llm-model", "/nonexistent.gguf", expect=2)
    assert "nonexistent.gguf" in proc.stderr and calls == []


def test_sad_wayland_asked_for_but_not_there(env):
    proc, calls = _run(env, "gui", "--display", "wayland", expect=2)
    assert "Wayland" in proc.stderr and calls == []


def test_sad_an_unknown_option(env):
    proc, _ = _run(env, "gui", "--frobnicate", expect=2)
    assert "--frobnicate" in proc.stderr


# --- edge -------------------------------------------------------------------


def test_edge_an_existing_llm_profile_file_is_left_alone(env, tmp_path):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env["DISPLAY"] = ":7"
    cfg = _home(env) / ".config" / "axross"
    cfg.mkdir(parents=True)
    (cfg / "llm.json").write_text('{"profiles": [], "active": ""}')
    proc, _ = _run(env, "gui", "--llm-url", "http://host.containers.internal:11434/v1")
    assert (cfg / "llm.json").read_text() == '{"profiles": [], "active": ""}'
    assert "llm.json exists" in proc.stderr


def test_edge_llm_url_seeds_a_profile_without_a_pod(env):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env["DISPLAY"] = ":7"
    _, calls = _run(env, "gui", "--llm-url", "http://host.containers.internal:11434/v1", "--llm-name", "qwen2.5:7b")
    assert not any(c[:1] == ["pod"] for c in calls)
    profile = json.loads((_home(env) / ".config" / "axross" / "llm.json").read_text())["profiles"][0]
    assert profile["endpoint"] == "http://host.containers.internal:11434/v1" and profile["model"] == "qwen2.5:7b"


def test_edge_home_is_private_and_data_is_mounted(env, tmp_path):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env["DISPLAY"] = ":7"
    data = tmp_path / "work"
    data.mkdir()
    _, calls = _run(env, "gui", "--data", str(data), "--", "--debug")
    call = _run_call(calls)
    assert stat.S_IMODE(_home(env).stat().st_mode) == 0o700
    assert f"{_home(env)}:~" in _pairs(call, "-v") and f"{data}:/data" in _pairs(call, "-v")
    assert call[-1] == "--debug"
    assert os.environ.get("PODMAN_LOG") is None  # the fake never leaks into the real environment


def test_sad_a_name_that_would_break_the_json_is_refused(env):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env["DISPLAY"] = ":7"
    proc, calls = _run(env, "gui", "--llm-url", "http://h:1/v1", "--llm-name", 'x", "evil": "1', expect=2)
    assert "llm-name" in proc.stderr and calls == []
    assert not (_home(env) / ".config" / "axross" / "llm.json").exists()


# --- the image -------------------------------------------------------------

DOCKERFILE = (ROOT / "Dockerfile.gui").read_text(encoding="utf-8")


def _final_stage() -> str:
    return DOCKERFILE.split("\nFROM ")[-1]


def test_happy_only_the_wheel_enters_the_final_image():
    final = _final_stage()
    copies = [line for line in final.splitlines() if line.startswith("COPY")]
    assert copies == ["COPY --from=wheel /wheels /wheels"]


def test_happy_both_desktop_platforms_are_checked_at_build_time():
    final = _final_stage()
    assert "libqxcb.so" in final and "libqwayland" in final and 'grep "not found"' in final


def test_edge_the_container_runs_as_an_ordinary_user():
    final = _final_stage()
    assert "\nUSER axross" in final and "ENTRYPOINT" in final.split("USER axross")[1]


def test_edge_env_reaches_the_container_and_a_bad_one_is_refused(env):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env["DISPLAY"] = ":7"
    _, calls = _run(env, "gui", "--env", "AXROSS_SMOKE_GUI_MS=3000")
    assert "AXROSS_SMOKE_GUI_MS=3000" in _pairs(_run_call(calls), "-e")
    proc, _ = _run(env, "gui", "--env", "NOEQUALS", expect=2)
    assert "KEY=VALUE" in proc.stderr


def test_sad_a_model_that_never_comes_up_stops_before_axross(env, tmp_path):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env.update(DISPLAY=":7", FAKE_LLM_LOG="load_model: loading\\n", AXROSS_LLM_WAIT="1")
    model = tmp_path / "m.gguf"
    model.write_bytes(b"GGUF")
    proc, calls = _run(env, "gui", "--llm-model", str(model), expect=2)
    assert "did not come up" in proc.stderr and "load_model: loading" in proc.stderr
    assert not any(c[0] == "run" and "axross-gui-llm" not in c for c in calls)  # axross never started
    assert ["rm", "-f", "axross-gui-llm"] in [c[:3] for c in calls]


def test_sad_a_model_container_that_dies_is_reported(env, tmp_path):
    _socket(Path(env["AXROSS_X11_DIR"]) / "X7")
    env.update(DISPLAY=":7", FAKE_LLM_LOG="error: failed to load model\\n", FAKE_LLM_DEAD="1")
    model = tmp_path / "m.gguf"
    model.write_bytes(b"GGUF")
    proc, _ = _run(env, "gui", "--llm-model", str(model), expect=2)
    assert "exited" in proc.stderr and "failed to load model" in proc.stderr
