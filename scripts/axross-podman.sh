#!/usr/bin/env bash
# Run axross in podman: the GUI on the host's Wayland or X11 display, the
# MCP server, and optionally a local LLM (llama.cpp) beside it.
#
#   scripts/axross-podman.sh build                   build localhost/axross-gui (Dockerfile.gui)
#   scripts/axross-podman.sh agent-image             build localhost/axross-agent:<version>
#                                                    (Dockerfile.agent), the agent sandbox image
#   scripts/axross-podman.sh gui [options] [-- axross args]
#   scripts/axross-podman.sh mcp [options] [-- axross args]   stdio MCP server (axross --mcp-server)
#
# Options:
#   --display auto|wayland|x11  default auto: Wayland when its socket is there, else X11
#   --home DIR          the container's home, kept between runs
#                       (default ${XDG_DATA_HOME:-~/.local/share}/axross-podman/home)
#   --data DIR          mounted at /data
#   --llm-model FILE    run llama.cpp with this GGUF model beside axross (axross
#                       shares its network: http://127.0.0.1:8080/v1) and add
#                       the LLM profile "pod-llm"
#   --llm-image IMAGE   llama.cpp server image (default ghcr.io/ggml-org/llama.cpp:server)
#   --llm-url URL       add an LLM profile for a server that already runs, e.g.
#                       http://host.containers.internal:11434/v1 (Ollama on the host)
#   --llm-name NAME     the model name the profile asks for (default: the file name)
#   --gpu               pass /dev/dri for hardware OpenGL
#   --dbus              pass the host's session bus (the keyring: stored passwords)
#   --agent-sandbox     let the Agent dock's bubblewrap sandbox start in the container:
#                       unmasks /proc (--security-opt unmask=/proc/*), which bubblewrap
#                       needs to mount its own /proc; capabilities stay dropped
#   --env KEY=VALUE     an environment variable for axross (repeatable)
#   --image IMAGE       default localhost/axross-gui:latest
#
# The container runs as your own user (--userns=keep-id), drops every
# capability and sees only the display socket, the home directory and
# --data. An LLM profile is added only when the home has no llm.json yet.

set -euo pipefail

IMAGE=localhost/axross-gui:latest
LLM_IMAGE=ghcr.io/ggml-org/llama.cpp:server
LLM_CONTAINER=axross-gui-llm
X11_DIR=${AXROSS_X11_DIR:-/tmp/.X11-unix}

die() { echo "axross-podman: $*" >&2; exit 2; }

mode=${1:-}
[ -n "$mode" ] || die "usage: $0 build|agent-image|gui|mcp [options] [-- axross args]"
shift
case "$mode" in build|agent-image|gui|mcp) ;; *) die "unknown mode '$mode' (build, agent-image, gui or mcp)" ;; esac

if [ "$mode" = agent-image ]; then
  cd "$(dirname "$0")/.."
  version=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' axross/_version.py)
  [ -n "$version" ] || die "no version in axross/_version.py"
  exec podman build -f Dockerfile.agent -t "localhost/axross-agent:$version" .
fi

display=auto home="" data="" llm_model="" llm_url="" llm_name="" gpu=0 dbus=0 agent_sandbox=0
extra_env=()
while [ $# -gt 0 ]; do
  case "$1" in
    --display) display=${2:?}; shift 2 ;;
    --home) home=${2:?}; shift 2 ;;
    --data) data=${2:?}; shift 2 ;;
    --llm-model) llm_model=${2:?}; shift 2 ;;
    --llm-image) LLM_IMAGE=${2:?}; shift 2 ;;
    --llm-url) llm_url=${2:?}; shift 2 ;;
    --llm-name) llm_name=${2:?}; shift 2 ;;
    --gpu) gpu=1; shift ;;
    --dbus) dbus=1; shift ;;
    --agent-sandbox) agent_sandbox=1; shift ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --env) case "${2:-}" in [A-Za-z_]*=*) extra_env+=(-e "$2") ;; *) die "--env takes KEY=VALUE, not '${2:-}'" ;; esac; shift 2 ;;
    --) shift; break ;;
    *) die "unknown option '$1'" ;;
  esac
done

if [ "$mode" = build ]; then
  cd "$(dirname "$0")/.."
  exec podman build -f Dockerfile.gui -t "$IMAGE" .
fi

[ -z "$llm_model" ] || [ -f "$llm_model" ] || die "no model file '$llm_model'"
[ -z "$llm_model" ] || [ -z "$llm_url" ] || die "--llm-model and --llm-url exclude each other"
# These go into llm.json as JSON strings: no quote, backslash or control character.
for value in "$llm_url" "$llm_name" "$(basename "${llm_model:-x}")"; do
  case "$value" in *[\\\"]*|*[[:cntrl:]]*) die "--llm-url, --llm-name and the model file name may not contain quotes, backslashes or control characters" ;; esac
done

home=${home:-${XDG_DATA_HOME:-$HOME/.local/share}/axross-podman/home}
mkdir -p "$home"
chmod 700 "$home"

args=(--rm --cap-drop=ALL --security-opt=no-new-privileges --security-opt=label=disable
      -v "$home:~" -e HOME=~)
[ -z "$data" ] || args+=(-v "$(cd "$data" && pwd):/data")
# podman masks /proc paths and mounts /proc/sys read-only; bubblewrap's
# --proc /proc and --disable-userns fail on both (measured 2026-10-17).
[ "$agent_sandbox" = 0 ] || args+=("--security-opt=unmask=/proc/*")

if [ "$mode" = gui ]; then
  wl=""
  if [ -n "${WAYLAND_DISPLAY:-}" ]; then
    case "$WAYLAND_DISPLAY" in /*) wl=$WAYLAND_DISPLAY ;; *) wl=${XDG_RUNTIME_DIR:-/nonexistent}/$WAYLAND_DISPLAY ;; esac
    [ -S "$wl" ] || wl=""
  fi
  x11=""
  if [ -n "${DISPLAY:-}" ]; then
    num=${DISPLAY#*:}; num=${num%%.*}
    [ -S "$X11_DIR/X$num" ] && x11=$num
  fi
  case "$display" in
    auto) if [ -n "$wl" ]; then display=wayland; elif [ -n "$x11" ]; then display=x11
          else die "no Wayland or X11 display found (WAYLAND_DISPLAY / DISPLAY)"; fi ;;
    wayland) [ -n "$wl" ] || die "no Wayland socket (WAYLAND_DISPLAY='${WAYLAND_DISPLAY:-}')" ;;
    x11) [ -n "$x11" ] || die "no X11 socket for DISPLAY='${DISPLAY:-}' in $X11_DIR" ;;
    *) die "--display must be auto, wayland or x11" ;;
  esac
  if [ "$display" = wayland ]; then
    args+=(-v "$wl:/run/wayland/wayland-0" -e WAYLAND_DISPLAY=/run/wayland/wayland-0
           -e QT_QPA_PLATFORM=wayland)
  else
    args+=(-v "$X11_DIR/X$x11:/tmp/.X11-unix/X$x11" -e "DISPLAY=:$x11" -e QT_QPA_PLATFORM=xcb)
    if command -v xauth >/dev/null 2>&1; then
      # A cookie of its own, family "any host" (ffff): the container's
      # hostname differs from the host's.
      cookie_dir=${XDG_RUNTIME_DIR:-/tmp}/axross-podman
      mkdir -p "$cookie_dir"
      chmod 700 "$cookie_dir"
      cookie=$cookie_dir/Xauthority
      : > "$cookie"
      chmod 600 "$cookie"
      xauth nlist "$DISPLAY" 2>/dev/null | sed -e 's/^..../ffff/' | xauth -f "$cookie" nmerge - 2>/dev/null || true
      if [ -s "$cookie" ]; then
        args+=(-v "$cookie:/tmp/.Xauthority:ro" -e XAUTHORITY=/tmp/.Xauthority)
      fi
    fi
  fi
  [ "$gpu" = 0 ] || [ ! -e /dev/dri ] || args+=(--device /dev/dri)
else
  args+=(-i)
fi

if [ "$dbus" = 1 ]; then
  bus=${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR:-/nonexistent}/bus}
  bus=${bus#unix:path=}; bus=${bus%%,*}
  [ -S "$bus" ] || die "no session bus socket at '$bus'"
  args+=(-v "$bus:/run/dbus/session_bus" -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/dbus/session_bus)
fi

seed_profile() {  # name endpoint model
  local cfg=$home/.config/axross
  if [ -e "$cfg/llm.json" ]; then
    echo "axross-podman: $cfg/llm.json exists, no profile added (set one up with LLM… in the Agent dock)" >&2
    return
  fi
  mkdir -p "$cfg"
  umask 077
  printf '{"profiles": [{"name": "%s", "provider": "openai", "endpoint": "%s", "model": "%s", "timeout": 300}], "active": "%s"}\n' \
    "$1" "$2" "$3" "$1" > "$cfg/llm.json"
}

if [ -n "$llm_url" ]; then
  seed_profile local-llm "$llm_url" "${llm_name:-default}"
fi

args+=(${extra_env[@]+"${extra_env[@]}"})
app_args=()
[ "$mode" = mcp ] && app_args=(--mcp-server)
app_args+=("$@")

if [ -z "$llm_model" ]; then
  exec podman run --userns=keep-id "${args[@]}" "$IMAGE" "${app_args[@]}"
fi

# No pod: a pod's infra container did not start on podman 6.1 with runc 1.5.2
# ("invalid rootfs"). axross joins the model container's user and network
# namespaces instead - rootless podman refuses a network namespace of
# another user namespace - and runs as the caller's uid inside it.
model_name=$(basename "$llm_model")
seed_profile pod-llm http://127.0.0.1:8080/v1 "${llm_name:-${model_name%.gguf}}"
podman rm -f "$LLM_CONTAINER" >/dev/null 2>&1 || true
trap 'podman rm -f "$LLM_CONTAINER" >/dev/null 2>&1 || true' EXIT
podman run -d --name "$LLM_CONTAINER" --userns=keep-id --cap-drop=ALL --security-opt=no-new-privileges \
  --security-opt=label=disable --read-only --tmpfs /tmp \
  -v "$(cd "$(dirname "$llm_model")" && pwd)/$model_name:/models/$model_name:ro" \
  "$LLM_IMAGE" -m "/models/$model_name" --host 127.0.0.1 --port 8080 --jinja -c 8192 >/dev/null
# Start axross once the model is loaded and the server listens: a first
# request while it loads would get HTTP 503.
waited=0
until podman logs "$LLM_CONTAINER" 2>&1 | grep -q "model loaded" \
      && podman logs "$LLM_CONTAINER" 2>&1 | grep -q "listening on"; do
  if ! podman container exists "$LLM_CONTAINER"; then
    die "the model server exited: $(podman logs "$LLM_CONTAINER" 2>&1 | tail -5)"
  fi
  if [ "$waited" -ge "${AXROSS_LLM_WAIT:-300}" ]; then
    die "the model server did not come up in ${waited}s: $(podman logs "$LLM_CONTAINER" 2>&1 | tail -5)"
  fi
  sleep 1
  waited=$((waited + 1))
done
podman run --userns "container:$LLM_CONTAINER" --network "container:$LLM_CONTAINER" \
  --user "$(id -u):$(id -g)" "${args[@]}" "$IMAGE" "${app_args[@]}"
