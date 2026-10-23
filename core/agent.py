"""A local LLM drives axross through the MCP tools, in process.

The agent sends a task to an OpenAI-compatible ``/chat/completions``
endpoint (LM Studio, Ollama, vLLM, llama.cpp - the profiles of
:mod:`core.llm_profiles`) with the MCP tools offered as functions. Every
tool call the model asks for runs through the MCP dispatcher
(``core.mcp_server._handle_request``) on tools built exactly like the
server builds them, so the same schemas, root confinement, production
guards, timeouts and audit apply. The result goes back to the model
until it answers.

Guards on top of the MCP ones:

* Only what the config allows is offered: the core file tools, the
  chosen groups, write tools only with ``allow_write`` (which needs a
  root), the exec group only with ``allow_exec``. The script tools are
  never offered.
* A mutating call and every remote command run only after ``confirm``
  said yes; without a confirm callback they never run.
* ``files_read_only`` (the tab's switch or Agent Settings > Access) wins
  over all of that: no write tool, no remote command (a command can change
  files), no writable extra folder, no write tool of another MCP server or
  an extension - neither offered nor run, whatever else the config says.
* A remote endpoint (or one reached through a proxy) needs the
  profile's consent first: tool results carry file content to it.
* Bounded: ``max_steps`` model requests per task, tool results cut to
  ``max_tool_chars`` for the model, the profile's request timeout.
* ``core.agent.audit`` logs every tool call with its outcome and the
  length and a hash of its arguments - never the arguments, which carry
  file content and commands.

Further MCP servers (core.mcp_client): ``external_tools`` yields their
tools, named ``<server>__<tool>``; they are called directly, never through
the dispatcher, and one that may change something asks first.

Remote files: ``remote_backends`` lends connections the GUI holds (the
panes') as backends ``pane:<name>``. In a sandbox they stay with axross:
the worker's agent gets *host tools* - names and schemas of tools axross
runs - and sends every call that names a remote backend, or a tool only
axross has, to ``host_call``; axross checks and confirms it there.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from core.llm_profiles import LLMProfile

log = logging.getLogger(__name__)
audit = logging.getLogger("core.agent.audit")

DEFAULT_MAX_STEPS = 20
#: The arguments that pick a backend ("local" or none: the local files).
BACKEND_ARGS = ("backend", "src_backend", "dst_backend")
DEFAULT_MAX_TOOL_CHARS = 16_000
#: Longest string argument shown in an event (the GUI transcript).
_EVENT_ARG_CHARS = 200

SYSTEM_PROMPT = """You operate axross, a file manager, through the tools you are given.
Rules:
- Paths are absolute on the backend they belong to. Call list_backends to see the
  backends; omit "backend" for the local file system, which is confined to a root
  directory.
- Explore before you act: list_dir and stat first, keep reads small.
- For text files use read_file with encoding "text" and write_file with "content";
  base64 (content_b64) is for binary data.
- A call that changes something (writing, removing, renaming, running a remote
  command) needs the user's approval and may be declined. If it is declined or
  refused, do not retry it in another way; say what you wanted to do.
- Never ask for passwords or keys. Report what you changed.
Answer in the user's language."""


class AgentError(RuntimeError):
    """The agent could not talk to the model (consent, network, protocol)."""


class AgentCancelled(AgentError):
    """The task was stopped while the model was answering."""


#: Said when the model's last message holds no answer at all.
NO_ANSWER_NOTICE = "The model ended without an answer."
#: Said before an answer the model wrote only into its reasoning.
REASONING_NOTICE = "The model gave its answer only as reasoning:"

_THINK_OPEN, _THINK_CLOSE = "<think>", "</think>"


def _think_tags(content: str) -> tuple[str, str]:
    """(thinking, answer) of a content that carries its thinking inline:
    ``<think>...</think>`` at its start, or - Qwen3 thinking models, whose
    template opens the tag in the prompt - text up to a lone ``</think>``.
    An unclosed ``<think>`` (cut at the output limit) is all thinking. Tags
    later in an answer are its text."""
    head = content.lstrip()
    if head.startswith(_THINK_OPEN):
        rest = head[len(_THINK_OPEN):]
        end = rest.find(_THINK_CLOSE)
        if end < 0:
            return rest.strip(), ""
        return rest[:end].strip(), rest[end + len(_THINK_CLOSE):].lstrip()
    end = content.find(_THINK_CLOSE)
    if end >= 0 and _THINK_OPEN not in content:
        return content[:end].strip(), content[end + len(_THINK_CLOSE):].lstrip()
    return "", content


def split_reasoning(message: dict) -> tuple[str, str]:
    """(reasoning, answer) of a model message. The reasoning comes in a
    field of its own - ``reasoning_content`` (LM Studio, measured with Qwen
    on MLX: beside every answer and tool call), ``reasoning`` (Ollama,
    vLLM) - or inline in ``content`` as ``<think>...</think>`` (llama.cpp
    without a reasoning parser, LM Studio without "separate
    reasoning_content"). The answer is ``content`` without that block,
    otherwise unchanged; values that are no text count as none."""
    content = message.get("content")
    content = content if isinstance(content, str) else ""
    field_text = message.get("reasoning_content") or message.get("reasoning")
    field_text = field_text.strip() if isinstance(field_text, str) else ""
    inline, answer = _think_tags(content)
    return "\n\n".join(part for part in (field_text, inline) if part), answer


@dataclass
class AgentConfig:
    profile: LLMProfile
    root: str
    api_key: str = ""
    #: Capability groups of core.mcp_groups offered besides the core file tools.
    groups: frozenset = field(default_factory=frozenset)
    allow_write: bool = False
    allow_exec: bool = False
    #: Files read-only: the agent reads but changes nothing (see restrict()).
    files_read_only: bool = False
    max_steps: int = DEFAULT_MAX_STEPS
    max_tool_chars: int = DEFAULT_MAX_TOOL_CHARS
    system_prompt: str = SYSTEM_PROMPT
    #: Further folders beside *root*: ``(path, writable)`` pairs.
    extra_roots: tuple = ()
    #: Connections the GUI lends: ``(backend id, backend, ConnectionProfile
    #: or None)``. Never sent into a sandbox.
    remote_backends: tuple = ()
    #: The tools of further MCP servers: called once, at the first task, as
    #: ``() -> (tools, errors)`` (core.mcp_client.McpClientPool.tools).
    #: Never sent into a sandbox.
    external_tools: Callable[[], tuple] | None = None
    #: The axross functions the tab allows (core.agent_access.FUNCTIONS);
    #: None: no limit (the MCP server's own agent group, tests).
    functions: frozenset | None = None
    #: Whether ``(host, port)`` may be reached by remote work and http MCP
    #: servers in axross (core.agent_access.firewall); None: no limit.
    firewall: Callable[[str, int], bool] | None = None


@dataclass
class AgentResult:
    answer: str
    #: "answered", "max_steps" or "cancelled"
    stopped: str
    #: One entry per tool call: {name, outcome} - outcome is "ok", "error",
    #: "declined" or "unavailable".
    calls: list = field(default_factory=list)


def chat_url(profile: LLMProfile) -> str:
    """The ``/chat/completions`` URL of a profile's server. Ollama serves its
    OpenAI-compatible API under ``/v1``; the other profiles name it."""
    base = profile.resolved_endpoint().rstrip("/")
    if profile.provider == "ollama" and not urlsplit(base).path.rstrip("/").endswith("/v1"):
        base += "/v1"
    return base + "/chat/completions"


def post_chat(profile: LLMProfile, api_key: str, body: dict, *,
              cancel: threading.Event | None = None) -> dict:
    """POST *body* to the profile's ``/chat/completions`` and return the
    decoded answer. Raises :class:`AgentError` for anything but JSON.

    With *cancel*, setting it ends the wait at once: the request's
    connection is cut (the server stops generating) and
    :class:`AgentCancelled` is raised. The answer is not streamed, so
    without this a Stop waited for the whole answer."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    from core.agent_net import AbortableConnections, opener_without_redirects

    _require_http(profile)
    url = chat_url(profile)
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=headers, method="POST"
    )
    if cancel is None:
        return _send_chat(opener_without_redirects(), request, profile)
    connections = AbortableConnections()
    opener = opener_without_redirects(*connections.handlers())
    box: dict = {}
    done = threading.Event()

    def send() -> None:
        try:
            box["value"] = _send_chat(opener, request, profile)
        except BaseException as exc:  # noqa: BLE001 - handed to the waiting thread
            box["error"] = exc
        finally:
            done.set()

    threading.Thread(target=send, name="axross-llm-request", daemon=True).start()
    while not done.wait(0.05):
        if cancel.is_set():
            connections.abort()
            raise AgentCancelled("the task was stopped while the model was answering")
    if "error" in box:
        raise box["error"]
    return box["value"]


def _send_chat(opener, request, profile: LLMProfile) -> dict:
    try:
        with opener.open(request, timeout=profile.timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise AgentError(
                f"the LLM server at {profile.host()} answered a redirect (HTTP {exc.code}), "
                "which is not followed"
            ) from None
        raise AgentError(f"the LLM server at {profile.host()} answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise AgentError(f"cannot reach the LLM server at {profile.host()}: {reason}") from None
    except ValueError:
        raise AgentError(f"the LLM server at {profile.host()} did not answer JSON") from None


def _require_http(profile: LLMProfile) -> None:
    """An endpoint typed without http(s):// gets a reason a person can act
    on, not urllib's "unknown url type" for an empty host."""
    from core.llm_profiles import endpoint_problem

    problem = endpoint_problem(profile.resolved_endpoint())
    if problem:
        raise AgentError(problem)


#: Seconds a model listing may take at most, whatever the profile allows.
MODELS_TIMEOUT = 15.0


def models_url(profile: LLMProfile) -> str:
    """Where a profile's server lists its models: Ollama's own ``/api/tags``
    at the server root, ``<endpoint>/models`` for the OpenAI-compatible
    servers (their endpoint already names ``/v1``)."""
    base = profile.resolved_endpoint().rstrip("/")
    if profile.provider == "ollama":
        if urlsplit(base).path.rstrip("/").endswith("/v1"):
            base = base[: -len("/v1")]
        return base + "/api/tags"
    return base + "/models"


def list_models(profile: LLMProfile, api_key: str) -> list[str]:
    """The model names the profile's server offers, asked directly - no
    sift needed. Raises :class:`AgentError` with a reason a person can act
    on; a redirect is never followed (it would carry the key elsewhere)."""
    field_name = "name" if profile.provider == "ollama" else "id"
    return [str(e[field_name]) for e in _model_listing(profile, api_key)]


def _model_listing(profile: LLMProfile, api_key: str) -> list[dict]:
    """The entries of the server's model list (Ollama ``/api/tags``, else
    ``<endpoint>/models``) that carry a name; raises :class:`AgentError`."""
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    from core.agent_net import opener_without_redirects

    _require_http(profile)
    request = urllib.request.Request(models_url(profile), headers=headers, method="GET")
    timeout = min(profile.timeout, MODELS_TIMEOUT)
    try:
        with opener_without_redirects().open(request, timeout=timeout) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise AgentError(
                f"the LLM server at {profile.host()} answered a redirect (HTTP {exc.code}), "
                "which is not followed"
            ) from None
        raise AgentError(f"the LLM server at {profile.host()} answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise AgentError(f"cannot reach the LLM server at {profile.host()}: {reason}") from None
    except ValueError:
        raise AgentError(f"the LLM server at {profile.host()} did not answer JSON") from None
    if not isinstance(data, dict):
        raise AgentError(f"the LLM server at {profile.host()} did not answer a model list")
    if data.get("error"):
        # LM Studio on a wrong path answers 200 {"error": "Unexpected endpoint ..."}.
        raise AgentError(f"the LLM server at {profile.host()} answered: {data['error']}")
    key, field_name = ("models", "name") if profile.provider == "ollama" else ("data", "id")
    entries = data.get(key)
    if not isinstance(entries, list):
        raise AgentError(f"the LLM server at {profile.host()} did not answer a model list")
    return [e for e in entries if isinstance(e, dict) and e.get(field_name)]


@dataclass(frozen=True)
class ModelEntry:
    """One model of a server's list, with what the server says about it -
    never a guess: a field the server does not report stays empty."""

    id: str
    #: Bytes of the model file(s), or None when the server does not say.
    size: int | None = None
    #: Parameter count as the server writes it ("7.6B"), or "".
    parameters: str = ""
    #: Quantisation ("Q4_K_M"), or "".
    quantization: str = ""
    #: In memory now; False: not loaded; None: the server does not say.
    loaded: bool | None = None
    #: The longest context the server reports for the model, or None.
    context: int | None = None


def _count(value) -> int | None:
    """*value* when it is a real count (an int >= 0, not a bool), else None."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _billions(n_params: int | None) -> str:
    """A parameter count as the servers write it: 1543714304 -> "1.5B"."""
    if not n_params:
        return ""
    if n_params >= 1_000_000_000:
        return f"{n_params / 1e9:.1f}B"
    if n_params >= 1_000_000:
        return f"{n_params / 1e6:.0f}M"
    return str(n_params)


def _optional_json(profile: LLMProfile, api_key: str, url: str):
    """The JSON at *url*, or None when the server cannot or will not tell
    (no such endpoint, an error, a 200 carrying an error, no JSON). Bounded
    by MODELS_TIMEOUT; a redirect is not followed."""
    try:
        data = _get_json(profile, api_key, url)
    except AgentError:
        return None
    if not isinstance(data, dict) or data.get("error"):
        return None
    return data


def model_inventory(profile: LLMProfile, api_key: str) -> list[ModelEntry]:
    """The server's models with size, parameters, quantisation and load
    state as far as the server reports them.

    The list itself is :func:`list_models`' request (its failure raises
    :class:`AgentError`). Then, as each server documents it: Ollama's
    ``/api/tags`` already carries size and details, ``/api/ps`` names the
    loaded models; an OpenAI-compatible server is asked LM Studio's
    ``/api/v1/models`` (size, parameters, quantisation, loaded instances)
    and, without it, ``/api/v0/models`` (load state and quantisation, no
    size); llama.cpp puts size and parameter count into its list's
    ``meta``. LM Studio's endpoints are asked only of an ``lmstudio``
    profile or a server on this machine or the local network - a cloud
    API has none. A further request that fails leaves its fields empty -
    it never fails the list."""
    entries = _model_listing(profile, api_key)
    root = _server_root(profile)
    if profile.provider == "ollama":
        ps = _optional_json(profile, api_key, root + "/api/ps")
        running = ps.get("models") if ps is not None else None
        loaded: set | None = None
        if isinstance(running, list):
            loaded = set()
            for e in running:
                if isinstance(e, dict):
                    loaded.update(n for n in (e.get("name"), e.get("model")) if isinstance(n, str))
        out = []
        for e in entries:
            details = e.get("details") if isinstance(e.get("details"), dict) else {}
            name = str(e["name"])
            out.append(ModelEntry(
                id=name,
                size=_count(e.get("size")),
                parameters=_text(details.get("parameter_size")),
                quantization=_text(details.get("quantization_level")),
                loaded=None if loaded is None else bool({name, e.get("model")} & loaded),
                context=_count(e.get("context_length")),
            ))
        return out

    out = []
    for e in entries:
        meta = e.get("meta") if isinstance(e.get("meta"), dict) else {}  # llama.cpp
        out.append(ModelEntry(
            id=str(e["id"]),
            size=_count(meta.get("size")),
            parameters=_billions(_count(meta.get("n_params"))),
            context=_count(meta.get("n_ctx_train")),
        ))
    if profile.provider != "lmstudio" and profile.is_remote():
        return out
    by_id = {m.id.lower(): i for i, m in enumerate(out)}  # LM Studio ignores case

    v1 = _optional_json(profile, api_key, root + "/api/v1/models")
    v1_models = v1.get("models") if v1 is not None else None
    matched = 0
    if isinstance(v1_models, list):
        for m in v1_models:
            if not isinstance(m, dict) or not isinstance(m.get("key"), str):
                continue
            i = by_id.get(m["key"].lower())
            if i is None:
                continue
            quant = m.get("quantization")
            instances = m.get("loaded_instances")
            size = _count(m.get("size_bytes"))
            out[i] = dataclasses.replace(
                out[i],
                size=out[i].size if size is None else size,
                parameters=_text(m.get("params_string")) or out[i].parameters,
                quantization=(_text(quant.get("name")) if isinstance(quant, dict) else "")
                or out[i].quantization,
                loaded=bool(instances) if isinstance(instances, list) else None,
                context=_count(m.get("max_context_length")) or out[i].context,
            )
            matched += 1
    if matched:
        return out

    v0 = _optional_json(profile, api_key, root + "/api/v0/models")
    v0_models = v0.get("data") if v0 is not None else None
    for m in v0_models if isinstance(v0_models, list) else []:
        if not isinstance(m, dict) or not isinstance(m.get("id"), str):
            continue
        i = by_id.get(m["id"].lower())
        if i is None:
            continue
        state = m.get("state")
        out[i] = dataclasses.replace(
            out[i],
            quantization=_text(m.get("quantization")) or out[i].quantization,
            loaded=None if state not in ("loaded", "not-loaded") else state == "loaded",
            context=_count(m.get("max_context_length")) or out[i].context,
        )
    return out


def _server_root(profile: LLMProfile) -> str:
    """The profile's server without the ``/v1`` of its OpenAI-compatible
    API: where LM Studio's and Ollama's own endpoints are."""
    base = profile.resolved_endpoint().rstrip("/")
    return base[: -len("/v1")] if urlsplit(base).path.rstrip("/").endswith("/v1") else base


def _get_json(profile: LLMProfile, api_key: str, url: str):
    from core.agent_net import opener_without_redirects

    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener_without_redirects().open(
            request, timeout=min(profile.timeout, MODELS_TIMEOUT)
        ) as response:
            return json.loads(response.read(4 << 20))
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 405, 501):
            raise _NoInventory(f"HTTP {exc.code}") from None
        raise AgentError(f"HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise _Unreachable(str(getattr(exc, "reason", exc))) from None
    except ValueError:
        raise AgentError("no JSON") from None


class _Unreachable(AgentError):
    """No connection to the server at all: it loads nothing either, and the
    request itself says why it cannot reach it."""


class _NoInventory(AgentError):
    """The server has no endpoint that lists its loaded models (a plain
    OpenAI-compatible server, a proxy that passes /v1 only): it cannot be
    asked, and there is nothing it reports as loaded to protect - as sift
    treats it."""


def _loaded_models(profile: LLMProfile, api_key: str) -> tuple[list[str], bool | None]:
    """(the models the server has loaded, whether the profile's model is
    among them - None when the server does not list it at all). LM Studio:
    ``/api/v0/models`` and its ``state``; Ollama: ``/api/ps``. Raises
    AgentError when the server cannot tell."""
    model = profile.model
    if profile.provider == "lmstudio":
        data = _get_json(profile, api_key, _server_root(profile) + "/api/v0/models")
        entries = data.get("data") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise AgentError("no model list")
        entries = [e for e in entries if isinstance(e, dict) and isinstance(e.get("id"), str)]
        if any("state" not in e for e in entries):
            raise AgentError("the list names no load state")
        loaded = [e["id"] for e in entries if e.get("state") == "loaded"]
        # LM Studio resolves a model id case-insensitively.
        mine = next((e for e in entries if e["id"].lower() == model.lower()), None)
        return loaded, None if mine is None else mine.get("state") == "loaded"
    data = _get_json(profile, api_key, _server_root(profile) + "/api/ps")
    entries = data.get("models") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise AgentError("no model list")
    loaded = [str(e.get("name") or e.get("model")) for e in entries
              if isinstance(e, dict) and (e.get("name") or e.get("model"))]
    # Ollama fills in the ":latest" tag.
    wanted = model if ":" in model else f"{model}:latest"
    return loaded, any(wanted in (e.get("name"), e.get("model"))
                       for e in entries if isinstance(e, dict))


def model_load_refusal(profile: LLMProfile, api_key: str) -> str:
    """Why the profile's model may not be asked now, or "".

    Asking LM Studio or Ollama for a model that is not loaded makes it load
    that model and evict the loaded one. As sift does for the Analysis dock
    (the profile's "May load a model that is not in memory"), a cold model is
    asked only when nothing is loaded or the profile allows the load; a
    server that answers but cannot tell what is loaded is a refusal, not a
    permission. One that cannot be reached at all is left to the request,
    which says so."""
    if profile.allow_model_load or profile.provider not in ("lmstudio", "ollama") \
            or not profile.model:
        return ""
    allow = ('allow it with "May load a model that is not in memory" in the profile '
             "(LLM…, Advanced)")
    try:
        loaded, mine = _loaded_models(profile, api_key)
    except (_NoInventory, _Unreachable):
        return ""
    except AgentError as exc:
        return (f"cannot check whether {profile.model} is loaded on {profile.host()} ({exc}): "
                f"nothing was sent, so no loaded model is evicted; {allow}")
    if mine is not False or not loaded:
        return ""  # loaded, not listed (the server answers itself), or nothing to evict
    return (f"{profile.model} is not loaded on {profile.host()}, {', '.join(loaded)} is: asking "
            f"it would make the server load {profile.model} and evict that. Load it there, "
            f"choose the loaded model, or {allow}")


#: Share of an Ollama model's context a request may fill before axross says
#: that Ollama has probably cut it: Ollama drops what does not fit and
#: reports what is left, so a cut request ends just below the context.
OLLAMA_FULL_SHARE = 0.9


def ollama_context_length(profile: LLMProfile, api_key: str) -> int | None:
    """The context (tokens) the profile's Ollama server runs its model with -
    ``context_length`` of ``/api/ps`` - or None when it cannot be told."""
    try:
        data = _get_json(profile, api_key, _server_root(profile) + "/api/ps")
    except AgentError:
        return None
    entries = data.get("models") if isinstance(data, dict) else None
    wanted = profile.model if ":" in profile.model else f"{profile.model}:latest"
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or wanted not in (entry.get("name"), entry.get("model")):
            continue
        length = entry.get("context_length")
        if isinstance(length, int) and not isinstance(length, bool) and length > 0:
            return length
    return None


def ollama_context_notice(profile: LLMProfile, usage: dict, context: int | None) -> str:
    """What to tell the user when an Ollama answer's *usage* fills the
    model's *context* (ollama_context_length): Ollama then cut the request
    without a word, and its OpenAI-compatible endpoint takes no context
    size. "" otherwise."""
    prompt, completion = usage.get("prompt_tokens"), usage.get("completion_tokens", 0)
    if profile.provider != "ollama" or not context:
        return ""
    if not isinstance(prompt, int) or not isinstance(completion, int):
        return ""
    if prompt + completion < OLLAMA_FULL_SHARE * context:
        return ""
    return (
        f"Ollama runs {profile.model} with a context of {context} tokens and this request "
        f"filled it ({prompt} tokens): Ollama drops what does not fit - the instructions, the "
        "tools or the start of the conversation - and the answers suffer. Give the model more "
        "context on the server: OLLAMA_CONTEXT_LENGTH=16384, or PARAMETER num_ctx in a Modelfile."
    )


class OllamaContextWatch:
    """Says once per conversation that Ollama cut a request: asks the
    model's context the first time an answer comes, keeps it."""

    def __init__(self, profile: LLMProfile, api_key: str) -> None:
        self._profile = profile
        self._api_key = api_key
        self._context: int | None = None
        self.said = False

    def notice(self, usage: dict) -> str:
        if self.said or self._profile.provider != "ollama" \
                or not isinstance(usage.get("prompt_tokens"), int):
            return ""
        if self._context is None:
            self._context = ollama_context_length(self._profile, self._api_key)
        text = ollama_context_notice(self._profile, usage, self._context)
        self.said = bool(text)
        return text


def needs_confirmation(name: str, *, write: bool, group: str) -> bool:
    """Whether a call needs the user's yes: every mutating tool, and every
    tool of the exec group that runs something."""
    return bool(write) or (group == "exec" and name in ("remote_exec", "remote_script"))


@dataclass
class FunctionTool:
    """A tool axross offers from its own Python code (an extension's, the
    tab's ask_user): called directly with the arguments, its return value
    (a string, or anything JSON can hold) goes to the model. An exception
    is an error for the model, never for the agent."""

    name: str
    description: str
    schema: dict
    handler: Callable[[dict], Any]
    write: bool = False
    group: str = "extension"
    always_ask: bool = False
    accepts_backend: bool = False
    external: bool = True
    #: False for a tool that reaches nothing outside axross (ask_user,
    #: update_plan): every sandbox level allows it.
    outside: bool = True
    #: Whether its owner is still there (an extension that was switched off).
    alive: Callable[[], bool] | None = None

    def call(self, args: dict) -> tuple[str, str]:
        if self.alive is not None and not self.alive():
            return "error", f"error: the tool {self.name} is gone (its extension was switched off)"
        try:
            value = self.handler(dict(args))
        except Exception as exc:  # noqa: BLE001 - the tool's failure is the model's to read
            log.warning("agent: the tool %s failed: %s", self.name, exc)
            return "error", f"error: {type(exc).__name__}: {exc}"
        if isinstance(value, str):
            return "ok", value
        try:
            return "ok", json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return "ok", str(value)


READ_ONLY_REFUSAL = "declined: files are read-only for this agent (Files read-only is on)"


#: Why axross refused a tool call (the tool_result event's "reason"): the
#: Agent dock's voice says it in a word. "" for no refusal.
REFUSAL_REASONS = ("read_only", "declined", "permission")


#: The longest reason a tool_result event carries for the transcript.
MAX_TOOL_DETAIL = 300
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


def tool_result_detail(outcome: str, text) -> str:
    """The reason a tool call did not succeed, for the transcript: the
    first line of the tool's text, without control characters or terminal
    escapes, at most MAX_TOOL_DETAIL characters. Empty for "ok" - that text
    is file contents or command output and stays out of the transcript."""
    if outcome == "ok" or not isinstance(text, str):
        return ""
    lines = text.strip().splitlines()
    line = _CONTROL.sub("", _ANSI.sub("", lines[0] if lines else "")).strip()
    return line if len(line) <= MAX_TOOL_DETAIL else line[:MAX_TOOL_DETAIL - 1] + "…"


def refusal_reason(outcome: str, text: str, *, files_read_only: bool = False) -> str:
    """The reason of a refused call: Files read-only, the user said No, or
    the system denied the permission; "" for anything else."""
    text = str(text or "")
    if outcome == "declined":
        return "read_only" if text == READ_ONLY_REFUSAL else "declined"
    if outcome == "unavailable" and files_read_only:
        return "read_only"  # the write tools are not offered at all then
    if outcome == "error" and ("permission denied" in text.lower() or "PermissionError" in text
                               or "Errno 13" in text):
        return "permission"
    return ""


def changes_files(write: bool, group: str) -> bool:
    """Whether a tool may change files: a mutating one, or one of the exec
    group (a remote command can change anything)."""
    return bool(write) or group == "exec"


def read_only(config: AgentConfig) -> AgentConfig:
    """*config* with nothing that can change a file: no write tools, no
    remote commands, every extra folder read-only, external tools without
    their mutating ones. *config* itself when the switch is off."""
    if not config.files_read_only:
        return config
    external = config.external_tools
    if external is not None:
        def external_tools(_source=external):
            tools, errors = _source()
            return [t for t in tools if not getattr(t, "write", False)], errors
    else:
        external_tools = None
    return dataclasses.replace(
        config,
        allow_write=False,
        allow_exec=False,
        groups=frozenset(config.groups) - {"exec"},
        extra_roots=tuple((path, False) for path, _writable in config.extra_roots or ()),
        external_tools=external_tools,
    )


def restrict(config: AgentConfig) -> AgentConfig:
    """*config* with only what its axross functions allow: lent
    connections need remote_files, the remote group saved_profiles, remote
    commands remote_commands. Files read-only applies first (read_only)."""
    config = read_only(config)
    allowed = config.functions
    if allowed is None:
        return config
    groups = set(config.groups)
    if "saved_profiles" not in allowed:
        groups.discard("remote")
    allow_exec = bool(config.allow_exec) and "remote_commands" in allowed
    if not allow_exec:
        groups.discard("exec")
    return dataclasses.replace(
        config, groups=frozenset(groups), allow_exec=allow_exec,
        remote_backends=tuple(config.remote_backends) if "remote_files" in allowed else (),
    )


def tool_allowed(tool, functions) -> bool:
    """Whether an external tool's axross function is allowed: an MCP
    server's needs mcp_servers, an extension's extensions; a tool that
    reaches nothing outside (ask_user, update_plan) always is."""
    if functions is None or not getattr(tool, "outside", True):
        return True
    return (
        "mcp_servers" if getattr(tool, "client", None) is not None else "extensions"
    ) in functions


def firewall_refusal(firewall, host: str, port) -> str | None:
    """Why the tab's network refuses ``host:port``, or None."""
    if firewall is None:
        return None
    if not host or not isinstance(port, int) or not firewall(host, port):
        return (
            f"{host or 'this connection'}:{port} is not an allowed host of this tab "
            "(its Access settings)"
        )
    return None


def firewall_gate(firewall):
    """A RemoteRegistry gate from a tab's firewall, or None."""
    if firewall is None:
        return None

    def gate(profile) -> None:
        refusal = firewall_refusal(
            firewall, str(getattr(profile, "host", "") or ""), getattr(profile, "port", 0)
        )
        if refusal is not None:
            raise PermissionError(refusal)

    return gate


def remote_args(args: dict) -> list[str]:
    """The remote backend ids a call names."""
    return [v for k in BACKEND_ARGS
            if isinstance(v := args.get(k), str) and v not in ("", "local")]


def remote_registry(config: AgentConfig, gate=None):
    """A registry with the config's lent connections, or None when there
    are none and the remote group is off."""
    from core.mcp_groups import RemoteRegistry

    if not config.remote_backends and "remote" not in config.groups:
        return None
    registry = RemoteRegistry(gate=gate)
    for bid, backend, profile in config.remote_backends:
        registry.attach(bid, backend, profile)
    return registry


def build_tools(config: AgentConfig, registry=None, *, backend=None, extra_roots=None) -> list:
    """The MCP tools the agent may offer, built like the server builds them."""
    from core import mcp_server
    from core.local_fs import LocalFS

    # Never the script tools, and never agent_run: an agent does not call agents.
    groups = frozenset(config.groups) - {"scripts", "agent"}
    return mcp_server._build_tools(
        backend if backend is not None else LocalFS(),
        allow_write=bool(config.allow_write),
        root=config.root,
        tool_groups=groups or None,
        allow_exec=bool(config.allow_exec),
        extra_roots=tuple(config.extra_roots or ()) if extra_roots is None else extra_roots,
        remote_registry=registry,
    )


def external_refusal(tool, firewall) -> str | None:
    """Why the tab's network keeps an http MCP server's tool out, or None."""
    client = getattr(tool, "client", None)
    where = client.config.host_port() if client is not None else None
    return firewall_refusal(firewall, *where) if where is not None else None


def tool_spec(tool) -> dict:
    """What the worker's agent needs to offer a host tool."""
    return {"name": tool.name, "description": tool.description, "schema": tool.schema,
            "write": bool(tool.write), "group": tool.group}


def _with_valid_arguments(call: dict) -> dict:
    function = dict(call.get("function") or {})
    raw = function.get("arguments")
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        parsed = None
    function["arguments"] = raw if isinstance(raw, str) and isinstance(parsed, dict) else (
        json.dumps(parsed) if isinstance(parsed, dict) else "{}"
    )
    return {**call, "function": function}


def _digest(args_text: str) -> str:
    return hashlib.sha256(args_text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _shown(args: dict, schema: dict) -> dict:
    """The arguments as the transcript shows them: secrets masked, long
    strings cut."""
    props = (schema or {}).get("properties") if isinstance(schema, dict) else None
    props = props if isinstance(props, dict) else {}
    out = {}
    for key, value in args.items():
        spec = props.get(key)
        if isinstance(spec, dict) and spec.get("writeOnly"):
            out[key] = "•••"
        elif isinstance(value, str) and len(value) > _EVENT_ARG_CHARS:
            out[key] = value[:_EVENT_ARG_CHARS] + f"… ({len(value)} characters)"
        else:
            out[key] = value
    return out


def system_prompt_for(config: AgentConfig) -> str:
    """The system message: the config's rules, then the folder the
    conversation works in and the further folders. A model that is not told
    the root guesses "/" for "this folder". Paths are JSON strings, so a
    folder name cannot add lines to the rules."""
    def quoted(path) -> str:
        return json.dumps(str(path), ensure_ascii=False)

    lines = [
        f"The local file system root, the folder this conversation works in, is "
        f"{quoted(config.root)}. \"Here\" and \"this folder\" mean it; give the file tools "
        f"absolute paths below it."
    ]
    for path, writable in config.extra_roots:
        lines.append(f"Further local folder, {'writable' if writable else 'read-only'}: "
                     f"{quoted(path)}")
    return "\n".join([config.system_prompt.rstrip("\n"), *lines]).lstrip("\n")


def _choice_of(payload) -> tuple[dict, dict]:
    """(first choice, its message) of a chat answer; AgentError when it
    holds none."""
    try:
        choice = payload["choices"][0]
        message = choice["message"]
    except (KeyError, IndexError, TypeError):
        raise AgentError("the LLM server's answer has no message") from None
    if not isinstance(choice, dict) or not isinstance(message, dict):
        raise AgentError("the LLM server's answer has no message")
    return choice, message


def with_system_message(history: list, system: dict) -> list:
    """*history* continued by an agent whose system message is *system*:
    the old system message (other root, other rules) is replaced, a missing
    one added. *history* itself is not changed."""
    rest = list(history[1:]) if history and history[0].get("role") == "system" \
        else list(history)
    return [dict(system), *rest]


class Agent:
    """One conversation with the model; :meth:`run` adds a task to it."""

    def __init__(
        self,
        config: AgentConfig,
        *,
        confirm: Callable[[str, dict], bool] | None = None,
        on_event: Callable[[dict], None] | None = None,
        cancel: threading.Event | None = None,
        transport: Callable[[dict], dict] | None = None,
        host_tools: list | None = None,
        host_call: Callable[[str, dict], tuple[str, str]] | None = None,
    ) -> None:
        """*transport* sends a request body to the model and returns its
        answer; by default :func:`post_chat` with the config's profile and
        key. The sandbox worker (core.agent_worker) relays it to the host,
        which owns the key, the consent and the only way out.

        *host_tools* (:func:`tool_spec` dicts) are the tools axross runs
        for a sandboxed agent; *host_call* sends one call there and returns
        ``(outcome, text)``. axross asks for the confirmation of those."""
        self.config = config
        self._transport = transport
        self._confirm = confirm
        self._on_event = on_event or (lambda event: None)
        self.cancel = cancel or threading.Event()
        config = self.config = restrict(config)
        self._registry = remote_registry(config, gate=firewall_gate(config.firewall))
        self._tool_list = build_tools(config, self._registry)
        self._tools = {t.name: t for t in self._tool_list}
        self._host_call = host_call
        self._external: dict | None = None
        self._host = {
            spec["name"]: spec for spec in host_tools or ()
            if isinstance(spec, dict) and isinstance(spec.get("name"), str)
            and isinstance(spec.get("schema"), dict)
        } if host_call is not None else {}
        self.messages: list[dict] = [{"role": "system", "content": system_prompt_for(config)}]
        self._request_id = 0
        self._context_watch = OllamaContextWatch(config.profile, config.api_key)

    # -- the model ------------------------------------------------------------

    def close(self) -> None:
        """Release the connections opened with remote_open (never the
        lent ones)."""
        if self._registry is not None:
            self._registry.close_all()

    def _load_external(self) -> None:
        if self._external is not None:
            return
        self._external = {}
        if self.config.external_tools is None:
            return
        try:
            tools, errors = self.config.external_tools()
        except Exception as exc:  # noqa: BLE001 - a broken server must not stop the agent
            log.warning("agent: the MCP servers could not be read: %s", exc)
            tools, errors = [], [str(exc)]
        for error in errors:
            self._on_event({"type": "notice", "text": f"MCP server not available: {error}"})
        self._external = {t.name: t for t in tools
                          if t.name not in self._tools and tool_allowed(t, self.config.functions)
                          and external_refusal(t, self.config.firewall) is None}

    def _functions(self) -> list[dict]:
        out = []
        for t in self._tool_list:
            # A tool axross also runs is offered with axross's schema: the
            # one that can name a remote backend.
            spec = self._host.get(t.name)
            schema, description = (spec["schema"], spec.get("description") or t.description) \
                if spec else (t.schema, t.description)
            out.append(
                {
                    "type": "function",
                    "function": {"name": t.name, "description": description, "parameters": schema},
                }
            )
        for name, spec in self._host.items():
            if name not in self._tools:
                out.append({"type": "function",
                            "function": {"name": name, "description": spec.get("description") or "",
                                         "parameters": spec["schema"]}})
        for name, tool in (self._external or {}).items():
            out.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": tool.description,
                        "parameters": tool.schema,
                    },
                }
            )
        return out

    def _complete(self) -> dict:
        profile = self.config.profile
        body = {
            "model": profile.model,
            "messages": self.messages,
            "tools": self._functions(),
            "tool_choice": "auto",
            "temperature": profile.temperature,
            "max_tokens": profile.max_output_tokens,
            "stream": False,
        }
        if self._transport is not None:
            # Its owner talks to the server, and says how that went.
            payload = self._transport(body)
            choice, message = _choice_of(payload)
        else:
            self._on_event({"type": "connection", "state": "trying"})
            try:
                payload = post_chat(profile, self.config.api_key, body, cancel=self.cancel)
                choice, message = _choice_of(payload)
            except AgentCancelled:
                self._on_event({"type": "connection", "state": "cancelled"})
                raise
            except AgentError as exc:
                self._on_event({"type": "connection", "state": "failed", "detail": str(exc)})
                raise
            self._on_event({"type": "connection", "state": "connected"})
        usage = payload.get("usage") if isinstance(payload, dict) else None
        if isinstance(usage, dict):
            counts = {k: usage[k] for k in ("prompt_tokens", "completion_tokens")
                      if isinstance(usage.get(k), int) and not isinstance(usage.get(k), bool)}
            if counts:
                self._on_event({"type": "usage", **counts})
            if self._transport is None:
                # The sandbox's host asks for its worker (agent_sandbox).
                notice = self._context_watch.notice(counts)
                if notice:
                    self._on_event({"type": "notice", "text": notice})
        return message, str(choice.get("finish_reason") or "")

    # -- tools ----------------------------------------------------------------

    def _run_tool(self, call: dict, *, cut: bool = False) -> tuple[str, str, str]:
        """(tool name, outcome, text for the model) of one tool call."""
        function = call.get("function") or {}
        name = str(function.get("name") or "")
        raw = function.get("arguments") or "{}"
        args_text = raw if isinstance(raw, str) else json.dumps(raw)
        tool = self._tools.get(name)
        spec = self._host.get(name)
        external = (self._external or {}).get(name)
        if tool is None and spec is None and external is None:
            return name, "unavailable", f"error: the tool {name!r} is not available to you"
        try:
            args = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            args = None
        if not isinstance(args, dict):
            reason = (
                " - the answer was cut at the output limit; send shorter arguments" if cut else ""
            )
            return name, "error", f"error: the arguments are not a JSON object{reason}"
        fields = f"tool={name} args_sha256={_digest(args_text)} args_len={len(args_text)}"
        if self.config.files_read_only:
            # The offer leaves these out already; the call is checked too.
            for candidate in (external, tool, spec):
                if candidate is None:
                    continue
                write = candidate.get("write") if isinstance(candidate, dict) else candidate.write
                group = candidate.get("group") if isinstance(candidate, dict) else candidate.group
                if changes_files(bool(write), str(group or "")):
                    audit.info("%s outcome=declined read_only=1", fields)
                    return name, "declined", READ_ONLY_REFUSAL
        if external is not None:
            return self._run_external(external, args, fields)
        remote = remote_args(args)
        if spec is not None and (tool is None or remote):
            return self._run_host_tool(name, args, spec, fields)
        if remote and not self._registry_holds(remote):
            return name, "error", (f"error: the backend {remote[0]!r} is not reachable for you; "
                                   "omit it for the local files")
        for key in BACKEND_ARGS:
            # "local" (or none) is the default backend; a schema without the
            # field would refuse it.
            if key in args and key not in tool.schema.get("properties", {}) and not remote:
                args.pop(key)
        self._on_event({"type": "tool_call", "name": name, "args": _shown(args, tool.schema)})
        if needs_confirmation(name, write=tool.write, group=tool.group):
            allowed = False
            if self._confirm is not None:
                try:
                    allowed = bool(self._confirm(name, args))
                except Exception as exc:  # noqa: BLE001 - a broken prompt is a "no"
                    log.warning("agent: the confirmation of %s failed: %s", name, exc)
            if not allowed:
                audit.info("%s outcome=declined", fields)
                return name, "declined", "declined: the user did not allow this call"
        from core import mcp_server

        self._request_id += 1
        response = mcp_server._handle_request(
            {"jsonrpc": "2.0", "id": self._request_id, "method": "tools/call",
             "params": {"name": name, "arguments": args}},
            self._tool_list,
            cancels=mcp_server._CancelRegistry(),
        )
        if "error" in response:
            audit.info("%s outcome=error", fields)
            return name, "error", f"error: {response['error'].get('message', 'failed')}"
        audit.info("%s outcome=ok", fields)
        parts = []
        for item in response.get("result", {}).get("content", []):
            if item.get("type") == "text":
                parts.append(item.get("text", ""))
            else:
                parts.append(f"[{item.get('type', 'binary')} result, not shown]")
        return name, "ok", "\n".join(parts)

    def _registry_holds(self, ids: list[str]) -> bool:
        return self._registry is not None and all(
            bid in dict(self._registry.entries()) or bid.startswith("profile:") for bid in ids)

    def _run_host_tool(
        self, name: str, args: dict, spec: dict, fields: str
    ) -> tuple[str, str, str]:
        """A call axross runs (and confirms): a remote backend's, or a tool
        only axross has."""
        self._on_event({"type": "tool_call", "name": name, "args": _shown(args, spec["schema"])})
        try:
            outcome, text = self._host_call(name, args)
        except AgentError as exc:
            outcome, text = "error", f"error: {exc}"
        if outcome not in ("ok", "error", "declined", "unavailable"):
            outcome = "error"
        audit.info("%s outcome=%s where=axross", fields, outcome)
        return name, outcome, str(text)

    def _run_external(self, tool, args: dict, fields: str) -> tuple[str, str, str]:
        """A tool of another MCP server: asked for when it may change
        something, then called directly."""
        shown = _shown(args, tool.schema)
        self._on_event({"type": "tool_call", "name": tool.name, "args": shown})
        if needs_confirmation(tool.name, write=tool.write, group=tool.group):
            allowed = False
            if self._confirm is not None:
                try:
                    # Masked: the tab cannot look a foreign tool's schema up.
                    allowed = bool(self._confirm(tool.name, shown))
                except Exception as exc:  # noqa: BLE001 - a broken prompt is a "no"
                    log.warning("agent: the confirmation of %s failed: %s", tool.name, exc)
            if not allowed:
                audit.info("%s outcome=declined", fields)
                return tool.name, "declined", "declined: the user did not allow this call"
        outcome, text = tool.call(args)
        audit.info("%s outcome=%s where=mcp", fields, outcome)
        return tool.name, outcome, text

    def _cut(self, text: str) -> str:
        limit = max(200, int(self.config.max_tool_chars))
        if len(text) <= limit:
            return text
        marker = f"\n... [truncated: {len(text) - limit} more characters]"
        return text[: limit - len(marker)] + marker

    # -- the loop -------------------------------------------------------------

    def _show_step(self, reasoning: str, answer: str) -> None:
        """A step's thinking as a "reasoning" event, then its text as an
        "assistant" event - each only when there is one."""
        if reasoning:
            self._on_event({"type": "reasoning", "text": reasoning})
        if answer.strip():
            self._on_event({"type": "assistant", "text": answer})

    def _final_answer(self, message: dict) -> str:
        """The answer of the model's last message, shown after its
        thinking. A reasoning model (Qwen3 on LM Studio) at times writes the
        whole answer into its reasoning and leaves the answer empty: the
        reasoning is then shown as the answer, marked as such. Nothing at
        all is said, never left silent."""
        reasoning, answer = split_reasoning(message)
        if answer.strip():
            self._show_step(reasoning, answer)
            return answer
        if reasoning:
            self._on_event({"type": "notice", "text": REASONING_NOTICE})
            self._on_event({"type": "assistant", "text": reasoning})
            return reasoning
        self._on_event({"type": "notice", "text": NO_ANSWER_NOTICE})
        return ""

    def run(self, task: str) -> AgentResult:
        profile = self.config.profile
        # With a transport its owner sends, and asks for the consent.
        if self._transport is None and profile.needs_consent():
            raise AgentError(
                f"the profile {profile.name!r} sends to {profile.host() or 'an unknown host'}, "
                "which has no consent yet: confirm it in the LLM settings first"
            )
        if self._transport is None:
            # A sandbox's host checks this for its worker (agent_sandbox).
            refusal = model_load_refusal(profile, self.config.api_key)
            if refusal:
                raise AgentError(refusal)
        self._load_external()
        self.messages.append({"role": "user", "content": task})
        calls: list[dict] = []
        for _step in range(max(1, int(self.config.max_steps))):
            if self.cancel.is_set():
                return AgentResult("", "cancelled", calls)
            try:
                message, finish = self._complete()
            except AgentError:
                # Stopped while the model answered (post_chat cut the
                # request; a sandbox worker's host dropped it).
                if self.cancel.is_set():
                    return AgentResult("", "cancelled", calls)
                raise
            if self.cancel.is_set():
                # Stop came while the answer was on its way: it is not
                # shown, and no tool call it asks for runs.
                return AgentResult("", "cancelled", calls)
            tool_calls = [c for c in (message.get("tool_calls") or []) if isinstance(c, dict)]
            content = message.get("content") or ""
            kept: dict[str, Any] = {"role": "assistant", "content": content}
            if tool_calls:
                # Arguments that are no JSON object (cut at the output limit,
                # or garbled) go back as "{}": servers parse the history, and
                # llama.cpp refused the whole next request over them.
                kept["tool_calls"] = [_with_valid_arguments(c) for c in tool_calls]
            self.messages.append(kept)
            if not tool_calls:
                answer = self._final_answer(message)
                return AgentResult(answer, "answered", calls)
            # A tool call's thinking often comes alone (content "\n\n").
            self._show_step(*split_reasoning(message))
            for call in tool_calls:
                name, outcome, text = self._run_tool(call, cut=finish == "length")
                calls.append({"name": name, "outcome": outcome})
                self.messages.append({"role": "tool", "tool_call_id": str(call.get("id", "")),
                                      "content": self._cut(text)})
                self._on_event({"type": "tool_result", "name": name, "outcome": outcome,
                                "reason": refusal_reason(
                                    outcome, text, files_read_only=self.config.files_read_only),
                                "detail": tool_result_detail(outcome, text)})
        return AgentResult("", "cancelled" if self.cancel.is_set() else "max_steps", calls)
