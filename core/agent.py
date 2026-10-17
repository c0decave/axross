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


@dataclass
class AgentConfig:
    profile: LLMProfile
    root: str
    api_key: str = ""
    #: Capability groups of core.mcp_groups offered besides the core file tools.
    groups: frozenset = field(default_factory=frozenset)
    allow_write: bool = False
    allow_exec: bool = False
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


def post_chat(profile: LLMProfile, api_key: str, body: dict) -> dict:
    """POST *body* to the profile's ``/chat/completions`` and return the
    decoded answer. Raises :class:`AgentError` for anything but JSON."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    from core.agent_net import opener_without_redirects

    url = chat_url(profile)
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=headers, method="POST"
    )
    try:
        with opener_without_redirects().open(request, timeout=profile.timeout) as response:
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


def restrict(config: AgentConfig) -> AgentConfig:
    """*config* with only what its axross functions allow: lent
    connections need remote_files, the remote group saved_profiles, remote
    commands remote_commands."""
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
        self.messages: list[dict] = [{"role": "system", "content": config.system_prompt}]
        self._request_id = 0

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
            payload = self._transport(body)
        else:
            payload = post_chat(profile, self.config.api_key, body)
        try:
            choice = payload["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError):
            raise AgentError("the LLM server's answer has no message") from None
        usage = payload.get("usage") if isinstance(payload, dict) else None
        if isinstance(usage, dict):
            counts = {k: usage[k] for k in ("prompt_tokens", "completion_tokens")
                      if isinstance(usage.get(k), int) and not isinstance(usage.get(k), bool)}
            if counts:
                self._on_event({"type": "usage", **counts})
        if not isinstance(message, dict):
            raise AgentError("the LLM server's answer has no message")
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

    def run(self, task: str) -> AgentResult:
        profile = self.config.profile
        # With a transport its owner sends, and asks for the consent.
        if self._transport is None and profile.needs_consent():
            raise AgentError(
                f"the profile {profile.name!r} sends to {profile.host() or 'an unknown host'}, "
                "which has no consent yet: confirm it in the LLM settings first"
            )
        self._load_external()
        self.messages.append({"role": "user", "content": task})
        calls: list[dict] = []
        for _step in range(max(1, int(self.config.max_steps))):
            if self.cancel.is_set():
                return AgentResult("", "cancelled", calls)
            message, finish = self._complete()
            tool_calls = [c for c in (message.get("tool_calls") or []) if isinstance(c, dict)]
            content = message.get("content") or ""
            kept: dict[str, Any] = {"role": "assistant", "content": content}
            if tool_calls:
                # Arguments that are no JSON object (cut at the output limit,
                # or garbled) go back as "{}": servers parse the history, and
                # llama.cpp refused the whole next request over them.
                kept["tool_calls"] = [_with_valid_arguments(c) for c in tool_calls]
            self.messages.append(kept)
            if content:
                self._on_event({"type": "assistant", "text": content})
            if not tool_calls:
                return AgentResult(content, "answered", calls)
            for call in tool_calls:
                name, outcome, text = self._run_tool(call, cut=finish == "length")
                calls.append({"name": name, "outcome": outcome})
                self.messages.append({"role": "tool", "tool_call_id": str(call.get("id", "")),
                                      "content": self._cut(text)})
                self._on_event({"type": "tool_result", "name": name, "outcome": outcome})
        return AgentResult("", "cancelled" if self.cancel.is_set() else "max_steps", calls)
