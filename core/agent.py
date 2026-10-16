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
"""

from __future__ import annotations

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


def needs_confirmation(name: str, *, write: bool, group: str) -> bool:
    """Whether a call needs the user's yes: every mutating tool, and every
    tool of the exec group that runs something."""
    return bool(write) or (group == "exec" and name in ("remote_exec", "remote_script"))


def build_tools(config: AgentConfig) -> list:
    """The MCP tools the agent may offer, built like the server builds them."""
    from core import mcp_server
    from core.local_fs import LocalFS

    # Never the script tools, and never agent_run: an agent does not call agents.
    groups = frozenset(config.groups) - {"scripts", "agent"}
    return mcp_server._build_tools(
        LocalFS(),
        allow_write=bool(config.allow_write),
        root=config.root,
        tool_groups=groups or None,
        allow_exec=bool(config.allow_exec),
    )


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
    props = (schema or {}).get("properties", {})
    out = {}
    for key, value in args.items():
        if props.get(key, {}).get("writeOnly"):
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
    ) -> None:
        self.config = config
        self._confirm = confirm
        self._on_event = on_event or (lambda event: None)
        self.cancel = cancel or threading.Event()
        self._tool_list = build_tools(config)
        self._tools = {t.name: t for t in self._tool_list}
        self.messages: list[dict] = [{"role": "system", "content": config.system_prompt}]
        self._request_id = 0

    # -- the model ------------------------------------------------------------

    def _functions(self) -> list[dict]:
        return [
            {"type": "function",
             "function": {"name": t.name, "description": t.description, "parameters": t.schema}}
            for t in self._tool_list
        ]

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
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        url = chat_url(profile)
        request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=profile.timeout) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise AgentError(f"the LLM server at {profile.host()} answered HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise AgentError(f"cannot reach the LLM server at {profile.host()}: {reason}") from None
        except ValueError:
            raise AgentError(f"the LLM server at {profile.host()} did not answer JSON") from None
        try:
            choice = payload["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError):
            raise AgentError("the LLM server's answer has no message") from None
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
        if tool is None:
            return name, "unavailable", f"error: the tool {name!r} is not available to you"
        try:
            args = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            args = None
        if not isinstance(args, dict):
            reason = " - the answer was cut at the output limit; send shorter arguments" if cut else ""
            return name, "error", f"error: the arguments are not a JSON object{reason}"
        self._on_event({"type": "tool_call", "name": name, "args": _shown(args, tool.schema)})
        fields = f"tool={name} args_sha256={_digest(args_text)} args_len={len(args_text)}"
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

    def _cut(self, text: str) -> str:
        limit = max(200, int(self.config.max_tool_chars))
        if len(text) <= limit:
            return text
        marker = f"\n... [truncated: {len(text) - limit} more characters]"
        return text[: limit - len(marker)] + marker

    # -- the loop -------------------------------------------------------------

    def run(self, task: str) -> AgentResult:
        profile = self.config.profile
        if profile.needs_consent():
            raise AgentError(
                f"the profile {profile.name!r} sends to {profile.host() or 'an unknown host'}, "
                "which has no consent yet: confirm it in the LLM settings first"
            )
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
