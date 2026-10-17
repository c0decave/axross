"""The agent in a process of its own - started by :mod:`core.agent_sandbox`,
usually inside bubblewrap, podman or docker.

The worker runs the whole agent: the loop of :class:`core.agent.Agent` and
every tool it calls, confined to the agent's folder. It has no network
and no secrets. It talks to axross over stdin / stdout, one JSON object
per line:

axross -> worker
    ``{"type": "start", "config": {...}}``   first line: the agent config
    ``{"type": "task", "text": "..."}``      a task for the conversation
    ``{"type": "answer", "id": n, "value": ...}`` / ``{..., "error": "..."}``
    ``{"type": "cancel"}``                   stop the running task
    ``{"type": "tcp_data"|"tcp_close", "stream": n, ...}`` an allowed host's bytes

worker -> axross
    ``{"type": "event", "event": {...}}``    for the transcript
    ``{"type": "confirm", "id": n, "name": ..., "args": {...}}``
        may this change run? (arguments already masked)
    ``{"type": "llm", "id": n, "body": {...}}``
        send this request to the model - axross holds the key and the
        only way out
    ``{"type": "tcp_open", "id": n, "host": ..., "port": ...}`` and
    ``{"type": "tcp_data"|"tcp_close", ...}`` - a connection to an allowed
        host, which axross opens and checks (core.agent_net)
    ``{"type": "host_tool", "id": n, "name": ..., "args": {...}}`` - run
        this tool in axross: a call on a remote backend, or a tool only
        axross has (the start config's ``host_tools``); axross checks,
        confirms and answers ``{"outcome": ..., "text": ...}``
    ``{"type": "history", "messages": [...]}`` the conversation so far, so
        that a new sandbox can continue it
    ``{"type": "result", "answer": ..., "stopped": ..., "calls": [...]}``
    ``{"type": "failed", "error": "..."}``

Anything a library prints goes to stderr: fd 1 is the protocol's alone.
"""

from __future__ import annotations

import io
import json
import logging
import os
import queue
import sys
import threading

log = logging.getLogger(__name__)

#: Longest protocol line read: a request body carries the conversation.
MAX_LINE = 64 * 1024 * 1024


class _Closed(Exception):
    """axross closed the channel."""


class _Channel:
    def __init__(self, reader, writer) -> None:
        self._reader = reader
        self._writer = writer
        self._write_lock = threading.Lock()
        self._lock = threading.Lock()
        self._next_id = 0
        self._waiting: dict[int, dict] = {}
        self._closed = False
        self.tasks: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        #: core.agent_net.WorkerBridge when the sandbox has allowed hosts.
        self.bridge = None

    def send(self, message: dict) -> None:
        line = json.dumps(message, ensure_ascii=False)
        with self._write_lock:
            self._writer.write(line + "\n")
            self._writer.flush()

    def read_message(self) -> dict | None:
        line = self._reader.readline(MAX_LINE)
        if not line:
            return None
        try:
            message = json.loads(line)
        except ValueError:
            log.warning("agent worker: a line that is no JSON")
            return {}
        return message if isinstance(message, dict) else {}

    def request(self, message: dict) -> dict:
        """Send *message* with a fresh id and wait for axross's answer."""
        slot = {"event": threading.Event(), "reply": None}
        with self._lock:
            if self._closed:
                raise _Closed()
            self._next_id += 1
            ident = self._next_id
            self._waiting[ident] = slot
        self.send({**message, "id": ident})
        slot["event"].wait()
        with self._lock:
            self._waiting.pop(ident, None)
        if slot["reply"] is None:
            raise _Closed()
        return slot["reply"]

    def serve(self) -> None:
        """Read axross's lines until the channel closes (reader thread)."""
        while True:
            message = self.read_message()
            if message is None:
                break
            kind = message.get("type")
            if kind == "answer":
                with self._lock:
                    slot = self._waiting.get(message.get("id"))
                if slot is not None:
                    slot["reply"] = message
                    slot["event"].set()
            elif kind == "task" and isinstance(message.get("text"), str):
                self.tasks.put(message["text"])
            elif kind == "cancel":
                self.cancel.set()
            elif kind == "tcp_data" and self.bridge is not None:
                self.bridge.deliver(message.get("stream"), message.get("data") or "")
            elif kind == "tcp_close" and self.bridge is not None:
                self.bridge.closed(message.get("stream"))
        with self._lock:
            self._closed = True
            waiting = list(self._waiting.values())
        for slot in waiting:
            slot["event"].set()
        self.cancel.set()
        self.tasks.put(None)


def _config_from(data: dict):
    from core import agent as A
    from core.agent_sandbox import allowed_groups
    from core.llm_profiles import LLMProfile

    profile_data = data.get("profile") or {}
    profile = LLMProfile(
        name=str(profile_data.get("name") or "sandbox"),
        provider=str(profile_data.get("provider") or "openai"),
        model=str(profile_data.get("model") or ""),
        temperature=float(profile_data.get("temperature", 0.2)),
        timeout=float(profile_data.get("timeout", 180.0)),
        max_output_tokens=int(profile_data.get("max_output_tokens", 2000)),
    )
    extra = tuple((str(path), bool(rw)) for path, rw in data.get("extra_roots") or ())
    prompt = data.get("system_prompt")
    return A.AgentConfig(
        profile=profile,
        root=str(data["root"]),
        groups=allowed_groups(frozenset(str(g) for g in data.get("groups") or ())),
        allow_write=bool(data.get("allow_write")),
        # Credentials and remote commands stay with axross: never offered here.
        allow_exec=False,
        max_steps=int(data.get("max_steps", A.DEFAULT_MAX_STEPS)),
        max_tool_chars=int(data.get("max_tool_chars", A.DEFAULT_MAX_TOOL_CHARS)),
        system_prompt=prompt if isinstance(prompt, str) and prompt.strip() else A.SYSTEM_PROMPT,
        extra_roots=extra,
    )


def serve(reader, writer) -> int:
    from core import agent as A

    channel = _Channel(reader, writer)
    first = channel.read_message()
    if not first or first.get("type") != "start" or not isinstance(first.get("config"), dict):
        channel.send({"type": "failed", "error": "the agent worker got no start message"})
        return 2
    try:
        config = _config_from(first["config"])
    except (KeyError, TypeError, ValueError) as exc:
        channel.send({"type": "failed", "error": f"the agent worker got a broken config: {exc}"})
        return 2

    agent: A.Agent | None = None

    def confirm(name: str, args: dict) -> bool:
        tool = agent._tools.get(name) if agent is not None else None
        shown = A._shown(args, tool.schema if tool is not None else {})
        try:
            reply = channel.request({"type": "confirm", "name": name, "args": shown})
        except _Closed:
            return False
        return reply.get("value") is True

    def transport(body: dict) -> dict:
        try:
            reply = channel.request({"type": "llm", "body": body})
        except _Closed:
            raise A.AgentError("axross closed the connection") from None
        if "error" in reply:
            raise A.AgentError(str(reply["error"]))
        value = reply.get("value")
        if not isinstance(value, dict):
            raise A.AgentError("the LLM server's answer has no message")
        return value

    def host_call(name: str, args: dict) -> tuple[str, str]:
        try:
            reply = channel.request({"type": "host_tool", "name": name, "args": args})
        except _Closed:
            raise A.AgentError("axross closed the connection") from None
        if "error" in reply:
            return "error", f"error: {reply['error']}"
        value = reply.get("value") if isinstance(reply.get("value"), dict) else {}
        return str(value.get("outcome") or "error"), str(value.get("text") or "")

    host_tools = [t for t in first["config"].get("host_tools") or () if isinstance(t, dict)]
    agent = A.Agent(
        config,
        confirm=confirm,
        on_event=lambda event: channel.send({"type": "event", "event": event}),
        cancel=channel.cancel,
        transport=transport,
        host_tools=host_tools,
        host_call=host_call if host_tools else None,
    )
    history = first["config"].get("messages")
    if isinstance(history, list) and history and all(isinstance(m, dict) for m in history):
        agent.messages = list(history)
    hosts = [h for h in first["config"].get("hosts") or () if isinstance(h, str)]
    if hosts:
        from core.agent_net import WorkerBridge

        channel.bridge = WorkerBridge(channel.request, channel.send, hosts)
        channel.bridge.install()
    threading.Thread(target=channel.serve, name="agent-worker-reader", daemon=True).start()
    while True:
        task = channel.tasks.get()
        if task is None:
            return 0
        channel.cancel.clear()
        try:
            result = agent.run(task)
            channel.send({"type": "history", "messages": agent.messages})
            channel.send({"type": "result", "answer": result.answer, "stopped": result.stopped,
                          "calls": result.calls})
        except A.AgentError as exc:
            channel.send({"type": "history", "messages": agent.messages})
            channel.send({"type": "failed", "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - reported to axross, not lost
            log.exception("agent worker: the task failed")
            channel.send({"type": "failed", "error": f"{type(exc).__name__}: {exc}"})


def main() -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    # The protocol owns fd 1: whatever else prints goes to stderr.
    protocol_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    writer = io.TextIOWrapper(os.fdopen(protocol_fd, "wb", buffering=0), encoding="utf-8",
                              line_buffering=True, write_through=True)
    reader = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
    return serve(reader, writer)


if __name__ == "__main__":
    sys.exit(main())
