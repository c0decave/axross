"""A client for further MCP servers, whose tools the agent may use.

axross's agent offers its own tools (core.mcp_server) and, configured in
Agent Settings > MCP Servers, the tools of other MCP servers: a program
spoken to over stdin/stdout (``stdio``) or a server reached over
Streamable HTTP (``http``). Their tools are named ``<server>__<tool>``.

The servers run with axross, never inside the agent's sandbox: their
credentials (an HTTP token in the keyring) stay here, and a sandboxed
agent reaches their tools as host tools (core.agent_sandbox), under the
sandbox's level and allowed hosts. A stdio server may itself run in a
sandbox profile (``sandbox``).

Bounded: at most :data:`MAX_TOOLS` tools per server, descriptions cut at
:data:`MAX_DESCRIPTION`, input schemas larger than :data:`MAX_SCHEMA_BYTES`
replaced by a plain object schema, answers larger than
:data:`MAX_MESSAGE_BYTES` refused, every request under the server's
timeout. A server's schema is never validated here (that is the server's
job, and validating a foreign schema could fetch remote references).
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
SEPARATOR = "__"
MAX_TOOLS = 128
MAX_DESCRIPTION = 2000
MAX_SCHEMA_BYTES = 64 * 1024
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_NAME = 64
TRANSPORTS = ("stdio", "http")
CONFIRMS = ("always", "writes")
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_TOOL_CHARS = re.compile(r"[^A-Za-z0-9_-]")


class McpClientError(RuntimeError):
    """The server could not be started, reached or understood."""


@dataclass
class McpServerConfig:
    name: str
    transport: str = "stdio"
    #: stdio: the program and its arguments.
    command: tuple[str, ...] = ()
    #: stdio: extra environment variables (no secrets: the file is plain JSON).
    env: dict = field(default_factory=dict)
    #: http: the endpoint, e.g. ``http://127.0.0.1:7331/messages``.
    url: str = ""
    #: http: send the keyring's token as ``Authorization: Bearer``.
    bearer: bool = False
    enabled: bool = True
    #: "always": every call asks (even in auto mode); "writes": a tool the
    #: server marks read-only (``readOnlyHint``) runs without asking.
    confirm: str = "always"
    timeout: float = 120.0
    #: stdio: run the program in this sandbox profile ("" = not).
    sandbox: str = ""

    def problems(self) -> list[str]:
        out = []
        if not _NAME.match(self.name or ""):
            out.append("a name of 1-32 letters, digits, '-' or '_'")
        if self.transport not in TRANSPORTS:
            out.append("transport stdio or http")
        elif self.transport == "stdio" and not self.command:
            out.append("a program to start")
        elif self.transport == "http":
            parts = urlsplit(self.url or "")
            if parts.scheme not in ("http", "https") or not parts.hostname:
                out.append("an http:// or https:// URL")
        if self.confirm not in CONFIRMS:
            out.append("confirm always or writes")
        if not (0 < self.timeout <= 3600):
            out.append("a timeout of 1-3600 seconds")
        return out

    def host_port(self) -> tuple[str, int] | None:
        """Where an http server is reached; None for stdio."""
        if self.transport != "http":
            return None
        parts = urlsplit(self.url)
        try:
            port = parts.port
        except ValueError:
            return None
        return (parts.hostname or "", port or (443 if parts.scheme == "https" else 80))

    def signature(self) -> tuple:
        return (self.transport, tuple(self.command), tuple(sorted(self.env.items())), self.url,
                self.bearer, self.timeout, self.sandbox, self.confirm)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "transport": self.transport,
            "command": list(self.command),
            "env": dict(self.env),
            "url": self.url,
            "bearer": self.bearer,
            "enabled": self.enabled,
            "confirm": self.confirm,
            "timeout": self.timeout,
            "sandbox": self.sandbox,
        }

    @classmethod
    def from_dict(cls, data) -> McpServerConfig | None:
        if not isinstance(data, dict) or not isinstance(data.get("name"), str):
            return None
        out = cls(name=data["name"])
        if data.get("transport") in TRANSPORTS:
            out.transport = data["transport"]
        command = data.get("command")
        if isinstance(command, list) and all(isinstance(c, str) for c in command):
            out.command = tuple(command)
        env = data.get("env")
        if isinstance(env, dict):
            out.env = {k: v for k, v in env.items() if isinstance(k, str) and isinstance(v, str)}
        for key in ("url", "sandbox"):
            if isinstance(data.get(key), str):
                setattr(out, key, data[key])
        for key in ("bearer", "enabled"):
            if isinstance(data.get(key), bool):
                setattr(out, key, data[key])
        if data.get("confirm") in CONFIRMS:
            out.confirm = data["confirm"]
        timeout = data.get("timeout")
        if (
            isinstance(timeout, (int, float))
            and not isinstance(timeout, bool)
            and 0 < timeout <= 3600
        ):
            out.timeout = float(timeout)
        return out if not out.problems() else None


def keyring_service(name: str) -> str:
    return f"axross-mcp-server/{name}"


def get_token(name: str) -> str:
    try:
        import keyring

        return keyring.get_password(keyring_service(name), "token") or ""
    except Exception as exc:  # noqa: BLE001 - no keyring: no token
        log.debug("mcp client: no token for %s: %s", name, exc)
        return ""


def set_token(name: str, token: str) -> None:
    import keyring

    if token:
        keyring.set_password(keyring_service(name), "token", token)
    else:
        try:
            keyring.delete_password(keyring_service(name), "token")
        except Exception:  # noqa: BLE001 - nothing stored
            pass


# -- transports ------------------------------------------------------------------


class _Stdio:
    def __init__(self, argv: list[str], env: dict, timeout: float) -> None:
        self._timeout = timeout
        base = {
            k: v
            for k, v in os.environ.items()
            if k
            in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "XDG_RUNTIME_DIR", "USER")
        }
        try:
            self._proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={**base, **env}, start_new_session=True,
            )
        except OSError as exc:
            raise McpClientError(f"cannot start {argv[0]}: {exc}") from None
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._waiting: dict[int, dict] = {}
        self._closed = False
        self.stderr: list[str] = []
        threading.Thread(target=self._read, daemon=True, name="mcp-client-stdio").start()
        threading.Thread(target=self._drain, daemon=True, name="mcp-client-stderr").start()

    def _drain(self) -> None:
        for raw in iter(self._proc.stderr.readline, b""):
            self.stderr = (self.stderr + [raw.decode("utf-8", "replace").rstrip()])[-20:]

    def _write(self, message: dict) -> None:
        data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        with self._write_lock:
            try:
                self._proc.stdin.write(data)
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                raise McpClientError("the server closed its input") from None

    def _read(self) -> None:
        while True:
            line = self._proc.stdout.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_MESSAGE_BYTES:
                log.warning(
                    "mcp client: an answer over %d bytes - the server is dropped", MAX_MESSAGE_BYTES
                )
                break
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if not isinstance(message, dict):
                continue
            if "method" in message:
                self._answer_server(message)
                continue
            with self._lock:
                slot = self._waiting.get(message.get("id"))
            if slot is not None:
                slot["reply"] = message
                slot["event"].set()
        with self._lock:
            self._closed = True
            waiting = list(self._waiting.values())
        for slot in waiting:
            slot["event"].set()

    def _answer_server(self, message: dict) -> None:
        """A request of the server: ping is answered, anything else refused."""
        if "id" not in message:
            return  # a notification
        if message.get("method") == "ping":
            reply = {"jsonrpc": "2.0", "id": message["id"], "result": {}}
        else:
            reply = {"jsonrpc": "2.0", "id": message["id"],
                     "error": {"code": -32601, "message": "axross offers no client features"}}
        try:
            self._write(reply)
        except McpClientError:
            pass

    def request(self, ident: int, message: dict) -> dict:
        slot = {"event": threading.Event(), "reply": None}
        with self._lock:
            if self._closed:
                raise McpClientError(self._ended())
            self._waiting[ident] = slot
        try:
            self._write(message)
            if not slot["event"].wait(self._timeout):
                raise McpClientError(f"no answer within {self._timeout:g} s")
        finally:
            with self._lock:
                self._waiting.pop(ident, None)
        if slot["reply"] is None:
            raise McpClientError(self._ended())
        return slot["reply"]

    def notify(self, message: dict) -> None:
        self._write(message)

    def _ended(self) -> str:
        tail = " | ".join(line for line in self.stderr if line)[-400:]
        return "the server ended" + (f": {tail}" if tail else "")

    def close(self) -> None:
        proc = self._proc
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


class _Http:
    def __init__(self, url: str, token: str, timeout: float) -> None:
        self._url = url
        self._token = token
        self._timeout = timeout
        self._session: str | None = None
        self._version: str | None = None

    def _post(self, message: dict) -> tuple[dict | None, dict]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        if self._version:
            headers["MCP-Protocol-Version"] = self._version
        request = urllib.request.Request(self._url, data=json.dumps(message).encode("utf-8"),
                                         headers=headers, method="POST")
        from core.agent_net import opener_without_redirects

        host = urlsplit(self._url).hostname
        deadline = time.monotonic() + self._timeout
        try:
            with opener_without_redirects().open(request, timeout=self._timeout) as response:
                session = response.headers.get("Mcp-Session-Id")
                if session:
                    self._session = session
                kind = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if response.status == 202 or "id" not in message:
                    return None, dict(response.headers)
                body = b""
                while len(body) <= MAX_MESSAGE_BYTES:
                    # The whole answer within the timeout, not each read: a
                    # server that drips would hold the agent forever.
                    if time.monotonic() > deadline:
                        raise McpClientError(f"no answer within {self._timeout:g} s")
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    body += chunk
                    if kind == "text/event-stream" and _from_events(body.decode("utf-8", "replace"),
                                                                    message.get("id")) is not None:
                        break  # a stream may stay open after the answer
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise McpClientError(
                    f"{host} answered a redirect (HTTP {exc.code}), which is not followed"
                ) from None
            raise McpClientError(f"{host} answered HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise McpClientError(f"cannot reach {host}: {getattr(exc, 'reason', exc)}") from None
        if len(body) > MAX_MESSAGE_BYTES:
            raise McpClientError(f"an answer over {MAX_MESSAGE_BYTES} bytes")
        if kind == "text/event-stream":
            return _from_events(body.decode("utf-8", "replace"), message.get("id")), {}
        try:
            reply = json.loads(body)
        except ValueError:
            raise McpClientError(f"{host} did not answer JSON") from None
        return (reply if isinstance(reply, dict) else None), {}

    def request(self, ident: int, message: dict) -> dict:
        reply, _ = self._post(message)
        if reply is None:
            raise McpClientError("the server sent no answer")
        return reply

    def notify(self, message: dict) -> None:
        self._post(message)

    def set_version(self, version: str) -> None:
        self._version = version

    def close(self) -> None:
        if not self._session:
            return
        headers = {"Mcp-Session-Id": self._session}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        from core.agent_net import opener_without_redirects

        try:
            opener_without_redirects().open(
                urllib.request.Request(self._url, headers=headers, method="DELETE"), timeout=5
            ).close()
        except Exception:  # noqa: BLE001 - ending a session is best effort
            pass


def _from_events(text: str, ident) -> dict | None:
    """The JSON-RPC answer with *ident* in a server-sent event stream."""
    data: list[str] = []
    for line in text.splitlines() + [""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and data:
            try:
                message = json.loads("\n".join(data))
            except ValueError:
                message = None
            data = []
            if isinstance(message, dict) and message.get("id") == ident and "method" not in message:
                return message
    return None


# -- the client ------------------------------------------------------------------------


@dataclass
class ExternalTool:
    """A tool of another MCP server, as the agent offers it. Not run by
    core.mcp_server's dispatcher: :meth:`call` asks the server."""

    name: str
    description: str
    schema: dict
    write: bool
    client: "McpClient"
    remote_name: str
    always_ask: bool
    group: str = "mcp"
    accepts_backend: bool = False
    external: bool = True

    def call(self, args: dict) -> tuple[str, str]:
        """``(outcome, text)``: "ok" or "error"."""
        try:
            result = self.client.call_tool(self.remote_name, args)
        except McpClientError as exc:
            return "error", f"error: {self.client.config.name}: {exc}"
        parts = []
        for item in result.get("content") or []:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            elif isinstance(item, dict):
                parts.append(f"[{item.get('type', 'binary')} result, not shown]")
        if not parts and result.get("structuredContent") is not None:
            parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
        text = "\n".join(parts)
        if result.get("isError") is True:
            return "error", f"error: {text}" if text else "error: the tool failed"
        return "ok", text


def tool_name(server: str, tool: str) -> str:
    return (server + SEPARATOR + _TOOL_CHARS.sub("_", tool))[:MAX_NAME]


def is_external(name: str) -> bool:
    return SEPARATOR in name


def _schema(raw) -> dict:
    """A foreign input schema as the agent offers it: an object schema
    whose properties map names to schemas, within MAX_SCHEMA_BYTES."""
    empty = {"type": "object", "properties": {}}
    if not isinstance(raw, dict) or raw.get("type") != "object":
        return empty
    try:
        size = len(json.dumps(raw))
    except (TypeError, ValueError):
        return empty
    if size > MAX_SCHEMA_BYTES:
        return empty
    out = dict(raw)
    props = raw.get("properties")
    out["properties"] = (
        {k: v for k, v in props.items() if isinstance(k, str) and isinstance(v, dict)}
        if isinstance(props, dict)
        else {}
    )
    required = raw.get("required")
    if isinstance(required, list) and all(isinstance(r, str) for r in required):
        out["required"] = [r for r in required if r in out["properties"]]
    else:
        out.pop("required", None)
    return out


class McpClient:
    """One connected server."""

    def __init__(self, config: McpServerConfig, *, token: str = "",
                 wrap: Callable[[list[str]], list[str]] | None = None) -> None:
        """*wrap* turns a stdio argv into the sandboxed one."""
        self.config = config
        self._lock = threading.Lock()
        self._next = 0
        if config.transport == "stdio":
            argv = list(config.command)
            self._transport = _Stdio(wrap(argv) if wrap else argv, dict(config.env), config.timeout)
        else:
            self._transport = _Http(config.url, token, config.timeout)
        try:
            self.server_info = self._initialize()
        except Exception:
            self.close()
            raise

    def _call(self, method: str, params: dict) -> dict:
        with self._lock:
            self._next += 1
            ident = self._next
        reply = self._transport.request(ident, {"jsonrpc": "2.0", "id": ident, "method": method,
                                                "params": params})
        if "error" in reply:
            error = reply["error"] if isinstance(reply["error"], dict) else {}
            raise McpClientError(str(error.get("message") or "the server refused")[:500])
        result = reply.get("result")
        if not isinstance(result, dict):
            raise McpClientError("the server's answer has no result")
        return result

    def _initialize(self) -> dict:
        from axross._version import __version__

        result = self._call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "axross", "version": __version__},
            },
        )
        version = result.get("protocolVersion")
        if isinstance(version, str) and isinstance(self._transport, _Http):
            self._transport.set_version(version)
        self._transport.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        info = result.get("serverInfo")
        return info if isinstance(info, dict) else {}

    def tools(self) -> list[ExternalTool]:
        out: list[ExternalTool] = []
        cursor = None
        seen: set = set()
        for _page in range(20):
            result = self._call("tools/list", {"cursor": cursor} if cursor else {})
            for raw in result.get("tools") or []:
                if len(out) >= MAX_TOOLS:
                    break
                if (
                    not isinstance(raw, dict)
                    or not isinstance(raw.get("name"), str)
                    or not raw["name"]
                ):
                    continue
                name = tool_name(self.config.name, raw["name"])
                if name in seen:
                    continue
                seen.add(name)
                annotations = (
                    raw.get("annotations") if isinstance(raw.get("annotations"), dict) else {}
                )
                read_only = annotations.get("readOnlyHint") is True
                always = self.config.confirm == "always"
                description = str(raw.get("description") or "")[:MAX_DESCRIPTION]
                out.append(ExternalTool(
                    name=name,
                    description=f"[{self.config.name}] {description}".strip(),
                    schema=_schema(raw.get("inputSchema")),
                    write=always or not read_only,
                    client=self,
                    remote_name=raw["name"],
                    always_ask=always,
                ))
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor or len(out) >= MAX_TOOLS:
                break
        return out

    def call_tool(self, name: str, args: dict) -> dict:
        return self._call("tools/call", {"name": name, "arguments": args})

    def close(self) -> None:
        try:
            self._transport.close()
        except Exception:  # noqa: BLE001 - closing is best effort
            log.debug("mcp client: closing %s failed", self.config.name, exc_info=True)


class McpClientPool:
    """The connected servers of the GUI, shared by every Agent tab:
    connected on first use, reconnected when their config changes."""

    def __init__(self, *, token_lookup: Callable[[str], str] | None = None,
                 wrap_for: Callable[[McpServerConfig], Callable | None] | None = None) -> None:
        self._token_lookup = token_lookup or get_token
        self._wrap_for = wrap_for or (lambda config: None)
        self._lock = threading.Lock()
        self._clients: dict[str, tuple[tuple, McpClient, list]] = {}
        self._always: set = set()

    def tools(self, configs, *, wrap_for=None) -> tuple[list[ExternalTool], list[str]]:
        """The tools of *configs* (connecting what is not yet) and one
        error line per server that failed. *wrap_for* replaces the pool's
        own for this call."""
        tools: list[ExternalTool] = []
        errors: list[str] = []
        for config in configs:
            try:
                tools.extend(self._tools_of(config, wrap_for or self._wrap_for))
            except McpClientError as exc:
                errors.append(f"{config.name}: {exc}")
        return tools, errors

    def _tools_of(self, config: McpServerConfig, wrap_for) -> list[ExternalTool]:
        with self._lock:
            held = self._clients.get(config.name)
            if held is not None and held[0] == config.signature():
                return list(held[2])
        if held is not None:
            self.drop(config.name)
        token = self._token_lookup(config.name) if config.bearer else ""
        client = McpClient(config, token=token, wrap=wrap_for(config))
        try:
            found = client.tools()
        except Exception:
            client.close()
            raise
        with self._lock:
            old = self._clients.get(config.name)
            self._clients[config.name] = (config.signature(), client, found)
            self._always |= {t.name for t in found if t.always_ask}
        if old is not None:
            old[1].close()
        return list(found)

    def always_ask(self, name: str) -> bool:
        with self._lock:
            return name in self._always

    def drop(self, name: str) -> None:
        with self._lock:
            held = self._clients.pop(name, None)
            if held is not None:
                self._always -= {t.name for t in held[2]}
        if held is not None:
            held[1].close()

    def keep_only(self, configs) -> None:
        """Close what is no longer configured as it is."""
        wanted = {c.name: c.signature() for c in configs}
        with self._lock:
            stale = [n for n, held in self._clients.items() if wanted.get(n) != held[0]]
        for name in stale:
            self.drop(name)

    def close_all(self) -> None:
        with self._lock:
            names = list(self._clients)
        for name in names:
            self.drop(name)
