"""Agent tabs as sessions: one simple JSON file per tab.

``~/.config/axross/agent/sessions/<id>.json`` (mode 0600)::

    {
      "version": 1,
      "id": "3f2a…",                    # 32 hex characters, also the file name
      "title": "Disk report",
      "created": "2026-10-17T14:02:11.204518",
      "updated": "2026-10-17T14:09:40.731002",
      "profile": "local",               # LLM profile, "" = the default
      "mode": "ask",                    # ask, plan, auto, bypass
      "sandbox": "Normal",              # sandbox profile, "" = none
      "folder": "~/Documents",
      "extra_folders": [{"path": "/srv/data", "mode": "ro"}],
      "groups": ["metadata", "filetype"],
      "allow_write": false,
      "allow_exec": false,
      "access": {"axross": false, "functions": ["mcp_servers"],   # core.agent_access
                 "network": "hosts", "hosts": ["db.example:5432"]},
      "transcript": [{"who": "You:", "text": "…", "muted": false}],
      "messages": [{"role": "user", "content": "…"}]   # what the model saw
    }

The transcript is what the tab shows; the messages are the conversation
the model continues from. Both hold file content the agent read: the
files are the user's own, 0600, and only kept when "Keep tabs" is on.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path

from core.agent_access import SessionAccess

log = logging.getLogger(__name__)

MODES = ("ask", "plan", "auto", "bypass")
_ID = re.compile(r"^[0-9a-f]{32}$")
#: Largest session file read back (a conversation with big tool results).
MAX_FILE_BYTES = 32 * 1024 * 1024


def sessions_dir() -> Path:
    return Path.home() / ".config" / "axross" / "agent" / "sessions"


def _now() -> str:
    # Microseconds: tabs opened within one second keep their order (the
    # order of the tabs is the order of "created").
    return datetime.now().isoformat(timespec="microseconds")


@dataclass
class AgentSession:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    title: str = "New task"
    created: str = field(default_factory=_now)
    updated: str = field(default_factory=_now)
    profile: str = ""
    mode: str = "ask"
    sandbox: str = ""
    folder: str = ""
    extra_folders: list = field(default_factory=list)  # [(path, writable)]
    groups: list = field(default_factory=list)
    allow_write: bool = False
    allow_exec: bool = False
    #: What the tab may reach (core.agent_access); None: a session from
    #: before, which takes Agent Settings > Access.
    access: SessionAccess | None = None
    transcript: list = field(default_factory=list)
    messages: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "id": self.id,
            "title": self.title,
            "created": self.created,
            "updated": self.updated,
            "profile": self.profile,
            "mode": self.mode,
            "sandbox": self.sandbox,
            "folder": self.folder,
            "extra_folders": [
                {"path": p, "mode": "rw" if w else "ro"} for p, w in self.extra_folders
            ],
            "groups": list(self.groups),
            "allow_write": self.allow_write,
            "allow_exec": self.allow_exec,
            **({"access": self.access.to_dict()} if self.access is not None else {}),
            "transcript": self.transcript,
            "messages": self.messages,
        }

    @classmethod
    def from_dict(cls, data) -> AgentSession | None:
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("id"), str)
            or not _ID.match(data["id"])
        ):
            return None
        out = cls(id=data["id"])
        for name in ("title", "created", "updated", "profile", "sandbox", "folder"):
            if isinstance(data.get(name), str):
                setattr(out, name, data[name])
        if data.get("mode") in MODES:
            out.mode = data["mode"]
        for name in ("allow_write", "allow_exec"):
            if isinstance(data.get(name), bool):
                setattr(out, name, data[name])
        out.access = SessionAccess.from_dict(data.get("access"))
        out.groups = [g for g in data.get("groups") or [] if isinstance(g, str)]
        out.extra_folders = [
            (os.path.normpath(e["path"]), e.get("mode") == "rw")
            for e in data.get("extra_folders") or []
            if isinstance(e, dict) and isinstance(e.get("path"), str) and os.path.isabs(e["path"])
        ]
        out.transcript = [
            {
                "who": str(e.get("who", "")),
                "text": str(e.get("text", "")),
                "muted": bool(e.get("muted")),
            }
            for e in data.get("transcript") or []
            if isinstance(e, dict)
        ]
        out.messages = [
            m
            for m in data.get("messages") or []
            if isinstance(m, dict) and isinstance(m.get("role"), str)
        ]
        return out


class SessionStore:
    """The session files of one folder."""

    def __init__(self, folder: Path | None = None) -> None:
        self.folder = Path(folder) if folder is not None else sessions_dir()

    def path(self, session_id: str) -> Path:
        if not _ID.match(session_id):
            raise ValueError(f"not a session id: {session_id!r}")
        return self.folder / f"{session_id}.json"

    def save(self, session: AgentSession) -> None:
        session.updated = _now()
        self.folder.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.folder, 0o700)
        except OSError:
            pass
        target = self.path(session.id)
        tmp = target.with_name(target.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(session.to_dict(), handle, ensure_ascii=False, indent=1)
        os.replace(tmp, target)

    def load(self, session_id: str) -> AgentSession | None:
        try:
            path = self.path(session_id)
            if path.stat().st_size > MAX_FILE_BYTES:
                log.warning("agent session %s is too large to load", session_id)
                return None
            return AgentSession.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return None

    def all(self) -> list[AgentSession]:
        """Every readable session, oldest first (the order of the tabs)."""
        out = []
        try:
            names = sorted(self.folder.glob("*.json"))
        except OSError:
            return out
        for path in names:
            session = self.load(path.stem) if _ID.match(path.stem) else None
            if session is None:
                if _ID.match(path.stem):
                    log.warning("agent session %s is unreadable: skipped", path.name)
                continue
            out.append(session)
        out.sort(key=lambda s: s.created)
        return out

    def delete(self, session_id: str) -> None:
        try:
            self.path(session_id).unlink()
        except (OSError, ValueError):
            pass
