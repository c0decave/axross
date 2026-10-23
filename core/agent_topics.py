"""Topics: prepared tasks for the agent, for the work besides code - look
at a host, install software, collect logs. A topic fills the task field of
an Agent tab (Topics ▸); the user reads it, changes it and sends it.

``{folder}`` in a topic's task becomes the tab's folder and ``{backend}``
the remote connection of the active pane (or "the remote host"). Nothing
else in the text is touched, so braces in commands stay as they are.

Extensions add their own (``api.add_agent_topic``); the user's own - the
"work prompts" - live in
``~/.config/axross/agent/work_prompts.json`` and are written in the dock's
Topics ▸ + New Topic… (changed or deleted in Edit or Delete My Topics…).
Every topic has a slash command: typing
``/free-space`` in the task field picks it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path

log = logging.getLogger(__name__)

MAX_TITLE = 80
MAX_TASK = 20_000
MAX_DESCRIPTION = 200
#: What a topic may ask to have switched on.
NEEDS = ("exec", "remote", "write")
#: Protection modes a topic may suggest (core.agent_settings.MODES).
TOPIC_MODES = ("ask", "plan", "auto")
_COMMAND = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


@dataclass(frozen=True)
class Topic:
    title: str
    task: str
    description: str = ""
    #: The protection mode the topic suggests (plan for installs), or None.
    mode: str | None = None
    #: What it needs switched on: "exec" (remote commands), "remote"
    #: (remote files), "write" (changes).
    needs: tuple[str, ...] = ()
    #: "axross", "user" or the extension's id.
    source: str = "axross"
    #: The slash command (without "/"); "" derives one from the title.
    command: str = ""
    #: Tool groups the topic ticks in the tab (core.agent_settings.OFFERED_GROUPS).
    groups: tuple[str, ...] = ()

    def render(self, folder: str, backend: str = "") -> str:
        return self.task.replace("{folder}", folder or "the folder").replace(
            "{backend}", backend or "the remote host")


BUILTIN_TOPICS: tuple[Topic, ...] = (
    Topic(
        "System inventory",
        "Make an inventory of {backend}: operating system and version, kernel, CPU, memory, "
        "disks and file systems with their usage, network interfaces, uptime. Use only commands "
        "that read (uname, cat /etc/os-release, lscpu, free, df, ip addr, uptime). Report it as a "
        "short table.",
        "Read-only facts about a host",
        needs=("exec",),
        command="inventory",
    ),
    Topic(
        "Install or update software",
        "On {backend}: find out which package manager the system uses, check whether the package "
        "<name> is installed and in which version, and show the exact commands to install or "
        "update it. Do not run anything that changes the system before I approved the plan.",
        "A plan first, then the install",
        mode="plan",
        needs=("exec",),
        command="install",
    ),
    Topic(
        "Service status",
        "On {backend}: list the failed systemd units and the state of the service <name> "
        "(systemctl status, journalctl -u <name> -n 50 --no-pager). Explain what is wrong and what "
        "you would do; change nothing.",
        "What runs, what failed, why",
        needs=("exec",),
        command="service",
    ),
    Topic(
        "Collect logs",
        "On {backend}: collect the last 500 lines of the system journal and of the logs under "
        "/var/log that changed in the last 24 hours, and save them into "
        "{folder}/logs-<host>-<date>/ on this machine, one file per log. "
        "Then summarise errors and warnings.",
        "Logs of a host into a local folder",
        needs=("exec", "remote", "write"),
        command="logs",
    ),
    Topic(
        "Disk usage",
        "Find what takes the space in {folder}: the 20 largest files and folders, and files not "
        "changed for more than a year. Change nothing; suggest what could go.",
        "Largest and oldest files",
        command="disk-usage",
    ),
    Topic(
        "Summarise a folder",
        "Look through {folder}: what kinds of files are there, how is it organised, what stands "
        "out (duplicates, very large or empty files, odd names)? A short report.",
        "An overview of a folder",
        command="summarise",
    ),
    Topic(
        "Read data out",
        "From the files in {folder}: extract <what you need> into one CSV file "
        "{folder}/extract.csv with a header line. "
        "Tell me which files you used and what you could not read.",
        "Pull data out of files into a CSV",
        needs=("write",),
        command="extract",
    ),
    Topic(
        "Review a config folder",
        "Analyse the configuration in {folder} (on {backend} if it is remote): read the files, "
        "then list what should be improved - insecure permissions or owners, secrets in plain "
        "text, deprecated or contradicting options, missing hardening, leftovers such as backup "
        "copies. For each point: the file and line, why it matters, the change you suggest. "
        "Change nothing.",
        "What should be improved in a config folder (e.g. /etc)",
        command="review-config",
        groups=("filetype",),
    ),
    Topic(
        "Free disk space",
        "Check where disk space can be saved in {folder}: the largest files and folders, "
        "duplicate files (use the duplicate finder tools: find duplicates, then list each set "
        "with its size and which copy to keep), old caches, logs and archives that were "
        "unpacked. Give the space each step frees and the total. Delete nothing; I decide.",
        "Largest files, duplicates and what could go",
        command="free-space",
        groups=("duplicates", "index"),
    ),
)


# -- slash commands -----------------------------------------------------------------


def command_of(topic: Topic) -> str:
    """The topic's slash command without "/": its own, or one made from the
    title (lower case ASCII letters and digits, words joined by "-")."""
    if topic.command:
        return topic.command
    words = re.findall(r"[a-z0-9]+", topic.title.lower())
    return "-".join(words)[:32].strip("-")


def find_topic(topics, command: str) -> Topic | None:
    """The topic whose command is *command* ("/name" or "name"), or None."""
    wanted = command.lstrip("/").strip()
    return next((t for t in topics if command_of(t) == wanted), None)


# -- the user's own topics ("work prompts") -------------------------------------------


def user_topics_file() -> Path:
    from core.agent_settings import agent_dir

    return agent_dir() / "work_prompts.json"


def validate_topic(topic: Topic) -> None:
    """Raise ValueError naming the field when *topic* cannot be stored."""
    from core.agent_settings import OFFERED_GROUPS

    if not isinstance(topic.title, str) or not topic.title.strip() or len(topic.title) > MAX_TITLE:
        raise ValueError(f"title must be 1 to {MAX_TITLE} characters")
    if not isinstance(topic.task, str) or not topic.task.strip() or len(topic.task) > MAX_TASK:
        raise ValueError(f"task must be 1 to {MAX_TASK} characters")
    if not isinstance(topic.description, str) or len(topic.description) > MAX_DESCRIPTION:
        raise ValueError(f"description must be at most {MAX_DESCRIPTION} characters")
    if topic.command and not (isinstance(topic.command, str) and _COMMAND.match(topic.command)):
        raise ValueError(
            "command must be lower case letters, digits and '-', 1 to 32 characters, without '/'"
        )
    if topic.mode is not None and topic.mode not in TOPIC_MODES:
        raise ValueError(f"mode must be one of {', '.join(TOPIC_MODES)} or none")
    if not all(n in NEEDS for n in topic.needs):
        raise ValueError(f"needs may only hold {', '.join(NEEDS)}")
    if not all(g in OFFERED_GROUPS for g in topic.groups):
        raise ValueError(f"groups may only hold {', '.join(OFFERED_GROUPS)}")
    if not command_of(topic):
        raise ValueError("command: the title has no letters to make one from; give a command")


def _from_json(raw) -> Topic:
    if not isinstance(raw, dict):
        raise ValueError("an entry must be an object")
    mode = raw.get("mode")
    topic = Topic(
        title=raw.get("title", ""),
        task=raw.get("task", ""),
        description=raw.get("description", "") or "",
        mode=mode if mode else None,
        needs=tuple(raw.get("needs") or ()),
        source="user",
        command=raw.get("command", "") or "",
        groups=tuple(raw.get("groups") or ()),
    )
    validate_topic(topic)
    return topic


def _read_user_topics(path: Path, *, quiet: bool = False) -> tuple[list[Topic], bool]:
    """``(topics, complete)`` from *path*: complete is False when the file
    exists but something in it could not be read (and was skipped)."""
    warn = (lambda *a: None) if quiet else log.warning
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], True
    except (OSError, ValueError) as exc:
        warn("Work prompts: %s is not readable (%s)", path, exc)
        return [], False
    entries = data.get("topics") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        warn("Work prompts: %s has no topic list", path)
        return [], False
    out: list[Topic] = []
    for index, raw in enumerate(entries):
        try:
            out.append(_from_json(raw))
        except (TypeError, ValueError) as exc:
            warn("Work prompts: entry %d of %s skipped: %s", index, path, exc)
    return out, len(out) == len(entries)


def load_user_topics() -> list[Topic]:
    """The user's topics; a missing or unreadable file is none, a bad entry
    is skipped (and logged) - the file is hand-editable."""
    return _read_user_topics(user_topics_file())[0]


#: Backups of one work prompts file at most (``.bak``, ``.bak.1`` ...).
MAX_BACKUPS = 100


def _backups(path: Path):
    """The backup names of *path*, in order: ``<name>.bak``, ``.bak.1`` ..."""
    yield path.with_name(path.name + ".bak")
    for n in range(1, MAX_BACKUPS):
        yield path.with_name(f"{path.name}.bak.{n}")


def _back_up_unreadable(path: Path) -> None:
    """Before a save replaces *path*: a copy of it as ``<name>.bak`` when the
    reader skipped part of it - a hand edit that broke the file or an entry
    must not vanish with the next save from the dialog. An earlier backup
    is never overwritten (it holds what an earlier save dropped): the copy
    goes to the next free ``<name>.bak.N``, unless one already holds the
    same bytes."""
    if _read_user_topics(path, quiet=True)[1]:
        return
    try:
        data = path.read_bytes()
        for backup in _backups(path):
            try:
                fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                try:
                    if backup.read_bytes() == data:
                        return  # this content is kept already
                except OSError:
                    pass
                continue
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(backup, 0o600)
            break
        else:
            raise OSError(f"all {MAX_BACKUPS} backup names are taken")
    except OSError as exc:
        raise OSError(f"{path} has entries that could not be read and no backup could be made "
                      f"({exc}); not overwritten") from exc
    log.warning("Work prompts: %s had unreadable entries; kept as %s", path, backup)


def save_user_topics(topics: list[Topic]) -> None:
    """Store the user's topics (private file, written atomically). Raises
    ValueError for an invalid topic or a command used twice or by a
    built-in topic."""
    builtin = {command_of(t) for t in BUILTIN_TOPICS}
    seen: set[str] = set()
    for topic in topics:
        validate_topic(topic)
        command = command_of(topic)
        if command in builtin:
            raise ValueError(f"command /{command} belongs to a built-in topic; choose another")
        if command in seen:
            raise ValueError(f"command /{command} is used twice")
        seen.add(command)
    path = user_topics_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    _back_up_unreadable(path)
    payload = {"topics": [
        {k: v for k, v in asdict(replace(t, source="user")).items() if k != "source"} for t in topics
    ]}
    fd, tmp = tempfile.mkstemp(prefix=".work_prompts.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
