"""Topics: prepared tasks for the agent, for the work besides code - look
at a host, install software, collect logs. A topic fills the task field of
an Agent tab (Topics ▸); the user reads it, changes it and sends it.

``{folder}`` in a topic's task becomes the tab's folder and ``{backend}``
the remote connection of the active pane (or "the remote host"). Nothing
else in the text is touched, so braces in commands stay as they are.

Extensions add their own (``api.add_agent_topic``).
"""

from __future__ import annotations

from dataclasses import dataclass


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
    #: "axross" or the extension's id.
    source: str = "axross"

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
    ),
    Topic(
        "Install or update software",
        "On {backend}: find out which package manager the system uses, check whether the package "
        "<name> is installed and in which version, and show the exact commands to install or "
        "update it. Do not run anything that changes the system before I approved the plan.",
        "A plan first, then the install",
        mode="plan",
        needs=("exec",),
    ),
    Topic(
        "Service status",
        "On {backend}: list the failed systemd units and the state of the service <name> "
        "(systemctl status, journalctl -u <name> -n 50 --no-pager). Explain what is wrong and what "
        "you would do; change nothing.",
        "What runs, what failed, why",
        needs=("exec",),
    ),
    Topic(
        "Collect logs",
        "On {backend}: collect the last 500 lines of the system journal and of the logs under "
        "/var/log that changed in the last 24 hours, and save them into "
        "{folder}/logs-<host>-<date>/ on this machine, one file per log. "
        "Then summarise errors and warnings.",
        "Logs of a host into a local folder",
        needs=("exec", "remote", "write"),
    ),
    Topic(
        "Disk usage",
        "Find what takes the space in {folder}: the 20 largest files and folders, and files not "
        "changed for more than a year. Change nothing; suggest what could go.",
        "Largest and oldest files",
    ),
    Topic(
        "Summarise a folder",
        "Look through {folder}: what kinds of files are there, how is it organised, what stands "
        "out (duplicates, very large or empty files, odd names)? A short report.",
        "An overview of a folder",
    ),
    Topic(
        "Read data out",
        "From the files in {folder}: extract <what you need> into one CSV file "
        "{folder}/extract.csv with a header line. "
        "Tell me which files you used and what you could not read.",
        "Pull data out of files into a CSV",
        needs=("write",),
    ),
)
