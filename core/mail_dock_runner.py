"""Runs one mail dock: connects its mailbox, builds its agent (sandboxed
when the dock says so) with only the mail tools, and does one run - the
dock's timer (ui/mail_dock.py) calls :meth:`MailDockRunner.run_once` on a
thread of its own. Qt-free, so it is tested without a window.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable

from core import mail_dock as MD
from core import mail_send as MS

log = logging.getLogger(__name__)


class _ListingMailbox(MD.Mailbox):
    """The dock's mailbox, remembering the mails :meth:`new` listed."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.listed: list[str] = []

    def new(self, *, mark: bool = True) -> list[dict]:
        out = super().new(mark=mark)
        self.listed.extend(m["name"] for m in out)
        return out


class MailDockRunner:
    def __init__(
        self,
        dock: MD.MailDockConfig,
        *,
        ask_send: Callable[[object, str], bool],
        on_log: Callable[[str], None] = lambda text: None,
        on_event: Callable[[dict], None] = lambda event: None,
        connect: Callable[[MD.MailDockConfig], object] | None = None,
        llm: Callable[[MD.MailDockConfig], tuple] | None = None,
        sandbox: Callable[[MD.MailDockConfig], object] | None = None,
        state_dir: Path = MD.STATE_DIR,
        bus: MD.DockBus = MD.BUS,
    ):
        self.dock = dock
        self._ask_send, self._on_log, self._on_event = ask_send, on_log, on_event
        self._connect = connect or _connect_profile
        self._llm = llm or _llm_profile
        self._sandbox = sandbox or _sandbox_profile
        self.state_dir = Path(state_dir) / dock.dock_id
        self.bus = bus
        self.cancel = threading.Event()
        self._lock = threading.Lock()
        self.backend = None
        self.tools: MD.MailTools | None = None

    def _smtp(self) -> MS.SmtpSettings:
        d = self.dock
        if not d.smtp_host:
            raise OSError("this dock has no SMTP server")
        return MS.SmtpSettings(host=d.smtp_host, port=int(d.smtp_port), security=d.smtp_security,
                               username=d.smtp_username, password=MD.smtp_password(d),
                               from_address=d.from_address)

    def close(self) -> None:
        self.cancel.set()
        backend, self.backend = self.backend, None
        if backend is not None:
            try:
                backend.close()
            except Exception:  # noqa: BLE001
                log.debug("mail dock %s: close", self.dock.name, exc_info=True)

    def run_once(self) -> str:
        """One run: the agent's final answer ('' when there was nothing to do)."""
        if not self._lock.acquire(blocking=False):
            return ""                       # the last run is still going
        try:
            return self._run()
        finally:
            self._lock.release()

    def _run(self) -> str:
        from core import agent as A

        self.cancel.clear()
        if self.backend is None:
            self.backend = self._connect(self.dock)
        work = self.state_dir / "work"          # the agent's only folder: empty, read-only
        work.mkdir(parents=True, exist_ok=True)
        mailbox = _ListingMailbox(self.backend, self.dock.folder, self.state_dir / "seen.json")
        reports = self.bus.take(self.dock.name)
        if not reports and not mailbox.new(mark=False):
            return ""
        mailbox.listed.clear()      # the runner's own look; only the agent's listings count
        self.tools = tools = MD.MailTools(self.dock, mailbox, ask_send=self._ask_send, smtp=self._smtp,
                                          drafts_dir=self.state_dir / "drafts", bus=self.bus,
                                          on_log=self._on_log)
        profile, api_key = self._llm(self.dock)
        if profile is None:
            raise OSError("no LLM profile: choose one in the dock's settings or make one active")
        config = A.AgentConfig(
            # No file writes (allow_write off: the file tools read the empty
            # work folder only); the mail tools are kept - "Files read-only"
            # would drop them, they check the send policy themselves.
            profile=profile, root=str(work), api_key=api_key, groups=frozenset(), allow_write=False,
            files_read_only=False, system_prompt=MD.system_prompt(),
            functions=frozenset({"extensions"}),
            external_tools=lambda: (tools.function_tools(), []),
        )
        task = MD.run_task(self.dock, None, reports)
        sandbox = self._sandbox(self.dock)
        # The mail tools ask themselves (the send policy); the agent's own
        # confirmation only meets them - nothing else can write.
        confirm = lambda name, args: name in ("mail_draft", "mail_send", "dock_report")  # noqa: E731
        if sandbox is not None:
            from core.agent_sandbox import SandboxedAgent

            agent = SandboxedAgent(config, sandbox, confirm=confirm, on_event=self._on_event, cancel=self.cancel)
        else:
            agent = A.Agent(config, confirm=confirm, on_event=self._on_event, cancel=self.cancel)
        try:
            result = agent.run(task)
        finally:
            close = getattr(agent, "close", None)
            if callable(close):
                close()
        if result.stopped == "answered":
            # The run ended without error: what the agent listed counts as
            # handled, opened or not - a mail it saw and left alone came
            # back in every run. A failed, cancelled or cut-off run (an
            # exception above, "cancelled", "max_steps") marks only what
            # the agent read (MailTools does that itself).
            for name in dict.fromkeys(mailbox.listed):
                mailbox.mark_seen(name)
        self._on_log(result.answer or f"(the run ended: {result.stopped})")
        return result.answer


def _connect_profile(dock: MD.MailDockConfig):
    from core.connection_manager import ConnectionManager
    from core.profiles import ProfileManager

    profile = ProfileManager().get(dock.mailbox_profile)
    if profile is None:
        raise OSError(f"the mailbox profile {dock.mailbox_profile!r} does not exist")
    if profile.protocol not in ("imap", "pop3", "exchange"):
        raise OSError(f"{dock.mailbox_profile!r} is a {profile.protocol} profile, not a mailbox")
    return ConnectionManager().connect(profile)


def _llm_profile(dock: MD.MailDockConfig):
    from core import llm_profiles as LP

    settings = LP.LLMSettings.load()
    profile = (settings.profile(dock.llm_profile) if dock.llm_profile else None) or settings.active_profile()
    return profile, (LP.get_api_key(profile.name) if profile is not None else "")


def _sandbox_profile(dock: MD.MailDockConfig):
    if not dock.sandbox:
        return None
    from core import agent_settings as AGS

    profile = AGS.AgentSettings.load().sandbox_profile(dock.sandbox)
    if profile is None:
        raise OSError(f"the sandbox profile {dock.sandbox!r} does not exist")
    return profile
