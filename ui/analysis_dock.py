"""Analysis dock: sift's explanation of the file selected in the active pane.

Two lanes, each its own background thread and worker process:

* **auto** - sift without an LLM, for every selection while the dock is
  open. The latest selection wins: a request that has not started is
  replaced, a running one older than CANCEL_AFTER_SECONDS is cancelled.
* **llm** - sift with the active LLM profile, on request: a FIFO queue. A
  model can take minutes, so this lane is never cancelled by a new
  selection and never holds up the auto lane; its answers are kept for the
  session and shown when a file is selected again. A folder or several
  selected files are offered as a batch (at most MAX_BATCH files, a folder
  listed on a background thread, files only); a single click on "Analyse
  with LLM" goes before the waiting batch, and Stop drops what still waits.

Only the answers for the file on screen are shown: its automatic result
(``_latest``) and its LLM request (``_latest_llm``), each tracked on its
own, so neither drops the other. A failed LLM answer leaves the automatic
result on screen with the error above it. Live progress shows counts only:
sift removes secrets from the model's answer once it is complete, and the
raw stream would show what it is about to hide.

Everything sift returns is derived from the file's content - the file can
be hostile - so every value is HTML-escaped before it reaches the
QTextBrowser, which loads no resources and opens no links.
"""

from __future__ import annotations

import collections
import html
import logging
import threading
import time
from typing import Callable

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDockWidget,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core import llm_profiles as LP
from core.file_analysis import AnalysisResult, FileAnalyzer, Target
from core.i18n import tr

log = logging.getLogger(__name__)

#: A running auto analysis older than this is cancelled when another file is selected.
CANCEL_AFTER_SECONDS = 2.0
#: Most files one batch may queue.
MAX_BATCH = 500


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _strings(value) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(v) for v in value if v is not None and str(v).strip()]


def _list(title: str, values: list[str]) -> str:
    if not values:
        return ""
    items = "".join(f"<li>{_esc(v)}</li>" for v in values)
    return f"<h4>{_esc(tr(title))}</h4><ul>{items}</ul>"


def _number(value) -> str:
    return f"{value:,}" if isinstance(value, int) and not isinstance(value, bool) else str(value)


def _stats(calls: list) -> str:
    """One line on what the model calls cost."""
    calls = [c for c in calls if isinstance(c, dict)]
    if not calls:
        return ""
    prompt = sum(c["prompt_tokens"] for c in calls if isinstance(c.get("prompt_tokens"), int))
    completion = sum(
        c["completion_tokens"] for c in calls if isinstance(c.get("completion_tokens"), int)
    )
    bits = [
        tr("{n} model call(s)").format(n=len(calls)),
        tr("{p} prompt / {c} answer tokens").format(p=_number(prompt), c=_number(completion)),
    ]
    last = calls[-1]
    if isinstance(last.get("tokens_per_second"), (int, float)):
        bits.append(f"{last['tokens_per_second']:.1f} tok/s")
    if isinstance(last.get("ttft_seconds"), (int, float)):
        bits.append(tr("first token after {s:.2f} s").format(s=last["ttft_seconds"]))
    return " · ".join(bits)


def render_result_html(result: AnalysisResult) -> str:
    """The dock body for one result. Every file-derived value is escaped."""
    if not result.ok:
        return f"<p><b>{_esc(tr('Analysis failed'))}</b></p><p>{_esc(result.error)}</p>"
    s = result.summary if isinstance(result.summary, dict) else {}
    parts: list[str] = []
    facts = [
        s.get("classification"),
        s.get("kind"),
        s.get("size_human"),
        s.get("language"),
        s.get("natural_language"),
        s.get("category"),
    ]
    facts = [str(f) for f in facts if f not in (None, "")]
    if facts:
        parts.append(
            f"<p><b>{_esc(facts[0])}</b>" + "".join(f" · {_esc(f)}" for f in facts[1:]) + "</p>"
        )
    if s.get("summary"):
        parts.append(f"<p>{_esc(s['summary'])}</p>")
    parts.append(_list("Key points", _strings(s.get("key_points"))))
    parts.append(_list("Entities", _strings(s.get("entities"))))
    tags = _strings(s.get("tags"))
    if tags:
        parts.append(f"<p><b>{_esc(tr('Tags'))}:</b> " + ", ".join(_esc(t) for t in tags) + "</p>")
    findings = []
    for f in s.get("findings") or []:
        if isinstance(f, dict):
            findings.append(f"{f.get('kind', '')}: {f.get('text', '')}".strip(": "))
        elif f is not None:
            findings.append(str(f))
    parts.append(_list("Findings", findings))
    parts.append(_list("Warnings", _strings(s.get("warnings"))))
    parts.append(_list("Notes", _strings(s.get("notes"))))
    if s.get("error"):
        parts.append(f"<p><b>{_esc(tr('Error'))}:</b> {_esc(s['error'])}</p>")
    origin = (
        tr("Explained by sift with an LLM")
        if s.get("llm_used")
        else tr("Explained by sift without an LLM")
    )
    detail = []
    if s.get("llm_used") and s.get("model"):
        detail.append(str(s["model"]))
    if result.from_cache or result.from_session_cache:
        detail.append(tr("from cache"))
    elif result.elapsed:
        detail.append(
            f"{result.elapsed * 1000:.0f} ms" if result.elapsed < 1 else f"{result.elapsed:.1f} s"
        )
    parts.append(
        f"<p><small>{_esc(origin)}"
        + (f" ({_esc(', '.join(detail))})" if detail else "")
        + "</small></p>"
    )
    stats = _stats(result.calls)
    if stats:
        parts.append(f"<p><small>{_esc(stats)}</small></p>")
    return "".join(p for p in parts if p)


class _Lane(QObject):
    """One background thread and analyzer.

    ``fifo=False``: the latest request replaces one that waits. ``fifo=True``:
    requests wait in order; ``front`` puts one first.
    """

    finished = pyqtSignal(int, object)
    event = pyqtSignal(int, object)
    started = pyqtSignal(int)

    def __init__(
        self,
        analyzer_factory: Callable[[], FileAnalyzer],
        *,
        cancel_after: float | None,
        fifo: bool = False,
    ) -> None:
        super().__init__()
        self._factory = analyzer_factory
        self._cancel_after = cancel_after
        self._fifo = fifo
        self.analyzer: FileAnalyzer | None = None
        self._cond = threading.Condition()
        self._waiting: collections.deque = collections.deque()
        self._busy_since: float | None = None
        #: The cancel event of the job in flight: a cancel reaches that job only.
        self._job_cancel: threading.Event | None = None
        self._stop = False
        self._thread: threading.Thread | None = None

    def request(
        self, token: int, target: Target, force: bool, llm: dict | None, *, front: bool = False
    ) -> None:
        with self._cond:
            item = (token, target, force, llm)
            if not self._fifo:
                self._waiting.clear()
            if front:
                self._waiting.appendleft(item)
            else:
                self._waiting.append(item)
            busy = self._busy_since
            if (
                self._cancel_after is not None
                and busy is not None
                and time.monotonic() - busy > self._cancel_after
                and self._job_cancel is not None
            ):
                self._job_cancel.set()  # decided and done under the lock: this job only
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="axross-analysis", daemon=True
                )
                self._thread.start()
            self._cond.notify()

    def drop_waiting(self, tokens: set[int]) -> list[int]:
        """Remove the waiting requests with these tokens; return those removed."""
        with self._cond:
            kept = collections.deque(i for i in self._waiting if i[0] not in tokens)
            removed = [i[0] for i in self._waiting if i[0] in tokens]
            self._waiting = kept
        return removed

    def cached(self, target: Target, llm: dict | None) -> AnalysisResult | None:
        analyzer = self.analyzer
        return analyzer.cached(target, llm) if analyzer is not None else None

    def _run(self) -> None:
        while True:
            with self._cond:
                while not self._waiting and not self._stop:
                    self._cond.wait()
                if self._stop:
                    return
                token, target, force, llm = self._waiting.popleft()
                self._busy_since = time.monotonic()
                cancel = self._job_cancel = threading.Event()
            self.started.emit(token)
            try:
                if self.analyzer is None:
                    self.analyzer = self._factory()
                result = self.analyzer.analyse(
                    target,
                    force=force,
                    llm=llm,
                    on_event=(lambda e, t=token: self.event.emit(t, e)) if llm else None,
                    cancel=cancel,
                )
            except Exception as exc:  # never let the thread die
                log.exception("analysis of %s failed", target.path)
                result = AnalysisResult(False, error=f"{type(exc).__name__}: {exc}")
            with self._cond:
                self._busy_since = None
                self._job_cancel = None
                if self._stop:
                    return  # the dock is gone: nobody to tell
            self.finished.emit(token, result)

    def shutdown(self) -> None:
        """Stop for good: no signal is sent after this, the job in flight is ended."""
        for signal in (self.finished, self.event, self.started):
            try:
                signal.disconnect()
            except TypeError:  # nothing connected
                pass
        with self._cond:
            self._stop = True
            if self._job_cancel is not None:
                self._job_cancel.set()
            self._cond.notify()
        if self.analyzer is not None:
            self.analyzer.close()


def _ask_remote(parent, profile: LP.LLMProfile, host: str) -> tuple[bool, bool]:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle(tr("Send the file to a remote LLM?"))
    # The name is the user's text: as rich text, "<!--" in it hid the host.
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setText(
        tr(
            "The profile {name} talks to {host}. Analysing this file sends its content there."
        ).format(name=profile.name, host=host)
    )
    # Parented to the box: setCheckBox() leaves the check box Python's, which
    # freed it on return - and the box, still holding it, crashed the next
    # time it was laid out again (any style change, e.g. a theme switch).
    remember = QCheckBox(tr("Do not ask again for this profile"), box)
    box.setCheckBox(remember)
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    box.setDefaultButton(QMessageBox.StandardButton.No)
    try:
        return box.exec() == QMessageBox.StandardButton.Yes, remember.isChecked()
    finally:
        box.deleteLater()  # a child of the dock: one per question otherwise


class AnalysisDock(QDockWidget):
    settings_requested = pyqtSignal()
    #: A feature key (core.features) to show in Help > Features….
    features_requested = pyqtSignal(str)

    def __init__(
        self,
        parent=None,
        *,
        analyzer_factory: Callable[[], FileAnalyzer] | None = None,
        available: Callable[[], bool] | None = None,
        settings_loader: Callable[[], LP.LLMSettings] | None = None,
        settings_saver: Callable[[LP.LLMSettings], None] | None = None,
        key_lookup: Callable[[str], str] | None = None,
        confirm_remote: Callable[[LP.LLMProfile, str], tuple[bool, bool]] | None = None,
    ) -> None:
        super().__init__(tr("Analysis"), parent)
        self.setObjectName("axAnalysisDock")
        from core.analysis_worker import sift_available

        factory = analyzer_factory or FileAnalyzer
        self._available = available or sift_available
        self._load_settings = settings_loader or LP.LLMSettings.load
        self._save_settings = settings_saver or (lambda s: s.save())
        self._key_lookup = key_lookup or LP.get_api_key
        self._confirm_remote = confirm_remote or (lambda p, h: _ask_remote(self, p, h))
        self._auto = _Lane(factory, cancel_after=CANCEL_AFTER_SECONDS)
        self._llm = _Lane(factory, cancel_after=None, fifo=True)
        for lane in (self._auto, self._llm):
            lane.finished.connect(self._on_finished)
            lane.event.connect(self._on_event)
        self._llm.started.connect(self._on_started)
        self._offer = None  # list[Target] | (backend, path) | None
        self._offer_label = ""
        self._started_at: dict[int, float] = {}
        self._rows: dict[int, QListWidgetItem] = {}
        self._row_targets: dict[int, Target] = {}
        self._row_results: dict[int, AnalysisResult] = {}
        self._lister = _Lister()
        self._lister.listed.connect(self._on_listed)
        #: (listing token, the offer it lists) of the listing whose answer is awaited.
        self._listing: tuple[int, object] | None = None
        self._stopped = False
        self._token = 0
        self._latest = -1  # the automatic (or queue row) request on screen
        self._latest_llm = -1  # the LLM request for the file on screen
        self._auto_result: AnalysisResult | None = None
        #: The model's answer for the file on screen, once it is there.
        self._llm_result: AnalysisResult | None = None
        self._target: Target | None = None
        self._profile: LP.LLMProfile | None = None

        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(6, 6, 6, 6)
        head = QHBoxLayout()
        self.mode_icon = QLabel()
        self.title = QLabel()
        self.title.setTextFormat(Qt.TextFormat.PlainText)
        self.title.setWordWrap(True)
        head.addWidget(self.mode_icon)
        head.addWidget(self.title, 1)
        layout.addLayout(head)
        self.progress_label = QLabel()
        self.progress_label.setTextFormat(Qt.TextFormat.PlainText)
        self.progress_label.hide()
        layout.addWidget(self.progress_label)
        self.body = QTextBrowser()
        self.body.setOpenLinks(False)
        self.body.anchorClicked.connect(self._on_link)
        self.body.setOpenExternalLinks(False)
        layout.addWidget(self.body, 1)
        self.batch_button = QPushButton()
        self.batch_button.clicked.connect(self.start_batch)
        self.batch_button.hide()
        layout.addWidget(self.batch_button)
        self.queue_list = QListWidget()
        self.queue_list.setMaximumHeight(160)
        self.queue_list.itemClicked.connect(self._show_row)
        self.queue_list.hide()
        layout.addWidget(self.queue_list)
        self.stop_button = QPushButton(tr("Stop the queue"))
        self.stop_button.clicked.connect(self.stop_queue)
        self.stop_button.hide()
        layout.addWidget(self.stop_button)
        buttons = QHBoxLayout()
        self.settings_button = QPushButton(tr("LLM…"))
        self.settings_button.setToolTip(tr("LLM profiles"))
        self.settings_button.clicked.connect(self.settings_requested.emit)
        self.again = QPushButton(tr("Analyse again"))
        self.again.clicked.connect(lambda: self._target and self.analyse(self._target, force=True))
        self.llm_button = QPushButton(tr("Analyse with LLM"))
        self.llm_button.clicked.connect(self.analyse_with_llm)
        buttons.addWidget(self.settings_button)
        buttons.addStretch(1)
        buttons.addWidget(self.again)
        buttons.addWidget(self.llm_button)
        layout.addLayout(buttons)
        self.setWidget(body)
        self._set_mode_icon(False)
        self.refresh_profiles()  # again on Show and after the profile dialog, never per selection
        self.show_message(tr("Select a file to see what it is."))

    # -- state ---------------------------------------------------------------
    def _set_mode_icon(self, with_llm: bool) -> None:
        self.mode_icon.setToolTip(
            tr("Analysis with an LLM") if with_llm else tr("Analysis without an LLM")
        )
        try:
            from ui import icon_provider

            self.mode_icon.setPixmap(
                icon_provider.icon("bot" if with_llm else "bot-off", 20).pixmap(20, 20)
            )
        except Exception:  # icon set unavailable: the tooltip says it anyway
            self.mode_icon.clear()

    def refresh_profiles(self) -> None:
        try:
            self._profile = self._load_settings().active_profile()
        except Exception:  # a broken settings file must not break the dock
            log.exception("LLM settings could not be read")
            self._profile = None
        self._update_buttons()

    def _update_buttons(self) -> None:
        has_target = self._target is not None
        self.again.setEnabled(has_target)
        self.llm_button.setEnabled(has_target and self._profile is not None)
        self.llm_button.setToolTip(
            tr("Explain this file with the LLM profile {name}").format(name=self._profile.name)
            if self._profile
            else tr("No LLM profile is active: set one up with LLM…")
        )

    def _next_token(self) -> int:
        self._token += 1
        self._latest = self._token
        return self._token

    def show_message(self, text: str) -> None:
        self._latest = self._latest_llm = -1  # no token is negative: a late result is dropped
        self._auto_result = self._llm_result = None
        self._target = None
        self._offer = None
        self.batch_button.hide()
        self.title.setText("")
        self.progress_label.hide()
        self.body.setHtml(f"<p>{_esc(text)}</p>")
        self._update_buttons()

    # -- batches ---------------------------------------------------------------
    # A reload of the pane (F5, an operation, the watcher) keeps the selection
    # and offers it again: the same offer on screen is kept as it is - its
    # listing in flight, its queued state - instead of being offered anew.
    def offer_batch(self, targets: list[Target], label: str) -> None:
        if isinstance(self._offer, list) and self._offer == list(targets):
            return
        self.show_message(label)
        self._offer, self._offer_label = list(targets), label
        self.batch_button.setText(tr("Analyse {n} file(s) with LLM").format(n=len(targets)))
        self._show_offer()

    def offer_folder(self, backend, path: str, name: str) -> None:
        offer = self._offer
        if isinstance(offer, tuple) and offer[0] is backend and offer[1] == path:
            return
        label = tr("Folder {name}").format(name=name)
        self.show_message(label)
        self._offer, self._offer_label = (backend, path), label
        self.batch_button.setText(tr("Analyse the files in {name} with LLM").format(name=name))
        self._show_offer()

    def _show_offer(self) -> None:
        self.batch_button.setEnabled(self._profile is not None)
        self.batch_button.setToolTip(
            "" if self._profile else tr("No LLM profile is active: set one up with LLM…")
        )
        self.batch_button.show()

    def start_batch(self) -> None:
        offer = self._offer
        if offer is None or self._profile is None:
            return
        if isinstance(offer, tuple):
            backend, path = offer
            self.batch_button.setEnabled(False)
            self.body.setHtml(f"<p><i>{_esc(tr('Listing the folder…'))}</i></p>")
            self._token += 1
            self._listing = (self._token, offer)
            self._lister.list(backend, path, self._token)
            return
        self.enqueue(offer)

    def _on_listed(self, token: int, targets, error: str) -> None:
        listing = self._listing
        if self._stopped or listing is None or listing[0] != token:
            return  # an older listing, or the dock is gone
        self._listing = None
        if listing[1] is not self._offer:
            return  # the user moved on to another file or folder
        if error:
            self.show_message(tr("The folder could not be listed: {error}").format(error=error))
            return
        if not targets:
            self.show_message(tr("The folder holds no files."))
            return
        self.enqueue(targets)

    def enqueue(self, targets: list[Target]) -> None:
        if len(targets) > MAX_BATCH:
            self.show_message(
                tr("{n} files are more than one batch takes ({max}); select fewer.").format(
                    n=len(targets), max=MAX_BATCH
                )
            )
            return
        request = self._llm_request(ask=True)
        if request is None:  # declined, or no profile: the offer stays as it was
            if self._offer is not None:
                self.body.setHtml(f"<p>{_esc(self._offer_label)}</p>")
                self._show_offer()
            return
        for target in targets:
            self._token += 1
            token = self._token
            row = QListWidgetItem(f"⏳ {target.name}")
            row.setData(Qt.ItemDataRole.UserRole, token)
            self.queue_list.addItem(row)
            self._rows[token] = row
            self._row_targets[token] = target
            self._llm.request(token, target, False, request)
        self.queue_list.show()
        self.stop_button.show()
        self.batch_button.hide()
        self.body.setHtml(
            f"<p>{_esc(tr('{n} file(s) queued for the LLM.').format(n=len(targets)))}</p>"
        )

    def stop_queue(self) -> None:
        waiting = {t for t, row in self._rows.items() if row.text().startswith("⏳")}
        for token in self._llm.drop_waiting(waiting):
            self._rows[token].setText(f"– {self._row_targets[token].name} ({tr('stopped')})")
        self.stop_button.hide()

    def _show_row(self, row: QListWidgetItem) -> None:
        token = row.data(Qt.ItemDataRole.UserRole)
        target = self._row_targets.get(token)
        if target is None:
            return
        self._target = target
        self._latest, self._latest_llm = -1, token
        self._auto_result = self._llm_result = None
        self.title.setText(target.name)
        self.progress_label.hide()  # the next event of this row shows it again
        result = self._row_results.get(token)
        if result is not None:
            self._on_finished(token, result)
        else:
            self.body.setHtml(f"<p><i>{_esc(row.text())}</i></p>")
        self._update_buttons()

    # -- requests --------------------------------------------------------------
    def _on_link(self, url) -> None:
        if url.scheme() == "axross" and url.path().startswith("features/"):
            self.features_requested.emit(url.path().split("/", 1)[1])

    def analyse(self, target: Target, *, force: bool = False) -> None:
        if not self._available():
            self.show_message(
                tr(
                    "File analysis needs the sift package, which is not installed in this "
                    "Python environment."
                )
            )
            self.body.append(
                '<p><a href="axross:features/extra:sift">' + _esc(tr("Show in Features…")) + "</a></p>"
            )
            return
        if not force and target == self._target:
            return  # on screen or under way already: a running LLM request is kept
        self._target = target
        self._offer = None  # a file replaces a folder or batch on offer
        self.batch_button.hide()
        self._latest_llm = -1
        self._auto_result = self._llm_result = None
        self.title.setText(target.name)
        self.progress_label.hide()
        self._update_buttons()
        # The cache is keyed without the API key: look it up without the keyring.
        probe = LP.worker_request(self._profile, "") if self._profile else None
        known = self._llm.cached(target, probe) if probe and not force else None
        token = self._next_token()
        if known is not None:  # the model already explained this file
            self._on_finished(token, known)
            return
        self.body.setHtml(f"<p><i>{_esc(tr('Analysing…'))}</i></p>")
        self._auto.request(token, target, force, None)

    def analyse_with_llm(self) -> None:
        if self._target is None:
            return
        request = self._llm_request(ask=True)
        if request is None:
            return
        self._token += 1
        token = self._latest_llm = self._token
        self.progress_label.setText(
            tr("Asking {model}…").format(model=request["model"] or self._profile.name)
        )
        self.progress_label.show()
        self._llm.request(token, self._target, False, request, front=True)

    def _llm_request(self, *, ask: bool) -> dict | None:
        """The worker request for the active profile, with its key from the keyring.

        Asks first when the profile sends files to a remote host it has no
        consent for; consent is for that host only.
        """
        profile = self._profile
        if profile is None:
            return None
        if ask and profile.needs_consent():
            host = profile.host() or profile.resolved_endpoint()
            go, remember = self._confirm_remote(profile, host)
            if not go:
                return None
            if remember:
                settings = self._load_settings()
                stored = settings.profile(profile.name)
                if stored is not None and stored.consent_key() == profile.consent_key():
                    stored.consent()
                    try:
                        self._save_settings(settings)
                    except OSError:
                        # The consent still holds for this analysis.
                        log.warning(
                            "Could not remember the consent for %s", profile.name, exc_info=True
                        )
                profile.consent()
        try:
            key = self._key_lookup(profile.name) or ""
        except Exception:
            log.exception("API key lookup failed for %s", profile.name)
            key = ""
        return LP.worker_request(profile, key)

    # -- answers ---------------------------------------------------------------
    def _on_started(self, token: int) -> None:
        self._started_at[token] = time.monotonic()
        row = self._rows.get(token)
        if row is not None:
            row.setText(f"▶ {self._row_targets[token].name}")

    def _on_event(self, token: int, event: dict) -> None:
        if not isinstance(event, dict):
            return
        row = self._rows.get(token)
        if row is not None and event.get("event") == "progress":
            row.setText(
                f"▶ {self._row_targets[token].name} — "
                f"{_number(int(event.get('answer') or 0))} {tr('characters')}"
            )
        if token not in (self._latest, self._latest_llm):
            return
        if event.get("event") == "progress":
            started = self._started_at.get(token)
            elapsed = time.monotonic() - started if started is not None else 0.0
            self.progress_label.setText(
                tr(
                    "The model is working: {reasoning} characters of thinking, "
                    "{answer} of answer · {s:.0f} s"
                ).format(
                    reasoning=_number(int(event.get("reasoning") or 0)),
                    answer=_number(int(event.get("answer") or 0)),
                    s=elapsed,
                )
            )
            self.progress_label.show()

    def _on_finished(self, token: int, result: AnalysisResult) -> None:
        self._started_at.pop(token, None)
        row = self._rows.get(token)
        if row is not None and token not in self._row_results:
            self._row_results[token] = result
            name = self._row_targets[token].name
            row.setText(f"✓ {name}" if result.ok else f"✗ {name} — {result.error[:80]}")
            if not any(r.text().startswith(("⏳", "▶")) for r in self._rows.values()):
                self.stop_button.hide()
        if token == self._latest_llm:
            self._latest_llm = -1
            self._llm_result = result
            self.progress_label.hide()
            self._show_answers()
        elif token == self._latest:
            self._latest = -1  # answered: a reselection of the file has nothing to wait for
            self._auto_result = result
            if self._latest_llm == -1:
                self.progress_label.hide()
            self._show_answers()

    def _show_answers(self) -> None:
        """The answers for the file on screen, whichever lane came last: the
        model's answer wins; a failed one stands above the automatic result."""
        llm, auto = self._llm_result, self._auto_result
        if llm is not None and (llm.ok or auto is None):
            self._show(render_result_html(llm), llm)
        elif llm is not None:  # the model failed: the automatic result stays
            self._show(render_result_html(llm) + render_result_html(auto), auto)
        elif auto is not None:
            self._show(render_result_html(auto), auto)

    def _show(self, body: str, result: AnalysisResult) -> None:
        self.body.setHtml(body)
        summary = result.summary if isinstance(result.summary, dict) else {}
        self._set_mode_icon(bool(result.ok and summary.get("llm_used")))
        self._update_buttons()

    def shutdown(self) -> None:
        self._stopped = True
        self._listing = None
        try:
            self._lister.listed.disconnect()
        except TypeError:  # nothing connected
            pass
        self._auto.shutdown()
        self._llm.shutdown()


class _Lister(QObject):
    """Lists a folder on a background thread: regular files only, no links."""

    listed = pyqtSignal(int, object, str)

    def list(self, backend, path: str, token: int) -> None:
        def work() -> None:
            try:
                items = backend.list_dir(path)
                targets = []
                for item in items:
                    if (
                        item.is_dir
                        or getattr(item, "is_link", False)
                        or item.name in ("", ".", "..")
                    ):
                        continue
                    try:
                        mtime = item.modified.timestamp() if item.modified else 0.0
                    except (OverflowError, OSError, ValueError):
                        mtime = 0.0
                    targets.append(
                        Target(
                            backend=backend,
                            path=backend.join(path, item.name),
                            name=item.name,
                            size=int(item.size or 0),
                            mtime=mtime,
                        )
                    )
                self.listed.emit(token, sorted(targets, key=lambda t: t.name.lower()), "")
            except Exception as exc:  # noqa: BLE001 - shown to the user
                self.listed.emit(token, [], f"{type(exc).__name__}: {exc}")

        threading.Thread(target=work, name="axross-analysis-list", daemon=True).start()
