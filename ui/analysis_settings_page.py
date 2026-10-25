"""Edit > Settings… > Analysis (sift): how the Analysis dock runs sift.

* **Status** - sift's version, or that this build has no sift (axross-slim,
  or a source install without the extra) with a link to Help > Features….
  Without sift the values are shown but cannot be changed.
* **Analysis** - automatic analysis of the selected file on or off, and the
  LLM profile of *Analyse with LLM* ("Active profile" follows LLM Profiles;
  the Agent keeps its own choice).
* **sift** - the read limit per file (it caps a remote file's copy too), the
  time budget per file, vision, the model's context (0 = what the server
  says), tags per file and the categories, one per line.
* **Cache** - keep sift's results on disk, the folder, *Clear Cache*.

Ranges and refusals are sift's own (core.analysis_settings). Saving writes
analysis.json; the Settings dialog then calls the window's
``refresh_analysis_settings`` and the open dock uses the new values at once.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core import analysis_settings as AS
from core.i18n import tr

log = logging.getLogger(__name__)

KEYWORDS = ("sift", "analysis", "analyse", "automatic", "max bytes", "read limit",
            "time budget", "vision", "context", "tokens", "tags", "categories", "cache",
            "clear cache", "llm profile")
#: max_bytes is shown in MB (sift's default, 25,000,000 bytes, is 25 MB).
MB = 1_000_000
#: The largest whole number a QSpinBox holds.
_SPIN_MAX = 2**31 - 1


def _muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setProperty("role", "muted")
    return label


class AnalysisPage(QWidget):
    """The Analysis (sift) page (see the module docstring)."""

    #: (number of results removed, error text) from the Clear Cache thread.
    cache_cleared = pyqtSignal(int, str)

    def __init__(self, parent: QWidget | None = None, *, window=None,
                 path: Path | None = None) -> None:
        super().__init__(parent)
        self._window = window
        self._path = path
        self._clearing = False
        self._settings = AS.AnalysisSettings.load(path)
        self._available, version = AS.sift_status()
        limits = AS.limits()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        status_box = QGroupBox(tr("Status"))
        status_layout = QVBoxLayout(status_box)
        self.status_label = QLabel(
            tr("sift {version} is installed.").format(version=version)
            if self._available
            else tr("sift is not installed in this build: file analysis comes with "
                    "axross-full, or as the axross[sift] extra.")
        )
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        status_layout.addWidget(self.status_label)
        self.features_link = QLabel(f'<a href="features">{tr("Show in Features…")}</a>')
        self.features_link.setTextFormat(Qt.TextFormat.RichText)
        self.features_link.linkActivated.connect(self._show_features)
        self.features_link.setVisible(not self._available)
        status_layout.addWidget(self.features_link)
        layout.addWidget(status_box)

        run_box = QGroupBox(tr("Analysis"))
        run_form = QFormLayout(run_box)
        self.auto_check = QCheckBox(tr("Analyse the selected file automatically (without an LLM)"))
        self.auto_check.setToolTip(tr("Off: selecting a file only names it in the Analysis dock; "
                                      "Analyse explains it"))
        run_form.addRow(self.auto_check)
        self.profile_combo = QComboBox()
        self.profile_combo.setToolTip(tr("The LLM profile of Analyse with LLM; the Agent keeps "
                                         "its own"))
        run_form.addRow(tr("LLM profile"), self.profile_combo)
        layout.addWidget(run_box)

        sift_box = QGroupBox(tr("sift"))
        sift_form = QFormLayout(sift_box)
        low, high = limits["max_bytes"]
        self.max_bytes_spin = QSpinBox()
        self.max_bytes_spin.setRange(max(1, -(-low // MB)), max(1, high // MB))
        self.max_bytes_spin.setSuffix(" MB")
        self.max_bytes_spin.setToolTip(tr("sift reads at most this much of a file; a remote "
                                          "file larger than this is not copied"))
        sift_form.addRow(tr("Max bytes read per file"), self.max_bytes_spin)
        self.time_spin = QSpinBox()
        self.time_spin.setRange(int(AS.TIME_BUDGET_RANGE[0]), int(AS.TIME_BUDGET_RANGE[1]))
        self.time_spin.setSuffix(" s")
        self.time_spin.setToolTip(tr("Seconds sift may spend on one file; then the file's "
                                     "analysis stops"))
        sift_form.addRow(tr("Time budget per file"), self.time_spin)
        self.vision_check = QCheckBox(tr("Send images to a vision-capable model"))
        sift_form.addRow(tr("Vision"), self.vision_check)
        self.context_spin = QSpinBox()
        self.context_spin.setRange(AS.CONTEXT_FROM_SERVER, _SPIN_MAX)
        self.context_spin.setSingleStep(1024)
        self.context_spin.setSpecialValueText(tr("Server's"))
        self.context_spin.setToolTip(tr("The model's context in tokens; Server's (0) asks the "
                                        "server what the model was loaded with"))
        sift_form.addRow(tr("Context tokens"), self.context_spin)
        self.tags_spin = QSpinBox()
        self.tags_spin.setRange(*limits["tags"])
        self.tags_spin.setToolTip(tr("How many tags the model is asked for per file; 0 asks "
                                     "for none"))
        sift_form.addRow(tr("Tags per file"), self.tags_spin)
        self.categories_edit = QPlainTextEdit()
        self.categories_edit.setPlaceholderText(tr("One category per line"))
        self.categories_edit.setMaximumHeight(110)
        self.categories_edit.setToolTip(tr("The model puts a file into one of these; empty asks "
                                           "for none"))
        sift_form.addRow(tr("Categories"), self.categories_edit)
        sift_form.addRow("", _muted(tr("Vision, context, tags and categories apply to Analyse "
                                       "with LLM.")))
        layout.addWidget(sift_box)

        cache_box = QGroupBox(tr("Cache"))
        cache_form = QFormLayout(cache_box)
        self.cache_check = QCheckBox(tr("Keep sift's results in the cache"))
        self.cache_check.setToolTip(tr("A file analysed again with the same settings is "
                                       "answered from the cache"))
        cache_form.addRow(self.cache_check)
        self.cache_location = QLabel(str(AS.cache_dir()))
        self.cache_location.setTextFormat(Qt.TextFormat.PlainText)
        self.cache_location.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cache_form.addRow(tr("Folder"), self.cache_location)
        self.clear_button = QPushButton(tr("Clear Cache"))
        self.clear_button.setToolTip(tr("Remove sift's results from the cache folder"))
        self.clear_button.clicked.connect(self.clear_cache)
        self.cache_label = QLabel()
        self.cache_label.setTextFormat(Qt.TextFormat.PlainText)
        row = QHBoxLayout()
        row.addWidget(self.clear_button)
        row.addWidget(self.cache_label, 1)
        cache_form.addRow("", row)
        layout.addWidget(cache_box)
        layout.addStretch(1)

        self.cache_cleared.connect(self._cache_cleared)
        self._fill_profiles(self._stored_profile_names())
        self.load(self._settings)
        for widget in (run_box, sift_box, cache_box):
            widget.setEnabled(self._available)

    # -- values ------------------------------------------------------------------------------

    def load(self, settings: AS.AnalysisSettings) -> None:
        self._settings = settings
        self.auto_check.setChecked(settings.auto_analyse)
        self._select_profile(settings.llm_profile)
        self.max_bytes_spin.setValue(round(settings.max_bytes / MB))
        self.time_spin.setValue(round(settings.time_budget))
        self.vision_check.setChecked(settings.vision)
        self.context_spin.setValue(settings.context_tokens)
        self.tags_spin.setValue(settings.tags)
        self.categories_edit.setPlainText("\n".join(settings.categories))
        self.cache_check.setChecked(settings.cache)
        #: What the widgets showed for the loaded values: a value the page
        #: rounds (bytes to MB, seconds) is kept to the byte while untouched.
        self._shown = (self.max_bytes_spin.value(), self.time_spin.value())
        self._baseline = self.values()

    def values(self) -> dict:
        s = self._settings
        mb, seconds = self.max_bytes_spin.value(), self.time_spin.value()
        lines = self.categories_edit.toPlainText().splitlines()
        return {
            "auto_analyse": self.auto_check.isChecked(),
            "llm_profile": self.profile_combo.currentData() or "",
            "max_bytes": s.max_bytes if mb == self._shown[0] else mb * MB,
            "time_budget": s.time_budget if seconds == self._shown[1] else float(seconds),
            "vision": self.vision_check.isChecked(),
            "context_tokens": self.context_spin.value(),
            "tags": self.tags_spin.value(),
            "categories": [line.strip() for line in lines if line.strip()],
            "cache": self.cache_check.isChecked(),
        }

    def changed_values(self) -> dict:
        return {k: v for k, v in self.values().items() if self._baseline.get(k) != v}

    def is_dirty(self) -> bool:
        return bool(self.changed_values())

    def problems(self) -> list[str]:
        return [why for name, value in self.changed_values().items()
                if (why := AS.problem(name, value))]

    def save(self, path: Path | None = None) -> bool:
        """Store the changed values (OSError on a disk error); False when one
        is invalid. The dialog then tells the window (refresh_analysis_settings)."""
        if self.problems():
            return False
        path = path if path is not None else self._path
        settings = AS.AnalysisSettings.load(path)
        for name, value in self.changed_values().items():
            settings.set(name, value)
        settings.save(path)
        self.load(settings)
        return True

    # -- the LLM profiles --------------------------------------------------------------------

    @staticmethod
    def _stored_profile_names() -> list[str]:
        from core import llm_profiles as LP

        try:
            return [p.name for p in LP.LLMSettings.load().profiles]
        except Exception:  # noqa: BLE001 - a broken llm.json must not break the page
            log.warning("LLM profiles could not be read", exc_info=True)
            return []

    def _fill_profiles(self, names: list[str]) -> None:
        current = self.profile_combo.currentData()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItem(tr("Active profile (LLM Profiles)"), "")
        for name in names:
            self.profile_combo.addItem(name, name)
        self.profile_combo.blockSignals(False)
        if current is not None:
            self._select_profile(current)

    def _select_profile(self, name: str) -> None:
        index = self.profile_combo.findData(name)
        if index < 0:  # a profile that is gone: kept, so saving does not lose it
            self.profile_combo.addItem(tr("{name} (not found)").format(name=name), name)
            index = self.profile_combo.count() - 1
        self.profile_combo.setCurrentIndex(index)

    def refresh_llm_choices(self, names: list[str]) -> None:
        """Profiles of the LLM page, saved or not, to choose from."""
        self._fill_profiles(list(names))

    # -- the cache ---------------------------------------------------------------------------

    def clear_cache(self) -> None:
        """Remove sift's results from the cache folder, off the GUI thread,
        and forget the results the open dock keeps for this session."""
        if self._clearing:
            return
        self._clearing = True
        self.clear_button.setEnabled(False)
        self.cache_label.setText(tr("Clearing…"))
        folder = AS.cache_dir()

        def work() -> None:
            try:
                count, error = AS.clear_cache(folder), ""
            except Exception as exc:  # noqa: BLE001 - shown on the page
                count, error = 0, f"{type(exc).__name__}: {exc}"
            try:
                self.cache_cleared.emit(count, error)
            except RuntimeError:  # the page is gone
                pass

        threading.Thread(target=work, name="axross-sift-cache-clear", daemon=True).start()

    def _cache_cleared(self, count: int, error: str) -> None:
        self._clearing = False
        self.clear_button.setEnabled(self._available)
        if error:
            self.cache_label.setText(tr("The cache could not be cleared: {error}").format(
                error=error))
            return
        self.cache_label.setText(tr("Removed {n} cached result(s).").format(n=count))
        clear = getattr(self._window, "clear_analysis_session", None)
        if callable(clear):
            clear()

    def _show_features(self, _link: str = "") -> None:
        show = getattr(self._window, "_show_features", None)
        if callable(show):
            show("extra:sift")


def settings_page(parent, window) -> AnalysisPage:
    return AnalysisPage(parent, window=window)


__all__ = ["KEYWORDS", "AnalysisPage", "settings_page"]
