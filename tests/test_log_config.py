"""Logging configuration (core.log_config): the saved settings, the levels
per area applied to the loggers, the log file and terminal handlers, the
--debug / --verbose floor, and the collapse of repeated records."""

from __future__ import annotations

import io
import json
import logging
import logging.handlers
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import log_areas as LA  # noqa: E402
from core import log_config as LC  # noqa: E402


@pytest.fixture(autouse=True)
def clean_logging():
    root = logging.getLogger()
    old_level = root.level
    old_handlers = list(root.handlers)
    yield
    LC.teardown()
    for handler in list(root.handlers):
        if handler not in old_handlers:
            root.removeHandler(handler)
            handler.close()
    root.setLevel(old_level)


def _file_lines(path: Path) -> list[str]:
    for handler in logging.getLogger().handlers:
        handler.flush()
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


# -- the settings -----------------------------------------------------------------------------


def test_happy_defaults():
    s = LC.LogSettings()
    assert s.level == "INFO"
    assert s.area_choice("protocols.smb") == "inherit"
    assert s.area_choice("third_party") == "WARNING"
    assert s.file_max_mib == 5 and s.file_backups == 3
    assert s.terminal is False and s.collapse_repeats is True
    assert s.repeat_window == 10


def test_happy_settings_round_trip_and_stay_private(tmp_path):
    path = tmp_path / "logging.json"
    s = LC.LogSettings()
    s.set("level", "WARNING")
    s.set_area("protocols.smb", "DEBUG")
    s.set_area("third_party.ssh", "off")
    s.set("file_max_mib", 20)
    s.set("terminal", True)
    s.save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    back = LC.LogSettings.load(path)
    assert back == s
    assert back.area_choice("protocols.smb") == "DEBUG"
    assert back.area_choice("third_party.ssh") == "off"


def test_happy_the_store_lives_in_the_config_folder():
    assert LC.settings_file() == Path.home() / ".config" / "axross" / "logging.json"


def test_sad_a_corrupt_or_missing_store_reads_as_the_defaults(tmp_path):
    assert LC.LogSettings.load(tmp_path / "missing.json") == LC.LogSettings()
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert LC.LogSettings.load(bad) == LC.LogSettings()
    bad.write_text("[1, 2]", encoding="utf-8")
    assert LC.LogSettings.load(bad) == LC.LogSettings()


def test_sad_invalid_values_in_the_store_keep_their_defaults(tmp_path):
    path = tmp_path / "logging.json"
    path.write_text(json.dumps({
        "level": "LOUD", "file_max_mib": 10_000, "file_backups": 0, "terminal": "yes",
        "repeat_window": -1, "collapse_repeats": 1,
        "areas": {"protocols.smb": "DEBUG", "no.such.area": "DEBUG", "ui": "VERBOSE",
                  "transfers": 3},
    }), encoding="utf-8")
    s = LC.LogSettings.load(path)
    assert s.level == "INFO" and s.file_max_mib == 5 and s.file_backups == 3
    assert s.terminal is False and s.repeat_window == 10 and s.collapse_repeats is True
    assert s.areas == {"protocols.smb": "DEBUG"}


@pytest.mark.parametrize(("name", "value"), [
    ("level", "off"), ("level", "inherit"), ("level", 10),
    ("file_max_mib", 0), ("file_max_mib", 101), ("file_max_mib", True), ("file_max_mib", 2.5),
    ("file_backups", 0), ("file_backups", 21),
    ("repeat_window", 0), ("repeat_window", 301),
    ("terminal", 1), ("collapse_repeats", None),
])
def test_sad_out_of_range_values_are_refused(name, value):
    with pytest.raises(ValueError):
        LC.LogSettings().set(name, value)


def test_sad_unknown_area_or_choice_is_refused():
    s = LC.LogSettings()
    with pytest.raises(KeyError):
        s.set_area("no.such.area", "DEBUG")
    with pytest.raises(ValueError):
        s.set_area("ui", "VERBOSE")
    with pytest.raises(KeyError):
        s.set("no_such_setting", 1)


def test_edge_bounds_are_accepted_and_a_default_choice_is_not_stored():
    s = LC.LogSettings()
    for name, (low, high) in (("file_max_mib", LC.FILE_MIB_RANGE),
                              ("file_backups", LC.BACKUPS_RANGE),
                              ("repeat_window", LC.WINDOW_RANGE)):
        s.set(name, low)
        s.set(name, high)
    s.set_area("ui", "DEBUG")
    s.set_area("ui", "inherit")
    s.set_area("third_party", "WARNING")
    assert s.areas == {}
    s.set_area("third_party", "inherit")  # differs from its default: kept
    assert s.areas == {"third_party": "inherit"}


# -- levels -----------------------------------------------------------------------------------


def test_happy_an_area_level_reaches_its_loggers_and_no_other():
    s = LC.LogSettings()
    s.set_area("protocols.smb", "DEBUG")
    LC.apply(s)
    smb = logging.getLogger("core.smb_client")
    ftp = logging.getLogger("core.ftp_client")
    assert smb.isEnabledFor(logging.DEBUG)
    assert not ftp.isEnabledFor(logging.DEBUG) and ftp.isEnabledFor(logging.INFO)
    assert logging.getLogger().level == logging.INFO


def test_happy_a_sub_area_inherits_its_parent_and_a_child_logger_its_module():
    s = LC.LogSettings()
    s.set_area("protocols", "WARNING")
    s.set_area("protocols.ssh", "DEBUG")
    LC.apply(s)
    assert logging.getLogger("core.smb_client").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("core.ssh_client").getEffectiveLevel() == logging.DEBUG
    assert logging.getLogger("core.mcp_server.audit").getEffectiveLevel() == logging.INFO


def test_happy_third_party_libraries_are_quiet_by_default():
    LC.apply(LC.LogSettings())
    assert logging.getLogger("paramiko.transport").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("urllib3.connectionpool").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("core.ssh_client").getEffectiveLevel() == logging.INFO


def test_happy_warnings_pass_by_default(tmp_path):
    log_file = tmp_path / "axross.log"
    LC.configure(log_file, settings=LC.LogSettings())
    logging.getLogger("core.smb_client").warning("disk full on %s", "share")
    logging.getLogger("paramiko.transport").warning("peer reset")
    logging.getLogger("test.unlisted").warning("unlisted warns too")
    text = "\n".join(_file_lines(log_file))
    assert "disk full on share" in text and "peer reset" in text and "unlisted warns too" in text


def test_sad_off_silences_an_area_completely():
    s = LC.LogSettings()
    s.set_area("media", "off")
    LC.apply(s)
    assert not logging.getLogger("core.audio_route").isEnabledFor(logging.CRITICAL)


def test_edge_changing_back_to_inherit_follows_the_overall_level_again():
    s = LC.LogSettings()
    s.set_area("ui", "ERROR")
    LC.apply(s)
    assert logging.getLogger("ui.main_window").getEffectiveLevel() == logging.ERROR
    s.set_area("ui", "inherit")
    s.set("level", "DEBUG")
    LC.apply(s)
    assert logging.getLogger("ui.main_window").getEffectiveLevel() == logging.DEBUG
    assert logging.getLogger().level == logging.DEBUG


def test_edge_teardown_gives_every_logger_back_its_own_level():
    s = LC.LogSettings()
    s.set_area("protocols.smb", "ERROR")
    LC.apply(s)
    LC.teardown()
    assert logging.getLogger("core.smb_client").level == logging.NOTSET
    assert logging.getLogger("paramiko").level == logging.NOTSET


def test_edge_a_run_time_extension_logger_follows_its_area_after_refresh():
    s = LC.LogSettings()
    s.set_area("extensions", "DEBUG")
    LC.apply(s)
    late = logging.getLogger("axross_extension_bundled_late_test")
    assert late.getEffectiveLevel() == logging.INFO  # made after apply
    LC.refresh()
    assert late.getEffectiveLevel() == logging.DEBUG
    assert logging.getLogger("axross.ext.late_test").getEffectiveLevel() == logging.DEBUG


def test_edge_an_unlisted_new_core_module_takes_the_application_area():
    s = LC.LogSettings()
    s.set_area("app", "WARNING")
    LC.apply(s)
    assert logging.getLogger("core.written_later").getEffectiveLevel() == logging.WARNING


# -- --debug / --verbose ----------------------------------------------------------------------


def test_happy_debug_flag_overrides_the_saved_levels_for_the_run(tmp_path):
    s = LC.LogSettings()
    s.set("level", "ERROR")
    s.set_area("protocols.smb", "off")
    LC.configure(tmp_path / "axross.log", debug=True, settings=s)
    assert logging.getLogger().level == logging.DEBUG
    assert logging.getLogger("core.smb_client").isEnabledFor(logging.DEBUG)
    assert logging.getLogger("ui.main_window").isEnabledFor(logging.DEBUG)
    # Third-party libraries keep their saved level: --debug floods no paramiko packets.
    assert logging.getLogger("paramiko").getEffectiveLevel() == logging.WARNING
    assert LC.terminal_handler() is not None
    # A later Settings save keeps the run's floor.
    LC.apply(s)
    assert logging.getLogger("core.smb_client").isEnabledFor(logging.DEBUG)


def test_happy_verbose_flag_raises_quiet_areas_to_info_and_keeps_debug(tmp_path):
    s = LC.LogSettings()
    s.set("level", "WARNING")
    s.set_area("protocols.ssh", "DEBUG")
    LC.configure(tmp_path / "axross.log", verbose=True, settings=s)
    assert logging.getLogger("ui.main_window").getEffectiveLevel() == logging.INFO
    assert logging.getLogger("core.ssh_client").getEffectiveLevel() == logging.DEBUG
    assert LC.terminal_handler() is not None


def test_edge_without_flags_the_terminal_follows_the_setting(tmp_path):
    s = LC.LogSettings()
    LC.configure(tmp_path / "axross.log", settings=s)
    assert LC.terminal_handler() is None
    s.set("terminal", True)
    LC.apply(s)
    assert LC.terminal_handler() is not None
    s.set("terminal", False)
    LC.apply(s)
    assert LC.terminal_handler() is None


# -- the file ---------------------------------------------------------------------------------


def test_happy_the_file_handler_takes_size_and_count_live(tmp_path):
    log_file = tmp_path / "logs" / "axross.log"
    s = LC.LogSettings()
    LC.configure(log_file, settings=s)
    handler = LC.file_handler()
    assert isinstance(handler, logging.handlers.RotatingFileHandler)
    assert handler.maxBytes == 5 * LC.MIB and handler.backupCount == 3
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600
    s.set("file_max_mib", 1)
    s.set("file_backups", 7)
    LC.apply(s)
    assert handler.maxBytes == LC.MIB and handler.backupCount == 7


def test_edge_configure_twice_leaves_one_file_handler(tmp_path):
    LC.configure(tmp_path / "a.log", settings=LC.LogSettings())
    LC.configure(tmp_path / "a.log", settings=LC.LogSettings())
    ours = [h for h in logging.getLogger().handlers if getattr(h, "_axross_handler", False)]
    assert len(ours) == 1


def test_happy_configure_reads_the_saved_settings(tmp_path, monkeypatch):
    store = tmp_path / "logging.json"
    s = LC.LogSettings()
    s.set_area("transfers", "DEBUG")
    s.save(store)
    monkeypatch.setattr(LC, "settings_file", lambda: store)
    LC.configure(tmp_path / "axross.log")
    assert logging.getLogger("core.transfer_worker").isEnabledFor(logging.DEBUG)


# -- repeated records -------------------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _collect_handler(window=10, enabled=True, clock=None):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    filt = LC.RepeatCollapseFilter(handler, window=window, enabled=enabled,
                                   clock=clock or _Clock())
    handler.addFilter(filt)
    logger = logging.getLogger("test.collapse")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    return logger, handler, filt, stream


@pytest.fixture
def collapse():
    made = []

    def make(**kw):
        logger, handler, filt, stream = _collect_handler(**kw)
        made.append((logger, handler))
        return logger, handler, filt, stream

    yield make
    for logger, handler in made:
        logger.removeHandler(handler)
        logger.propagate = True
        logger.setLevel(logging.NOTSET)


def test_happy_a_burst_of_1000_identical_records_collapses_to_two_lines(collapse):
    clock = _Clock()
    logger, _h, filt, stream = collapse(clock=clock)
    for _ in range(1000):
        try:
            raise RuntimeError("tick failed")
        except RuntimeError:
            logger.exception("Media Player tick failed")
        clock.now += 0.001
    filt.flush()
    lines = [ln for ln in stream.getvalue().splitlines() if ln.startswith(("ERROR", "INFO"))]
    assert len(lines) == 2, stream.getvalue()[:2000]
    assert "Media Player tick failed" in lines[0]
    assert "repeated 999 more times" in lines[1] and "Media Player tick failed" in lines[1]
    assert stream.getvalue().count("Traceback") == 1


def test_happy_the_summary_comes_before_the_next_record_after_the_window(collapse):
    clock = _Clock()
    logger, _h, _f, stream = collapse(window=10, clock=clock)
    for _ in range(5):
        logger.warning("disk slow")
    clock.now += 11
    logger.warning("disk slow")
    lines = stream.getvalue().splitlines()
    summary = "Last message repeated 4 more times in 0.0 s: disk slow"
    assert lines == ["WARNING test.collapse: disk slow",
                     f"WARNING test.collapse: {summary}",
                     "WARNING test.collapse: disk slow"]


def test_happy_other_records_flush_an_expired_summary(collapse):
    clock = _Clock()
    logger, _h, _f, stream = collapse(window=10, clock=clock)
    logger.info("a")
    logger.info("a")
    clock.now += 12
    logger.info("b")
    assert stream.getvalue().splitlines() == [
        "INFO test.collapse: a",
        "INFO test.collapse: Last message repeated 1 more times in 0.0 s: a",
        "INFO test.collapse: b"]


def test_sad_different_messages_levels_or_loggers_are_not_collapsed(collapse):
    logger, handler, _f, stream = collapse()
    other = logging.getLogger("test.collapse.other")
    other.addHandler(handler)
    other.propagate = False
    try:
        logger.info("copied %s", "a.txt")
        logger.info("copied %s", "b.txt")
        logger.warning("copied %s", "b.txt")
        other.info("copied %s", "b.txt")
    finally:
        other.removeHandler(handler)
        other.propagate = True
    assert len(stream.getvalue().splitlines()) == 4


def test_sad_collapse_switched_off_lets_every_record_through(collapse):
    logger, _h, _f, stream = collapse(enabled=False)
    for _ in range(1000):
        logger.info("same")
    assert len(stream.getvalue().splitlines()) == 1000


def test_edge_the_key_table_is_bounded(collapse):
    logger, _h, filt, stream = collapse()
    for i in range(LC.MAX_REPEAT_KEYS * 3):
        logger.info("distinct %d", i)
    assert len(filt._seen) <= LC.MAX_REPEAT_KEYS
    assert len(stream.getvalue().splitlines()) == LC.MAX_REPEAT_KEYS * 3


def test_edge_flush_without_repeats_writes_nothing(collapse):
    logger, _h, filt, stream = collapse()
    logger.info("once")
    filt.flush()
    filt.flush()
    assert stream.getvalue().splitlines() == ["INFO test.collapse: once"]


def test_happy_the_file_handler_collapses_and_apply_switches_it(tmp_path):
    log_file = tmp_path / "axross.log"
    s = LC.LogSettings()
    LC.configure(log_file, settings=s)
    log = logging.getLogger("core.transfer_worker")
    for _ in range(1000):
        log.warning("same failure")
    LC.flush_repeats()
    ours = [ln for ln in _file_lines(log_file) if "core.transfer_worker" in ln]
    assert len(ours) == 2 and "repeated 999 more times" in ours[1]
    s.set("collapse_repeats", False)
    LC.apply(s)
    for _ in range(50):
        log.warning("second failure")
    ours = [ln for ln in _file_lines(log_file) if "second failure" in ln]
    assert len(ours) == 50


def test_edge_attach_gives_another_handler_the_same_collapse(tmp_path):
    LC.configure(tmp_path / "axross.log", settings=LC.LogSettings())
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    LC.attach_filters(handler)
    log = logging.getLogger("test.attach")
    log.addHandler(handler)
    log.propagate = False
    try:
        for _ in range(100):
            log.error("x")
    finally:
        log.removeHandler(handler)
        log.propagate = True
    assert len(stream.getvalue().splitlines()) == 1


def test_edge_a_summary_never_carries_a_secret_the_record_did_not(collapse):
    # The summary repeats the formatted message only - no args, no traceback.
    logger, _h, filt, stream = collapse()
    try:
        raise ValueError("boom")
    except ValueError:
        logger.exception("failed")
        logger.exception("failed")
    filt.flush()
    assert stream.getvalue().count("Traceback") == 1


def test_edge_umask_does_not_widen_the_log_file(tmp_path):
    old = os.umask(0)
    try:
        LC.configure(tmp_path / "axross.log", settings=LC.LogSettings())
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "axross.log").stat().st_mode) == 0o600


def test_edge_every_area_has_a_label_for_the_page():
    assert all(a.label for a in LA.AREAS)


# -- main.setup_logging -----------------------------------------------------------------------


def _main_with_tmp_logs(tmp_path, monkeypatch):
    import main

    monkeypatch.setattr(main, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(main, "LOG_FILE", tmp_path / "logs" / "axross.log")
    return main


def test_happy_setup_logging_applies_the_saved_settings(tmp_path, monkeypatch):
    main = _main_with_tmp_logs(tmp_path, monkeypatch)
    s = LC.LogSettings()
    s.set_area("protocols.smb", "DEBUG")
    s.save()  # the isolated HOME of the test run
    main.setup_logging()
    assert logging.getLogger("core.smb_client").isEnabledFor(logging.DEBUG)
    assert not logging.getLogger("core.ftp_client").isEnabledFor(logging.DEBUG)
    assert LC.terminal_handler() is None
    logging.getLogger("core.smb_client").debug("smb detail")
    assert any("smb detail" in ln for ln in _file_lines(tmp_path / "logs" / "axross.log"))


def test_happy_setup_logging_debug_flag_still_means_everything_on_the_terminal(
        tmp_path, monkeypatch):
    main = _main_with_tmp_logs(tmp_path, monkeypatch)
    s = LC.LogSettings()
    s.set("level", "ERROR")
    s.save()
    main.setup_logging(debug=True)
    assert logging.getLogger().level == logging.DEBUG
    assert logging.getLogger("ui.main_window").isEnabledFor(logging.DEBUG)
    assert LC.terminal_handler() is not None


def test_sad_setup_logging_survives_a_broken_store(tmp_path, monkeypatch):
    main = _main_with_tmp_logs(tmp_path, monkeypatch)
    LC.settings_file().parent.mkdir(parents=True, exist_ok=True)
    LC.settings_file().write_text("{broken", encoding="utf-8")
    main.setup_logging(verbose=True)
    assert logging.getLogger().level == logging.INFO
    assert any("unreadable" in ln for ln in _file_lines(tmp_path / "logs" / "axross.log"))


def test_edge_prepare_logger_sets_an_extension_level_before_its_code_runs():
    s = LC.LogSettings()
    s.set_area("extensions", "ERROR")
    LC.apply(s)
    LC.prepare_logger("axross_extension_bundled_prepared")
    assert logging.getLogger("axross_extension_bundled_prepared").level == logging.ERROR
    LC.prepare_logger("test.no_area")  # outside every area: left alone
    assert logging.getLogger("test.no_area").level == logging.NOTSET


def test_sad_prepare_logger_before_any_apply_changes_nothing():
    LC.prepare_logger("axross_extension_bundled_untouched")
    assert logging.getLogger("axross_extension_bundled_untouched").level == logging.NOTSET


def test_happy_the_extension_host_prepares_the_logger_of_the_extension_it_runs():
    source = (ROOT / "ui" / "extension_host.py").read_text(encoding="utf-8")
    body = source[source.index("    def load(self, info"):source.index("    def unload(self")]
    assert body.index("prepare_logger(module_name)") < body.index("_exec_source(module_name")


def test_sad_a_record_whose_arguments_do_not_fit_never_raises_into_the_caller(collapse, capsys):
    # A wrong %-argument count raised inside the filter, past the handler's
    # handleError: the caller's log line would have thrown.
    logger, _h, _f, stream = collapse()
    logger.warning("two %s %s", "only-one")  # no exception here
    logger.warning("two %s %s", "only-one")
    assert "only-one" not in stream.getvalue()  # the handler could not format it either
    assert "Logging error" in capsys.readouterr().err  # reported the usual way


def test_edge_an_exception_whose_str_raises_is_still_keyed(collapse):
    class _Odd(Exception):
        def __str__(self):
            raise RuntimeError("no text")

    logger, _h, filt, stream = collapse()
    for _ in range(3):
        try:
            raise _Odd()
        except _Odd:
            logger.error("odd failure", exc_info=True)
    filt.flush()
    assert stream.getvalue().count("odd failure") == 2  # the line and its count
