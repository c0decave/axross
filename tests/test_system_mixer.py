"""core.system_mixer: the system's sound through pactl, tested against a fake pactl.

The request was an Audio Mixer panel that controls axross's own sound and
the system's sound (PipeWire or PulseAudio). core.system_mixer is the
widget-free half for the system: it lists outputs, inputs, application
streams and cards with ``pactl -f json list ...``, changes volume, mute,
the default device, a stream's device and a card's profile, and follows
``pactl subscribe`` - every command a QProcess with a timeout, so the GUI
thread never waits.

The pure parsing and command-building functions are tested on their own;
the engine runs against tests/fake_pactl.py, put first on PATH as
``pactl``, whose state file the tests read and change. That covers the
real process handling: the version check, a server that is not running, a
command that hangs, broken JSON, events coalesced into one refresh, a dead
``pactl subscribe`` started again, and shutdown.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import fake_pactl as FP  # noqa: E402
from PyQt6.QtCore import QCoreApplication  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import system_mixer as SM  # noqa: E402

APP = QApplication.instance() or QApplication([])

BUILTIN = "alsa_output.pci-0000_00_1f.3.analog-stereo"
HEADSET = "bluez_output.AA_BB_CC_DD_EE_01.1"
MIC = "alsa_input.pci-0000_00_1f.3.analog-stereo"


def wait_until(predicate, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QCoreApplication.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    QCoreApplication.processEvents()
    return bool(predicate())


def pump(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        QCoreApplication.processEvents()
        time.sleep(0.01)


class Recorder:
    def __init__(self, mixer: SM.SystemMixer) -> None:
        self.changed = 0
        self.errors: list[str] = []
        self.states: list[str] = []
        mixer.changed.connect(self._on_changed)
        mixer.error.connect(self.errors.append)
        mixer.state_changed.connect(self.states.append)

    def _on_changed(self) -> None:
        self.changed += 1


@pytest.fixture
def fake(tmp_path, monkeypatch):
    paths = FP.install(tmp_path)
    monkeypatch.setenv("PATH", f"{paths['bin']}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_PACTL_STATE", str(paths["state"]))
    monkeypatch.setenv("FAKE_PACTL_LOG", str(paths["log"]))
    return paths


@pytest.fixture
def mixers():
    made: list[SM.SystemMixer] = []
    yield made
    for m in made:
        m.shutdown()
        m.deleteLater()
    QCoreApplication.processEvents()


def make(mixers, *, ready=True, **kw):
    kw.setdefault("timeout_ms", 15000)
    mixer = SM.SystemMixer(**kw)
    mixers.append(mixer)
    rec = Recorder(mixer)
    mixer.start()
    if ready:
        assert wait_until(lambda: mixer.state() != SM.STATE_PROBING), mixer.state()
        assert mixer.state() == SM.STATE_READY, mixer.reason()
        log = Path(os.environ["FAKE_PACTL_LOG"])
        # pactl subscribe runs: its call is logged once the fake started.
        assert wait_until(lambda: ["subscribe"] in FP.calls(log))
    return mixer, rec


def set_knob(fake, **values) -> None:
    FP.update_state(fake["state"], lambda st: st.update(values))


def entry(fake, kind: str, index: int) -> dict:
    return next(e for e in FP.read_state(fake["state"])[kind] if e["index"] == index)


def raw_volumes(fake, kind: str, index: int) -> list[int]:
    return [v["value"] for v in entry(fake, kind, index)["volume"].values()]


def list_calls(fake, what: str = "sinks") -> int:
    return sum(1 for c in FP.calls(fake["log"]) if c[-2:] == ["list", what])


def fake_outputs() -> dict[str, str]:
    import json

    st = FP.default_state()
    out = {k: json.dumps(st[k]) for k in ("sinks", "sources", "sink-inputs",
                                          "source-outputs", "cards")}
    out["default-sink"] = st["default_sink"] + "\n"
    out["default-source"] = st["default_source"] + "\n"
    return out


# ------------------------------------------------------------ pure parsing
def test_happy_parse_version_reads_pactl_and_pipewire_lines():
    assert SM.parse_version("pactl 16.1\nCompiled with libpulse 16.1.0\n") == (16, 1, 0)
    assert SM.parse_version("pactl 17.0.0\n") == (17, 0, 0)
    assert SM.parse_version("pactl 15\n") == (15, 0, 0)


def test_sad_parse_version_without_a_version_is_none():
    assert SM.parse_version("") is None
    assert SM.parse_version("command not found") is None


def test_happy_build_snapshot_reads_every_list():
    snap = SM.build_snapshot(fake_outputs())
    assert [d.name for d in snap.sinks] == [BUILTIN, HEADSET]
    builtin, headset = snap.sinks
    assert builtin.is_default and not headset.is_default
    assert [(c.name, round(c.percent)) for c in builtin.channels] == [
        ("front-left", 60), ("front-right", 30)]
    assert round(builtin.volume_percent) == 60
    assert builtin.state == "running"
    assert builtin.active_port == "analog-output-speaker"
    assert [(p.name, p.available) for p in builtin.ports] == [
        ("analog-output-speaker", None), ("analog-output-headphones", False)]
    assert (builtin.card_index, builtin.card_name) == (41, "alsa_card.pci-0000_00_1f.3")
    assert (headset.card_index, headset.card_name) == (77, "bluez_card.AA_BB_CC_DD_EE_01")
    assert headset.bus == "bluetooth" and headset.form_factor == "headset"
    monitors = [d for d in snap.sources if d.is_monitor]
    assert [d.monitor_of for d in monitors] == [BUILTIN, HEADSET]
    mic = next(d for d in snap.sources if not d.is_monitor)
    assert mic.name == MIC and mic.is_default
    firefox, own = snap.sink_inputs
    assert (firefox.application, firefox.media, firefox.device_index) == (
        "Firefox", "YouTube - Audio", 56)
    assert (firefox.pid, firefox.binary, firefox.corked) == (4242, "firefox", False)
    assert own.corked and round(own.volume_percent) == 70
    (rec,) = snap.source_outputs
    assert rec.device_index == 58 and [c.name for c in rec.channels] == ["mono"]
    builtin_card, bt_card = snap.cards
    assert builtin_card.description == "Built-in Audio"
    assert bt_card.active_profile == "a2dp-sink"
    assert [p.name for p in bt_card.profiles] == ["a2dp-sink", "headset-head-unit", "off"]
    assert builtin_card.profile("output:hdmi-stereo").available is False


def test_edge_cards_link_by_name_when_ids_are_missing():
    """PulseAudio names: bluez_sink.<addr>.a2dp_sink belongs to bluez_card.<addr>."""
    import json

    sinks = [{"index": 3, "name": "bluez_sink.AA_BB.a2dp_sink", "properties": {}},
             {"index": 4, "name": "alsa_output.usb-Foo-00.analog-stereo", "properties": {}},
             {"index": 5, "name": "null-sink", "properties": {}}]
    cards = [{"index": 9, "name": "bluez_card.AA_BB", "profiles": {}, "properties": {}},
             {"index": 8, "name": "alsa_card.usb-Foo-00", "profiles": {}, "properties": {}}]
    snap = SM.build_snapshot({"sinks": json.dumps(sinks), "cards": json.dumps(cards)})
    assert [(d.name, d.card_index) for d in snap.sinks] == [
        ("bluez_sink.AA_BB.a2dp_sink", 9), ("alsa_output.usb-Foo-00.analog-stereo", 8),
        ("null-sink", -1)]


def test_sad_malformed_json_raises_a_parse_error():
    with pytest.raises(SM.MixerParseError):
        SM.parse_devices('[{"index": 1, ', SM.SINK)
    with pytest.raises(SM.MixerParseError):
        SM.parse_cards('{"index": 1}')
    with pytest.raises(SM.MixerParseError):
        SM.parse_streams("[" * 100_000 + "]" * 100_000, SM.SINK_INPUT)


def test_edge_odd_entries_are_skipped_and_values_tolerated():
    text = ('[{"name": "no index"}, 7, {"index": "12", "name": "s", "mute": "yes",'
            ' "volume": {"mono": {"value_percent": "45%"}, "x": 1}, "state": null}]')
    (dev,) = SM.parse_devices(text, SM.SINK)
    assert (dev.index, dev.muted, dev.state, dev.channels) == (
        12, True, "", (SM.Channel("mono", 45.0),))
    (stream,) = SM.parse_streams('[{"index": 1, "sink": 4294967295, "volume": {}}]',
                                 SM.SINK_INPUT)
    assert stream.device_index == -1 and not stream.has_volume
    assert stream.label == "Stream #1" and stream.pid is None


def test_happy_parse_event_and_which_events_refresh():
    assert SM.parse_event("Event 'change' on sink #56") == ("change", "sink", 56)
    assert SM.parse_event("Event 'change' on server") == ("change", "server", None)
    assert SM.event_wants_refresh("Event 'new' on sink-input #91")
    assert SM.event_wants_refresh("Event 'remove' on card #77")
    assert not SM.event_wants_refresh("Event 'new' on client #12")
    assert not SM.event_wants_refresh("garbage")


def test_happy_connection_failures_are_recognised():
    assert SM.is_connection_failure("Connection failure: Connection refused\n")
    assert SM.is_connection_failure("pa_context_connect() failed: Connection refused")
    assert not SM.is_connection_failure("Failure: No such entity")


def test_edge_volume_values_keep_the_balance_and_clamp():
    stereo = (SM.Channel("front-left", 60.0), SM.Channel("front-right", 30.0))
    assert SM.volume_values(stereo, 100) == [str(SM.VOLUME_NORM), str(SM.VOLUME_NORM // 2)]
    assert SM.volume_values(stereo, 400) == ["98304", "49152"]  # 150 % at most
    assert SM.volume_values(stereo, -20) == ["0", "0"]
    assert SM.volume_values(stereo, [10, 20]) == ["6554", "13107"]
    assert SM.volume_values((), 50) == ["32768"]
    with pytest.raises(ValueError):
        SM.volume_values(stereo, [10, 20, 30])
    for bad in (float("nan"), "loud", None, True):
        with pytest.raises(ValueError):
            SM.clamp_percent(bad)


def test_sad_names_that_look_like_options_are_refused():
    for bad in ("-x", "--server=tcp:evil", "", "a\nb", "x" * 2000, None, 5):
        with pytest.raises(ValueError):
            SM.validate_name(bad)
    for bad in (-1, 0xFFFFFFFF, "3", True, 1.5):
        with pytest.raises(ValueError):
            SM.validate_index(bad)
    dev = SM.Device(SM.SINK, 1, "-evil", "Evil")
    with pytest.raises(ValueError):
        SM.default_command(dev)


def test_happy_commands_are_argument_lists_with_end_of_options():
    sink = SM.Device(SM.SINK, 56, BUILTIN, "Built-in", channels=(SM.Channel("mono", 50.0),))
    stream = SM.Stream(SM.SINK_INPUT, 90, "Firefox")
    assert SM.mute_command(sink, True) == ["--", "set-sink-mute", BUILTIN, "1"]
    assert SM.volume_command(stream, 50) == ["--", "set-sink-input-volume", "90", "32768"]
    assert SM.move_command(stream, sink) == ["--", "move-sink-input", "90", BUILTIN]
    card = SM.Card(77, "bluez_card.X", "Headset")
    assert SM.card_profile_command(card, "a2dp-sink") == [
        "--", "set-card-profile", "bluez_card.X", "a2dp-sink"]
    with pytest.raises(ValueError):
        SM.move_command(stream, SM.Device(SM.SOURCE, 1, MIC, "Mic"))


def test_happy_error_sentences_name_the_action_and_the_reason():
    assert SM.error_sentence("mute X", "Failure: Access denied\n") == (
        "Could not mute X: the sound server refused it.")
    assert SM.error_sentence("mute X", "") == "Could not mute X: pactl failed without saying why."
    assert SM.error_sentence("mute X", "weird thing.\nmore") == "Could not mute X: weird thing."


# ------------------------------------------------------------ the engine
def test_happy_start_lists_everything_from_pactl(fake, mixers):
    mixer, rec = make(mixers)
    assert mixer.available() and mixer.reason() == ""
    assert rec.states[-1] == SM.STATE_READY and rec.changed >= 1
    assert mixer.pactl_version() == (16, 1, 0)
    assert [d.name for d in mixer.sinks()] == [BUILTIN, HEADSET]
    assert [d.name for d in mixer.sources()] == [MIC]
    assert len(mixer.sources(include_monitors=True)) == 3
    assert [s.application for s in mixer.sink_inputs()] == ["Firefox", "axross"]
    assert [s.application for s in mixer.source_outputs()] == ["Audacity"]
    assert [c.name for c in mixer.cards()] == ["alsa_card.pci-0000_00_1f.3",
                                               "bluez_card.AA_BB_CC_DD_EE_01"]
    assert (mixer.default_sink(), mixer.default_source()) == (BUILTIN, MIC)
    assert mixer.device(SM.SINK, 80).name == HEADSET
    assert mixer.stream(SM.SOURCE_OUTPUT, 95).application == "Audacity"
    assert mixer.card(77).name == mixer.card("bluez_card.AA_BB_CC_DD_EE_01").name
    calls = FP.calls(fake["log"])
    assert calls[0] == ["--version"]
    assert ["-f", "json", "list", "cards"] in calls and ["get-default-sink"] in calls
    assert ["subscribe"] in calls


def test_happy_set_volume_keeps_the_balance_and_shows_up_in_the_lists(fake, mixers):
    mixer, rec = make(mixers)
    sink = mixer.device(SM.SINK, 56)
    assert mixer.set_volume(sink, 100)
    assert wait_until(lambda: raw_volumes(fake, "sinks", 56) == [65536, 32768])
    assert wait_until(lambda: round(mixer.device(SM.SINK, 56).volume_percent) == 100)
    assert [round(c.percent) for c in mixer.device(SM.SINK, 56).channels] == [100, 50]
    assert rec.errors == []


def test_happy_stream_volume_and_per_channel_volume(fake, mixers):
    mixer, rec = make(mixers)
    assert mixer.set_volume(mixer.stream(SM.SINK_INPUT, 90), 25)
    assert mixer.set_volume(mixer.device(SM.SINK, 80), [10, 90])
    assert wait_until(lambda: raw_volumes(fake, "sink-inputs", 90) == [16384, 16384])
    assert wait_until(lambda: raw_volumes(fake, "sinks", 80) == [6554, 58982])
    assert rec.errors == []


def test_happy_mute_devices_and_streams(fake, mixers):
    mixer, rec = make(mixers)
    assert mixer.set_mute(mixer.device(SM.SINK, 56), True)
    assert mixer.set_mute(mixer.device(SM.SOURCE, 58), True)
    assert mixer.set_mute(mixer.stream(SM.SOURCE_OUTPUT, 95), True)
    assert wait_until(lambda: entry(fake, "sinks", 56)["mute"]
                      and entry(fake, "sources", 58)["mute"]
                      and entry(fake, "source-outputs", 95)["mute"])
    assert wait_until(lambda: mixer.device(SM.SINK, 56).muted
                      and mixer.stream(SM.SOURCE_OUTPUT, 95).muted)
    assert mixer.set_mute(mixer.device(SM.SINK, 56), False)
    assert wait_until(lambda: not mixer.device(SM.SINK, 56).muted)
    assert rec.errors == []


def test_happy_default_sink_follows_through_subscribe(fake, mixers):
    mixer, rec = make(mixers)
    assert mixer.set_default(mixer.device(SM.SINK, 80))
    assert wait_until(lambda: FP.read_state(fake["state"])["default_sink"] == HEADSET)
    assert wait_until(lambda: mixer.default_sink() == HEADSET)
    assert mixer.device(SM.SINK, 80).is_default and not mixer.device(SM.SINK, 56).is_default
    assert rec.errors == []


def test_happy_move_a_stream_to_another_output(fake, mixers):
    mixer, rec = make(mixers)
    assert mixer.move_stream(mixer.stream(SM.SINK_INPUT, 90), mixer.device(SM.SINK, 80))
    assert wait_until(lambda: entry(fake, "sink-inputs", 90)["sink"] == 80)
    assert wait_until(lambda: mixer.stream(SM.SINK_INPUT, 90).device_index == 80)
    assert ["--", "move-sink-input", "90", HEADSET] in FP.calls(fake["log"])
    assert rec.errors == []


def test_happy_switch_a_headsets_card_profile(fake, mixers):
    mixer, rec = make(mixers)
    card = mixer.card(77)
    assert mixer.set_card_profile(card, "headset-head-unit")
    assert wait_until(lambda: mixer.card(77).active_profile == "headset-head-unit")
    assert entry(fake, "cards", 77)["active_profile"] == "headset-head-unit"
    assert rec.errors == []


def test_sad_a_failing_command_becomes_a_sentence(fake, mixers):
    mixer, rec = make(mixers)
    set_knob(fake, fail={"set-sink-mute": "Failure: Access denied\n"})
    assert mixer.set_mute(mixer.device(SM.SINK, 56), True)
    assert wait_until(lambda: rec.errors)
    assert rec.errors == ["Could not mute Built-in Audio Analog Stereo: "
                          "the sound server refused it."]
    assert mixer.available()


def test_sad_an_entity_that_vanished_is_reported(fake, mixers):
    mixer, rec = make(mixers)
    gone = SM.Device(SM.SINK, 99, "alsa_output.gone", "Gone Speaker")
    assert mixer.set_mute(gone, True)
    assert wait_until(lambda: rec.errors)
    assert rec.errors == ["Could not mute Gone Speaker: it does not exist (any more)."]


def test_sad_pactl_missing_is_unavailable_with_a_reason(tmp_path, monkeypatch, mixers):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    mixer, rec = make(mixers, ready=False)
    assert mixer.state() == SM.STATE_UNAVAILABLE and not mixer.available()
    assert "pactl was not found" in mixer.reason()
    assert rec.states == [SM.STATE_UNAVAILABLE]
    assert not mixer.set_mute(SM.Device(SM.SINK, 1, "x", "X"), True)
    assert rec.errors and "not available" in rec.errors[0]


def test_sad_server_not_running_is_unavailable_then_a_retry_works(fake, mixers):
    set_knob(fake, server_down=True)
    mixer, rec = make(mixers, ready=False)
    assert wait_until(lambda: mixer.state() == SM.STATE_UNAVAILABLE)
    assert "No sound server answers" in mixer.reason()
    assert "Connection refused" in mixer.reason()
    assert ["subscribe"] not in FP.calls(fake["log"])
    set_knob(fake, server_down=False)
    mixer.refresh()  # a retry
    assert wait_until(lambda: mixer.state() == SM.STATE_READY), mixer.reason()
    assert len(mixer.sinks()) == 2


def test_sad_the_server_going_away_turns_the_mixer_unavailable(fake, mixers):
    mixer, rec = make(mixers)
    set_knob(fake, server_down=True)
    mixer.refresh()
    assert wait_until(lambda: mixer.state() == SM.STATE_UNAVAILABLE)
    assert wait_until(lambda: mixer.running_processes() == 0)


def test_sad_pactl_older_than_16_is_too_old(fake, mixers):
    set_knob(fake, version="15.0")
    mixer, rec = make(mixers, ready=False)
    assert wait_until(lambda: mixer.state() == SM.STATE_TOO_OLD)
    assert "pactl 15.0.0 is too old" in mixer.reason() and "16" in mixer.reason()
    assert FP.calls(fake["log"]) == [["--version"]]


def test_sad_a_hanging_listing_times_out_and_is_killed(fake, mixers):
    set_knob(fake, hang=["list sinks"])
    mixer, rec = make(mixers, ready=False, timeout_ms=1500)
    assert wait_until(lambda: mixer.state() == SM.STATE_UNAVAILABLE, 30)
    assert "did not answer within 1.5 s" in mixer.reason()
    assert wait_until(lambda: mixer.running_processes() == 0)


def test_sad_a_hanging_operation_times_out_with_an_error(fake, mixers):
    mixer, rec = make(mixers)
    mixer.set_timeout_ms(4000)
    set_knob(fake, hang=["set-sink-mute"])
    assert mixer.set_mute(mixer.device(SM.SINK, 56), True)
    assert wait_until(lambda: rec.errors, 30)
    assert rec.errors[0] == ("Could not mute Built-in Audio Analog Stereo: the sound server "
                             "did not answer within 4 s.")
    assert mixer.available()


def test_happy_events_are_coalesced_into_one_refresh(fake, mixers):
    mixer, rec = make(mixers, coalesce_ms=600)
    assert wait_until(lambda: mixer._subscribe is not None
                      and mixer._subscribe.state().name == "Running")
    pump(1.0)  # let the subscriber start reading
    before = list_calls(fake)
    changed = rec.changed
    for i in range(6):
        FP.update_state(fake["state"], lambda st, i=i: st["events"].append(
            f"Event 'change' on sink-input #{90 + i % 2}"))
        pump(0.05)
    assert wait_until(lambda: rec.changed > changed)
    pump(1.5)
    assert 1 <= list_calls(fake) - before <= 2


def test_edge_events_of_clients_do_not_refresh(fake, mixers):
    mixer, rec = make(mixers, coalesce_ms=50)
    pump(1.0)
    before = list_calls(fake)
    FP.update_state(fake["state"], lambda st: st["events"].extend(
        ["Event 'new' on client #7", "Event 'remove' on module #3"]))
    pump(1.0)
    assert list_calls(fake) == before


def test_sad_malformed_json_is_an_error_not_a_crash(fake, mixers):
    mixer, rec = make(mixers)
    changed = rec.changed
    set_knob(fake, malformed=["sink-inputs"])
    mixer.refresh()
    assert wait_until(lambda: rec.errors)
    assert rec.errors[0].startswith("pactl gave output axross cannot read: the list of "
                                    "sink-inputs is not valid JSON")
    assert rec.changed == changed and mixer.available()
    assert len(mixer.sink_inputs()) == 2  # the last good lists stay


def test_sad_malformed_json_at_start_is_unavailable(fake, mixers):
    set_knob(fake, malformed=["cards"])
    mixer, rec = make(mixers, ready=False)
    assert wait_until(lambda: mixer.state() == SM.STATE_UNAVAILABLE)
    assert "cannot read" in mixer.reason()


def test_sad_option_injection_is_refused_before_any_process(fake, mixers):
    mixer, rec = make(mixers)
    before = len(FP.calls(fake["log"]))
    evil = SM.Device(SM.SINK, 56, "--server=tcp:evil.example", "Evil")
    assert not mixer.set_default(evil)
    assert not mixer.set_mute(evil, True)
    assert not mixer.set_card_profile(mixer.card(77), "-h")
    assert not mixer.move_stream(mixer.stream(SM.SINK_INPUT, 90), evil)
    assert len(rec.errors) == 4 and all("option" in e for e in rec.errors)
    pump(0.3)
    assert len(FP.calls(fake["log"])) == before


def test_sad_wrong_targets_are_refused(fake, mixers):
    mixer, rec = make(mixers)
    assert not mixer.move_stream(mixer.stream(SM.SINK_INPUT, 90), mixer.device(SM.SOURCE, 58))
    assert not mixer.set_card_profile(mixer.card(77), "no-such-profile")
    assert not mixer.set_volume(mixer.device(SM.SINK, 56), float("nan"))
    assert not mixer.set_default(mixer.stream(SM.SINK_INPUT, 90))
    assert len(rec.errors) == 4
    assert "has no profile 'no-such-profile'" in rec.errors[1]


def test_edge_volumes_are_clamped_to_0_and_150_percent(fake, mixers):
    mixer, rec = make(mixers)
    assert mixer.set_volume(mixer.stream(SM.SINK_INPUT, 90), 400)
    assert wait_until(lambda: raw_volumes(fake, "sink-inputs", 90) == [98304, 98304])
    assert mixer.set_volume(mixer.stream(SM.SINK_INPUT, 90), -20)
    assert wait_until(lambda: raw_volumes(fake, "sink-inputs", 90) == [0, 0])
    assert rec.errors == []


def test_edge_a_slider_burst_ends_on_the_last_value(fake, mixers):
    mixer, rec = make(mixers)
    stream = mixer.stream(SM.SINK_INPUT, 90)
    for p in range(10, 60, 2):
        assert mixer.set_volume(stream, p)
    assert wait_until(lambda: raw_volumes(fake, "sink-inputs", 90) == [38011, 38011])
    sent = [c for c in FP.calls(fake["log"]) if c[1:2] == ["set-sink-input-volume"]]
    assert 1 <= len(sent) < 25  # the values in between were dropped
    assert rec.errors == []


def test_edge_a_dead_subscribe_is_started_again(fake, mixers):
    mixer, rec = make(mixers, restart_delay_ms=100)
    assert wait_until(lambda: mixer._subscribe is not None)
    first = mixer._subscribe
    set_knob(fake, subscribe_exit=True)
    assert wait_until(lambda: mixer._subscribe is None or mixer._subscribe is not first)
    set_knob(fake, subscribe_exit=False)
    assert wait_until(lambda: sum(c == ["subscribe"] for c in FP.calls(fake["log"])) >= 2)
    assert wait_until(lambda: mixer._subscribe is not None
                      and mixer._subscribe.state().name == "Running")
    assert mixer.available() and rec.errors == []


def test_edge_subscribe_restarts_are_bounded(fake, mixers):
    mixer, rec = make(mixers, restart_delay_ms=50)
    set_knob(fake, subscribe_exit=True)
    assert wait_until(lambda: any("Live updates" in e for e in rec.errors), 60)
    pump(0.5)
    runs = sum(c == ["subscribe"] for c in FP.calls(fake["log"]))
    assert runs == 1 + SM.SUBSCRIBE_RESTARTS
    assert mixer.available()


def test_happy_shutdown_stops_every_process(fake, mixers):
    set_knob(fake, hang=["set-sink-mute"])
    mixer, rec = make(mixers)
    assert wait_until(lambda: mixer._subscribe is not None
                      and mixer._subscribe.state().name == "Running")
    assert mixer.set_mute(mixer.device(SM.SINK, 56), True)
    assert wait_until(lambda: mixer.running_processes() >= 2)
    pids = [p.processId() for p in mixer._procs]
    mixer.shutdown()
    assert mixer.state() == SM.STATE_STOPPED and mixer.running_processes() == 0
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    mixer.start()  # done for good
    assert mixer.state() == SM.STATE_STOPPED
    assert not mixer.set_mute(mixer.device(SM.SINK, 56), False)
    pump(0.3)
    assert rec.states[-1] == SM.STATE_STOPPED
