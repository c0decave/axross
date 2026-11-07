"""Connection streams in an HCI capture (core.bluetooth_stream).

The request: identification and visualisation of connection streams. A
btsnoop capture (btmon -w, Android, Bumble) is split into links (from the
connection events) and L2CAP channels; a dynamic channel's protocol comes
from the PSM of its Connection Request (SDP, RFCOMM, AVDTP = A2DP audio,
HID ...). Packets here are built per the Core spec's layouts; the
over-the-air capture is checked in tests/test_bluetooth_radio.py.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import bluetooth_stream as BS  # noqa: E402

PEER = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])  # 06:05:04:03:02:01


def event(code: int, body: bytes) -> bytes:
    return bytes([0x04, code, len(body)]) + body


def classic_connected(handle: int) -> bytes:
    return event(0x03, bytes([0]) + struct.pack("<H", handle) + PEER + bytes([0x01, 0x00]))


def le_connected(handle: int, role: int = 0) -> bytes:
    return event(0x3E, bytes([0x01, 0x00]) + struct.pack("<HBB", handle, role, 0) + PEER +
                 bytes(7))


def disconnected(handle: int) -> bytes:
    return event(0x05, bytes([0]) + struct.pack("<HB", handle, 0x13))


def acl(handle: int, frame: bytes, first: bool = True) -> bytes:
    word = handle | ((0x2 if first else 0x1) << 12)
    return bytes([0x02]) + struct.pack("<HH", word, len(frame)) + frame


def l2cap(cid: int, body: bytes) -> bytes:
    return struct.pack("<HH", len(body), cid) + body


def signal(code: int, ident: int, data: bytes, cid: int = 0x0001) -> bytes:
    return l2cap(cid, struct.pack("<BBH", code, ident, len(data)) + data)


def test_happy_a_classic_link_with_an_avdtp_audio_stream():
    h = 0x000B
    packets = [
        (1.0, True, classic_connected(h)),
        # we ask for PSM 0x0019 (AVDTP) from our cid 0x0040; the peer answers with 0x0071
        (1.1, False, acl(h, signal(0x02, 7, struct.pack("<HH", 0x0019, 0x0040)))),
        (1.2, True, acl(h, signal(0x03, 7, struct.pack("<HHHH", 0x0071, 0x0040, 0, 0)))),
        # media: we send to the peer's cid, it answers on ours
        *((2.0 + n * 0.1, False, acl(h, l2cap(0x0071, bytes(600)))) for n in range(20)),
        (3.0, True, acl(h, l2cap(0x0040, bytes(10)))),
        (4.0, True, disconnected(h)),
    ]
    parsed = BS.StreamParser().feed_all(packets)
    [link] = parsed.all_links()
    assert (link.address, link.radio, link.start, link.end) == ("06:05:04:03:02:01",
                                                                 "Classic", 1.0, 4.0)
    out = parsed.streams[(h, 0x0071, "out")]
    assert (out.protocol, out.psm, out.frames, out.bytes) == ("AVDTP (audio/video stream)",
                                                              0x0019, 20, 12000)
    assert out.rate == pytest.approx(12000 / 1.9)
    assert parsed.streams[(h, 0x0040, "in")].protocol == "AVDTP (audio/video stream)"
    assert parsed.sorted_streams()[0] is out
    assert parsed.streams[(h, 0x0001, "out")].protocol == "L2CAP signalling"
    assert parsed.errors == 0


def test_happy_le_att_counts_and_role():
    h = 0x0040
    packets = [(0.0, True, le_connected(h, role=0)),
               (0.1, False, acl(h, l2cap(0x0004, bytes([0x0A, 0x03, 0x00])))),  # read
               (0.2, True, acl(h, l2cap(0x0004, bytes([0x0B, 0x5A])))),          # response
               (0.3, True, acl(h, l2cap(0x0004, bytes([0x1B, 0x03, 0x00, 0x59])))),  # notify
               (0.4, False, acl(h, l2cap(0x0006, bytes([0x01, 0x03]))))]          # SMP
    parsed = BS.StreamParser().feed_all(packets)
    assert parsed.links[h].radio == "LE" and parsed.links[h].role == "central"
    assert parsed.streams[(h, 4, "out")].att == {"read": 1}
    assert parsed.streams[(h, 4, "in")].att == {"read": 1, "notify": 1}
    assert parsed.streams[(h, 6, "out")].protocol == "SMP (pairing)"


def test_happy_le_credit_based_channel():
    h = 0x0041
    packets = [(0.0, True, le_connected(h)),
               (0.1, False, acl(h, signal(0x14, 3, struct.pack("<HHHHH", 0x0027, 0x0041, 64,
                                                                64, 10), cid=0x0005))),
               (0.2, True, acl(h, signal(0x15, 3, struct.pack("<HHHHH", 0x0090, 64, 64, 10,
                                                                0), cid=0x0005))),
               (0.3, False, acl(h, l2cap(0x0090, bytes(20))))]
    parsed = BS.StreamParser().feed_all(packets)
    assert parsed.streams[(h, 0x0090, "out")].protocol == "EATT"


def test_edge_fragments_are_reassembled():
    h = 0x0002
    frame = l2cap(0x0004, bytes([0x1B, 0x03, 0x00]) + bytes(100))
    packets = [(0.0, True, le_connected(h)),
               (0.1, True, acl(h, frame[:27])),
               (0.2, True, acl(h, frame[27:60], first=False)),
               (0.3, True, acl(h, frame[60:], first=False))]
    parsed = BS.StreamParser().feed_all(packets)
    stream = parsed.streams[(h, 4, "in")]
    assert (stream.frames, stream.bytes, stream.att) == (1, 103, {"notify": 1})


def test_edge_a_channel_seen_before_its_response_is_named_afterwards():
    h = 0x0003
    packets = [(0.0, True, classic_connected(h)),
               (0.1, False, acl(h, signal(0x02, 1, struct.pack("<HH", 0x0003, 0x0041)))),
               (0.15, True, acl(h, l2cap(0x0041, b"x"))),
               (0.2, True, acl(h, signal(0x03, 1, struct.pack("<HHHH", 0x0050, 0x0041, 0,
                                                                0))))]
    parsed = BS.StreamParser().feed_all(packets)
    assert parsed.streams[(h, 0x0041, "in")].protocol == "RFCOMM"


def test_sad_a_refused_channel_stays_unnamed_and_broken_packets_count():
    h = 0x0004
    packets = [(0.0, True, classic_connected(h)),
               (0.1, False, acl(h, signal(0x02, 1, struct.pack("<HH", 0x0001, 0x0042)))),
               (0.2, True, acl(h, signal(0x03, 1, struct.pack("<HHHH", 0, 0x0042, 2, 0)))),
               (0.3, True, acl(h, l2cap(0x0042, b"x"))),
               (0.4, True, acl(h, b"\x01", first=False)),  # a continuation with no start
               (0.5, True, bytes([0x02, 0x04, 0x20])),     # too short
               (0.6, True, acl(h, b"\x05\x00"))]           # a first fragment of 2 bytes
    parsed = BS.StreamParser().feed_all(packets)
    assert parsed.streams[(h, 0x0042, "in")].protocol == "Dynamic channel 0x0042"
    assert parsed.errors == 2  # the 3-byte ACL is too short to be looked at
    assert parsed.packets == 7


def test_edge_a_reused_handle_starts_a_new_link():
    packets = [(0.0, True, le_connected(1)), (5.0, True, le_connected(1)),
               (6.0, True, disconnected(1))]
    parsed = BS.StreamParser().feed_all(packets)
    first, second = parsed.all_links()
    assert (first.start, first.end, second.start, second.end) == (0.0, 5.0, 5.0, 6.0)


def test_happy_rate_series():
    stream = BS.Stream(1, 0x40, "out", "x")
    for t, size in ((10.0, 100), (10.5, 100), (12.2, 50)):
        stream.note(t, size)
    assert BS.rate_series(stream) == [200.0, 0.0, 50.0]
    assert BS.rate_series(stream, bucket=0.5) == [200.0, 200.0, 0.0, 0.0, 100.0]
    assert BS.rate_series(BS.Stream(1, 1, "in", "x")) == []


def test_happy_btsnoop_round_trip(tmp_path):
    packets = [(1_800_000_000.25, True, le_connected(5)),
               (1_800_000_001.5, False, acl(5, l2cap(4, b"\x0a\x01\x00")))]
    path = tmp_path / "c.btsnoop"
    BS.write_btsnoop(path, packets)
    datalink, back = BS.read_btsnoop(path)
    assert datalink == BS.DATALINK_H4
    assert [(round(t, 6), r, p) for t, r, p in back] == packets
    assert BS.parse_file(path).links[5].radio == "LE"


def test_happy_h1_and_monitor_datalinks():
    def record(flags: int, body: bytes) -> bytes:
        return struct.pack(">IIIIq", len(body), len(body), flags, 0, BS._EPOCH_DELTA_US) + body

    ev = le_connected(9)[1:]
    h1 = BS.BTSNOOP_MAGIC + struct.pack(">II", 1, BS.DATALINK_H1) + record(3, ev)
    _dl, [(_t, received, packet)] = BS.parse_btsnoop(h1)
    assert received and packet == le_connected(9)
    mon = BS.BTSNOOP_MAGIC + struct.pack(">II", 1, BS.DATALINK_MONITOR) + \
        record(3, ev) + record(0, b"index")  # opcode 3: event; 0: new index (skipped)
    _dl, packets = BS.parse_btsnoop(mon)
    assert [p for _t, _r, p in packets] == [le_connected(9)]


def test_sad_not_a_btsnoop_file():
    with pytest.raises(ValueError):
        BS.parse_btsnoop(b"PK\x03\x04 not a capture")
    with pytest.raises(ValueError):
        BS.parse_btsnoop(BS.BTSNOOP_MAGIC + struct.pack(">II", 1, 9999))
    # a truncated last record is dropped, not an error
    data = BS.BTSNOOP_MAGIC + struct.pack(">II", 1, BS.DATALINK_H4) + \
        struct.pack(">IIIIq", 50, 50, 0, 0, 0) + b"short"
    assert BS.parse_btsnoop(data)[1] == []


# =====================================================================================
# the Streams dialog
# =====================================================================================

def capture_file(tmp_path, name="c.btsnoop"):
    h = 0x000B
    t0 = 1_800_000_000.0
    packets = [
        (t0, True, classic_connected(h)),
        (t0 + 0.1, False, acl(h, signal(0x02, 7, struct.pack("<HH", 0x0019, 0x0040)))),
        (t0 + 0.2, True, acl(h, signal(0x03, 7, struct.pack("<HHHH", 0x0071, 0x0040, 0, 0)))),
        *((t0 + 1 + n * 0.1, False, acl(h, l2cap(0x0071, bytes(600)))) for n in range(30)),
        (t0 + 2.0, True, acl(h, l2cap(0x0040, bytes(10)))),
        (t0 + 5.0, True, le_connected(0x40)),
        (t0 + 5.1, False, acl(0x40, l2cap(0x0004, bytes([0x0A, 0x03, 0x00])))),
    ]
    path = tmp_path / name
    BS.write_btsnoop(path, packets)
    return path, packets


@pytest.fixture
def qt():
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_happy_the_streams_dialog_shows_links_streams_and_a_graph(qt, tmp_path):
    from ui.bluetooth_streams import StreamsDialog

    path, _packets = capture_file(tmp_path)
    dialog = StreamsDialog(path=str(path))
    try:
        assert dialog.links.rowCount() == 3  # (all) + 2 links
        assert dialog.table.rowCount() == len(dialog.parsed.streams)
        assert dialog.table.item(0, 1).text() == "AVDTP (audio/video stream)"  # busiest
        assert dialog.table.item(0, 2).text() == "sent"
        assert any(values for values, _c in dialog.graph.series)
        dialog.links.selectRow(2)  # the LE link
        assert {dialog.table.item(r, 1).text() for r in range(dialog.table.rowCount())} == \
            {"ATT (GATT)"}
        assert dialog.table.item(0, 6).text() == "read 1"
        assert "7 packets" in dialog.info.text() or "packets" in dialog.info.text()
    finally:
        dialog.close()


def test_happy_visualize_feeds_the_media_players_visualizer(qt, tmp_path):
    pytest.importorskip("numpy")
    from ui import bluetooth_streams as UBS

    path, _packets = capture_file(tmp_path)
    dialog = UBS.StreamsDialog(path=str(path))
    try:
        window = dialog.visualize()
        assert window is not None and window.visualizer.timer.isActive()
        engine = window.engine
        clock = {"t": 0.0}
        engine._clock = lambda: clock["t"]
        engine.restart()
        clock["t"] = 1.9  # inside the AVDTP burst
        bars = engine.current_bars(8)
        assert len(bars) == 8 and max(bars) > 0.5
        samples = engine.current_samples()
        assert samples.shape == (engine.FRAMES, 2) and float(abs(samples[:, 0]).max()) > 0
        window.visualizer.tick()  # one frame paints without error
        window.close()
    finally:
        dialog.close()


def test_sad_a_file_that_is_no_capture_says_so(qt, tmp_path):
    from ui.bluetooth_streams import StreamsDialog

    bad = tmp_path / "notes.txt"
    bad.write_text("hello")
    dialog = StreamsDialog(ask_open=lambda *_a: str(bad))
    try:
        dialog.open_button.click()
        assert "cannot be read" in dialog.info.text() and dialog.parsed is None
        assert not dialog.visual_button.isEnabled()
    finally:
        dialog.close()


def test_edge_follow_reads_a_growing_capture_again(qt, tmp_path):
    import os

    from ui.bluetooth_streams import StreamsDialog

    path, packets = capture_file(tmp_path)
    dialog = StreamsDialog(path=str(path))
    try:
        dialog.follow_check.setChecked(True)
        assert dialog._follow.isActive()
        BS.write_btsnoop(path, packets + [(1_800_000_009.0, True, le_connected(0x41))])
        os.utime(path, ns=(1, 2))  # a new mtime even on a coarse clock
        dialog._follow_tick()
        assert dialog.links.rowCount() == 4
    finally:
        dialog.close()


# =====================================================================================
# found in review: forged timestamps and big captures
# =====================================================================================

def test_sad_a_capture_spanning_years_does_not_eat_the_memory():
    stream = BS.Stream(1, 0x40, "out", "x")
    stream.note(0.0, 10)                # year 0 of a forged record
    stream.note(1_800_000_000.0, 10)    # now
    series = BS.rate_series(stream)
    assert 1 <= len(series) <= BS.MAX_BUCKETS + 1
    nan = BS.Stream(1, 0x40, "in", "x")
    nan.note(float("nan"), 1)
    assert BS.rate_series(nan) == []


def test_happy_the_traffic_engine_matches_a_plain_count(qt):
    from ui.bluetooth_streams import TrafficEngine

    stream = BS.Stream(1, 0x40, "out", "x")
    for n in range(200):
        stream.note(100.0 + n * 0.05, 10 + n % 7)
    engine = TrafficEngine([stream], clock=lambda: 0.0)
    for t in (100.0, 100.5, 104.0, 109.9, 110.9):  # within one round of the replay
        engine._t0 = -(t - engine.begin)
        plain = sum(size for when, size in stream.samples if t - 1.0 < when <= t)
        assert engine.levels()[0] == pytest.approx(min(1.0, plain / engine.top))


def test_edge_many_one_byte_fragments_reassemble_quickly():
    import time

    h = 0x0005
    frame = l2cap(0x0040, bytes(60_000))
    packets = [(0.0, True, le_connected(h)), (0.1, True, acl(h, frame[:4]))]
    packets += [(0.2, True, acl(h, frame[i:i + 1], first=False)) for i in range(4, len(frame))]
    start = time.monotonic()
    parsed = BS.StreamParser().feed_all(packets)
    assert time.monotonic() - start < 5
    assert parsed.streams[(h, 0x0040, "in")].bytes == 60_000
