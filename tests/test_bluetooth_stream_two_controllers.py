"""A btmon capture of two controllers keeps their links apart (review
round 2).

Before: a btmon (Linux monitor) record carries the controller's index in
the upper 16 bits of its flags, and the parser dropped it: links, L2CAP
channels and ACL fragments were kept by connection handle alone. A
handle is the controller's own number, so hci0's link 0x0040 and hci1's
link 0x0040 were one: the second Connection Complete closed the first
link, hci1's traffic was booked to hci0's peer, and a fragment from one
controller was glued to the other's. Now everything is kept by
(controller, handle).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import bluetooth_stream as BS  # noqa: E402
from tests.test_bluetooth_stream import acl, l2cap, le_connected  # noqa: E402

#: btmon opcodes: event, ACL sent (TX), ACL received (RX)
EVENT, ACL_TX, ACL_RX = 3, 4, 5


def _monitor(records) -> bytes:
    """A btmon capture: (controller, opcode, H4 packet) records."""
    parts = [BS.BTSNOOP_MAGIC, struct.pack(">II", 1, BS.DATALINK_MONITOR)]
    for n, (controller, opcode, packet) in enumerate(records):
        body = packet[1:]  # the monitor format has no H4 type byte
        parts.append(struct.pack(">IIIIq", len(body), len(body), (controller << 16) | opcode, 0,
                                 BS._EPOCH_DELTA_US + n * 1_000_000))
        parts.append(body)
    return b"".join(parts)


def _with_address(packet: bytes, last: int) -> bytes:
    """*packet* (LE Connection Complete) with a peer address ending in *last*."""
    data = bytearray(packet)
    data[3 + 6] = last  # the event body (after 3 bytes) has the peer address at 6, LSB first
    return bytes(data)


def test_sad_two_controllers_with_the_same_handle_are_two_links(tmp_path):
    h = 0x0040
    capture = tmp_path / "two.btsnoop"
    capture.write_bytes(_monitor([
        (0, EVENT, _with_address(le_connected(h), 0x01)),
        (1, EVENT, _with_address(le_connected(h), 0x02)),
        (0, ACL_RX, acl(h, l2cap(4, b"\x1b\x03\x00\x10"))),  # a notification on hci0
        (1, ACL_TX, acl(h, l2cap(4, b"\x0a\x03\x00"))),  # a read on hci1
        (1, ACL_TX, acl(h, l2cap(4, b"\x0a\x04\x00"))),
    ]))
    parsed = BS.parse_file(capture)
    links = parsed.all_links()
    assert len(links) == 2
    assert all(link.end is None for link in links), "hci1's link closed hci0's"
    first, second = parsed.links[(0, h)], parsed.links[(1, h)]
    assert first.address != second.address
    att0 = parsed.streams[(0, h, 4, "in")]
    att1 = parsed.streams[(1, h, 4, "out")]
    assert att0.att == {"notify": 1} and att0.address == first.address
    assert att1.att == {"read": 2} and att1.address == second.address
    assert (0, h, 4, "out") not in parsed.streams and (1, h, 4, "in") not in parsed.streams


def test_edge_a_fragment_is_not_glued_to_the_other_controllers_frame(tmp_path):
    h = 0x0041
    whole = l2cap(4, b"\x1b" + b"\x00" * 9)  # 14 bytes: split into two fragments below
    first_part = acl(h, whole[:8])
    rest = acl(h, whole[8:], first=False)
    capture = tmp_path / "fragments.btsnoop"
    capture.write_bytes(_monitor([
        (0, EVENT, le_connected(h)), (1, EVENT, le_connected(h)),
        (0, ACL_RX, first_part),
        (1, ACL_RX, rest),  # hci1 continues nothing: an error, not hci0's frame
        (0, ACL_RX, rest),
    ]))
    parsed = BS.parse_file(capture)
    assert parsed.streams[(0, h, 4, "in")].frames == 1
    assert (1, h, 4, "in") not in parsed.streams
    assert parsed.errors == 1
