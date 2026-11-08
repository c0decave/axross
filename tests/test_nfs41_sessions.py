"""core.nfs4_rpc's NFSv4.1 session: one slot used by one call at a time, its
sequence id kept in step with the server, and a lost session made again.

What was wrong: ``Nfs4.compound`` incremented ``_slot_seq`` outside any lock
and sent the call after it, so a listing and a transfer on two threads sent
sequence ids out of order (SEQ_MISORDERED); the counter was never put back
after a SEQUENCE the server refused or a reply that never came, so after
one such error every later call failed too; and NFS4ERR_BADSESSION /
DEADSESSION (a server reboot, a lease that ran out) were never handled - the
connection stayed broken for good.
"""

from __future__ import annotations

import errno
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import nfs3_rpc as R  # noqa: E402
from core import nfs4_rpc as N  # noqa: E402


class FakeServer:
    """The NFSv4.1 part of a server behind Nfs4.rpc: EXCHANGE_ID,
    CREATE_SESSION and a SEQUENCE that checks slot 0's sequence id."""

    def __init__(self):
        self.lock = threading.Lock()
        self.expected = 1
        self.sessions = 0
        self.misordered = 0
        self.calls = 0
        self.session_ok = True
        self.refuse_sequence: list[int] = []     # statuses for the next SEQUENCEs
        self.lose_reply_after = False            # done, but the reply is lost
        self.lose_request = False                # lost before the server saw it
        self.done_ops = 0                        # compounds the server carried out

    def call(self, proc, body):
        with self.lock:
            self.calls += 1
            if self.lose_request:
                self.lose_request = False
                raise R.RpcError(errno.ECONNRESET, "connection reset")
            u = R.Unpacker(body)
            u.string()
            u.uint()
            n = u.uint()
            first = u.uint()
            out = R.Packer()
            if first == N.OP_EXCHANGE_ID:
                return R.Unpacker(out.uint(0).string("").uint(1).uint(first).uint(0).hyper(7).uint(1).uint(0)
                                  .uint(0).hyper(0).opaque(b"o").opaque(b"s").uint(0).bytes())
            if first == N.OP_CREATE_SESSION:
                self.expected, self.session_ok = 1, True
                self.sessions += 1
                p = out.uint(0).string("").uint(1).uint(first).uint(0).fixed(b"S" * 16).uint(1).uint(0)
                for _ in range(2):
                    for _ in range(6):
                        p.uint(0)
                    p.uint(0)
                return R.Unpacker(p.bytes())
            assert first == N.OP_SEQUENCE, first
            u.fixed(16)
            seq = u.uint()
            u.uint(), u.uint(), u.uint()
            refuse = None
            if not self.session_ok:
                refuse = N.NFS4ERR_BADSESSION
            elif self.refuse_sequence:
                refuse = self.refuse_sequence.pop(0)
            elif seq != self.expected:
                self.misordered += 1
                refuse = N.NFS4ERR_SEQ_MISORDERED
            if refuse is not None:
                return R.Unpacker(out.uint(refuse).string("").uint(1).uint(first).uint(refuse).bytes())
            self.expected = (seq + 1) & 0xFFFFFFFF
            self.done_ops += 1
            p = out.uint(0).string("").uint(n).uint(first).uint(0).fixed(b"S" * 16)
            for _ in range(5):
                p.uint(0)
            for _ in range(n - 1):
                op = u.uint()
                if op == N.OP_PUTFH:
                    u.opaque(256)
                p.uint(op).uint(0)
            if self.lose_reply_after:
                self.lose_reply_after = False
                raise R.RpcError(errno.ECONNRESET, "connection reset")
            return R.Unpacker(p.bytes())


def client():
    srv = FakeServer()
    return srv, N.Nfs4(srv, minor=1)


def call(nfs):
    return nfs.compound([nfs._putfh(b"fh")], "x")


@pytest.fixture
def busy_switching():
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(old)


def test_sad_two_threads_on_one_session_stay_in_order(busy_switching):
    srv, nfs = client()
    errors = []

    def work():
        for _ in range(800):
            try:
                call(nfs)
            except OSError as exc:
                errors.append(str(exc))
    threads = [threading.Thread(target=work) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert not any(t.is_alive() for t in threads)
    assert (srv.misordered, errors[:3]) == (0, [])
    assert srv.sessions == 1


@pytest.mark.parametrize("status", [N.NFS4ERR_BADSESSION, N.NFS4ERR_DEADSESSION, N.NFS4ERR_STALE_CLIENTID])
def test_sad_a_lost_session_is_made_again_and_the_call_sent_once_more(status):
    srv, nfs = client()
    call(nfs)
    srv.refuse_sequence = [status]
    done = srv.done_ops
    assert call(nfs)[0][0] == N.OP_PUTFH
    assert srv.sessions == 2 and srv.done_ops == done + 2      # RECLAIM_COMPLETE, then the call
    call(nfs)


def test_sad_a_server_that_rebooted_is_recovered_from():
    # the review's repro: the server forgets the session; every call after it worked again
    srv, nfs = client()
    call(nfs)
    srv.session_ok = False
    for _ in range(3):
        call(nfs)
    assert srv.sessions == 2


def test_sad_the_slot_advances_only_when_the_server_took_the_sequence():
    srv, nfs = client()
    call(nfs)
    srv.refuse_sequence = [10008]                               # NFS4ERR_DELAY: refused, nothing done
    with pytest.raises(OSError, match="busy"):
        call(nfs)
    call(nfs)                           # the same id again: in step
    srv.lose_reply_after = True         # done, but the answer is lost: the id was used
    with pytest.raises(OSError):
        call(nfs)
    for _ in range(3):
        call(nfs)
    assert srv.misordered == 0 and srv.sessions == 1


def test_sad_a_request_lost_before_the_server_saw_it_is_resynced():
    srv, nfs = client()
    call(nfs)
    srv.lose_request = True
    with pytest.raises(OSError):
        call(nfs)
    for _ in range(3):
        call(nfs)                       # one SEQ_MISORDERED, a new session, then in step
    assert srv.sessions == 2


def test_edge_a_server_that_never_keeps_a_session_fails_after_one_retry():
    srv, nfs = client()
    call(nfs)

    class Forgetful:
        """Every session is gone again as soon as it was made."""

        @staticmethod
        def call(proc, body):
            reply = srv.call(proc, body)
            srv.session_ok = False
            return reply
    srv.session_ok = False
    nfs.rpc = Forgetful()
    with pytest.raises(OSError, match="does not know the session"):
        call(nfs)
    assert srv.sessions == 2            # one new session, one more try - no loop
