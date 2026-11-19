"""WMI: the connection is checked, recovers, is shared safely, and quotes.

Review of the WMI backend (connection types, 2026-11):

* home() returned "C:\\Users\\<user>" without connecting: Test Connection
  reported success with a wrong password or an unreachable host.
* A DCOM connection that broke (reset, RPC_E_DISCONNECTED) stayed cached:
  every later call failed on the dead object until axross restarted, and
  the session had no ``connected`` attribute for ConnectionManager.
* Two threads (a pane's listing, a transfer's stat) ran queries on one
  DCOM connection at once.
* A refused login was impacket's "rpc_s_access_denied".
* WQL escapes with a backslash, not by doubling quotes: ``'..O''Brien..'``
  is no valid WQL string. Values now travel as double-quoted literals (a
  Windows name never holds a double quote).

No DCOM server here: impacket's DCOMConnection and the WBEM login are
replaced by fakes that count connects and record queries.
"""

from __future__ import annotations

import threading
import time

import pytest

pytest.importorskip("impacket.dcerpc.v5.dcom.wmi")

from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError  # noqa: E402
from impacket.dcerpc.v5.rpcrt import DCERPCException  # noqa: E402

from core import wmi_client as W  # noqa: E402
from core.user_errors import describe  # noqa: E402

S_FALSE = DCERPCSessionError(error_code=1)


class _Obj:
    def __init__(self, props):
        self._props = props

    def getProperties(self):  # noqa: N802
        return {k: {"value": v} for k, v in self._props.items()}


class _Enum:
    def __init__(self, wbem, rows):
        self._wbem, self._rows = wbem, list(rows)

    def Next(self, timeout, count):  # noqa: N802
        self._wbem.enter()
        try:
            time.sleep(0.001)
            if self._rows:
                return [_Obj(self._rows.pop(0))]
            raise S_FALSE
        finally:
            self._wbem.leave()

    def RemRelease(self):  # noqa: N802
        pass


class _Wbem:
    def __init__(self, rows=None, fail=None):
        self.rows = rows if rows is not None else [{"Name": "c:\\x", "FileName": "x"}]
        self.fail = fail
        self.queries: list[str] = []
        self.busy = 0
        self.overlaps = 0
        self._guard = threading.Lock()

    def enter(self):
        with self._guard:
            self.busy += 1
            if self.busy > 1:
                self.overlaps += 1

    def leave(self):
        with self._guard:
            self.busy -= 1

    def ExecQuery(self, query):  # noqa: N802
        self.queries.append(query)
        if self.fail is not None:
            raise self.fail
        return _Enum(self, self.rows)

    def RemRelease(self):  # noqa: N802
        pass


@pytest.fixture
def dcom(monkeypatch):
    """Fake DCOM stack; ``state["wbems"]`` holds one _Wbem per connect."""
    state = {"connects": 0, "wbems": [], "connect_fails": None, "args": None, "next_fail": None}

    class _Dcom:
        def __init__(self, *args, **kwargs):
            state["args"] = args
            if state["connect_fails"] is not None:
                raise state["connect_fails"]
            state["connects"] += 1

        def CoCreateInstanceEx(self, *a):  # noqa: N802
            return object()

        def disconnect(self):
            pass

    class _Login:
        def __init__(self, iface):
            pass

        def NTLMLogin(self, *a):  # noqa: N802
            wbem = _Wbem(fail=state["next_fail"])
            state["next_fail"] = None
            state["wbems"].append(wbem)
            return wbem

        def RemRelease(self):  # noqa: N802
            pass

    monkeypatch.setattr(W, "DCOMConnection", _Dcom)
    monkeypatch.setattr(W, "IWbemLevel1Login", _Login)
    return state


def _session(username="u"):
    return W.WMISession("win.example.test", username, "pw")


# --- Test Connection --------------------------------------------------------


def test_happy_home_connects_first(dcom):
    s = _session("alice")
    assert s.home() == "C:\\Users\\alice"
    assert dcom["connects"] == 1


def test_sad_home_of_an_unreachable_host_fails(dcom):
    dcom["connect_fails"] = ConnectionRefusedError(111, "Connection refused")
    with pytest.raises(OSError) as info:
        _session().home()
    assert "refused the connection" in describe(info.value)


def test_sad_a_refused_login_says_what_to_check(dcom):
    dcom["connect_fails"] = DCERPCException("rpc_s_access_denied")
    with pytest.raises(W.WmiLoginRefused) as info:
        _session().home()
    text = describe(info.value)
    assert "refused the WMI login" in text and "DOMAIN\\user" in text


def test_edge_domain_backslash_user_is_split(dcom):
    s = _session("CORP\\alice")
    assert s.home() == "C:\\Users\\alice"
    host, user, password, domain = dcom["args"][:4]
    assert (user, domain) == ("alice", "CORP")


# --- dropped connection -----------------------------------------------------


def test_sad_a_broken_connection_reconnects_on_the_next_call(dcom):
    dcom["next_fail"] = DCERPCException("RPC_E_DISCONNECTED")
    s = _session()
    with pytest.raises(OSError):
        s.exists("C:\\x")
    assert s.exists("C:\\x") is True  # a new connection, not the dead one
    assert dcom["connects"] == 2
    assert s.connected is True


def test_edge_a_wmi_error_answer_keeps_the_connection(dcom):
    dcom["next_fail"] = DCERPCSessionError(error_code=0x80041003)  # WBEM_E_ACCESS_DENIED
    s = _session()
    with pytest.raises(OSError):
        s.exists("C:\\x")
    assert dcom["connects"] == 1
    assert s._wbem is dcom["wbems"][0]


def test_happy_close_says_not_connected(dcom):
    s = _session()
    s.home()
    s.close()
    assert s.connected is False


# --- threads ------------------------------------------------------------------


def test_edge_two_threads_never_query_at_once(dcom):
    s = _session()
    s.home()
    errors = []

    def work():
        try:
            for _ in range(20):
                s.stat("C:\\x")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors
    assert dcom["wbems"][0].overlaps == 0


# --- quoting ------------------------------------------------------------------


def test_sad_an_apostrophe_is_no_doubled_quote(dcom):
    s = _session()
    s.stat("C:\\Bob's files")
    query = dcom["wbems"][0].queries[0]
    assert "''" not in query
    assert 'WHERE Name = "C:\\\\Bob\'s files"' in query


def test_edge_a_double_quote_is_refused():
    with pytest.raises(W.WmiValueError):
        W._wql_literal('C:\\a"b')
    assert W._wql_literal("C:\\") == '"C:\\\\"'
