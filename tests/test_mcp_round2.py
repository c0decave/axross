"""Round 2 of the adversarial review of the headless MCP server.

- H1/H2: a private key past the first MiB never leaves through a tool that
  copies or transforms bytes (encrypt, pack, transfer to a remote, copy)
  or through resources/read: every local read is scanned whole.
- H3: tools that open files by name (archive_list/extract, preview,
  file(1)) get the file the confined backend opened - a folder swapped for
  a symlink after the check no longer leads them outside the root.
- H4: an SFTP listing stops at MAX_LISTING_ENTRIES and at a cancel.
- M1: preview tells the type from the header (an ICO is never decoded),
  budgets the decode's copies and decodes two at a time.
- M2: stdio runs tool calls on workers: ping is answered meanwhile, a
  cancelled call gets no response, stdin EOF ends the server.
- M3: outputs are written under a temporary name and renamed when whole;
  what a killed process left is swept at the next start.
- M4: a remote copy of a symlink or device is refused.
- M5: calls that did not stop are counted; past the cap new work waits.
- LOW: preview as a task, text paging over bad bytes, one initialize per
  session, legacy AXXE1 streamed, secret names with backup suffixes and
  more, strict base64, names_b64 length, pack of a non-UTF-8 name,
  write_file 0600, recursive_checksum's total, remote secret names, the
  release check, a resumable copy from a lying source, walk caps.
"""

from __future__ import annotations

import base64
import io
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from core import mcp_server as M
from core.local_fs import LocalFS
from tests import mcp_group_testkit as T

ROOT = Path(__file__).resolve().parents[1]
_KEY_MARK = b"OPENSSH " + b"PRIVATE KEY-----"  # split: the leak gate reads this file
KEY = (b"-----BEGIN " + _KEY_MARK + b"\nb3BlbnNzaC1rZXktdjE=\n-----END " + _KEY_MARK + b"\n")


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    r.mkdir()
    return r


def _late_key(root: Path) -> Path:
    from core import protected_places as PP

    path = root / "late.txt"
    path.write_bytes(b"a" * (PP.SECRET_CONTENT_SCAN + 600_000) + KEY)
    return path


# --- H1 / H2 ----------------------------------------------------------------------


@pytest.mark.parametrize("tool,args", [
    ("encrypt", lambda r: {"path": str(r / "late.txt"), "passphrase": "known-pass"}),
    ("pack", lambda r: {"folder": str(r), "names": ["late.txt"], "archive_name": "p",
                        "format": "zip"}),
    ("pack", lambda r: {"folder": str(r), "names": ["late.txt"], "archive_name": "q",
                        "format": "tar.gz"}),
])
def test_sad_a_key_past_the_first_mib_is_not_encrypted_or_packed(root, tool, args):
    _late_key(root)
    tools = T.build(root, {"crypto", "packer"}, allow_write=True)
    with pytest.raises(T.RpcError):
        T.call(tools, tool, args(root))
    assert sorted(p.name for p in root.iterdir()) == ["late.txt"]  # nothing left behind


def test_sad_a_key_past_the_first_mib_is_not_copied_to_a_remote(root, tmp_path, monkeypatch):
    from core import credentials
    from core import profiles as P
    from core.profiles import ConnectionProfile

    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)
    path = tmp_path / "profiles.json"
    monkeypatch.setattr(P, "PROFILES_FILE", path)
    path.write_text(json.dumps({"ram": ConnectionProfile(name="ram", protocol="ramfs").to_dict()}))
    _late_key(root)
    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    bid = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    out = T.call(tools, "transfer_copy", {"src": str(root / "late.txt"), "dst_backend": bid,
                                          "dst": "/late.txt"})
    assert out["entries"][0]["action"] == "error" and "private key" in out["entries"][0]["error"]
    with pytest.raises(T.RpcError):
        T.call(tools, "read_file", {"backend": bid, "path": "/late.txt"})
    from core import mcp_groups

    for registry in list(mcp_groups.RemoteRegistry._live):
        registry.close_all()


def test_sad_resources_read_does_not_serve_a_key_past_the_first_mib(root):
    _late_key(root)
    catalog = M._build_resources(LocalFS(), root=str(root))
    with pytest.raises(PermissionError):
        catalog.read(f"axross://{root}/late.txt")


def test_edge_the_scanner_sees_a_marker_split_between_two_reads():
    from core.protected_places import SecretScanningReader

    data = b"x" * 1000 + KEY
    reader = SecretScanningReader(io.BytesIO(data), "f")
    with pytest.raises(PermissionError):
        while reader.read(7):
            pass
    plain = SecretScanningReader(io.BytesIO(b"no key here " * 1000), "g")
    assert len(plain.read()) == 12000


# --- H3 -----------------------------------------------------------------------------


def test_sad_archive_extract_after_a_folder_swap_never_reads_the_outside(root, tmp_path,
                                                                        monkeypatch):
    import zipfile

    from core import mcp_groups

    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "real").mkdir()
    (root / "out").mkdir()
    with zipfile.ZipFile(root / "real" / "t.zip", "w") as z:
        z.writestr("inside_member", "i")
    with zipfile.ZipFile(outside / "t.zip", "w") as z:
        z.writestr("OUTSIDE_MEMBER", "o")
    real_check = mcp_groups._local_archive

    def check_then_swap(env, args):
        found = real_check(env, args)
        os.rename(root / "real", root / "real_tmp")  # the race, made certain
        os.symlink(outside, root / "real")
        return found

    monkeypatch.setattr(mcp_groups, "_local_archive", check_then_swap)
    tools = T.build(root, {"archive"}, allow_write=True)
    try:
        out = T.call(tools, "archive_extract", {"path": str(root / "real" / "t.zip"),
                                               "dest_dir": str(root / "out")})
    except T.RpcError:
        out = None  # refused is fine; outside content is not
    found = [p.name for p in (root / "out").rglob("*")]
    assert "OUTSIDE_MEMBER" not in found
    if out is not None:
        assert "inside_member" in found


def test_happy_a_pinned_path_stays_the_opened_file(root, tmp_path):
    from core.confined_fs import ConfinedLocalFS, pinned_path

    (root / "d").mkdir()
    (root / "d" / "f.txt").write_text("INSIDE")
    other = tmp_path / "other"
    other.mkdir()
    (other / "f.txt").write_text("OUTSIDE")
    backend = ConfinedLocalFS([str(root)])
    with pinned_path(backend, str(root / "d" / "f.txt")) as pinned:
        os.rename(root / "d", root / "d2")
        os.symlink(other, root / "d")
        assert Path(pinned).read_text() == "INSIDE" and pinned.endswith("f.txt")


# --- H4 -----------------------------------------------------------------------------


def test_sad_an_endless_sftp_listing_stops_at_the_cap_and_at_cancel(tmp_path, monkeypatch):
    pytest.importorskip("paramiko")
    import paramiko

    from core import ssh_client, transfer_hooks
    from tests.sftp_testkit import SftpServer

    served = tmp_path / "served"
    (served / "big").mkdir(parents=True)
    for i in range(300):
        (served / "big" / f"f{i}").write_text("")
    server = SftpServer(str(served))
    try:
        transport = paramiko.Transport(("127.0.0.1", server.port))
        transport.connect(username="u", password="p")
        sftp = paramiko.SFTPClient.from_transport(transport)
        monkeypatch.setattr(ssh_client, "MAX_LISTING_ENTRIES", 100)
        with pytest.raises(OSError, match="more than 100 entries"):
            ssh_client._listdir_attr(sftp, "/big")
        monkeypatch.setattr(ssh_client, "MAX_LISTING_ENTRIES", 10_000)
        stop = threading.Event()
        stop.set()
        with transfer_hooks.active(transfer_hooks.TransferHooks(cancel_event=stop)):
            with pytest.raises(InterruptedError):
                ssh_client._listdir_attr(sftp, "/big")
        assert len(ssh_client._listdir_attr(sftp, "/big")) == 300
        transport.close()
    finally:
        server.close()


# --- M1 -----------------------------------------------------------------------------


def test_sad_preview_tells_the_type_from_the_header_and_never_decodes_an_ico(tmp_path):
    from core import previews as P

    ico = tmp_path / "x.png"  # an ICO named .png
    ico.write_bytes(b"\x00\x00\x01\x00" + b"\x00" * 60)
    assert P._sniff(str(ico)) is None
    png = tmp_path / "y.bin"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
    assert P._sniff(str(png)) == ("PNG", "image/png")


def test_sad_preview_budgets_the_decodes_copies(tmp_path, monkeypatch):
    pil = pytest.importorskip("PIL.Image")
    from core import previews as P

    big = tmp_path / "big.png"
    pil.new("RGB", (3000, 3000)).save(big)
    # 3000*3000*4 = 34 MiB once; three copies 103 MiB: over a 64 MiB budget.
    monkeypatch.setattr(P, "PILLOW_ALLOC_LIMIT_MIB", 64)
    with pytest.raises(P.PreviewTooLarge):
        P._decode_with_pillow(str(big), 256)
    assert P._PILLOW_SLOTS._value == 2  # released after the refusal


# --- M2 -----------------------------------------------------------------------------


def _slow_tool(release: threading.Event) -> M._Tool:
    def handler(args, ctx):
        while not release.is_set():
            ctx.check_cancel()
            time.sleep(0.01)
        return {"done": True}

    return M._Tool(name="slow", description="", schema={"type": "object"}, handler=handler,
                   timeout_seconds=60)


class _Pipe:
    """stdin fed line by line by the test; readline blocks until fed."""

    def __init__(self) -> None:
        self._lines: list[str] = []
        self._cond = threading.Condition()
        self._closed = False

    def feed(self, obj) -> None:
        with self._cond:
            self._lines.append(json.dumps(obj) + "\n")
            self._cond.notify_all()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def readline(self, limit: int = -1) -> str:
        with self._cond:
            while not self._lines and not self._closed:
                self._cond.wait()
            return self._lines.pop(0) if self._lines else ""


class _Out(io.StringIO):
    def lines(self):
        return [json.loads(x) for x in self.getvalue().splitlines() if x.strip()]


def _serve_with(tool, monkeypatch):
    stdin, out = _Pipe(), _Out()
    monkeypatch.setattr(M, "_build_tools", lambda *a, **k: [tool])
    thread = threading.Thread(target=M.serve, args=(M.ServerConfig(
        backend=LocalFS(), stdin=stdin, stdout=out, rate_limit_enabled=False),), daemon=True)
    thread.start()
    stdin.feed({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    return stdin, out, thread


def _wait_for(out, pred, seconds=10.0):
    end = time.time() + seconds
    while time.time() < end:
        if any(pred(m) for m in out.lines()):
            return True
        time.sleep(0.02)
    return False


def test_happy_ping_is_answered_while_a_call_runs_and_a_cancelled_call_gets_no_answer(
        monkeypatch):
    release = threading.Event()
    stdin, out, thread = _serve_with(_slow_tool(release), monkeypatch)
    stdin.feed({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "slow", "arguments": {}}})
    time.sleep(0.2)
    stdin.feed({"jsonrpc": "2.0", "id": "p", "method": "ping"})
    assert _wait_for(out, lambda m: m.get("id") == "p"), "ping waited for the call"
    stdin.feed({"jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 5}})
    time.sleep(0.5)
    stdin.feed({"jsonrpc": "2.0", "id": "p2", "method": "ping"})
    assert _wait_for(out, lambda m: m.get("id") == "p2")
    time.sleep(0.3)
    assert not any(m.get("id") == 5 for m in out.lines()), "a cancelled call was answered"
    stdin.close()
    thread.join(10)
    assert not thread.is_alive()
    release.set()


def test_sad_stdin_eof_ends_the_server_while_a_call_hangs(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(M, "SHUTDOWN_TASK_WAIT_SECONDS", 0.5)

    def stuck(args, ctx):
        release.wait(30)  # ignores cancel
        return {}

    tool = M._Tool(name="stuck", description="", schema={"type": "object"}, handler=stuck,
                   timeout_seconds=60)
    stdin, out, thread = _serve_with(tool, monkeypatch)
    stdin.feed({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "stuck", "arguments": {}}})
    time.sleep(0.2)
    started = time.monotonic()
    stdin.close()
    thread.join(10)
    assert not thread.is_alive() and time.monotonic() - started < 5
    release.set()


# --- M3 -----------------------------------------------------------------------------


def test_sad_a_write_that_fails_leaves_nothing_under_the_final_name(root):
    from core import mcp_groups

    env = mcp_groups.GroupEnv.__new__(mcp_groups.GroupEnv)
    env.entry_path = lambda path, backend: path

    seen = {}

    def broken(fh):
        fh.write(b"half")
        # A kill -9 here: what is on disk under the final name right now?
        seen["final"] = (root / "out.bin").exists()
        raise OSError("killed here")

    with pytest.raises(OSError):
        mcp_groups._place_new(env, LocalFS(), str(root / "out.bin"), broken)
    assert seen["final"] is False  # only the temporary name existed mid-write
    assert list(root.iterdir()) == []


def test_happy_what_a_killed_process_left_is_swept(tmp_path, monkeypatch):
    from core import partials

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    left = tmp_path / ".x.axross-part-999999999-ab"
    left.write_text("half")
    record = partials.track(str(left))
    # As if a process that no longer runs had written it.
    folder = partials._state_dir()
    (folder / record).rename(folder / ("999999999-" + record.split("-", 1)[1]))
    keep = tmp_path / "keep.txt"
    keep.write_text("mine")
    mine = partials.track(str(keep))  # this process: alive, left alone
    assert partials.sweep() == 1
    assert not left.exists() and keep.exists()
    partials.done(mine)


def test_sad_a_confined_copy_killed_mid_write_leaves_nothing_after_the_sweep(tmp_path):
    """copy / transfer_copy / bulk_copy into the MCP root go through the
    confined backend's temp file (``.name.<hex>.tmp``); a kill -9 before its
    rename left it for good until the temp name was recorded too."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "src.bin").write_bytes(b"x" * 4096)
    state = tmp_path / "state"
    child = (
        "import os, signal\n"
        "from core.confined_fs import ConfinedLocalFS\n"
        "fs = ConfinedLocalFS([%r])\n"
        "os.rename = lambda *a, **k: os.kill(os.getpid(), signal.SIGKILL)\n"
        "fs.copy(%r, %r)\n" % (str(root), str(root / "src.bin"), str(root / "dst.bin"))
    )
    env = dict(os.environ, XDG_STATE_HOME=str(state))
    proc = subprocess.run([sys.executable, "-c", child], cwd=str(Path(__file__).resolve().parents[1]),
                          env=env, timeout=60)
    assert proc.returncode == -9
    left = [p.name for p in root.iterdir() if p.name.endswith(".tmp")]
    assert left, "the kill should have left the temp file"
    sweep = subprocess.run(
        [sys.executable, "-c", "from core import partials; print(partials.sweep())"],
        cwd=str(Path(__file__).resolve().parents[1]), env=env, timeout=60,
        capture_output=True, text=True)
    assert sweep.stdout.strip() == "1"
    assert sorted(p.name for p in root.iterdir()) == ["src.bin"]


# --- M4 / M5 -------------------------------------------------------------------------


def test_sad_a_remote_copy_of_a_link_to_a_device_is_refused(root):
    from core.mcp_groups import RemoteRegistry
    from models.file_item import FileItem

    copied = []

    class Attr:
        st_mode = stat.S_IFLNK | 0o777

    class Sftp:
        def lstat(self, path):
            return Attr()

    class Remote:
        sftp = Sftp()

        def stat(self, path):
            return FileItem(name="zero", is_link=True)

        def exists(self, path):
            return False

        def copy(self, src, dst):  # the server-side `cp -p` that follows the link
            copied.append((src, dst))

    registry = RemoteRegistry()
    registry.attach("r", Remote(), None)
    tools = T.build(root, set(), allow_write=True, remote_registry=registry)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "copy", {"backend": "r", "src": "/zero", "dst": "/sink/z"})
    assert "symlink" in err.value.message and copied == []


def test_sad_new_work_waits_while_too_many_calls_did_not_stop(monkeypatch):
    stop = threading.Event()
    zombies = [threading.Thread(target=stop.wait, daemon=True) for _ in range(3)]
    for z in zombies:
        z.start()
    monkeypatch.setattr(M, "MAX_ABANDONED_WORKERS", 3)
    registry = M._AbandonedWorkers()
    monkeypatch.setattr(M, "_ABANDONED", registry)
    for z in zombies:
        registry.add(z)
    resp = M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "x", "arguments": {}}}, [])
    assert resp["error"]["code"] == M.ERR_RATE_LIMITED and "did not stop" in \
        resp["error"]["message"]
    stop.set()
    for z in zombies:
        z.join(5)
    assert registry.refusal() is None


# --- LOW ----------------------------------------------------------------------------


def test_happy_preview_as_a_task_has_a_json_result():
    tasks = M._TaskRegistry()
    tool = M._Tool(name="preview", description="", schema={"type": "object"},
                   handler=lambda a, c: M._PreviewResult(data_b64="AA==", mime="image/png",
                                                         width=1, height=1))
    task = tasks.start("", "preview", {})
    M._run_task(task, tool, None, tasks)
    assert task.status == "done" and task.result["mimeType"] == "image/png"


def test_sad_paging_byte_by_byte_over_bad_bytes_keeps_every_character(root):
    (root / "t.txt").write_bytes(b"\xff\xfe\xe4\xb8\xad")
    tools = {t.name: t for t in M._build_tools(LocalFS(), allow_write=False, root=str(root))}
    offset, text = 0, ""
    for _ in range(10):
        r = tools["read_file"].handler({"path": str(root / "t.txt"), "encoding": "text",
                                        "max_bytes": 1, "offset": offset}, M._ToolContext())
        text += r["text"]
        if not r["truncated"]:
            break
        offset = r["next_offset"]
    assert text.endswith("中") and text.count("�") == 2


def test_sad_a_second_initialize_is_refused(root):
    tools = M._build_tools(LocalFS(), allow_write=False, root=str(root))
    state = M.ProtocolState()
    first = M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": "2025-11-25"}}, tools,
                              protocol=state)
    assert first["result"]["protocolVersion"] == "2025-11-25"
    again = M._handle_request({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                               "params": {"protocolVersion": "2024-11-05"}}, tools,
                              protocol=state)
    assert again["error"]["code"] == M.ERR_INVALID_REQUEST and state.version == "2025-11-25"


def test_happy_legacy_axxe1_decrypts_streamed(root):
    from core import encrypted_overlay as E

    data = os.urandom(3 * 1024 * 1024)
    blob = E.encrypt_bytes(data, "pw-123456")
    out = io.BytesIO()
    assert E.decrypt_v1_stream(io.BytesIO(blob), len(blob), out, "pw-123456",
                               chunk_size=65536) == len(data)
    assert out.getvalue() == data
    bad = bytearray(blob)
    bad[100] ^= 1
    with pytest.raises(E.InvalidCiphertext):
        E.decrypt_v1_stream(io.BytesIO(bytes(bad)), len(bad), io.BytesIO(), "pw-123456")
    (root / "old.axenc").write_bytes(bytes(bad))
    tools = T.build(root, {"crypto"}, allow_write=True)
    with pytest.raises(T.RpcError):
        T.call(tools, "decrypt", {"path": str(root / "old.axenc"), "passphrase": "pw-123456"})
    assert sorted(p.name for p in root.iterdir()) == ["old.axenc"]  # nothing left


@pytest.mark.parametrize("name", [".env~", ".git-credentials.bak", ".netrc.bak",
                                  "credentials.json.bak", "token.json", "service-account.json",
                                  "credentials.tfrc.json", ".dockercfg", "keys.jks",
                                  "secring.gpg"])
def test_sad_more_secret_names_and_their_backups(name):
    from core import protected_places as PP

    assert PP._secret_anywhere(name)


def test_sad_lenient_base64_and_a_short_names_b64_are_refused():
    with pytest.raises(ValueError, match="canonical"):
        M._decode_path_args({"path_b64": "YWJj="})
    with pytest.raises(ValueError, match="entries"):
        M._decode_path_args({"names": ["a", "b"], "names_b64": ["YQ=="]})
    assert M._decode_path_args({"path_b64": "YWJj"}) == {"path": "abc"}


@pytest.mark.skipif(sys.platform == "darwin", reason="APFS refuses names that are not UTF-8")
def test_happy_pack_keeps_a_name_that_is_not_utf8(root):
    import zipfile

    with open(os.fsencode(root) + b"/bad\xffname.txt", "wb") as fh:
        fh.write(b"x")
    tools = T.build(root, {"packer"}, allow_write=True)
    out = T.call(tools, "pack", {"folder": str(root), "names_b64": [
        base64.b64encode(b"bad\xffname.txt").decode()], "archive_name": "a", "format": "zip"})
    with zipfile.ZipFile(out["path"]) as z:
        assert z.infolist()[0].filename.encode("cp437") == b"bad\xffname.txt"


def test_happy_write_file_creates_0600(root):
    tools = T.build(root, set(), allow_write=True)
    T.call(tools, "write_file", {"path": str(root / "new.txt"), "content": "x"})
    assert stat.S_IMODE((root / "new.txt").stat().st_mode) == 0o600
    (root / "old.txt").write_text("y")
    os.chmod(root / "old.txt", 0o644)
    T.call(tools, "write_file", {"path": str(root / "old.txt"), "content": "z"})
    assert stat.S_IMODE((root / "old.txt").stat().st_mode) == 0o644  # kept


def test_sad_recursive_checksum_does_not_report_the_cap_as_the_total(root):
    (root / "a").write_text("a")
    seen = []
    tools = {t.name: t for t in M._build_tools(LocalFS(), allow_write=False, root=str(root))}
    ctx = M._ToolContext()
    ctx.progress = lambda progress, total=None, message="": seen.append(total)
    tools["recursive_checksum"].handler({"path": str(root)}, ctx)
    assert seen and all(t is None for t in seen)


def test_sad_remote_reads_refuse_secret_names():
    from core import protected_places as PP

    assert PP.remote_secret_refusal("/home/u/.ssh/id_ed25519")
    assert PP.remote_secret_refusal("/srv/app/.env.bak")
    assert PP.remote_secret_refusal("/home/u/.ssh/id_ed25519.pub") is None
    assert PP.remote_secret_refusal("/srv/readme.txt") is None


def test_sad_the_release_check_is_strict(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("cmr", ROOT / "scripts" / "check_mcp_release.py")
    cmr = importlib.util.module_from_spec(spec)
    sys.modules["cmr"] = cmr
    spec.loader.exec_module(cmr)
    for rel in ("server.json", "Dockerfile.mcp", "scripts/export_standalone.py",
                "axross/_version.py", "core/mcp_server.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text((ROOT / rel).read_text(encoding="utf-8"))
    from axross._version import __version__ as v

    assert cmr.problems(v, tmp_path) == []
    server = json.loads((tmp_path / "server.json").read_text())
    extra = dict(server["packages"][0], identifier="someone-else")
    server["packages"].append(extra)
    server["packages"][1]["transport"] = {"type": "sse"}
    server["packages"][0]["registryBaseUrl"] = "https://evil.example"
    (tmp_path / "server.json").write_text(json.dumps(server))
    found = " | ".join(cmr.problems(v, tmp_path))
    assert "exactly one pypi" in found and "transport" in found and "registryBaseUrl" in found
    docker = (tmp_path / "Dockerfile.mcp").read_text()
    (tmp_path / "Dockerfile.mcp").write_text(docker.replace(
        'server.name="io.github.c0decave/axross-headless-mcp"',
        'server.name="io.github.c0decave/axross-headless-mcp-evil"'))
    assert any("Dockerfile.mcp" in p for p in cmr.problems(v, tmp_path))


def test_sad_a_resumable_copy_from_a_source_that_holds_more_is_no_copy(tmp_path):
    from core import mcp_groups

    class Lying(LocalFS):
        pass

    src = tmp_path / "s.bin"
    src.write_bytes(b"x" * 100)
    assert mcp_groups._sends_more_than(Lying(), str(src), 5) is True
    assert mcp_groups._sends_more_than(Lying(), str(src), 100) is False


def test_happy_index_build_stops_at_max_files(root):
    for i in range(30):
        (root / f"f{i}").write_text("")
    tools = T.build(root, {"index"}, allow_write=False)
    out = T.call(tools, "index_build", {"path": str(root), "max_files": 5})
    assert out["truncated"] is True and out["indexed"] < 30


def test_sad_the_host_key_advice_works_for_another_port():
    from core import mcp_groups

    class Profile:
        host, port = "nas.example", 2222

    class Exc:
        host, key_type, fingerprint_sha256 = "[nas.example]:2222", "ssh-ed25519", "abc"

    text = mcp_groups._unknown_host_advice(Profile(), Exc())
    assert "ssh-keyscan -p 2222 -t ed25519 nas.example >" in text
    assert "[nas.example]:2222 >" not in text and "ssh -p 2222 nas.example" in text



def test_sad_a_non_utf8_name_does_not_break_the_log_file(tmp_path, capsys):
    """A path with an undecodable byte (``bad\\xffname``) reaches the log as
    a surrogate; the log file must take it (escaped) instead of printing
    "--- Logging error ---" with a traceback on stderr and losing the line."""
    import logging

    from core import log_config

    handler = log_config._make_file_handler(tmp_path / "axross.log", log_config.LogSettings())
    logger = logging.getLogger("test.round2.surrogate")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        logger.warning("copy %s", "bad\udcffname.txt")
    finally:
        logger.removeHandler(handler)
        handler.close()
    assert "Logging error" not in capsys.readouterr().err
    assert "bad\\udcffname.txt" in (tmp_path / "axross.log").read_text(encoding="utf-8")


def test_sad_an_error_names_the_path_asked_for_not_the_pinned_one(root):
    """A preview refused for its size said ``/tmp/axross-pin-xxxx/big.tif:
    ... would need more than 512 MiB``: the private pin name, not the file."""
    from core.confined_fs import ConfinedLocalFS, pinned_path

    backend = ConfinedLocalFS([str(root)])
    target = root / "big.tif"
    target.write_bytes(b"II*\x00")
    with pytest.raises(ValueError) as caught:
        with pinned_path(backend, str(target)) as pinned:
            raise ValueError(f"{pinned}: 11000x11000 would need more than 512 MiB")
    assert str(caught.value) == f"{target}: 11000x11000 would need more than 512 MiB"
    with pytest.raises(OSError) as caught_os:
        with pinned_path(backend, str(target)) as pinned:
            raise OSError(5, "Input/output error", pinned)
    assert caught_os.value.filename == str(target) and "axross-pin-" not in str(caught_os.value)


def test_sad_an_unknown_total_is_left_out_of_the_progress_frame():
    """``total`` is an optional number in notifications/progress: when it is
    not known (recursive_checksum walks without knowing the count) it is
    left out, not sent as null."""
    stdout = io.StringIO()
    ctx = M._ToolContext(progress_token="p-1", stdout=stdout)
    ctx.progress(3.0)
    ctx.progress(4.0, 8.0)
    first, second = (json.loads(line)["params"] for line in stdout.getvalue().splitlines())
    assert "total" not in first and first["progress"] == 3.0
    assert second["total"] == 8.0


def test_sad_no_walk_reports_its_cap_as_the_total(root):
    """walk, bulk_copy and file_type_scan sent their cap (max_entries /
    max_files) as the progress total - a client showed "2 of 10000" for a
    finished walk of two files. The count is not known while walking."""
    (root / "src").mkdir()
    (root / "src" / "a").write_text("a")
    (root / "src" / "b").write_text("b")
    seen = []
    ctx = M._ToolContext()
    ctx.progress = lambda progress, total=None, message="": seen.append((progress, total))
    tools = T.build(root, {"filetype"}, allow_write=True)
    tools["walk"].handler({"path": str(root / "src")}, ctx)
    tools["bulk_copy"].handler({"src": str(root / "src"), "dst": str(root / "dst")}, ctx)
    tools["file_type_scan"].handler({"path": str(root / "src")}, ctx)
    assert seen and all(total is None for _progress, total in seen), seen
