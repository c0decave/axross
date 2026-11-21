"""Round 1 of the adversarial review of the headless MCP server: files.

- C1: transfer_copy from a remote copies regular files only (a symlink to
  /dev/zero, a device, a FIFO are refused), counts the bytes a source
  really sends against max_file_bytes (a server said 5 bytes and sent
  gigabytes), stops at a cancel mid-file and removes the partial file.
- M7: a protected destination leaves that file out and keeps the report;
  a name with a control character is refused; local copies are 0600.
- H2: two profiles of one server - one production-flagged - never share a
  connection: the production one stays read-only.
- H5: encrypt streams (a few MiB of memory, not the file several times);
  the chunked format detects a cut file; old single-shot files still decrypt.
- M2 / LOW: pack stages beside the archive, not in the system temp folder,
  and a tree deeper than Python's recursion limit packs.
- LOW secrets: .my.cnf and .vault-token are secret anywhere; a private key
  past the first MiB is refused by read_file with an offset and by grep.
- M8: an SSH command line is never logged.
- LOW: a missing package leaves its group out with one line, no traceback;
  the unknown-host-key error says how to trust a key without the GUI.
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
import tracemalloc
from datetime import datetime
from pathlib import Path

import pytest

from core import mcp_names as N  # noqa: E402
from core import credentials
from core import mcp_server as M
from core import profiles as P
from core.local_fs import LocalFS
from core.profiles import ConnectionProfile
from models.file_item import FileItem
from tests import mcp_group_testkit as T

ROOT = Path(__file__).resolve().parents[1]
PW = "sftp-password-round1"


@pytest.fixture(autouse=True)
def _no_keyring(monkeypatch):
    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    from core import mcp_groups

    for registry in list(mcp_groups.RemoteRegistry._live):
        registry.close_all()


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    r.mkdir()
    return r


@pytest.fixture
def sftp(tmp_path, monkeypatch):
    pytest.importorskip("paramiko")
    from tests.sftp_testkit import SftpServer, _host_key

    served = tmp_path / "served"
    served.mkdir()
    (served / "hello.txt").write_text("hello\n")
    os.symlink("/dev/zero", served / "zero")
    (served / "big.bin").write_bytes(b"B" * (3 * 1024 * 1024))
    server = SftpServer(str(served))
    path = tmp_path / "profiles.json"
    monkeypatch.setattr(P, "PROFILES_FILE", path)
    base = dict(protocol="sftp", host="127.0.0.1", port=server.port, username="u",
                auth_type="password", store_password=True)
    profiles = [ConnectionProfile(name="nas", **base).to_dict(),
                ConnectionProfile(name="prod", production=True, **base).to_dict()]
    path.write_text(json.dumps({p["name"]: p for p in profiles}))
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    key = _host_key()
    (home / ".ssh" / "known_hosts").write_text(
        f"[127.0.0.1]:{server.port} {key.get_name()} {key.get_base64()}\n")
    monkeypatch.setattr(ConnectionProfile, "get_password", lambda self: PW)
    try:
        yield server, served
    finally:
        server.close()


def _tools(root, groups=("remote", "transfer"), **kw):
    return T.build(root, set(groups), allow_write=True, **kw)


# --- C1 ----------------------------------------------------------------------------


def test_sad_a_symlink_to_dev_zero_is_not_copied(root, sftp):
    tools = _tools(root)
    T.call(tools, "remote_open", {"profile": "nas"})
    out = T.call(tools, "transfer_copy", {"src_backend": "profile:nas", "src": "/zero",
                                          "dst": str(root / "zero.out")})
    assert out["entries"][0]["action"] == "skipped"
    # A link (or, where the server's stat follows it, the device behind it).
    assert out["entries"][0]["reason"] in ("symlink", "special-file")
    assert not (root / "zero.out").exists()


@pytest.mark.parametrize("resumable", [False, True])
def test_sad_a_source_that_sends_more_than_it_said_stops_at_the_cap(root, sftp, monkeypatch,
                                                                     resumable):
    from tests import sftp_testkit as K

    real_stat, real_lstat = K._Sftp.stat, K._Sftp.lstat

    def lying(orig):
        def stat_(self, path):
            attr = orig(self, path)
            if not isinstance(attr, int) and path.endswith("big.bin"):
                attr.st_size = 5  # says 5 bytes, sends 3 MiB
            return attr
        return stat_

    monkeypatch.setattr(K._Sftp, "stat", lying(real_stat))
    monkeypatch.setattr(K._Sftp, "lstat", lying(real_lstat))
    tools = _tools(root)
    T.call(tools, "remote_open", {"profile": "nas"})
    out = T.call(tools, "transfer_copy", {"src_backend": "profile:nas", "src": "/big.bin",
                                          "dst": str(root / "big.out"), "max_file_bytes": 1000,
                                          "resumable": resumable})
    entry = out["entries"][0]
    landed = (root / "big.out").stat().st_size if (root / "big.out").exists() else 0
    assert landed <= 1000, entry
    if not resumable:
        assert entry["action"] == "skipped" and entry["reason"] == "too-large"
        assert not (root / "big.out").exists()
    assert [p.name for p in root.iterdir() if p.name != "big.out"] == []  # no partial left


class _EndlessRemote:
    """A remote backend whose file never ends (reads count, slowly)."""

    def __init__(self) -> None:
        self.reads = 0

    def stat(self, path):
        return FileItem(name="endless", size=10, modified=datetime.now())

    def list_dir(self, path):
        return [self.stat(path)]

    def exists(self, path):
        return True

    def is_dir(self, path):
        return False

    def parent(self, path):
        return "/"

    def join(self, *parts):
        return "/".join(parts)

    def open_read(self, path):
        remote = self

        class Endless(io.RawIOBase):
            def read(self, n=-1):
                remote.reads += 1
                time.sleep(0.002)
                return b"z" * 65536

        return Endless()


def test_sad_cancel_stops_a_copy_mid_file_and_removes_the_partial(root):
    from core.mcp_groups import RemoteRegistry

    remote = _EndlessRemote()
    registry = RemoteRegistry()
    registry.attach("endless", remote, None)
    tools = T.build(root, {"transfer"}, allow_write=True, remote_registry=registry)
    cancels = M._CancelRegistry()
    box = {}

    def run():
        box["resp"] = M._handle_request(
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "transfer_copy",
                        "arguments": {"src_backend": "endless", "src": "/endless",
                                      "dst": str(root / "out.bin")}}},
            list(tools.values()), cancels=cancels)

    worker = threading.Thread(target=run)
    worker.start()
    deadline = time.time() + 10
    while remote.reads < 20 and time.time() < deadline:
        time.sleep(0.01)
    cancels.cancel(7)
    worker.join(30)
    assert not worker.is_alive()
    reads = remote.reads
    time.sleep(0.2)
    assert remote.reads == reads  # it stopped reading
    assert "cancelled" in json.dumps(box["resp"])
    assert list(root.iterdir()) == []  # the partial file is gone


# --- M7, names, modes -----------------------------------------------------------------


@pytest.fixture
def ram_profile(tmp_path, monkeypatch):
    path = tmp_path / "profiles.json"
    monkeypatch.setattr(P, "PROFILES_FILE", path)
    ram = ConnectionProfile(name="ram", protocol="ramfs").to_dict()
    path.write_text(json.dumps({"ram": ram}))


def test_sad_a_protected_destination_is_left_out_and_the_report_kept(root, ram_profile):
    tools = _tools(root)
    bid = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    for path, data in (("/proj/ok.txt", b"ok"), ("/proj/.git/hooks/post-checkout", b"evil"),
                       ("/proj/bad\nname.txt", b"x")):
        T.call(tools, "write_file", {"backend": bid, "path": path,
                                     "content_b64": base64.b64encode(data).decode()})
    out = T.call(tools, "transfer_copy", {"src_backend": bid, "src": "/proj",
                                          "dst": str(root / "proj")})
    by_reason = {e.get("reason"): e for e in out["entries"]}
    assert (root / "proj" / "ok.txt").read_bytes() == b"ok"
    assert "protected" in by_reason and "post-checkout" in by_reason["protected"]["src"]
    assert not (root / "proj" / ".git" / "hooks" / "post-checkout").exists()
    assert "unsafe-name" in by_reason
    assert not any("\n" in p.name for p in (root / "proj").iterdir())
    assert stat.S_IMODE((root / "proj" / "ok.txt").stat().st_mode) == 0o600
    assert out["complete"] is False


# --- H2 ------------------------------------------------------------------------------


def test_sad_production_stays_read_only_beside_a_profile_of_the_same_server(root, sftp):
    tools = _tools(root)
    T.call(tools, "remote_open", {"profile": "nas"})
    T.call(tools, "remote_open", {"profile": "prod"})
    data = base64.b64encode(b"x").decode()
    for name, args in (("write_file", {"path": "/p.txt", "content_b64": data}),
                       ("mkdir", {"path": "/pd"}), ("remove", {"path": "/hello.txt"}),
                       ("chmod", {"path": "/hello.txt", "mode": "0600"})):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, name, {**args, "backend": "profile:prod"})
        assert "production" in err.value.message, name
    assert (sftp[1] / "hello.txt").exists() and not (sftp[1] / "p.txt").exists()
    # The ordinary profile of the same server still writes.
    T.call(tools, "write_file", {"path": "/n.txt", "content_b64": data, "backend": "profile:nas"})
    assert (sftp[1] / "n.txt").read_bytes() == b"x"


def test_sad_the_unknown_host_key_error_says_how_to_trust_it_headless(root, sftp):
    (Path(os.environ["HOME"]) / ".ssh" / "known_hosts").unlink()
    with pytest.raises(T.RpcError) as err:
        T.call(_tools(root), "remote_open", {"profile": "nas"})
    assert "ssh-keyscan" in err.value.message and "known_hosts" in err.value.message


# --- H5 ------------------------------------------------------------------------------


def test_happy_encrypt_streams_and_decrypt_restores(root):
    data = os.urandom(64 * 1024 * 1024)
    (root / "a.bin").write_bytes(data)
    tools = T.build(root, {"crypto"}, allow_write=True)
    tracemalloc.start()
    try:
        out = T.call(tools, "encrypt", {"path": str(root / "a.bin"), "passphrase": "pw-123456"})
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 32 * 1024 * 1024, peak  # a few chunks, not the 64 MiB file several times
    enc = Path(out["path"])
    assert enc.read_bytes()[:5] == b"AXXE2" and out["plaintext_size"] == len(data)
    assert stat.S_IMODE(enc.stat().st_mode) == 0o600
    (root / "a.bin").unlink()
    back = T.call(tools, "decrypt", {"path": str(enc), "passphrase": "pw-123456"})
    assert Path(back["path"]).read_bytes() == data
    from core import encrypted_overlay as E

    assert E.read_encrypted(LocalFS(), str(enc), "pw-123456") == data  # the GUI's reader


def test_sad_a_cut_or_wrongly_keyed_file_decrypts_to_nothing(root):
    (root / "a.txt").write_bytes(b"secret text " * 100_000)
    tools = T.build(root, {"crypto"}, allow_write=True)
    enc = Path(T.call(tools, "encrypt", {"path": str(root / "a.txt"),
                                         "passphrase": "pw-123456"})["path"])
    (root / "a.txt").unlink()
    blob = enc.read_bytes()
    enc.write_bytes(blob[: len(blob) // 2])
    with pytest.raises(T.RpcError):
        T.call(tools, "decrypt", {"path": str(enc), "passphrase": "pw-123456"})
    enc.write_bytes(blob)
    with pytest.raises(T.RpcError):
        T.call(tools, "decrypt", {"path": str(enc), "passphrase": "wrong-pass"})
    assert sorted(p.name for p in root.iterdir()) == ["a.txt.axenc"]


def test_happy_old_single_shot_files_still_decrypt(root):
    from core import encrypted_overlay as E

    (root / "old.txt.axenc").write_bytes(E.encrypt_bytes(b"from before", "pw-123456"))
    tools = T.build(root, {"crypto"}, allow_write=True)
    back = T.call(tools, "decrypt", {"path": str(root / "old.txt.axenc"),
                                     "passphrase": "pw-123456"})
    assert Path(back["path"]).read_bytes() == b"from before"


# --- M2 / pack ----------------------------------------------------------------------


def test_happy_pack_stages_in_the_root_not_the_system_temp(root, monkeypatch):
    import tempfile

    from core import packer

    (root / "in.txt").write_text("x")
    seen = []
    real = packer._staging_folder

    def spy(backend, folder):
        path = real(backend, folder)
        seen.append(path)
        return path

    monkeypatch.setattr(packer, "_staging_folder", spy)
    tools = T.build(root, {"packer"}, allow_write=True)
    out = T.call(tools, "pack", {"folder": str(root), "names": ["in.txt"],
                                 "archive_name": "a", "format": "zip"})
    assert Path(out["path"]).exists()
    assert seen and Path(seen[0]).parent == root.resolve()
    assert not seen[0].startswith(tempfile.gettempdir() + os.sep + "axross-pack-")
    assert not Path(seen[0]).exists()  # cleaned


def test_happy_staging_left_by_an_interrupted_pack_goes_at_exit(root):
    from core import packer

    path = packer._staging_folder(LocalFS(), str(root))
    packer._remove_staging_at_exit()
    assert not os.path.exists(path)


def test_edge_a_tree_deeper_than_the_recursion_limit_packs(root):
    cur = str(root / "deep")
    os.mkdir(cur)
    for _ in range(sys.getrecursionlimit() + 50):
        cur = os.path.join(cur, "d")
        os.mkdir(cur)
    with open(os.path.join(cur, "leaf.txt"), "w") as fh:
        fh.write("leaf")
    try:
        tools = T.build(root, {"packer"}, allow_write=True)
        out = T.call(tools, "pack", {"folder": str(root), "names": ["deep"],
                                     "archive_name": "deep", "format": "zip"})
        assert out["files"] == 1
    finally:
        # Bottom-up, without recursion (shutil.rmtree recurses as deep).
        os.remove(os.path.join(cur, "leaf.txt"))
        while cur != str(root):
            os.rmdir(cur)
            cur = os.path.dirname(cur)


# --- secrets -----------------------------------------------------------------------


@pytest.mark.parametrize("name", [".my.cnf", ".vault-token", ".s3cfg"])
def test_sad_credential_files_are_secret_anywhere(root, name):
    (root / "proj").mkdir()
    (root / "proj" / name).write_text("password=supersecret\n")
    tools = T.build(root, set())
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "read_file", {"path": str(root / "proj" / name), "encoding": "text"})
    assert "secret" in err.value.message


def test_sad_a_key_past_the_first_mib_is_refused_with_an_offset(root):
    from core import protected_places as PP

    marker = b"OPENSSH " + b"PRIVATE KEY-----"  # split: the leak gate reads the source
    key = b"-----BEGIN " + marker + b"\nb3BlbnNzaC1rZXk=\n-----END " + marker + b"\n"
    filler = b"x" * (PP.SECRET_CONTENT_SCAN + 4096)
    (root / "bundle.txt").write_bytes(filler + key)
    tools = T.build(root, {"crypto"})
    # The first MiB is fine and served.
    T.call(tools, "read_file", {"path": str(root / "bundle.txt"), "max_bytes": 100})
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "read_file", {"path": str(root / "bundle.txt"),
                                    "offset": len(filler) + 40, "max_bytes": 20})
    assert "private key" in err.value.message
    found = T.call(tools, "grep", {"path": str(root), "pattern": "b3BlbnNzaC1rZXk"})
    assert found["matches"] == [] and found["unreadable"]


# --- M8 / packaging ----------------------------------------------------------------


def test_sad_an_ssh_command_line_is_never_logged(caplog):
    from core.redaction import command_summary

    caplog.set_level("INFO")
    url = "https://bob" + ":" + "TOPSECRET2" + "@h/"  # assembled: no credential in the source
    text = command_summary("mysql -pTOPSECRET1 && curl " + url)
    assert "TOPSECRET" not in text and "bytes" in text
    src = (ROOT / "core" / "ssh_client.py").read_text()
    assert "command_summary(cmd)" in src and "cmd[:120]" not in src


def test_sad_without_cryptography_the_crypto_group_is_left_out_with_one_line(tmp_path):
    code = ("import sys\n"
            "class _No:\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] == 'cryptography':\n"
            "            raise ImportError(name=name)\n"
            "sys.meta_path.insert(0, _No())\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "sys.argv = ['axross-headless-mcp', '--mcp-list-tools', '--mcp-tools', 'all']\n"
            "from core.mcp_cli import main\n"
            "sys.exit(main())\n")
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_STATE_HOME=str(home / ".state"))
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=120, env=env, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert "Traceback" not in proc.stderr
    assert "'crypto' left out" in proc.stderr and "cryptography" in proc.stderr
    names = {N.internal(t["name"]) for t in json.loads(proc.stdout)["tools"]}
    assert "encrypt" not in names and "metadata_read" in names
