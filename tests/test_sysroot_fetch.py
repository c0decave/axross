"""scripts/sysroot_fetch.py: the target systems' packages for the release build.

The request: every release artifact must build cleanly from the sandbox.
The packages that go into the binaries come from the Debian and AlmaLinux
mirrors, so whoever can tamper with a mirror must not get anything into
them: only the text a signature covers is read, the key pin covers the
whole key file, and unpacking never writes outside the root (no "..",
nothing through a symlink). Built from crafted archives here, no network.
"""

from __future__ import annotations

import gzip
import io
import os
import stat
import struct
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sysroot_fetch as SF  # noqa: E402


# -- versions ---------------------------------------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0), ("1.1", "1.0", 1), ("1.0", "1.1", -1),
    ("1.1.el9", "1.el9", 1),          # a number against letters: the number wins
    ("1.0~rc1", "1.0", -1),           # ~ sorts before the release
    ("1.0^1", "1.0", 1),              # ^ after it
    ("2.0", "10.0", -1), ("1.010", "1.9", 1), ("1.a", "1.1", -1),
    ("5.el9_8", "5.el9_10", -1), ("2.6.0-1", "2.6.0", 1),
])
def test_happy_rpmvercmp_as_rpm(a, b, expected):
    assert SF.rpmvercmp(a, b) == expected
    assert SF.rpmvercmp(b, a) == -expected


def test_happy_epoch_then_version_then_release():
    assert SF._rpm_newer((1, "1.0", "1"), (0, "9.9", "9"))
    assert SF._rpm_newer((0, "1.0", "2.el9"), (0, "1.0", "1.el9"))
    assert not SF._rpm_newer((0, "1.0~rc1", "1"), (0, "1.0", "1"))


# -- keys --------------------------------------------------------------------------------------

def packet(tag: int, body: bytes) -> bytes:
    return bytes([0xC0 | tag, len(body)]) + body  # new format, one-byte length


def test_happy_the_pinned_key_passes():
    body = b"\x04" + b"k" * 40
    key = packet(6, body) + packet(13, b"uid") + packet(14, b"\x04sub")
    assert SF.pinned_key(key, SF._fingerprint(body)) == key


def test_sad_a_second_primary_key_appended_is_refused():
    body = b"\x04" + b"k" * 40
    key = packet(6, body) + packet(13, b"uid") + packet(6, b"\x04" + b"evil" * 10)
    with pytest.raises(SystemExit, match="2 primary keys"):
        SF.pinned_key(key, SF._fingerprint(body))


def test_sad_another_key_is_refused():
    with pytest.raises(SystemExit, match="fingerprint"):
        SF.pinned_key(packet(6, b"\x04other"), SF.ALMA9_KEY)


# -- Release files ----------------------------------------------------------------------------

def test_happy_the_release_names_its_suite():
    SF._check_release("Origin: Debian\nSuite: oldstable-updates\nCodename: bookworm-updates\n",
                      "bookworm-updates")


def test_sad_another_suites_or_an_expired_release_is_refused():
    with pytest.raises(SystemExit, match="trixie"):
        SF._check_release("Suite: stable\nCodename: trixie\n", "bookworm")
    with pytest.raises(SystemExit, match="expired"):
        SF._check_release("Codename: bookworm-security\n"
                          "Valid-Until: Sat, 01 Jan 2000 00:00:00 UTC\n", "bookworm-security")


def test_sad_text_around_the_signature_is_never_read(tmp_path, monkeypatch):
    """A SHA256 block put before the signed message must not count: only
    what gpgv writes out (the signed part) is read."""
    good = "Codename: bookworm\nSHA256:\n 00" + "0" * 62 + " 1 main/binary-amd64/Packages.xz\n"
    forged = ("SHA256:\n " + "f" * 64 + " 1 main/binary-amd64/Packages.xz\n"
              "-----BEGIN PGP SIGNED MESSAGE-----\n\n" + good)
    monkeypatch.setattr(SF, "DEBIAN_SUITES", (("https://mirror", "bookworm"),))
    monkeypatch.setattr(SF, "get", lambda url: forged.encode() if url.endswith("InRelease")
                        else b"whatever")

    def fake_gpgv(signed, keyrings, *, detached_data=None, output=None):
        output.write_text(good)  # what gpgv writes: the signed text only

    monkeypatch.setattr(SF, "gpgv", fake_gpgv)
    monkeypatch.setattr(SF, "DEBIAN_KEYRINGS", ("x",))
    monkeypatch.setattr(Path, "exists", lambda self: True)
    with pytest.raises(SystemExit, match="does not match"):
        SF.debian_index(tmp_path)  # the forged ffff... hash is not used


# -- unpacking --------------------------------------------------------------------------------

def tar_bytes(members) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size, info.mode = len(payload), 0o755
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, payload
                archive.addfile(info)
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, payload
                archive.addfile(info)
    return out.getvalue()


def unpack_tar(monkeypatch, tmp_path, members) -> Path:
    data = tar_bytes(members)
    monkeypatch.setattr(SF.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": data})())
    root = tmp_path / "root"
    root.mkdir()
    SF.unpack_deb(tmp_path / "x.deb", root)
    return root


def test_happy_a_deb_keeps_its_execute_bits_and_links(monkeypatch, tmp_path):
    root = unpack_tar(monkeypatch, tmp_path, [
        ("./usr/", "dir", None), ("./usr/bin/", "dir", None),
        ("./usr/bin/objdump", "file", b"\x7fELF"),
        ("./usr/bin/x86_64-linux-gnu-objdump", "hardlink", "./usr/bin/objdump"),
        ("./usr/lib/libz.so", "symlink", "/lib/libz.so.1"), ("./.hidden", "file", b"h")])
    tool = root / "usr/bin/objdump"
    assert stat.S_IMODE(tool.stat().st_mode) & 0o100
    assert (root / "usr/bin/x86_64-linux-gnu-objdump").read_bytes() == b"\x7fELF"
    assert (root / ".hidden").read_bytes() == b"h"  # a dot file keeps its name
    SF.relink_absolute(root)
    assert os.readlink(root / "usr/lib/libz.so") == "../../lib/libz.so.1"


def test_sad_a_deb_cannot_write_outside_the_root(monkeypatch, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = unpack_tar(monkeypatch, tmp_path, [
        ("../escape", "file", b"x"), ("./../escape2", "file", b"x"),
        ("/abs", "file", b"x"),
        ("./door", "symlink", str(outside)), ("./door/through", "file", b"x"),
        ("./setuid", "file", b"x"),
        ("./copy", "hardlink", "../../etc/passwd")])
    assert not (tmp_path / "escape").exists() and not (tmp_path / "escape2").exists()
    assert list(outside.iterdir()) == []
    assert not (root / "copy").exists()


def rpm_bytes(entries) -> bytes:
    """A minimal rpm: lead, empty signature header and header, gzip cpio newc."""
    def header() -> bytes:
        return b"\x8e\xad\xe8\x01" + bytes(4) + struct.pack(">II", 0, 0)

    sig = header()
    sig += bytes((-(96 + len(sig))) % 8)
    cpio = b""
    for ino, (name, mode, nlink, data) in enumerate(entries + [("TRAILER!!!", 0, 1, b"")], 1):
        raw = name.encode() + b"\x00"
        fields = [ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(raw), 0]
        head = b"070701" + b"".join(f"{f:08X}".encode() for f in fields)
        cpio += head + raw
        cpio += bytes((-len(cpio)) % 4) + data
        cpio += bytes((-len(cpio)) % 4)
    return bytes(96) + sig + header() + gzip.compress(cpio)


def test_happy_an_rpm_unpacks_files_links_and_empty_hard_links(tmp_path):
    rpm = tmp_path / "x.rpm"
    rpm.write_bytes(rpm_bytes([("./usr/bin/tool", 0o100755, 1, b"bin"),
                               ("./usr/lib64/libx.so", 0o120777, 1, b"libx.so.1"),
                               ("./.dot", 0o100644, 1, b"d")]))
    root = tmp_path / "root"
    root.mkdir()
    SF.unpack_rpm(rpm, root)
    assert stat.S_IMODE((root / "usr/bin/tool").stat().st_mode) & 0o100
    assert os.readlink(root / "usr/lib64/libx.so") == "libx.so.1"
    assert (root / ".dot").read_bytes() == b"d"


def test_sad_an_rpm_cannot_write_outside_the_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    rpm = tmp_path / "x.rpm"
    rpm.write_bytes(rpm_bytes([("../escape", 0o100644, 1, b"x"),
                               ("./door", 0o120777, 1, str(outside).encode()),
                               ("./door/through", 0o100644, 1, b"x"),
                               ("./suid", 0o104755, 1, b"x")]))
    root = tmp_path / "root"
    root.mkdir()
    SF.unpack_rpm(rpm, root)
    assert not (tmp_path / "escape").exists() and list(outside.iterdir()) == []
    assert not stat.S_IMODE((root / "suid").stat().st_mode) & 0o4000  # never set-id


# -- ldd / ldconfig as the target answers (scripts/target_ldd.py) --------------------------

def test_happy_ldd_keeps_the_target_and_glibc_and_drops_the_host():
    import re

    import target_ldd as TL

    keep = "/w o r k/$x\"/"  # spaces, quotes and $ in the path are no problem
    out = TL.filter_ldd(
        "\tlinux-vdso.so.1 (0x00007f)\n"
        f"\tlibX11.so.6 => {keep}libs/libX11.so.6 (0x00007f)\n"
        "\tlibgtk-3.so.0 => /lib/x86_64-linux-gnu/libgtk-3.so.0 (0x00007f)\n"
        "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f)\n"
        "\tlibmissing.so.1 => not found\n"
        "\t/lib64/ld-linux-x86-64.so.2 (0x00007f)\n",
        keep, re.compile(r"^(ld-linux.*|libc|libm)\.so"))
    lines = out.splitlines()
    assert lines[1].endswith("libX11.so.6 (0x00007f)")
    assert lines[2] == "\tlibgtk-3.so.0 => not found"
    assert "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6" in lines[3]
    assert lines[4] == "\tlibmissing.so.1 => not found"


def test_happy_ldconfig_lists_only_the_target(tmp_path):
    import target_ldd as TL

    (tmp_path / "libz.so.1").write_bytes(b"")
    (tmp_path / "README").write_text("")
    out = TL.ldconfig_cache(str(tmp_path)).splitlines()
    assert out[0].startswith("1 libs found")
    assert out[1] == f"\tlibz.so.1 (libc6,x86-64) => {tmp_path / 'libz.so.1'}"


def test_happy_a_usrmerged_symlink_is_followed_inside_the_root(tmp_path):
    """AlmaLinux's libgcc ships ./lib64/libgcc_s.so.1 where lib64 -> usr/lib64."""
    root = tmp_path / "root"
    (root / "usr/lib64").mkdir(parents=True)
    os.symlink("usr/lib64", root / "lib64")
    os.symlink("/usr/lib64", root / "abs64")  # absolute: counts from the root
    rpm = tmp_path / "x.rpm"
    rpm.write_bytes(rpm_bytes([("./lib64/libgcc_s.so.1", 0o100755, 1, b"gcc"),
                               ("./abs64/libz.so.1", 0o100755, 1, b"z")]))
    SF.unpack_rpm(rpm, root)
    assert (root / "usr/lib64/libgcc_s.so.1").read_bytes() == b"gcc"
    assert (root / "usr/lib64/libz.so.1").read_bytes() == b"z"


def test_sad_a_symlink_climbing_out_of_the_root_is_refused(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.symlink("../..", root / "up")
    assert SF.safe_target(root, "./up/escape") is None
    os.symlink("loop", root / "loop")
    assert SF.safe_target(root, "./loop/x") is None


# -- gpgv: several signatures, a keyring that lacks one of the keys --------------------------
# gpgv's status lines for Debian's bookworm InRelease (signed by the 12 and
# 13 archive keys and the 12 release key) checked against a keyring package
# that predates the 13 key - an Ubuntu 24.04 CI runner; gpgv exits 2 there.
_BOOKWORM_STATUS = """\
[GNUPG:] PLAINTEXT 74 0
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8 0
[GNUPG:] GOODSIG 6ED0E7B82643E131 Debian Archive Automatic Signing Key (12/bookworm)
[GNUPG:] VALIDSIG 4CB50190207B4758A3F73A796ED0E7B82643E131 2026-07-11 1783765031 0 4 0 1 8 01 B8B8
[GNUPG:] NEWSIG
[GNUPG:] ERRSIG 78DBA3BC47EF2265 1 8 01 1783765032 9 B8E5F13176D2A7A75220028078DBA3BC47EF2265
[GNUPG:] NO_PUBKEY 78DBA3BC47EF2265
[GNUPG:] NEWSIG
[GNUPG:] GOODSIG F8D2585B8783D481 Debian Stable Release Key (12/bookworm)
[GNUPG:] VALIDSIG 4D64FEC119C2029067D6E791F8D2585B8783D481 2026-07-11 1783765141 0 4 0 22 8 01 4D64
"""


class _Ran:
    def __init__(self, returncode, stdout, stderr="gpgv: Can't check signature: No public key"):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _fake_gpgv(monkeypatch, returncode, status, *, writes=True):
    def run(args, **_kw):
        if writes and "--output" in args:
            Path(args[args.index("--output") + 1]).write_text("Suite: bookworm\n")
        return _Ran(returncode, status)
    monkeypatch.setattr(SF.subprocess, "run", run)


def test_happy_a_release_signed_also_by_an_unknown_key_passes(monkeypatch, tmp_path):
    # the third CI Linux build stopped here: "bad signature on bookworm.InRelease"
    _fake_gpgv(monkeypatch, 2, _BOOKWORM_STATUS)
    out = tmp_path / "bookworm.Release"
    SF.gpgv(tmp_path / "bookworm.InRelease", [tmp_path / "k.gpg"], output=out)
    assert out.read_text() == "Suite: bookworm\n"


def test_sad_one_bad_signature_refuses_whatever_else_is_good(monkeypatch, tmp_path):
    status = _BOOKWORM_STATUS + "[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 6ED0E7B82643E131 Debian\n"
    _fake_gpgv(monkeypatch, 1, status)
    with pytest.raises(SystemExit, match="bad signature"):
        SF.gpgv(tmp_path / "x.InRelease", [], output=tmp_path / "x.Release")


@pytest.mark.parametrize("word", ["EXPKEYSIG", "REVKEYSIG", "EXPSIG"])
def test_sad_an_expired_or_revoked_key_refuses(word):
    assert not SF.signature_accepted(_BOOKWORM_STATUS + f"[GNUPG:] {word} 6ED0E7B82643E131 x\n")


def test_sad_only_unknown_keys_is_refused(monkeypatch, tmp_path):
    status = ("[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 78DBA3BC47EF2265 1 8 01 1 9 B8E5\n"
              "[GNUPG:] NO_PUBKEY 78DBA3BC47EF2265\n")
    _fake_gpgv(monkeypatch, 2, status)
    with pytest.raises(SystemExit, match="bad signature"):
        SF.gpgv(tmp_path / "x.InRelease", [], output=tmp_path / "x.Release")


def test_edge_no_signed_text_written_is_refused(monkeypatch, tmp_path):
    _fake_gpgv(monkeypatch, 0, _BOOKWORM_STATUS, writes=False)
    with pytest.raises(SystemExit, match="no signed text"):
        SF.gpgv(tmp_path / "x.InRelease", [], output=tmp_path / "x.Release")


def test_edge_gpgv_reports_its_status_on_stdout(monkeypatch, tmp_path):
    seen = {}

    def run(args, **_kw):
        seen["args"] = args
        return _Ran(0, _BOOKWORM_STATUS)
    monkeypatch.setattr(SF.subprocess, "run", run)
    SF.gpgv(tmp_path / "x.sig", [], detached_data=tmp_path / "x")
    assert seen["args"][1:3] == ["--status-fd", "1"]
