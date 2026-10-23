"""Loop-mounting a partition of a disk image (punch-list item 6).

Operator: *„bei rechtem mausklick anbieten loop zu mounten (sudo / root rechte
dann abfragen damit es klappt falls notwendig)"*; decided: udisksctl first
(polkit asks), then pkexec, then sudo; read-only unless writing was allowed
explicitly (*„schreiben muss durch z.b. extra hacken oder RW mount vorher
erlaubt werden"*).

The commands run through an injected runner: the argument lists, the order
of the fallbacks, the parsing of what the tools print and the clean-up after
a failure are checked without root. Nothing here mounts for real.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import loop_mount as LM  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import sudo_password as SP  # noqa: E402


@pytest.fixture(autouse=True)
def decided_chain(tmp_path_factory, monkeypatch):
    """These tests pin the chain decided for item 6 - udisksctl (polkit
    asks), pkexec, sudo asked each time - which is what runs with
    remembering switched off; tests/test_sudo_password.py covers the
    default (remembering on)."""
    # Not under tmp_path: tests there check that a failed mount leaves it empty.
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path_factory.mktemp("config") / "settings.json")
    SP.set_remember(False)
    yield
    SP.forget()


class Runner:
    """Answers commands from a script of (argv-prefix, rc, stdout, stderr)."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []  # argv[0] as the tool's name ("sudo"), for short expectations
        self.raw_calls = []  # argv as run (argv[0] is the resolved absolute path)

    def __call__(self, argv, *, input_text=None, timeout=None):
        self.raw_calls.append(list(argv))
        argv = [os.path.basename(argv[0]), *argv[1:]] if argv else []
        self.calls.append((list(argv), input_text))
        for i, (prefix, rc, out, err) in enumerate(self.answers):
            if list(argv[:len(prefix)]) == list(prefix):
                del self.answers[i]
                return LM.Result(rc, out, err)
        raise AssertionError(f"unexpected command {argv}")


def tools(*names):
    return lambda name: f"/usr/bin/{name}" if name in names else None


IMG = "/data/disk.img"


# -- happy ------------------------------------------------------------------------------


def test_happy_udisksctl_maps_read_only_and_mounts_read_only():
    run = Runner([
        (["udisksctl", "loop-setup"], 0, "Mapped file /data/disk.img as /dev/loop7.\n", ""),
        (["udisksctl", "mount"], 0, "Mounted /dev/loop7 at /run/media/u/ROOT\n", ""),
    ])
    m = LM.mount_partition(IMG, offset=1048576, size=8388608, runner=run, which=tools("udisksctl"))
    assert m.method == "udisksctl" and m.device == "/dev/loop7"
    assert m.mountpoint == "/run/media/u/ROOT" and m.read_only
    assert run.calls[0][0] == ["udisksctl", "loop-setup", "--file", IMG, "--offset", "1048576",
                               "--size", "8388608", "--read-only"]
    assert run.calls[1][0] == ["udisksctl", "mount", "--block-device", "/dev/loop7",
                               "--options", "ro"]
    assert m in LM.active_mounts()
    LM.forget(m)


def fake_system(tmp_path, monkeypatch, device, image, point, backing=None):
    """A /sys/block/loopN/loop/backing_file and a mountinfo line, as the
    kernel shows a loop mount."""
    n = device.rsplit("/", 1)[-1]
    sys_root = tmp_path / "sys"
    (sys_root / "block" / n / "loop").mkdir(parents=True)
    (sys_root / "block" / n / "loop" / "backing_file").write_text((backing or image) + "\n")
    info = tmp_path / "mountinfo"
    escaped = point.replace(" ", "\\040")
    info.write_text(f"36 35 7:3 / {escaped} ro,relatime shared:1 - ext4 {device} ro\n")
    monkeypatch.setattr(LM, "SYS_ROOT", str(sys_root))
    monkeypatch.setattr(LM, "MOUNTINFO", str(info))


def test_happy_unmount_with_udisksctl_unmounts_and_deletes_the_loop(tmp_path, monkeypatch):
    fake_system(tmp_path, monkeypatch, "/dev/loop7", IMG, "/run/media/u/ROOT")
    m = LM.Mount(IMG, "/dev/loop7", "/run/media/u/ROOT", "udisksctl", True)
    run = Runner([(["udisksctl", "unmount"], 0, "Unmounted /dev/loop7.\n", ""),
                  (["udisksctl", "loop-delete"], 0, "", "")])
    LM.unmount(m, runner=run, which=tools("udisksctl"))
    assert [c[0] for c in run.calls] == [
        ["udisksctl", "unmount", "--block-device", "/dev/loop7"],
        ["udisksctl", "loop-delete", "--block-device", "/dev/loop7"],
    ]


def test_happy_pkexec_runs_one_helper_with_positional_arguments(tmp_path):
    run = Runner([(["pkexec"], 0, "/dev/loop3\n", "")])
    m = LM.mount_partition(IMG, offset=512, size=1024, runner=run, which=tools("pkexec"),
                           mount_root=str(tmp_path))
    argv = run.calls[0][0]
    assert argv[:4] == ["pkexec", "/bin/sh", "-c", LM.MOUNT_SCRIPT]
    # The image path and every number are arguments, never part of the script.
    assert argv[4:] == ["axross-mount", IMG, "512", "1024", "ro", m.mountpoint]
    assert m.method == "pkexec" and m.device == "/dev/loop3" and m.read_only
    assert Path(m.mountpoint).parent == tmp_path and Path(m.mountpoint).is_dir()
    LM.forget(m)


def test_happy_sudo_gets_the_password_on_stdin_not_argv(tmp_path):
    run = Runner([(["sudo", "-n", "-v"], 1, "", "a password is required"),
                  (["sudo", "-S", "-p", "", "-v"], 0, "", ""),
                  (["sudo"], 0, "/dev/loop4\n", "")])
    m = LM.mount_partition(IMG, offset=0, size=4096, runner=run, which=tools("sudo"),
                           mount_root=str(tmp_path), password=lambda retry=False: "s3cret")
    argv, stdin = run.calls[-1]
    assert argv[:4] == ["sudo", "-S", "-p", ""]
    assert "s3cret" not in " ".join(argv) and stdin == "s3cret\n"
    assert m.method == "sudo"
    LM.forget(m)


def test_happy_read_write_only_when_allowed():
    run = Runner([
        (["udisksctl", "loop-setup"], 0, "Mapped file x as /dev/loop1.", ""),
        (["udisksctl", "mount"], 0, "Mounted /dev/loop1 at /mnt/x.", ""),
    ])
    m = LM.mount_partition(IMG, offset=0, size=10, writable=True, runner=run,
                           which=tools("udisksctl"))
    assert "--read-only" not in run.calls[0][0]
    assert run.calls[1][0] == ["udisksctl", "mount", "--block-device", "/dev/loop1"]
    assert not m.read_only and m.mountpoint == "/mnt/x"
    LM.forget(m)


# -- sad --------------------------------------------------------------------------------


def test_sad_udisks_refused_falls_back_to_pkexec(tmp_path):
    run = Runner([
        (["udisksctl", "loop-setup"], 1, "", "Error setting up loop device: Not authorized\n"),
        (["pkexec"], 0, "/dev/loop9\n", ""),
    ])
    m = LM.mount_partition(IMG, offset=0, size=10, runner=run,
                           which=tools("udisksctl", "pkexec"), mount_root=str(tmp_path))
    assert m.method == "pkexec"
    LM.forget(m)


def test_sad_a_failed_udisks_mount_deletes_its_loop_device(tmp_path):
    run = Runner([
        (["udisksctl", "loop-setup"], 0, "Mapped file x as /dev/loop2.", ""),
        (["udisksctl", "mount"], 1, "", "wrong fs type"),
        (["udisksctl", "loop-delete"], 0, "", ""),
    ])
    with pytest.raises(LM.MountError) as err:
        LM.mount_partition(IMG, offset=0, size=10, runner=run, which=tools("udisksctl"))
    assert "wrong fs type" in str(err.value)
    assert ["udisksctl", "loop-delete", "--block-device", "/dev/loop2"] in [c[0] for c in run.calls]
    assert LM.active_mounts() == []


def test_sad_no_tool_at_all():
    with pytest.raises(LM.MountError, match="udisksctl, pkexec or sudo"):
        LM.mount_partition(IMG, offset=0, size=10, runner=Runner([]), which=tools())


def test_sad_every_method_failing_reports_each(tmp_path):
    run = Runner([
        (["udisksctl", "loop-setup"], 1, "", "Not authorized"),
        (["pkexec"], 126, "", "Request dismissed"),
    ])
    with pytest.raises(LM.MountError) as err:
        LM.mount_partition(IMG, offset=0, size=10, runner=run,
                           which=tools("udisksctl", "pkexec"), mount_root=str(tmp_path))
    text = str(err.value)
    assert "udisksctl: Not authorized" in text and "pkexec: Request dismissed" in text
    assert list(tmp_path.iterdir()) == []  # the empty mount folder is gone again


@pytest.mark.parametrize("offset, size", [(-1, 10), (0, 0), (0, -5), ("0", 10)])
def test_sad_bad_numbers_are_refused(offset, size):
    with pytest.raises(ValueError):
        LM.mount_partition(IMG, offset=offset, size=size, runner=Runner([]),
                           which=tools("udisksctl"))


def test_sad_a_relative_or_dash_path_is_refused():
    for bad in ("disk.img", "-rf", ""):
        with pytest.raises(ValueError):
            LM.mount_partition(bad, offset=0, size=10, runner=Runner([]), which=tools("udisksctl"))


def test_sad_unparseable_output_is_an_error():
    run = Runner([(["udisksctl", "loop-setup"], 0, "something else", "")])
    with pytest.raises(LM.MountError, match="loop device"):
        LM.mount_partition(IMG, offset=0, size=10, runner=run, which=tools("udisksctl"))


# -- edge -------------------------------------------------------------------------------


def test_edge_parse_the_variants_udisksctl_prints():
    assert LM.parse_loop("Mapped file /a b/c.img as /dev/loop12.") == "/dev/loop12"
    assert LM.parse_mountpoint("Mounted /dev/loop0 at /run/media/u/My Disk") == "/run/media/u/My Disk"
    assert LM.parse_mountpoint("Mounted /dev/loop0 at /run/media/u/x.\n") == "/run/media/u/x"
    assert LM.parse_loop("nothing") is None and LM.parse_mountpoint("") is None


def test_edge_the_helper_script_quotes_every_argument():
    script = LM.MOUNT_SCRIPT
    for var in ('"$1"', '"$2"', '"$3"', '"$5"'):
        assert var in script
    assert "losetup" in script and "--read-only" in script and "mount" in script
    # A failed mount gives the loop device back.
    assert "losetup -d" in script


def test_edge_unmount_with_pkexec_removes_the_folder(tmp_path, monkeypatch):
    point = tmp_path / "disk-1"
    point.mkdir()
    fake_system(tmp_path, monkeypatch, "/dev/loop3", IMG, str(point))
    m = LM.Mount(IMG, "/dev/loop3", str(point), "pkexec", True)
    run = Runner([(["pkexec"], 0, "", "")])
    LM.unmount(m, runner=run, which=tools("pkexec"))
    argv = run.calls[0][0]
    assert argv[:4] == ["pkexec", "/bin/sh", "-c", LM.UNMOUNT_SCRIPT]
    assert argv[4:] == ["axross-unmount", str(point), "/dev/loop3"]
    assert not point.exists()


def test_edge_the_mount_folder_name_is_safe(tmp_path):
    name = LM.mount_folder(str(tmp_path), "/x/../we ird;$(rm).img")
    assert Path(name).parent == tmp_path
    assert all(c.isalnum() or c in "-_." for c in Path(name).name)


def _stub_tools(tmp_path, mount_rc=0):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "log"
    for name, body in (
        ("losetup", 'printf "losetup|%s\\n" "$*" >> "$LOG"; '
                    'case "$1" in -d) exit 0;; esac; echo /dev/loop42'),
        ("mount", f'printf "mount|%s\\n" "$*" >> "$LOG"; exit {mount_rc}'),
        ("umount", 'printf "umount|%s\\n" "$*" >> "$LOG"'),
    ):
        tool = bin_dir / name
        tool.write_text(f"#!/bin/sh\n{body}\n")
        tool.chmod(0o755)
    return bin_dir, log


@pytest.mark.parametrize("mount_rc", [0, 32])
def test_e2e_the_helper_script_runs_with_hostile_names(tmp_path, mount_rc):
    """The real /bin/sh runs the script against stub tools: arguments
    arrive intact, a failed mount frees the loop device."""
    import os
    import subprocess

    bin_dir, log = _stub_tools(tmp_path, mount_rc)
    image = str(tmp_path / "my disk $(touch pwned).img")
    point = str(tmp_path / "point")
    proc = subprocess.run(
        ["/bin/sh", "-c", LM.MOUNT_SCRIPT, "axross-mount", image, "1048576", "4096", "ro", point],
        capture_output=True, text=True,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "LOG": str(log)},
    )
    lines = log.read_text().splitlines()
    assert lines[0] == f"losetup|--find --show --read-only --offset 1048576 --sizelimit 4096 -- {image}"
    assert lines[1] == f"mount|-o ro -- /dev/loop42 {point}"
    assert not (tmp_path / "pwned").exists() and not os.path.exists("pwned")
    if mount_rc == 0:
        assert proc.returncode == 0 and proc.stdout.strip() == "/dev/loop42"
    else:
        assert proc.returncode == 32 and lines[2] == "losetup|-d /dev/loop42"


def test_e2e_the_unmount_script(tmp_path):
    import subprocess

    bin_dir, log = _stub_tools(tmp_path)
    proc = subprocess.run(
        ["/bin/sh", "-c", LM.UNMOUNT_SCRIPT, "axross-unmount", "/x y/p", "/dev/loop42"],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "LOG": str(log)},
    )
    assert proc.returncode == 0
    assert log.read_text().splitlines() == ["umount|-- /x y/p", "losetup|-d /dev/loop42"]



# -- a stored mount is checked before a privileged unmount (verification round:
# mounts.json entries were trusted as long as the folder was a mount) ----------


def test_sad_a_loop_device_now_backing_another_file_is_refused(tmp_path, monkeypatch):
    fake_system(tmp_path, monkeypatch, "/dev/loop3", IMG, "/mnt/p", backing="/home/u/other.img")
    m = LM._remember(LM.Mount(IMG, "/dev/loop3", "/mnt/p", "pkexec", True))
    run = Runner([])
    with pytest.raises(LM.MountError, match="no longer") as err:
        LM.unmount(m, runner=run)
    assert run.calls == [] and m not in LM.active_mounts()
    assert "/" not in str(err.value).splitlines()[0]  # paths stay off the markup line


def test_sad_a_folder_mounted_from_another_device_is_refused(tmp_path, monkeypatch):
    fake_system(tmp_path, monkeypatch, "/dev/loop9", IMG, "/mnt/p")  # mountinfo: loop9
    n = tmp_path / "sys" / "block" / "loop3" / "loop"
    n.mkdir(parents=True)
    (n / "backing_file").write_text(IMG + "\n")
    m = LM.Mount(IMG, "/dev/loop3", "/mnt/p", "sudo", True)
    with pytest.raises(LM.MountError, match="no longer"):
        LM.unmount(m, runner=Runner([]), password=lambda: "pw")


def test_edge_a_mount_that_is_already_gone_is_just_forgotten(tmp_path, monkeypatch):
    fake_system(tmp_path, monkeypatch, "/dev/loop3", IMG, "/elsewhere")
    m = LM._remember(LM.Mount(IMG, "/dev/loop3", "/mnt/p", "pkexec", True))
    run = Runner([])
    LM.unmount(m, runner=run)  # nothing to do, no password prompt
    assert run.calls == [] and m not in LM.active_mounts()


def test_edge_a_deleted_backing_file_and_spaces(tmp_path, monkeypatch):
    fake_system(tmp_path, monkeypatch, "/dev/loop3", IMG, "/mnt/my disk",
                backing=IMG + " (deleted)")
    assert LM.still_ours(LM.Mount(IMG, "/dev/loop3", "/mnt/my disk", "pkexec", True)) == ""


# -- bughunt 2026-10-22 ----------------------------------------------------------------------


def test_sad_a_mount_stacked_over_ours_is_not_unmounted(tmp_path, monkeypatch):
    """Something else was mounted over our folder after we mounted it:
    ``umount <folder>`` takes the topmost mount, which is not ours. Before,
    still_ours only asked whether our loop device is mounted there at all."""
    fake_system(tmp_path, monkeypatch, "/dev/loop3", IMG, "/mnt/p")
    info = tmp_path / "mountinfo"
    info.write_text(info.read_text()
                    + "41 36 8:17 / /mnt/p rw,relatime shared:9 - ext4 /dev/sdb1 rw\n")
    m = LM._remember(LM.Mount(IMG, "/dev/loop3", "/mnt/p", "pkexec", True))
    run = Runner([])
    try:
        with pytest.raises(LM.MountError, match="no longer"):
            LM.unmount(m, runner=run)
        assert run.calls == [] and m not in LM.active_mounts()
    finally:
        LM.forget(m)


def test_happy_ours_on_top_of_another_mount_is_unmounted(tmp_path, monkeypatch):
    """The reverse stacking: our loop mount sits on top of another mount of
    the same folder - umount takes ours, so it is still ours."""
    fake_system(tmp_path, monkeypatch, "/dev/loop3", IMG, "/mnt/p")
    info = tmp_path / "mountinfo"
    ours = info.read_text().replace("36 35 7:3", "42 41 7:3")
    info.write_text("41 35 8:17 / /mnt/p rw,relatime shared:9 - ext4 /dev/sdb1 rw\n" + ours)
    assert LM.still_ours(LM.Mount(IMG, "/dev/loop3", "/mnt/p", "pkexec", True)) == ""


def test_edge_mount_ids_out_of_listing_order_pick_the_top_by_parent(tmp_path, monkeypatch):
    """The top mount is the one no other mount at the folder has as its
    parent - not simply the last line."""
    fake_system(tmp_path, monkeypatch, "/dev/loop3", IMG, "/mnt/p")
    info = tmp_path / "mountinfo"
    ours = info.read_text().replace("36 35 7:3", "42 41 7:3")
    # Listed first, but mounted on top of the foreign one (parent 41).
    info.write_text(ours + "41 35 8:17 / /mnt/p rw,relatime shared:9 - ext4 /dev/sdb1 rw\n")
    assert LM.still_ours(LM.Mount(IMG, "/dev/loop3", "/mnt/p", "pkexec", True)) == ""


def test_sad_a_mount_folder_that_cannot_be_made_lets_the_next_method_try(tmp_path):
    """The folder for sudo / pkexec cannot be made (a file is in the way):
    that method fails with a MountError and the chain goes on; before, the
    OSError escaped the chain and udisksctl was never tried."""
    blocked = tmp_path / "mounts"
    blocked.write_text("a file, not a folder")
    run = Runner([
        (["udisksctl", "loop-setup"], 1, "", "Error: Not authorized"),
        (["udisksctl", "loop-setup"], 0, "Mapped file /data/disk.img as /dev/loop4.", ""),
        (["udisksctl", "mount"], 0, "Mounted /dev/loop4 at /run/media/u/x", ""),
    ])
    SP.set_remember(True)
    m = LM.mount_partition(IMG, offset=0, size=10, runner=run,
                           which=tools("udisksctl", "pkexec"), mount_root=str(blocked))
    assert m.method == "udisksctl" and m.mountpoint == "/run/media/u/x"
    LM.forget(m)


def test_sad_a_cancelled_mount_tries_no_further_method(tmp_path):
    """*cancelled* (the dialog closed) ends the chain between methods."""
    flag = {"on": False}
    run = Runner([(["udisksctl", "loop-setup"], 1, "", "Error: Not authorized")])

    def refused_then_cancel(argv, **kw):
        result = run(argv, **kw)
        flag["on"] = True
        return result

    with pytest.raises(LM.MountError, match="cancelled"):
        LM.mount_partition(IMG, offset=0, size=10, runner=refused_then_cancel,
                           which=tools("udisksctl", "pkexec", "sudo"),
                           mount_root=str(tmp_path / "m"), cancelled=lambda: flag["on"])
    assert len(run.calls) == 1
