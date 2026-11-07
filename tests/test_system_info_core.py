"""System Information: gathering what hardware axross runs on (core/system_info.py).

Request: a system information extension that gathers everything about the
hardware it runs on and shows it in a window of its own, perfectly and
intuitively visualised.

The gathering reads /proc and /sys only (no root, no program started), each
source in a probe of its own with a deadline that fails soft: a section then
says "not available" and why, and the other sections are unaffected. These
tests run it against a fake laptop tree in tmp_path
(tests/system_info_fixture.py), plus once against the real machine.
Serial numbers, MAC and IP addresses and UUIDs are identifiers: hidden in
exports unless asked for, because such reports get pasted in public.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import system_info as SI  # noqa: E402
from core.posix_compat import effective_uid  # noqa: E402
from tests.system_info_fixture import (  # noqa: E402
    IDENTIFIERS,
    _proc_stat,
    build_laptop,
    build_minimal,
    fake_usage,
)


@pytest.fixture
def laptop(tmp_path):
    return build_laptop(tmp_path / "root")


def gather(root, **kwargs) -> dict:
    kwargs.setdefault("usage", fake_usage)
    kwargs.setdefault("hostname", "x1-carbon")
    kwargs.setdefault("env", {"XDG_CURRENT_DESKTOP": "GNOME", "XDG_SESSION_TYPE": "wayland"})
    kwargs.setdefault("system", "Linux")
    return SI.SystemInfo(root, **kwargs).gather()


def sections(report: dict) -> dict:
    return {s["key"]: s for s in report["sections"]}


def fields(section: dict) -> dict:
    return {f["label"]: f["value"] for f in section["fields"]}


# --- happy ----------------------------------------------------------------


def test_happy_the_laptop_is_described_in_every_section(laptop):
    report = gather(laptop)
    s = sections(report)
    assert all(sec["available"] for sec in report["sections"]), [
        (sec["key"], sec["reason"]) for sec in report["sections"] if not sec["available"]]
    json.dumps(report)  # JSON-serialisable as it is
    assert fields(s["machine"])["Model"] == "ThinkPad X1 Carbon Gen 11"
    assert s["machine"]["data"]["vendor_short"] == "Lenovo"
    assert s["machine"]["data"]["form"] == "laptop"
    assert fields(s["machine"])["Secure Boot"] == "on"
    assert fields(s["os"])["Operating system"] == "Fedora Linux 41 (Workstation Edition)"
    assert fields(s["os"])["Uptime"] == "1 d 2 h 3 min"
    assert fields(s["os"])["Desktop"] == "GNOME"


def test_happy_cpu_topology_frequencies_caches_and_features(laptop):
    cpu = sections(gather(laptop))["cpu"]
    data = cpu["data"]
    assert data["model"] == "13th Gen Intel(R) Core(TM) i7-1365U"
    assert (data["threads"], data["cores"], data["sockets"]) == (12, 10, 1)
    assert data["p_cores"] == [0, 1, 2, 3] and len(data["e_cores"]) == 8
    assert data["max_mhz"] == 5200 and data["min_mhz"] == 400
    assert fields(cpu)["Frequency range"] == "400 MHz – 5.20 GHz"
    l3 = [c for c in data["caches"] if c["level"] == 3]
    assert l3 == [{"level": 3, "type": "Unified", "type_short": "", "size": 12 * 1024**2,
                   "instances": 1, "total": 12 * 1024**2, "shared_by": 12}]
    l2 = sorted((c["size"], c["instances"]) for c in data["caches"] if c["level"] == 2)
    assert l2 == [(1280 * 1024, 2), (2048 * 1024, 2)]
    present = {f["name"] for f in data["features"] if f["present"]}
    assert {"AVX2", "AES-NI", "VT-x", "SHA", "CET-IBT"} <= present
    assert "AVX-512" not in present
    assert not any(f["name"] == "NEON / ASIMD" for f in data["features"])  # not on x86
    vulns = {v["name"]: v["status"] for v in data["vulnerabilities"]}
    assert vulns["meltdown"] == "Not affected"


def test_happy_memory_in_bytes_and_human_units(laptop):
    mem = sections(gather(laptop))["memory"]
    assert mem["data"]["total"] == 32535008 * 1024
    assert mem["data"]["used"] == (32535008 - 20123456) * 1024
    assert mem["data"]["installed"] == 256 * 0x8000000
    assert fields(mem)["Total (usable)"] == "31.0 GiB"
    assert fields(mem)["Swap"] == "1.0 GiB used of 8.0 GiB"


def test_happy_storage_disks_partitions_mounts_and_usage(laptop):
    storage = sections(gather(laptop))["storage"]
    disks = {d["name"]: d for d in storage["data"]["disks"]}
    assert set(disks) == {"nvme0n1", "sda"}  # loop0 left out
    nvme, stick = disks["nvme0n1"], disks["sda"]
    assert nvme["kind"] == "NVMe SSD" and nvme["model"] == "Samsung SSD 990 PRO 1TB"
    assert nvme["size"] == 1953525168 * 512
    assert [p["name"] for p in nvme["partitions"]] == ["nvme0n1p1", "nvme0n1p2"]
    assert nvme["partitions"][1]["mounts"] == ["/", "/home"]
    assert nvme["partitions"][1]["usage"][0]["percent"] == pytest.approx(61.2)
    assert stick["kind"] == "USB drive" and stick["removable"]
    assert stick["partitions"][0]["mounts"] == ["/run/media/user/USB STICK"]
    mounts = [f["mount"] for f in storage["data"]["filesystems"]]
    assert mounts == ["/", "/boot/efi", "/tmp", "/run/media/user/USB STICK"]  # /home: bind


def test_happy_graphics_and_displays_from_pci_drm_and_edid(laptop):
    g = sections(gather(laptop))["graphics"]
    (gpu,) = g["data"]["gpus"]
    assert gpu["name"] == "Raptor Lake-P [Iris Xe Graphics]" and gpu["driver"] == "i915"
    assert gpu["boot_vga"]
    displays = g["data"]["displays"]
    assert [d["connector"] for d in displays] == ["eDP-1", "DP-1", "HDMI-A-1"]
    edp, dp = displays[0], displays[1]
    assert edp["monitor"] == "ATNA40YK07-0" and edp["resolution"] == "2880x1800"
    assert round(edp["refresh"]) == 90 and edp["internal"]
    assert dp["monitor"] == "DELL U2720Q" and dp["maker"] == "DEL"
    assert dp["diagonal_in"] == pytest.approx(27.2, abs=0.1)
    assert "serial" not in dp  # the EDID serial is not kept at all


def test_happy_network_interfaces_kinds_and_route(laptop):
    net = sections(gather(laptop, addresses=lambda: {
        "wlp0s20f3": [{"address": "192.168.178.42", "family": "ipv4"}]}))["network"]
    kinds = {i["name"]: i["kind"] for i in net["data"]["interfaces"]}
    assert kinds == {"lo": "Loopback", "enp0s31f6": "Ethernet", "wlp0s20f3": "Wi-Fi",
                     "docker0": "Bridge", "tailscale0": "Tunnel / VPN"}
    wifi = next(i for i in net["data"]["interfaces"] if i["name"] == "wlp0s20f3")
    assert wifi["state"] == "up" and wifi["signal_dbm"] == -52 and wifi["driver"] == "iwlwifi"
    assert wifi["addresses"] == ["192.168.178.42"]
    assert net["data"]["gateway"] == "192.168.178.1"
    assert net["data"]["default_interface"] == "wlp0s20f3"


def test_happy_usb_and_pci_are_trees_with_names_from_the_id_files(laptop):
    s = sections(gather(laptop))
    usb = s["usb"]["tables"][0]
    names = [r[0] for r in usb["rows"]]
    depths = SI.tree_depths(usb["parents"])
    assert names[0].startswith("USB bus 1") and depths[0] == 0
    receiver = names.index("Unifying Receiver")  # from usb.ids: the device has no strings
    assert depths[receiver] == 1 and usb["rows"][receiver][1] == "Logitech, Inc."
    pci = s["pci"]["tables"][0]
    nvme = [r[0] for r in pci["rows"]].index("NVMe SSD Controller S4LV008[Pascal]")
    bridge = pci["parents"][nvme]
    assert pci["rows"][bridge][0] == "Raptor Lake-P PCI Express Root Port #9"
    assert [r[6] for r in pci["rows"]][:2] == ["0000:00:00.0", "0000:00:02.0"]  # bus order


def test_happy_battery_health_cycles_and_time(laptop):
    bat = sections(gather(laptop))["battery"]
    (b0, mouse) = bat["data"]["batteries"]
    assert b0["health"] == pytest.approx(100 * 50.56 / 57.0)
    assert b0["cycles"] == 182 and b0["capacity"] == 76
    assert b0["time_text"] == "23 min until full"
    assert mouse["scope"] == "Device"
    assert bat["data"]["on_ac"] is True
    assert fields(bat)["Battery health"] == "89 % of design capacity"


def test_happy_sensors_audio_input_and_virtualisation(laptop):
    s = sections(gather(laptop))
    temps = {(t["chip"], t["label"]): t for t in s["sensors"]["data"]["temperatures"]}
    assert temps[("coretemp", "Package id 0")]["celsius"] == 58.0
    assert temps[("thermal zone", "x86_pkg_temp")]["crit"] == 105.0
    assert s["sensors"]["data"]["fans"] == [{"chip": "thinkpad", "label": "fan1", "rpm": 2380}]
    assert fields(s["audio"])["Codecs"] == "Realtek ALC711, Intel Raptorlake HDMI"
    kinds = {d["name"]: d["kind"] for d in s["input"]["data"]["devices"]}
    assert kinds["AT Translated Set 2 keyboard"] == "Keyboard"
    assert kinds["SYNA8017:00 Touchpad"] == "Touchpad"
    assert s["virtualization"]["data"]["kind"] == "bare"


def test_happy_export_text_and_json_hide_identifiers(laptop):
    report = gather(laptop, addresses=lambda: {
        "wlp0s20f3": [{"address": "192.168.178.42", "family": "ipv4"},
                      {"address": "2001:db8:1234:5678::42", "family": "ipv6"}]})
    text = SI.export_text(report)
    data = SI.export_json(report)
    for ident in IDENTIFIERS:
        assert ident not in text, ident
        assert ident not in data, ident
    assert SI.HIDDEN in text and "hidden" in json.loads(data)["identifiers"]
    shown = SI.export_text(report, show_identifiers=True)
    assert all(ident in shown for ident in ("PF3XAMPL", "a4:c3:f0:12:34:56", "192.168.178.42"))
    assert "Samsung SSD 990 PRO 1TB" in text and "ThinkPad X1 Carbon Gen 11" in text


def test_happy_live_sampler_cpu_use_from_proc_stat_deltas(tmp_path):
    root = build_minimal(tmp_path / "root")
    (root / "proc/stat").write_text(_proc_stat(2))
    sampler = SI.LiveSampler(root, system="Linux", use_psutil=False)
    first = sampler.sample()
    assert first["cpu"] is None and first["per_cpu"] == [None, None]
    assert first["memory"]["total"] == 2048000 * 1024
    (root / "proc/stat").write_text(
        "cpu  1300 10 600 8100 50 0 20 0 0 0\n"  # +300 user, +100 system, +100 idle
        "cpu0 200 1 50 800 5 0 2 0 0 0\n"  # +100 busy, +0 idle: 100 %
        "cpu1 100 1 50 900 5 0 2 0 0 0\n")  # +0 busy, +100 idle: 0 %
    second = sampler.sample()
    assert second["cpu"] == pytest.approx(80.0)
    assert second["per_cpu"] == [pytest.approx(100.0), pytest.approx(0.0)]


def test_happy_live_sampler_reads_temperatures_and_network_rates(laptop):
    now = [100.0]
    sampler = SI.LiveSampler(laptop, system="Linux", use_psutil=False, clock=lambda: now[0])
    first = sampler.sample()
    assert any(t["label"] == "Package id 0" and t["celsius"] == 58.0
               for t in first["temperatures"])
    stats = laptop / "sys/devices/pci0000:00/0000:00:14.3/net/wlp0s20f3/statistics"
    (stats / "rx_bytes").write_text(str(123456789 + 2_000_000))
    now[0] = 102.0
    second = sampler.sample()
    assert second["net"]["wlp0s20f3"]["rx"] == pytest.approx(1_000_000)
    assert second["net"]["wlp0s20f3"]["tx"] == 0


# --- sad --------------------------------------------------------------------


def test_sad_an_empty_root_gives_reasons_not_exceptions(tmp_path):
    report = gather(tmp_path)
    s = sections(report)
    assert not s["cpu"]["available"] and "/proc/cpuinfo" in s["cpu"]["reason"]
    assert not s["memory"]["available"] and "meminfo" in s["memory"]["reason"]
    assert not s["pci"]["available"] and s["pci"]["reason"]
    assert s["os"]["available"]  # the OS section always has something
    SI.export_text(report)  # and the report still exports


def test_sad_a_failing_probe_costs_its_section_only(laptop, monkeypatch):
    def broken(self):
        raise PermissionError("no access to the PCI bus")

    monkeypatch.setattr(SI.SystemInfo, "probe_pci", broken)
    s = sections(gather(laptop))
    assert not s["pci"]["available"]
    assert s["pci"]["reason"] == "PermissionError: no access to the PCI bus"
    assert s["cpu"]["available"] and s["storage"]["available"]


def test_sad_a_hanging_probe_times_out_and_the_rest_arrive(laptop, monkeypatch):
    release = threading.Event()

    def hangs(self):
        release.wait(30)
        raise RuntimeError("late")

    monkeypatch.setattr(SI.SystemInfo, "probe_audio", hangs)
    started = time.monotonic()
    try:
        # 3 s, not 1 s: on a loaded host (a parallel suite) the quick probes
        # took longer than 1 s too and timed out with the hanging one.
        s = sections(gather(laptop, timeout=3.0))
    finally:
        release.set()
    assert time.monotonic() - started < 15
    assert not s["audio"]["available"] and "timed out after 3 s" in s["audio"]["reason"]
    assert s["cpu"]["available"] and s["memory"]["available"]


def test_sad_unreadable_files_are_skipped_quietly(laptop):
    if effective_uid() == 0:
        # root reads a 000 file anyway: make it a folder, which open() refuses too
        target = laptop / "sys/class/dmi/id/product_serial"
        target.unlink()
        target.mkdir()
    else:
        (laptop / "sys/class/dmi/id/product_serial").chmod(0)
    machine = sections(gather(laptop))["machine"]
    assert machine["available"] and "Serial number" not in fields(machine)
    assert fields(machine)["Model"] == "ThinkPad X1 Carbon Gen 11"


def test_sad_garbage_contents_do_not_break_a_probe(laptop):
    (laptop / "proc/meminfo").write_text("MemTotal: lots kB\n\x00\xff garbage\nMemTotal:\n")
    (laptop / "proc/cpuinfo").write_bytes(b"\xff\xfe\x00 nonsense : : :\n\n\n")
    (laptop / "sys/class/power_supply/BAT0/capacity").write_text("full\n")
    (laptop / "sys/class/hwmon/hwmon4/temp1_input").write_text("-\n")
    (laptop / "sys/class/drm/card1-DP-1/edid").write_bytes(b"\x00\xff\xff")
    s = sections(gather(laptop))
    assert not s["memory"]["available"]
    assert s["cpu"]["available"]  # still the 12 CPUs from /sys
    assert s["cpu"]["data"]["threads"] == 12
    assert s["battery"]["data"]["batteries"][0]["capacity"] == 86  # energy now / full
    assert s["graphics"]["data"]["displays"][1].get("monitor") is None
    assert s["sensors"]["available"]


def test_sad_without_sys_the_machine_section_says_why(tmp_path):
    root = build_minimal(tmp_path / "root")
    s = sections(gather(root))
    assert not s["machine"]["available"] and "/sys" in s["machine"]["reason"]
    assert s["cpu"]["available"] and s["memory"]["available"]


def test_sad_other_platforms_without_psutil_say_what_is_missing(tmp_path):
    report = gather(build_minimal(tmp_path / "root"), system="Windows", use_psutil=False)
    s = sections(report)
    assert not s["network"]["available"] and "psutil" in s["network"]["reason"]
    assert not s["audio"]["available"] and "Windows" in s["audio"]["reason"]
    assert s["os"]["available"]


def test_sad_a_dead_mount_is_unknown_after_its_timeout():
    release = threading.Event()

    def usage(path):
        if path == "/mnt/nas":
            release.wait(30)
        return 100, 40, 60

    try:
        out = SI.measure_usage([{"mount": "/"}, {"mount": "/mnt/nas"}], usage, timeout=0.5)
    finally:
        release.set()
    assert out[0]["percent"] == pytest.approx(40.0)
    assert "timed out" in out[1]["error"] and out[1].get("total") is None


# --- edge -------------------------------------------------------------------


def test_edge_huge_files_are_read_capped(tmp_path):
    big = tmp_path / "big"
    big.write_bytes(b"x" * (SI.READ_LIMIT * 4))
    info = SI.SystemInfo(tmp_path, system="Linux")
    assert len(info.read(big)) == SI.READ_LIMIT
    ids = tmp_path / "usr/share/hwdata/pci.ids"
    ids.parent.mkdir(parents=True)
    with open(ids, "w") as fh:
        fh.write("8086  Intel\n")
        fh.write(("#" + "y" * 99 + "\n") * (SI.IDS_LIMIT // 100 + 10))
        fh.write("10de  NVIDIA\n")  # past the cap: never reached
    vendors, _devices = info.id_names(SI.PCI_IDS, {"8086", "10de"}, set())
    assert vendors == {"8086": "Intel"}


def test_edge_redaction_scrubs_unmarked_macs_and_uuids():
    section = SI.make_section("x", "X", [SI.field("Note", "dock at 00:11:22:33:44:55")],
                              [SI.table("T", ["A"], [["id 123e4567-e89b-12d3-a456-426614174000"]])],
                              {"mac": "00:11:22:33:44:55", "nested": [{"serial": "S1"}]})
    out = SI.redact({"sections": [section]})["sections"][0]
    assert out["fields"][0]["value"] == f"dock at {SI.HIDDEN}"
    assert out["tables"][0]["rows"][0][0] == f"id {SI.HIDDEN}"
    assert out["data"] == {"mac": SI.HIDDEN, "nested": [{"serial": SI.HIDDEN}]}
    assert section["data"]["mac"] == "00:11:22:33:44:55"  # the original stays


def test_edge_cpu_percent_counters_going_back_or_standing_still():
    assert SI.cpu_percent(None, (10, 100)) is None
    assert SI.cpu_percent((10, 100), (10, 100)) is None  # no time passed
    assert SI.cpu_percent((50, 100), (40, 200)) is None  # a CPU went offline and back
    assert SI.cpu_percent((0, 0), (25, 100)) == 25.0
    assert SI.parse_proc_stat("cpu  a b c\ncpu0 1 2\n") == {}


def test_edge_units_and_small_parsers():
    assert SI.human_bytes(0) == "0 B" and SI.human_bytes(1536) == "1.5 KiB"
    assert SI.human_bytes(5 * 1024**4) == "5.0 TiB"
    assert SI.human_mhz(800) == "800 MHz" and SI.human_mhz(3400) == "3.40 GHz"
    assert SI.human_duration(59) == "0 min" and SI.human_duration(3 * 86400) == "3 d 0 h 0 min"
    assert SI.parse_cpu_list("0-3,8,10-11,x,5-2") == [0, 1, 2, 3, 8, 10, 11]
    assert SI.parse_size_text("1280K") == 1280 * 1024 and SI.parse_size_text("big") is None
    assert SI.parse_edid(b"") == {} and SI.parse_edid(b"\x00" * 128) == {}
    assert SI.tree_depths([None, 0, 1, 2]) == [0, 1, 2, 3]
    assert SI.tree_depths([1, 0]) == [1, 1]  # a cycle ends


def test_edge_minimal_machine_with_cpuinfo_only(tmp_path):
    s = sections(gather(build_minimal(tmp_path / "root")))
    assert s["cpu"]["data"]["threads"] == 2
    assert s["cpu"]["data"]["per_cpu"][0]["cur_mhz"] == 1400.0
    assert s["memory"]["data"]["used"] == 1024000 * 1024


def test_edge_a_cancelled_gather_returns_at_once(laptop, monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(SI.SystemInfo, "probe_usb", lambda self: release.wait(30))
    started = time.monotonic()
    try:
        report = SI.SystemInfo(laptop, system="Linux", usage=fake_usage).gather(
            cancel=lambda: True)
    finally:
        release.set()
    assert time.monotonic() - started < 5
    assert len(report["sections"]) == len(SI.SystemInfo(laptop).probes())


# --- end to end ---------------------------------------------------------------


def test_e2e_the_real_machine_has_a_cpu_and_memory():
    report = SI.gather()
    s = sections(report)
    assert s["cpu"]["available"], s["cpu"]["reason"]
    assert s["cpu"]["data"]["threads"] >= 1
    assert s["memory"]["available"], s["memory"]["reason"]
    assert s["memory"]["data"]["total"] > 0
    json.loads(SI.export_json(report))
    assert "CPU" in SI.export_text(report)
    sampler = SI.LiveSampler()
    sampler.sample()
    assert sampler.sample()["memory"] is not None


# --- found by the review of 2026-11-06 -----------------------------------------


def test_edge_installed_memory_counts_past_the_directory_limit(laptop):
    """A 1 TiB machine has 8192 memory blocks of 128 MiB: listdir stops at
    DIR_LIMIT, the header showed half the RAM."""
    base = laptop / "sys/devices/system/memory"
    for n in range(256, SI.DIR_LIMIT + 1000):
        (base / f"memory{n}").mkdir()
    info = SI.SystemInfo(laptop, system="Linux")
    assert info.count_entries("sys/devices/system/memory", r"memory\d+") == SI.DIR_LIMIT + 1000
    mem = sections(gather(laptop))["memory"]
    assert mem["data"]["installed"] == (SI.DIR_LIMIT + 1000) * 0x8000000


def test_edge_fewer_memory_blocks_than_the_total_are_not_the_installed_amount(laptop):
    base = laptop / "sys/devices/system/memory"
    for n in range(10, 256):
        (base / f"memory{n}").rmdir()
    assert sections(gather(laptop))["memory"]["data"]["installed"] is None


def test_edge_emmc_boot_areas_are_not_disks(laptop):
    for name in ("mmcblk0boot0", "mmcblk0boot1", "mmcblk0rpmb"):
        (laptop / "sys/block" / name).mkdir(parents=True)
        (laptop / "sys/block" / name / "size").write_text("8192\n")
    disks = [d["name"] for d in sections(gather(laptop))["storage"]["data"]["disks"]]
    assert not any(n.startswith("mmcblk0") for n in disks)


def test_edge_a_later_chip_keeps_its_device_folder_sensors(laptop):
    """The device/ folder was skipped for every chip once any chip had a
    sensor ("out" was all chips' list)."""
    d = laptop / "sys/class/hwmon/hwmon9"
    (d / "device").mkdir(parents=True)
    (d / "name").write_text("oldchip\n")
    (d / "device/temp1_input").write_text("39000\n")
    (d / "device/temp1_label").write_text("Board\n")
    temps = sections(gather(laptop))["sensors"]["data"]["temperatures"]
    assert any(t["chip"] == "oldchip" and t["celsius"] == 39.0 for t in temps)


def test_edge_a_negative_discharge_current_still_gives_the_time_left(laptop):
    bat = laptop / "sys/class/power_supply/BAT0"
    (bat / "power_now").unlink()
    for name, value in (("status", "Discharging"), ("current_now", "-2000000"),
                        ("voltage_now", "11000000")):
        (bat / name).write_text(value + "\n")
    b0 = sections(gather(laptop))["battery"]["data"]["batteries"][0]
    assert b0["power_w"] == pytest.approx(22.0)
    assert b0["time_text"] == "1 h 58 min until empty"


def test_sad_a_hanging_mount_is_not_measured_again_while_it_hangs():
    release = threading.Event()
    calls = []

    def usage(path):
        calls.append(path)
        if path == "/mnt/dead":
            release.wait(30)
        return 100, 40, 60

    try:
        SI.measure_usage([{"mount": "/mnt/dead"}], usage, timeout=0.2)
        out = SI.measure_usage([{"mount": "/"}, {"mount": "/mnt/dead"}], usage, timeout=0.2)
        assert calls.count("/mnt/dead") == 1          # no second stuck thread
        assert out[1]["error"] == "still not answering" and out[0]["percent"] == 40.0
    finally:
        release.set()
    time.sleep(0.1)
    SI.measure_usage([{"mount": "/mnt/dead"}], usage, timeout=0.5)
    assert calls.count("/mnt/dead") == 2              # answered: measured again


def test_happy_the_sampler_names_the_online_cpus(tmp_path):
    root = build_minimal(tmp_path / "root")
    (root / "proc/stat").write_text("cpu  10 0 10 100 0 0 0 0 0 0\n"
                                    "cpu0 5 0 5 50 0 0 0 0 0 0\ncpu2 5 0 5 50 0 0 0 0 0 0\n")
    sample = SI.LiveSampler(root, system="Linux", use_psutil=False).sample()
    assert sample["cpu_ids"] == [0, 2]


def test_edge_short_volume_serials_in_mount_paths_are_hidden():
    assert SI.scrub_text("/run/media/alice/1A2B-3C4D") == f"/run/media/alice/{SI.HIDDEN}"
    assert SI.scrub_text("/media/x/0123456789ABCDEF/dir") == f"/media/x/{SI.HIDDEN}/dir"
    assert SI.scrub_text("/mnt/backup-2026") == "/mnt/backup-2026"
