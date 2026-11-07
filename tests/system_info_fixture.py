"""A fake /proc, /sys and /etc of a laptop for the System Information tests.

:func:`build_laptop` writes the tree below a folder: a ThinkPad with a hybrid
Intel CPU, NVMe disk and USB stick, an internal and an external display, Wi-Fi,
Bluetooth, a battery, sensors and a USB/PCI topology. Identifiers in it
(serials, MACs, the UUID, addresses) are listed in :data:`IDENTIFIERS` so the
privacy tests can check that none of them leaks.
"""

from __future__ import annotations

import os
from pathlib import Path

IDENTIFIERS = (
    "PF3XAMPL",  # product serial
    "L1HF2EXAMPLE",  # board serial
    "4c4c4544-0042-3510-8052-b4c04f4a3633",  # product UUID
    "S6B0NL0W123456A",  # NVMe serial
    "4C530001234567890123",  # USB stick serial
    "a4:c3:f0:12:34:56",  # Wi-Fi MAC
    "8c:16:45:ab:cd:ef",  # Ethernet MAC
    "02:42:9f:11:22:33",  # docker0 MAC
    "f4:4e:e3:aa:bb:cc",  # Bluetooth address
    "192.168.178.42",  # IPv4 address
    "2001:db8:1234:5678::42",  # IPv6 address
    "192.168.178.1",  # gateway
    "9.9.9.9",  # DNS server
    "41ZXSERIAL",  # battery serial
)


def _w(root: Path, rel: str, text: str | bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _link(root: Path, rel: str, target: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, path)


def _files(root: Path, base: str, values: dict) -> None:
    for name, value in values.items():
        _w(root, f"{base}/{name}", f"{value}\n")


def make_edid(maker: str, product: int, name: str, w_cm: int, h_cm: int, h_px: int, v_px: int,
              refresh: int = 60, serial: str = "") -> bytes:
    raw = bytearray(128)
    raw[0:8] = b"\x00\xff\xff\xff\xff\xff\xff\x00"
    code = sum((ord(c) - 64) << s for c, s in zip(maker, (10, 5, 0)))
    raw[8], raw[9] = code >> 8, code & 0xFF
    raw[10], raw[11] = product & 0xFF, product >> 8
    raw[18], raw[19] = 1, 4
    raw[21], raw[22] = w_cm, h_cm
    h_blank, v_blank = 160, 30
    clock = (h_px + h_blank) * (v_px + v_blank) * refresh // 10_000
    d = bytearray(18)
    d[0], d[1] = clock & 0xFF, clock >> 8
    d[2], d[3] = h_px & 0xFF, h_blank & 0xFF
    d[4] = ((h_px >> 8) << 4) | (h_blank >> 8)
    d[5], d[6] = v_px & 0xFF, v_blank & 0xFF
    d[7] = ((v_px >> 8) << 4) | (v_blank >> 8)
    raw[54:72] = d
    raw[72:90] = bytes([0, 0, 0, 0xFC, 0]) + (name + "\n").encode().ljust(13, b" ")[:13]
    raw[90:108] = bytes([0, 0, 0, 0xFF, 0]) + (serial + "\n").encode().ljust(13, b" ")[:13]
    raw[108:126] = bytes([0, 0, 0, 0x10, 0]) + bytes(13)
    raw[127] = (-sum(raw[:127])) & 0xFF
    return bytes(raw)


CPUINFO_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr "
    "sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc nonstop_tsc pni pclmulqdq "
    "vmx ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand "
    "lahf_lm abm fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt sha_ni "
    "avx_vnni hwp ibt user_shstk"
)


def _cpuinfo(threads: int) -> str:
    blocks = []
    for n in range(threads):
        core = n // 2 if n < 4 else n - 2
        blocks.append(
            f"processor\t: {n}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 186\n"
            "model name\t: 13th Gen Intel(R) Core(TM) i7-1365U\nstepping\t: 3\n"
            "microcode\t: 0x4121\ncpu MHz\t\t: 1400.000\ncache size\t: 12288 KB\n"
            f"physical id\t: 0\nsiblings\t: {threads}\ncore id\t\t: {core}\ncpu cores\t: 10\n"
            f"flags\t\t: {CPUINFO_FLAGS}\nbogomips\t: 5376.00\n"
            "address sizes\t: 39 bits physical, 48 bits virtual\n")
    return "\n".join(blocks) + "\n"


def _proc_stat(threads: int, scale: int = 1) -> str:
    lines = [f"cpu  {1000 * scale} 10 {500 * scale} {8000 * scale} 50 0 20 0 0 0"]
    for n in range(threads):
        lines.append(f"cpu{n} {100 * scale} 1 {50 * scale} {800 * scale} 5 0 2 0 0 0")
    lines.append("intr 1 2 3")
    return "\n".join(lines) + "\n"


PCI_IDS = """\
# fake pci.ids
8086  Intel Corporation
\ta7a1  Raptor Lake-P [Iris Xe Graphics]
\t\t17aa 22e6  ThinkPad X1 Carbon Gen 11
\ta71d  Raptor Lake-P Thunderbolt 4 USB Controller
\t51ca  Raptor Lake-P/U/H cAVS
\t51f1  Raptor Lake PCH CNVi WiFi
\ta74d  Raptor Lake-P PCI Express Root Port #9
\ta706  Raptor Lake-P/U/H Host Bridge
144d  Samsung Electronics Co Ltd
\ta80c  NVMe SSD Controller S4LV008[Pascal]
C 03  Display controller
\t00  VGA compatible controller
"""

USB_IDS = """\
# fake usb.ids
046d  Logitech, Inc.
\tc52b  Unifying Receiver
8087  Intel Corp.
\t0033  AX211 Bluetooth
"""


def build_laptop(root: Path) -> Path:
    """Write the laptop's /proc, /sys, /etc and /usr/share below *root*."""
    root = Path(root)
    threads = 12
    # -- /proc -------------------------------------------------------------
    _w(root, "proc/cpuinfo", _cpuinfo(threads))
    _w(root, "proc/meminfo", "\n".join([
        "MemTotal:       32535008 kB", "MemFree:         9876543 kB",
        "MemAvailable:   20123456 kB", "Buffers:          456789 kB",
        "Cached:          8765432 kB", "SwapCached:            0 kB",
        "Shmem:           1234567 kB", "SReclaimable:     345678 kB",
        "SwapTotal:       8388604 kB", "SwapFree:        7340028 kB",
        "Dirty:              1234 kB", "CommitLimit:    24655908 kB",
        "Committed_AS:   18765432 kB", "HugePages_Total:       0",
        "Hugepagesize:       2048 kB"]) + "\n")
    _w(root, "proc/stat", _proc_stat(threads))
    _w(root, "proc/uptime", "93784.21 1000000.00\n")
    _w(root, "proc/loadavg", "0.52 0.61 0.70 2/1234 98765\n")
    _w(root, "proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n"
       "/dev/zram0  partition\t8388604\t1048576\t100\n")
    _w(root, "proc/sys/kernel/osrelease", "6.11.4-301.fc41.x86_64\n")
    _w(root, "proc/sys/kernel/version", "#1 SMP PREEMPT_DYNAMIC Thu Oct 17 2024\n")
    _w(root, "proc/1/comm", "systemd\n")
    _w(root, "proc/1/cgroup", "0::/init.scope\n")
    mounts = (
        "/dev/nvme0n1p2 / btrfs rw,relatime 0 0\n"
        "proc /proc proc rw 0 0\n"
        "sysfs /sys sysfs rw 0 0\n"
        "/dev/nvme0n1p1 /boot/efi vfat rw 0 0\n"
        "/dev/nvme0n1p2 /home btrfs rw,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw 0 0\n"
        "/dev/sda1 /run/media/user/USB\\040STICK exfat rw 0 0\n"
    )
    _w(root, "proc/mounts", mounts)
    _w(root, "proc/self/mounts", mounts)
    _w(root, "proc/asound/cards",
       " 0 [sofhdadsp      ]: sof-hda-dsp - sof-hda-dsp\n"
       "                      LENOVO-21HMCTO1WW-ThinkPadX1CarbonGen11\n")
    _w(root, "proc/asound/card0/codec#0", "Codec: Realtek ALC711\nAddress: 0\n")
    _w(root, "proc/asound/card0/codec#2", "Codec: Intel Raptorlake HDMI\nAddress: 2\n")
    _w(root, "proc/asound/pcm",
       "00-00: HDA Analog (*) :  : playback 1 : capture 1\n"
       "00-03: HDMI 0 (*) :  : playback 1\n"
       "00-06: DMIC (*) :  : capture 1\n")
    _w(root, "proc/bus/input/devices", "\n".join([
        'I: Bus=0019 Vendor=0000 Product=0001 Version=0000\nN: Name="Power Button"\n'
        "P: Phys=LNXPWRBN/button/input0\nH: Handlers=kbd event0\nB: EV=3\n",
        'I: Bus=0011 Vendor=0001 Product=0001 Version=ab83\n'
        'N: Name="AT Translated Set 2 keyboard"\nP: Phys=isa0060/serio0/input0\n'
        "H: Handlers=sysrq kbd leds event3\nB: EV=120013\n",
        'I: Bus=0018 Vendor=06cb Product=cef5 Version=0100\nN: Name="SYNA8017:00 Touchpad"\n'
        "P: Phys=i2c-SYNA8017:00\nH: Handlers=mouse0 event7\nB: EV=1b\n",
        'I: Bus=0003 Vendor=046d Product=4082 Version=0111\nN: Name="Logitech MX Master 3"\n'
        "P: Phys=usb-0000:00:14.0-3/input2:1\nH: Handlers=sysrq kbd mouse1 event9\nB: EV=17\n",
        'I: Bus=0000 Vendor=0000 Product=0000 Version=0000\n'
        'N: Name="sof-hda-dsp Headphone"\nP: Phys=ALSA\nH: Handlers=event12\nB: EV=21\n',
    ]))
    _w(root, "proc/net/route",
       "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
       "wlp0s20f3\t00000000\t01B2A8C0\t0003\t0\t0\t600\t00000000\n"
       "wlp0s20f3\t00B2A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n")
    _w(root, "proc/net/wireless",
       "Inter-| sta-|   Quality        |   Discarded packets\n"
       " face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n"
       "wlp0s20f3: 0000   58.  -52.  -256        0      0      0      0     12        0\n")
    _w(root, "proc/net/if_inet6",
       "20010db8123456780000000000000042 03 40 00 00 wlp0s20f3\n"
       "00000000000000000000000000000001 01 80 10 80 lo\n")
    # -- /etc, /usr/share --------------------------------------------------
    _w(root, "etc/os-release", 'NAME="Fedora Linux"\nVERSION="41 (Workstation Edition)"\n'
       "ID=fedora\nVERSION_ID=41\nPRETTY_NAME=\"Fedora Linux 41 (Workstation Edition)\"\n")
    _w(root, "etc/timezone", "Europe/Berlin\n")
    _w(root, "etc/resolv.conf", "# generated\nnameserver 9.9.9.9\n")
    _w(root, "usr/share/hwdata/pci.ids", PCI_IDS)
    _w(root, "usr/share/hwdata/usb.ids", USB_IDS)
    # -- DMI -----------------------------------------------------------------
    _files(root, "sys/class/dmi/id", {
        "sys_vendor": "LENOVO", "product_name": "21HMCTO1WW",
        "product_version": "ThinkPad X1 Carbon Gen 11",
        "product_family": "ThinkPad X1 Carbon Gen 11",
        "product_sku": "LENOVO_MT_21HM_BU_Think_FM_ThinkPad X1 Carbon Gen 11",
        "board_vendor": "LENOVO", "board_name": "21HMCTO1WW", "board_version": "SDK0T76530 WIN",
        "bios_vendor": "LENOVO", "bios_version": "N3XET53W (1.28 )", "bios_date": "06/14/2024",
        "chassis_type": "10", "chassis_vendor": "LENOVO",
        "product_serial": "PF3XAMPL", "board_serial": "L1HF2EXAMPLE",
        "product_uuid": "4c4c4544-0042-3510-8052-b4c04f4a3633",
        "chassis_serial": "To Be Filled By O.E.M.",
    })
    _w(root, "sys/firmware/efi/efivars/SecureBoot-8be97c4b-0000-0000-0000-000000000000",
       b"\x06\x00\x00\x00\x01")
    # -- CPU -------------------------------------------------------------------
    cpu = "sys/devices/system/cpu"
    _w(root, f"{cpu}/online", f"0-{threads - 1}\n")
    _w(root, "sys/devices/cpu_core/cpus", "0-3\n")
    _w(root, "sys/devices/cpu_atom/cpus", f"4-{threads - 1}\n")
    for n in range(threads):
        p_core = n < 4
        core = n // 2 if p_core else n - 2
        base = f"{cpu}/cpu{n}"
        _files(root, f"{base}/topology", {"core_id": core, "physical_package_id": 0})
        _files(root, f"{base}/cpufreq", {
            "scaling_cur_freq": 1400000 + 100000 * n, "cpuinfo_min_freq": 400000,
            "cpuinfo_max_freq": 5200000 if p_core else 3900000,
            "scaling_governor": "powersave", "scaling_driver": "intel_pstate"})
        _files(root, f"{base}/cache/index0", {"level": 1, "type": "Data",
                                              "size": "48K" if p_core else "32K",
                                              "shared_cpu_list": f"{n}"})
        _files(root, f"{base}/cache/index1", {"level": 1, "type": "Instruction",
                                              "size": "32K" if p_core else "64K",
                                              "shared_cpu_list": f"{n}"})
        l2_group = f"{n - n % 2}-{n - n % 2 + 1}" if p_core else f"{4 + (n - 4) // 4 * 4}-" \
            f"{4 + (n - 4) // 4 * 4 + 3}"
        _files(root, f"{base}/cache/index2", {"level": 2, "type": "Unified",
                                              "size": "1280K" if p_core else "2048K",
                                              "shared_cpu_list": l2_group})
        _files(root, f"{base}/cache/index3", {"level": 3, "type": "Unified", "size": "12288K",
                                              "shared_cpu_list": f"0-{threads - 1}"})
    _files(root, f"{cpu}/vulnerabilities", {
        "spectre_v1": "Mitigation: usercopy/swapgs barriers and __user pointer sanitization",
        "spectre_v2": "Mitigation: Enhanced / Automatic IBRS; IBPB: conditional",
        "meltdown": "Not affected", "retbleed": "Not affected",
        "gather_data_sampling": "Not affected", "reg_file_data_sampling": "Mitigation: Clear "
        "Register File"})
    _w(root, "sys/devices/system/memory/block_size_bytes", "8000000\n")
    for n in range(256):
        (root / f"sys/devices/system/memory/memory{n}").mkdir(parents=True, exist_ok=True)
    # -- PCI -----------------------------------------------------------------------
    pci = "sys/devices/pci0000:00"
    pci_devices = {
        "0000:00:00.0": ("0x060000", "0x8086", "0xa706", "", None),
        "0000:00:02.0": ("0x030000", "0x8086", "0xa7a1", "i915", None),
        "0000:00:0d.0": ("0x0c0330", "0x8086", "0xa71d", "xhci_hcd", None),
        "0000:00:14.3": ("0x028000", "0x8086", "0x51f1", "iwlwifi", None),
        "0000:00:1d.0": ("0x060400", "0x8086", "0xa74d", "pcieport", None),
        "0000:04:00.0": ("0x010802", "0x144d", "0xa80c", "nvme", "0000:00:1d.0"),
        "0000:00:1f.3": ("0x040100", "0x8086", "0x51ca", "sof-audio-pci-intel-tgl", None),
    }
    for addr, (cls, vendor, device, driver, parent) in pci_devices.items():
        rel = f"{pci}/{parent}/{addr}" if parent else f"{pci}/{addr}"
        _files(root, rel, {"class": cls, "vendor": vendor, "device": device,
                           "subsystem_vendor": "0x17aa", "subsystem_device": "0x22e6",
                           "revision": "0x04"})
        if driver:
            _link(root, f"{rel}/driver", f"../../../bus/pci/drivers/{driver}")
        _link(root, f"sys/bus/pci/devices/{addr}", "../../../" + rel.split("/", 1)[1])
    _w(root, f"{pci}/0000:00:02.0/boot_vga", "1\n")
    # -- DRM / displays ------------------------------------------------------------------
    drm = "sys/class/drm"
    (root / f"{drm}/card1").mkdir(parents=True)
    _link(root, f"{drm}/card1/device", "../../../devices/pci0000:00/0000:00:02.0")
    _files(root, f"{drm}/card1-eDP-1", {"status": "connected", "enabled": "enabled",
                                        "modes": "2880x1800\n1920x1200\n1280x800"})
    _w(root, f"{drm}/card1-eDP-1/edid",
       make_edid("ATN", 0x9C4, "ATNA40YK07-0", 30, 19, 2880, 1800, 90, "SERIALPANEL1"))
    _files(root, f"{drm}/card1-DP-1", {"status": "connected", "enabled": "enabled",
                                       "modes": "3840x2160\n2560x1440\n1920x1080\n1920x1080"})
    _w(root, f"{drm}/card1-DP-1/edid",
       make_edid("DEL", 0x41A8, "DELL U2720Q", 60, 34, 3840, 2160, 60, "CFV9N03"))
    _files(root, f"{drm}/card1-HDMI-A-1", {"status": "disconnected", "enabled": "disabled",
                                           "modes": ""})
    # -- block devices ---------------------------------------------------------------------
    nvme = f"{pci}/0000:00:1d.0/0000:04:00.0/nvme/nvme0/nvme0n1"
    _files(root, nvme, {"size": 1953525168, "removable": 0})
    _files(root, f"{nvme}/queue", {"rotational": 0, "scheduler": "[none] mq-deadline",
                                   "logical_block_size": 512, "physical_block_size": 512})
    _files(root, f"{pci}/0000:00:1d.0/0000:04:00.0/nvme/nvme0", {
        "model": "Samsung SSD 990 PRO 1TB", "serial": "S6B0NL0W123456A",
        "firmware_rev": "4B2QJXD7"})
    _link(root, f"{nvme}/device", "../../nvme0")
    for name, start, size in (("nvme0n1p1", 2048, 1228800), ("nvme0n1p2", 1230848, 1952292864)):
        _files(root, f"{nvme}/{name}", {"partition": name[-1], "start": start, "size": size})
    _link(root, "sys/block/nvme0n1", "../" + nvme.split("/", 1)[1])
    usb_disk = f"{pci}/0000:00:0d.0/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0"
    _files(root, f"{usb_disk}/block/sda", {"size": 61341696, "removable": 1})
    _files(root, f"{usb_disk}/block/sda/queue", {"rotational": 1, "scheduler": "[bfq] none"})
    _files(root, usb_disk, {"model": "Extreme Pro     ", "vendor": "SanDisk ", "rev": "0001"})
    _link(root, f"{usb_disk}/block/sda/device", "../../../0:0:0:0")
    _files(root, f"{usb_disk}/block/sda/sda1", {"partition": 1, "start": 2048,
                                               "size": 61339648})
    _link(root, "sys/block/sda", "../" + f"{usb_disk}/block/sda".split("/", 1)[1])
    _files(root, "sys/devices/virtual/block/loop0", {"size": 0})
    _link(root, "sys/block/loop0", "../devices/virtual/block/loop0")
    # -- network ---------------------------------------------------------------------------
    nets = {
        "lo": ("sys/devices/virtual/net/lo", 772, "00:00:00:00:00:00", "unknown", None, ""),
        "enp0s31f6": (f"{pci}/0000:00:1f.6/net/enp0s31f6", 1, "8c:16:45:ab:cd:ef", "down",
                      None, "e1000e"),
        "wlp0s20f3": (f"{pci}/0000:00:14.3/net/wlp0s20f3", 1, "a4:c3:f0:12:34:56", "up", None,
                      "iwlwifi"),
        "docker0": ("sys/devices/virtual/net/docker0", 1, "02:42:9f:11:22:33", "down", None, ""),
        "tailscale0": ("sys/devices/virtual/net/tailscale0", 65534, "", "unknown", None, ""),
    }
    for name, (rel, arptype, mac, state, _speed, driver) in nets.items():
        _files(root, rel, {"type": arptype, "address": mac, "operstate": state, "mtu": 1500})
        _files(root, f"{rel}/statistics", {"rx_bytes": 123456789, "tx_bytes": 23456789})
        if driver:
            _link(root, f"{rel}/device/driver", f"../../../../bus/pci/drivers/{driver}")
        _link(root, f"sys/class/net/{name}", "../../" + rel.split("/", 1)[1])
    _w(root, f"{pci}/0000:00:14.3/net/wlp0s20f3/phy80211/name", "phy0\n")
    _w(root, f"{pci}/0000:00:1f.6/net/enp0s31f6/speed", "-1\n")
    (root / "sys/devices/virtual/net/docker0/bridge").mkdir()
    _w(root, "sys/devices/virtual/net/tailscale0/tun_flags", "0x1002\n")
    # -- Bluetooth and radios ---------------------------------------------------------------
    _w(root, "sys/class/bluetooth/hci0/address", "f4:4e:e3:aa:bb:cc\n")
    _link(root, "sys/class/bluetooth/hci0/device/driver", "../../../../bus/usb/drivers/btusb")
    _files(root, "sys/class/rfkill/rfkill0", {"name": "tpacpi_bluetooth_sw", "type": "bluetooth",
                                              "soft": 0, "hard": 0})
    _files(root, "sys/class/rfkill/rfkill1", {"name": "phy0", "type": "wlan", "soft": 0,
                                              "hard": 0})
    # -- USB --------------------------------------------------------------------------------
    usb = {
        "usb1": {"idVendor": "1d6b", "idProduct": "0002", "manufacturer": "Linux 6.11 xhci-hcd",
                 "product": "xHCI Host Controller", "speed": "480", "bDeviceClass": "09",
                 "serial": "0000:00:14.0", "version": " 2.00"},
        "1-3": {"idVendor": "046d", "idProduct": "c52b", "speed": "12", "bDeviceClass": "00",
                "version": " 2.00", "bMaxPower": "98mA"},
        "1-6": {"idVendor": "04f2", "idProduct": "b7b6", "manufacturer": "Chicony Electronics",
                "product": "Integrated Camera", "speed": "480", "bDeviceClass": "ef",
                "version": " 2.01"},
        "1-10": {"idVendor": "8087", "idProduct": "0033", "speed": "12", "bDeviceClass": "e0",
                 "version": " 2.01"},
        "usb2": {"idVendor": "1d6b", "idProduct": "0003", "manufacturer": "Linux 6.11 xhci-hcd",
                 "product": "xHCI Host Controller", "speed": "10000", "bDeviceClass": "09"},
        "2-1": {"idVendor": "0781", "idProduct": "5591", "manufacturer": "SanDisk",
                "product": "Extreme Pro", "speed": "5000", "bDeviceClass": "00",
                "serial": "4C530001234567890123", "version": " 3.20"},
    }
    interfaces = {"1-3": ("03", "usbhid"), "1-6": ("0e", "uvcvideo"), "1-10": ("e0", "btusb"),
                  "2-1": ("08", "usb-storage"), "usb1": ("09", "hub"), "usb2": ("09", "hub")}
    for name, attrs in usb.items():
        rel = f"sys/bus/usb/devices/{name}"
        _files(root, rel, {"busnum": name[3] if name.startswith("usb") else name[0],
                           "devnum": 1, **attrs})
        cls, driver = interfaces[name]
        iface = f"{rel}/{name if '-' in name else name[3] + '-0'}:1.0"
        _files(root, iface, {"bInterfaceClass": cls})
        _link(root, f"{iface}/driver", f"../../../../bus/usb/drivers/{driver}")
    # -- power ------------------------------------------------------------------------------
    _files(root, "sys/class/power_supply/AC", {"type": "Mains", "online": 1})
    _files(root, "sys/class/power_supply/BAT0", {
        "type": "Battery", "status": "Charging", "capacity": 76, "energy_now": 43_320_000,
        "energy_full": 50_560_000, "energy_full_design": 57_000_000, "power_now": 18_400_000,
        "cycle_count": 182, "technology": "Li-poly", "manufacturer": "SMP",
        "model_name": "5B10W51867", "serial_number": "41ZXSERIAL",
        "charge_control_end_threshold": 80})
    _files(root, "sys/class/power_supply/hidpp_battery_0", {
        "type": "Battery", "scope": "Device", "status": "Discharging", "capacity": 55,
        "model_name": "MX Master 3"})
    # -- sensors ----------------------------------------------------------------------------
    _files(root, "sys/class/hwmon/hwmon4", {
        "name": "coretemp", "temp1_input": 58000, "temp1_label": "Package id 0",
        "temp1_max": 100000, "temp1_crit": 100000,
        "temp2_input": 54000, "temp2_label": "Core 0", "temp2_max": 100000,
        "temp3_input": 61000, "temp3_label": "Core 4", "temp3_max": 100000,
        "temp4_input": 83000, "temp4_label": "Core 8", "temp4_max": 100000})
    _files(root, "sys/class/hwmon/hwmon2", {
        "name": "nvme", "temp1_input": 41850, "temp1_label": "Composite",
        "temp1_max": 81850, "temp1_crit": 84850})
    _files(root, "sys/class/hwmon/hwmon6", {"name": "thinkpad", "fan1_input": 2380,
                                            "temp1_input": 47000})
    _files(root, "sys/class/hwmon/hwmon7", {"name": "BAT0", "in0_input": 16912})
    _files(root, "sys/class/thermal/thermal_zone0", {
        "type": "x86_pkg_temp", "temp": 58000, "trip_point_0_type": "passive",
        "trip_point_0_temp": 0, "trip_point_1_type": "critical", "trip_point_1_temp": 105000})
    _files(root, "sys/class/thermal/thermal_zone1", {"type": "acpitz", "temp": 45000})
    return root


def build_minimal(root: Path) -> Path:
    """A machine with only /proc/cpuinfo and /proc/meminfo."""
    root = Path(root)
    _w(root, "proc/cpuinfo", _cpuinfo(2))
    _w(root, "proc/meminfo", "MemTotal: 2048000 kB\nMemAvailable: 1024000 kB\n")
    return root


def fake_usage(path: str) -> tuple[int, int, int]:
    """Disk usage of the laptop's file systems, by mount point."""
    sizes = {
        "/": (1_000_000_000_000, 612_000_000_000), "/home": (1_000_000_000_000, 612_000_000_000),
        "/boot/efi": (627_000_000, 72_000_000), "/tmp": (16_000_000_000, 1_200_000_000),
        "/run/media/user/USB STICK": (31_400_000_000, 29_900_000_000),
    }
    total, used = sizes.get(path, (100, 50))
    return total, used, total - used
