"""Disk images: what an image is, its partitions and their file systems
(punch-list item 6).

Operator: *„wenn wir z.b. ein festplatten image haben, partitionen auslesen
und dann bei rechtem mausklick anbieten loop zu mounten"*.

core.disk_image reads containers (qcow2, VDI, VMDK, VHD/VHDX, E01, ISO),
partition tables (MBR with logical partitions, GPT) and file-system
superblocks in plain Python, from any seekable file. The images here are
built byte by byte; one more is made by the real tools (sfdisk, mkfs.ext4)
and the parser has to agree with sfdisk's own JSON.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import struct
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import disk_image as DI  # noqa: E402

SECTOR = 512
MiB = 1024 * 1024


# -- builders ---------------------------------------------------------------------------


def mbr_entry(boot, ptype, lba, sectors) -> bytes:
    return struct.pack("<B3sB3sII", 0x80 if boot else 0, b"\0" * 3, ptype, b"\0" * 3, lba, sectors)


def with_mbr(image: bytearray, entries, offset=0) -> None:
    table = b"".join(entries).ljust(64, b"\0")
    image[offset + 446:offset + 510] = table
    image[offset + 510:offset + 512] = b"\x55\xaa"


def put_ext4(image: bytearray, start: int, label: bytes = b"rootfs", journal=True, extents=True):
    sb = start + 1024
    image[sb + 56:sb + 58] = struct.pack("<H", 0xEF53)
    image[sb + 92:sb + 96] = struct.pack("<I", 0x4 if journal else 0)
    image[sb + 96:sb + 100] = struct.pack("<I", 0x40 if extents else 0)
    image[sb + 120:sb + 136] = label.ljust(16, b"\0")


def put_fat32(image: bytearray, start: int, label=b"BOOT       "):
    image[start + 3:start + 11] = b"MSDOS5.0"
    image[start + 71:start + 82] = label
    image[start + 82:start + 90] = b"FAT32   "
    image[start + 510:start + 512] = b"\x55\xaa"


def put_ntfs(image: bytearray, start: int):
    image[start + 3:start + 11] = b"NTFS    "
    image[start + 510:start + 512] = b"\x55\xaa"


def guid_bytes(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


def gpt_image(parts, size=8 * MiB) -> bytearray:
    image = bytearray(size)
    with_mbr(image, [mbr_entry(False, 0xEE, 1, size // SECTOR - 1)])
    entries = bytearray(128 * 128)
    for i, (type_guid, first, last, name) in enumerate(parts):
        e = 128 * i
        entries[e:e + 16] = guid_bytes(type_guid)
        entries[e + 16:e + 32] = uuid.uuid4().bytes_le
        entries[e + 32:e + 48] = struct.pack("<QQ", first, last)
        entries[e + 56:e + 128] = name.encode("utf-16-le").ljust(72, b"\0")
    header = bytearray(92)
    header[0:8] = b"EFI PART"
    header[8:12] = struct.pack("<I", 0x10000)
    header[12:16] = struct.pack("<I", 92)
    header[72:80] = struct.pack("<Q", 2)
    header[80:84] = struct.pack("<I", 128)
    header[84:88] = struct.pack("<I", 128)
    image[SECTOR:SECTOR + 92] = header
    image[2 * SECTOR:2 * SECTOR + len(entries)] = entries
    return image


def info_of(image) -> DI.ImageInfo:
    return DI.inspect(io.BytesIO(bytes(image)), len(image))


LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
SWAP = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F"


# -- happy ------------------------------------------------------------------------------


def test_happy_mbr_with_primary_and_logical_partitions():
    image = bytearray(16 * MiB)
    # 1: FAT32 at 1 MiB (2 MiB), 2: extended at 4 MiB (10 MiB) holding two
    # logical partitions, 3: Linux at 14 MiB.
    with_mbr(image, [
        mbr_entry(True, 0x0C, 2048, 4096),
        mbr_entry(False, 0x05, 8192, 20480),
        mbr_entry(False, 0x83, 28672, 4096),
    ])
    put_fat32(image, 2048 * SECTOR)
    ext = 8192 * SECTOR
    # EBR 1: logical at +2048 sectors (4096), next EBR at +8192 (relative to the extended start)
    with_mbr(image, [mbr_entry(False, 0x83, 2048, 4096), mbr_entry(False, 0x05, 8192, 8192)], ext)
    put_ext4(image, ext + 2048 * SECTOR, b"home")
    with_mbr(image, [mbr_entry(False, 0x82, 2048, 4096)], ext + 8192 * SECTOR)
    image[ext + (8192 + 2048) * SECTOR + 4086:ext + (8192 + 2048) * SECTOR + 4096] = b"SWAPSPACE2"
    put_ext4(image, 28672 * SECTOR, b"data", journal=True, extents=False)

    info = info_of(image)
    assert info.kind == "raw" and info.scheme == "mbr"
    got = [(p.number, p.start // SECTOR, p.size // SECTOR, p.filesystem, p.label, p.bootable)
           for p in info.partitions]
    assert got == [
        (1, 2048, 4096, "vfat", "BOOT", True),
        (3, 28672, 4096, "ext3", "data", False),
        (5, 8192 + 2048, 4096, "ext4", "home", False),
        (6, 8192 + 8192 + 2048, 4096, "swap", "", False),
    ]
    assert info.partitions[0].type_name.startswith("FAT32")
    assert all(p.mountable for p in info.partitions if p.filesystem != "swap")
    assert not info.partitions[3].mountable  # swap is no file system


def test_happy_gpt_with_names_and_types():
    image = gpt_image([
        (ESP, 2048, 4095, "EFI system"),
        (LINUX, 4096, 12287, "root"),
        (SWAP, 12288, 14335, "swap"),
    ])
    put_fat32(image, 2048 * SECTOR, b"ESP        ")
    put_ext4(image, 4096 * SECTOR, b"root")
    info = info_of(image)
    assert info.scheme == "gpt"
    assert [(p.number, p.name, p.type_name, p.filesystem) for p in info.partitions] == [
        (1, "EFI system", "EFI System", "vfat"),
        (2, "root", "Linux filesystem", "ext4"),
        (3, "swap", "Linux swap", ""),
    ]
    assert info.partitions[1].start == 4096 * SECTOR
    assert info.partitions[1].size == 8192 * SECTOR
    assert info.partitions[1].type_id == LINUX


@pytest.mark.parametrize(
    "build, fs, label",
    [
        (lambda im: put_ext4(im, 0, b"whole"), "ext4", "whole"),
        (lambda im: put_ntfs(im, 0), "ntfs", ""),
        (lambda im: put_fat32(im, 0, b"STICK      "), "vfat", "STICK"),
        (lambda im: im.__setitem__(slice(0x8001, 0x8006), b"CD001")
         or im.__setitem__(slice(0x8028, 0x8048), b"MY_DISC".ljust(32)), "iso9660", "MY_DISC"),
        (lambda im: im.__setitem__(slice(0, 6), b"LUKS\xba\xbe"), "crypto_LUKS", ""),
        (lambda im: im.__setitem__(slice(0, 4), b"XFSB")
         or im.__setitem__(slice(108, 120), b"xfsdata".ljust(12, b"\0")), "xfs", "xfsdata"),
        (lambda im: im.__setitem__(slice(0x10040, 0x10048), b"_BHRfS_M")
         or im.__setitem__(slice(0x1012B, 0x1012F), b"pool"), "btrfs", "pool"),
        (lambda im: im.__setitem__(slice(0, 4), b"hsqs"), "squashfs", ""),
    ],
)
def test_happy_a_bare_file_system_is_one_mountable_volume(build, fs, label):
    image = bytearray(2 * MiB)
    build(image)
    info = info_of(image)
    assert info.scheme == "none"
    assert info.filesystem == fs and info.label == label
    (whole,) = info.partitions
    assert whole.number == 0 and whole.start == 0 and whole.size == len(image)
    # A FAT or NTFS boot sector ends in 55 AA as an MBR does: still no table.
    assert whole.filesystem == fs


@pytest.mark.parametrize(
    "head, kind",
    [
        (b"QFI\xfb" + b"\0\0\0\x03" + b"\0" * 16 + struct.pack(">Q", 10 * 1024 ** 3), "qcow2"),
        (b"KDMV" + b"\0" * 60, "vmdk"),
        (b"# Disk DescriptorFile\nversion=1\n", "vmdk"),
        (b"vhdxfile" + b"\0" * 56, "vhdx"),
        (b"conectix" + b"\0" * 56, "vhd"),
        (b"EVF\x09\x0d\x0a\xff\x00" + b"\0" * 56, "ewf"),
    ],
)
def test_happy_virtual_disk_containers_are_named(head, kind):
    image = bytearray(1 * MiB)
    image[:len(head)] = head
    info = info_of(image)
    assert info.kind == kind
    assert not info.mountable and info.note
    if kind == "qcow2":
        assert info.virtual_size == 10 * 1024 ** 3 and "qcow2 v3" in info.description


def test_happy_a_fixed_vdi_shows_the_partitions_inside():
    inner = bytearray(4 * MiB)
    with_mbr(inner, [mbr_entry(False, 0x83, 2048, 4096)])
    put_ext4(inner, 2048 * SECTOR, b"guest")
    header = bytearray(0x200)
    header[0:40] = b"<<< Oracle VM VirtualBox Disk Image >>>\n"
    header[0x40:0x44] = struct.pack("<I", 0xBEDA107F)
    header[0x4C:0x50] = struct.pack("<I", 2)  # fixed
    header[0x158:0x15C] = struct.pack("<I", 0x200000)  # data offset 2 MiB
    header[0x170:0x178] = struct.pack("<Q", len(inner))
    image = header.ljust(0x200000, b"\0") + inner
    info = info_of(image)
    assert info.kind == "vdi" and "fixed" in info.description
    assert info.data_offset == 0x200000
    assert [(p.filesystem, p.label) for p in info.partitions] == [("ext4", "guest")]
    assert info.partitions[0].start == 0x200000 + 2048 * SECTOR
    assert not info.mountable  # loop-mounting a VDI needs its offset; offered per partition
    assert info.partitions[0].mountable


def test_happy_inspect_path_reads_a_local_file(tmp_path):
    image = gpt_image([(LINUX, 2048, 4095, "data")], size=4 * MiB)
    put_ext4(image, 2048 * SECTOR, b"lbl")
    path = tmp_path / "disk.img"
    path.write_bytes(image)
    info = DI.inspect_path(str(path))
    assert info.partitions[0].label == "lbl" and info.size == 4 * MiB


@pytest.mark.skipif(not (shutil.which("sfdisk") and shutil.which("mkfs.ext4")),
                    reason="sfdisk / mkfs.ext4 not installed")
@pytest.mark.parametrize("label", ["dos", "gpt"])
def test_e2e_agrees_with_sfdisk_and_mkfs(tmp_path, label):
    """An image made by the real tools: the partitions sfdisk reports, the
    file system and label mkfs.ext4 wrote."""
    img = tmp_path / "real.img"
    subprocess.run(["truncate", "-s", "40M", str(img)], check=True)
    layout = f"label: {label}\n,8M,L\n,16M,L\n,,L\n"
    if label == "dos":
        layout = "label: dos\n,8M,83\n,16M,5\n,8M,83\n,,82\n"
    subprocess.run(["sfdisk", "-q", str(img)], input=layout.encode(), check=True,
                   env={**os.environ, "LC_ALL": "C"})
    table = json.loads(subprocess.run(["sfdisk", "--json", str(img)], check=True,
                                      capture_output=True).stdout)["partitiontable"]
    first = table["partitions"][0]
    part = tmp_path / "p1.img"
    subprocess.run(["truncate", "-s", str(first["size"] * 512), str(part)], check=True)
    subprocess.run(["mkfs.ext4", "-q", "-F", "-L", "axross-p1", str(part)], check=True)
    subprocess.run(["dd", f"if={part}", f"of={img}", "bs=512", f"seek={first['start']}",
                    "conv=notrunc", "status=none"], check=True)
    info = DI.inspect_path(str(img))
    expected = [(int(p["node"].rsplit("img", 1)[1]), p["start"], p["size"])
                for p in table["partitions"] if p.get("type") not in ("5", "f", "85")]
    got = [(p.number, p.start // 512, p.size // 512) for p in info.partitions]
    assert got == expected
    assert (info.partitions[0].filesystem, info.partitions[0].label) == ("ext4", "axross-p1")


def test_happy_file_type_names_disk_images():
    from core import file_type as FT

    image = bytearray(1 * MiB)
    image[:4] = b"QFI\xfb"
    assert "qcow2" in FT.identify_bytes(bytes(image[:65536]), name="x.qcow2").description.lower()


@pytest.mark.parametrize(
    "name, head",
    [
        ("vm.qcow2", b"QFI\xfb\0\0\0\x03" + b"\0" * 16 + struct.pack(">Q", 1 << 30)),
        ("vm.vdi", b"\0" * 0x40 + struct.pack("<I", 0xBEDA107F) + b"\0" * 8 + struct.pack("<I", 1)),
        ("vm.vmdk", b"KDMV" + b"\0" * 60),
        ("vm.vhdx", b"vhdxfile" + b"\0" * 56),
        ("vm.vhd", b"conectix" + b"\0" * 56),
    ],
)
def test_happy_file_type_finds_no_mismatch_in_a_correctly_named_container(name, head):
    """Identify File Type must not call a correctly named virtual disk a
    mismatch: the MIME type it reports is the container's own, the one its
    extension stands for - not a raw disk image."""
    from core import file_type as FT

    data = bytes(bytearray(head).ljust(64 * 1024, b"\0"))
    info = FT.identify_bytes(data, name=name)
    assert info.engine == "disk image"
    assert info.verdict != FT.MISMATCH, (info.mime, info.extension_mime)
    if info.extension_mime:
        assert info.verdict == FT.MATCH


def test_sad_file_type_still_flags_a_container_under_a_foreign_extension():
    from core import file_type as FT

    data = (b"QFI\xfb\0\0\0\x03").ljust(64 * 1024, b"\0")
    info = FT.identify_bytes(data, name="holiday.jpg")
    assert info.verdict == FT.MISMATCH and "qcow2" in info.description.lower()


def test_happy_image_suffixes():
    assert DI.looks_like_image("disk.IMG") and DI.looks_like_image("a.qcow2")
    assert DI.looks_like_image("sda.dd") and DI.looks_like_image("x.iso")
    assert not DI.looks_like_image("notes.txt") and not DI.looks_like_image("img")


# -- sad --------------------------------------------------------------------------------


def test_sad_random_bytes_are_no_image():
    image = bytearray(os.urandom(256 * 1024))
    image[510:512] = b"\0\0"
    info = info_of(image)
    assert info.kind == "unknown" and info.partitions == [] and not info.mountable


def test_sad_an_mbr_with_garbage_status_is_no_table():
    image = bytearray(1 * MiB)
    with_mbr(image, [struct.pack("<B3sB3sII", 0x13, b"\0" * 3, 0x83, b"\0" * 3, 2048, 100)])
    info = info_of(image)
    assert info.scheme != "mbr" and info.partitions == []


def test_sad_an_empty_file_and_unreadable_path(tmp_path):
    assert DI.inspect(io.BytesIO(b""), 0).kind == "unknown"
    with pytest.raises(OSError):
        DI.inspect_path(str(tmp_path / "missing.img"))


def test_sad_a_partition_past_the_end_is_flagged():
    image = bytearray(4 * MiB)
    with_mbr(image, [mbr_entry(False, 0x83, 2048, 1_000_000)])
    (p,) = info_of(image).partitions
    assert p.beyond_end and not p.mountable


def test_sad_a_gpt_claiming_absurd_entry_counts_is_bounded():
    image = gpt_image([(LINUX, 2048, 4095, "x")], size=4 * MiB)
    image[SECTOR + 80:SECTOR + 84] = struct.pack("<I", 10_000_000)
    info = info_of(image)
    assert info.scheme == "gpt" and len(info.partitions) <= DI.MAX_GPT_ENTRIES
    assert any("entries" in w for w in info.warnings)


# -- edge -------------------------------------------------------------------------------


def test_edge_an_ebr_chain_that_loops_ends():
    image = bytearray(8 * MiB)
    with_mbr(image, [mbr_entry(False, 0x0F, 2048, 12288)])
    ext = 2048 * SECTOR
    # The EBR's "next" points back at itself.
    with_mbr(image, [mbr_entry(False, 0x83, 64, 1024), mbr_entry(False, 0x05, 0, 12288)], ext)
    info = info_of(image)
    assert [p.number for p in info.partitions] == [5]
    assert any("loop" in w for w in info.warnings)


def test_edge_a_long_chain_of_empty_ebrs_is_bounded():
    """Every link of an EBR chain costs a read (a network round trip on a
    remote image): a chain of empty links ends after MAX_LOGICAL links, as
    one of logical partitions does, instead of running through the image."""
    links = 4 * DI.MAX_LOGICAL
    image = bytearray((2048 + links + 8) * SECTOR)
    with_mbr(image, [mbr_entry(False, 0x05, 2048, links + 4)])
    ext = 2048 * SECTOR
    for k in range(links):
        # Entry 0 empty, entry 1 points at the next sector of the chain.
        with_mbr(image, [mbr_entry(False, 0, 0, 0), mbr_entry(False, 0x05, k + 1, 1)],
                 ext + k * SECTOR)

    class Counting(io.BytesIO):
        reads = 0

        def read(self, n=-1):
            Counting.reads += 1
            return super().read(n)

    info = DI.inspect(Counting(bytes(image)), len(image))
    assert info.partitions == []
    assert Counting.reads <= DI.MAX_LOGICAL + 16, Counting.reads
    assert any("logical" in w for w in info.warnings)


def test_edge_4k_sector_gpt():
    size = 16 * MiB
    image = bytearray(size)
    with_mbr(image, [mbr_entry(False, 0xEE, 1, size // 4096 - 1)])
    header = bytearray(92)
    header[0:8] = b"EFI PART"
    header[72:80] = struct.pack("<Q", 2)
    header[80:84] = struct.pack("<I", 4)
    header[84:88] = struct.pack("<I", 128)
    image[4096:4096 + 92] = header
    entry = bytearray(128)
    entry[0:16] = guid_bytes(LINUX)
    entry[32:48] = struct.pack("<QQ", 256, 511)
    image[8192:8192 + 128] = entry
    put_ext4(image, 256 * 4096, b"big")
    info = info_of(image)
    assert info.sector_size == 4096
    assert [(p.start, p.size, p.label) for p in info.partitions] == [(256 * 4096, 256 * 4096, "big")]


def test_edge_a_stream_that_cannot_seek_reads_only_the_head():
    class Stream(io.RawIOBase):
        def __init__(self, data):
            self._data = io.BytesIO(data)

        def readable(self):
            return True

        def readinto(self, b):
            chunk = self._data.read(len(b))
            b[:len(chunk)] = chunk
            return len(chunk)

        def seekable(self):
            return False

    image = gpt_image([(LINUX, 2048, 4095, "far")], size=8 * MiB)
    put_ext4(image, 2048 * SECTOR, b"far")
    info = DI.inspect(Stream(bytes(image)), len(image))
    assert info.scheme == "gpt" and info.partitions[0].name == "far"
    # The superblock lies 1 MiB in, past the head that was read.
    assert info.partitions[0].filesystem in ("", "ext4")


def test_edge_human_sizes_in_the_summary():
    image = gpt_image([(LINUX, 2048, 4095, "x")], size=4 * MiB)
    info = info_of(image)
    assert "GPT" in info.summary() and "1 partition" in info.summary()
