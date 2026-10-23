"""Disk images: what an image is, its partitions and their file systems.

Plain Python on any seekable binary file - a local image, or a remote one
through the backend's ``open_read`` - and nothing is written or mounted:

* **Containers** by their header: qcow2, VirtualBox VDI, VMware VMDK,
  VHD / VHDX, EnCase E01 (EWF). A *fixed* VDI keeps a raw disk after its
  header, so its partitions are read through the data offset; the other
  containers need converting (``qemu-img convert``) or ``qemu-nbd`` first.
* **Partition tables**: MBR with the logical partitions of an extended
  one (EBR chain, loop-safe) and GPT (512- and 4096-byte sectors, names,
  bounded entry count). A protective MBR yields to its GPT.
* **File systems** by superblock: ext2/3/4, XFS, Btrfs, FAT12/16/32,
  exFAT, NTFS, ISO 9660, HFS+, APFS, squashfs, LUKS, LVM2, Linux swap -
  with the label where the superblock keeps one. A FAT or NTFS boot sector
  ends in 55 AA like an MBR; a file system found at offset 0 wins.

Numbers come from untrusted bytes: every count, offset and chain is
bounded, and a partition that runs past the end of the image is flagged
instead of trusted.
"""

from __future__ import annotations

import io
import os
import stat
import struct
import uuid
from dataclasses import dataclass, field

SECTOR = 512
#: Bytes read from the start when the file cannot seek.
HEAD_BYTES = 2 * 1024 * 1024
MAX_GPT_ENTRIES = 256
MAX_LOGICAL = 128
#: Superblock probes read this much from a partition's start (Btrfs keeps
#: its superblock at 64 KiB, ISO 9660 at 32 KiB).
PROBE_BYTES = 0x10200

IMAGE_SUFFIXES = (
    ".img", ".raw", ".dd", ".bin", ".iso", ".qcow", ".qcow2", ".vdi", ".vmdk",
    ".vhd", ".vhdx", ".e01", ".dmg", ".hdd", ".001",
)

#: MBR partition type byte -> name.
MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16 (<32 MB)", 0x05: "Extended", 0x06: "FAT16",
    0x07: "NTFS / exFAT / HPFS", 0x0B: "FAT32 (CHS)", 0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)", 0x11: "Hidden FAT12",
    0x17: "Hidden NTFS", 0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32 (LBA)",
    0x27: "Windows recovery", 0x42: "Windows dynamic disk", 0x82: "Linux swap",
    0x83: "Linux", 0x85: "Linux extended", 0x8E: "Linux LVM", 0xA5: "FreeBSD",
    0xA6: "OpenBSD", 0xA8: "macOS UFS", 0xA9: "NetBSD", 0xAB: "macOS boot",
    0xAF: "HFS / HFS+", 0xEE: "GPT protective", 0xEF: "EFI System", 0xFB: "VMware VMFS",
    0xFD: "Linux RAID",
}
EXTENDED_TYPES = (0x05, 0x0F, 0x85)

#: GPT partition type GUID -> name.
GPT_TYPES = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "21686148-6449-6E6F-744E-656564454649": "BIOS boot",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
    "B921B045-1DF0-41C3-AF44-4C6F280D3FAE": "Linux root (ARM64)",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux home",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "CA7D7CCB-63ED-4C53-861C-1742536059CC": "Linux LUKS",
    "BC13C2FF-59E6-4262-A352-B275FD6F7172": "Linux extended boot",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft basic data",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft reserved",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows recovery",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD data",
    "516E7CBA-6ECF-11D6-8FF8-00022D09712B": "FreeBSD ZFS",
    "6A898CC3-1DD2-11B2-99A6-080020736631": "ZFS",
}

#: File systems a loop mount can open (not swap, LUKS or LVM).
MOUNTABLE_FS = frozenset({
    "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs", "iso9660",
    "hfsplus", "squashfs", "apfs",
})


@dataclass(frozen=True)
class Partition:
    """One volume. ``number`` 0 is a whole image without a partition
    table; logical partitions count from 5 as Linux names them. ``start``
    and ``size`` are bytes from the start of the image file."""

    number: int
    start: int
    size: int
    scheme: str
    type_id: str = ""
    type_name: str = ""
    name: str = ""
    bootable: bool = False
    filesystem: str = ""
    label: str = ""
    beyond_end: bool = False

    @property
    def mountable(self) -> bool:
        return (not self.beyond_end and self.size > 0
                and (self.filesystem in MOUNTABLE_FS or not self.filesystem
                     and self.type_name not in ("Linux swap", "Extended", "GPT protective")))


@dataclass
class ImageInfo:
    """``kind``: raw, qcow2, vdi, vmdk, vhd, vhdx, ewf or unknown.
    ``scheme``: mbr, gpt, none (a bare file system) or "" (nothing read)."""

    size: int
    kind: str = "unknown"
    description: str = ""
    scheme: str = ""
    sector_size: int = SECTOR
    partitions: list[Partition] = field(default_factory=list)
    filesystem: str = ""
    label: str = ""
    virtual_size: int = 0
    data_offset: int = 0
    note: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def mountable(self) -> bool:
        """The image file itself can be loop-mounted (raw data at offset 0)."""
        return self.kind == "raw" and any(p.mountable for p in self.partitions)

    def summary(self) -> str:
        parts = [self.description or self.kind]
        if self.scheme == "mbr":
            parts.append("MBR")
        elif self.scheme == "gpt":
            parts.append("GPT")
        elif self.scheme == "none" and self.filesystem:
            parts.append(self.filesystem + (f" '{self.label}'" if self.label else ""))
        if self.scheme in ("mbr", "gpt"):
            n = len(self.partitions)
            parts.append(f"{n} partition{'s' if n != 1 else ''}")
        parts.append(human_size(self.virtual_size or self.size))
        return ", ".join(parts)


def human_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


def looks_like_image(name: str) -> bool:
    """A disk image by its name - cheap, for menus."""
    base = os.path.basename(name).lower()
    return any(base.endswith(s) and len(base) > len(s) for s in IMAGE_SUFFIXES)


#: Bytes the pane menu reads from a local file to tell a disk image by its
#: content: every container header, the MBR, the GPT header at 512 or 4096
#: and the boot sector or ext superblock that rules out a bare volume.
CONTENT_PROBE_BYTES = 4096


def type_says_image(mime: str, engine: str) -> bool:
    """Whether Identify File Type's result (core.file_type) names a disk
    image: core.disk_image decided it, or the MIME type is an image's."""
    return engine == "disk image" or mime in DISK_IMAGE_MIMES


def local_content_says_image(path: str, limit: int = CONTENT_PROBE_BYTES) -> bool:
    """Whether the first *limit* bytes of the local file *path* start a disk
    image (detect_container) - for the pane menu, so it is bounded: a regular
    file only (a FIFO would block the open, a device read or rewind), at
    most *limit* bytes, and every error is "no"."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return False
        # O_NONBLOCK: should *path* turn into a FIFO after the stat, the open
        # does not wait for a writer; fstat then refuses it.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_BINARY", 0))
    except (OSError, ValueError):
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        chunks, left = [], limit
        while left > 0:
            chunk = os.read(fd, left)
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
    except OSError:
        return False
    finally:
        os.close(fd)
    return bool(detect_container(b"".join(chunks))[0])


# -- reading ------------------------------------------------------------------------------


class _Reader:
    """Reads at offsets from a seekable file, or from the head of one that
    cannot seek (everything past HEAD_BYTES then reads as empty)."""

    def __init__(self, fh, size: int) -> None:
        self.size = size
        self._fh = fh
        self._head: bytes | None = None
        try:
            seekable = fh.seekable()
        except (AttributeError, OSError, ValueError):
            seekable = False
        if not seekable:
            self._head = _read_exact(fh, HEAD_BYTES)
            self._fh = None

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        if self._head is not None:
            return self._head[offset:offset + length]
        self._fh.seek(offset)
        return _read_exact(self._fh, length)


def _read_exact(fh, length: int) -> bytes:
    chunks = []
    while length > 0:
        chunk = fh.read(length)
        if not chunk:
            break
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0] if len(b) >= o + 2 else 0


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0] if len(b) >= o + 4 else 0


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0] if len(b) >= o + 8 else 0


def _text(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace").strip()


# -- file systems -------------------------------------------------------------------------


def probe_filesystem(data: bytes) -> tuple[str, str]:
    """``(filesystem, label)`` from the first bytes of a volume, or ("", "")."""
    if len(data) >= 1024 + 136 and _u16(data, 1024 + 56) == 0xEF53:
        compat, incompat = _u32(data, 1024 + 92), _u32(data, 1024 + 96)
        fs = "ext4" if incompat & 0x2C0 else "ext3" if compat & 0x4 else "ext2"
        return fs, _text(data[1024 + 120:1024 + 136])
    if data[:4] == b"XFSB":
        return "xfs", _text(data[108:120])
    if data[0x10040:0x10048] == b"_BHRfS_M":
        return "btrfs", _text(data[0x1012B:0x1012B + 256])
    if data[:6] == b"LUKS\xba\xbe":
        return "crypto_LUKS", ""
    if data[512 + 24:512 + 32] == b"LVM2 001" or data[512:520] == b"LABELONE":
        return "LVM2_member", ""
    if data[:4] in (b"hsqs", b"sqsh"):
        return "squashfs", ""
    if data[3:11] == b"NTFS    ":
        return "ntfs", ""
    if data[3:11] == b"EXFAT   ":
        return "exfat", ""
    if data[82:90] == b"FAT32   ":
        return "vfat", _fat_label(data[71:82])
    if data[54:59] in (b"FAT12", b"FAT16", b"FAT  "):
        return "vfat", _fat_label(data[43:54])
    if data[0x8001:0x8006] == b"CD001":
        return "iso9660", _text(data[0x8028:0x8048])
    if data[1024:1026] in (b"H+", b"HX"):
        return "hfsplus", ""
    if data[32:36] == b"NXSB":
        return "apfs", ""
    if data[4086:4096] in (b"SWAPSPACE2", b"SWAP-SPACE"):
        return "swap", ""
    return "", ""


def _fat_label(raw: bytes) -> str:
    label = raw.decode("ascii", "replace").strip()
    return "" if label.upper() == "NO NAME" else label


# -- containers ---------------------------------------------------------------------------


def _container(head: bytes, tail: bytes) -> tuple[str, str, int, int, str]:
    """``(kind, description, virtual_size, data_offset, note)`` or kind ""."""
    if head[:4] == b"QFI\xfb":
        version = struct.unpack_from(">I", head, 4)[0] if len(head) >= 8 else 0
        vsize = struct.unpack_from(">Q", head, 24)[0] if len(head) >= 32 else 0
        return ("qcow2", f"QEMU qcow2 v{version} disk image", vsize, 0,
                "Convert it to a raw image (qemu-img convert -O raw) or attach it with "
                "qemu-nbd to read its partitions.")
    if _u32(head, 0x40) == 0xBEDA107F:
        image_type = _u32(head, 0x4C)
        offset = _u32(head, 0x158)
        vsize = _u64(head, 0x170)
        kind_name = {1: "dynamic", 2: "fixed"}.get(image_type, f"type {image_type}")
        note = ("" if image_type == 2 else
                "A dynamic VDI keeps its blocks out of order: convert it "
                "(VBoxManage clonemedium --format RAW, or qemu-img convert) to read the partitions.")
        return "vdi", f"VirtualBox VDI disk image ({kind_name})", vsize, \
            offset if image_type == 2 else 0, note
    if head[:4] == b"KDMV" or head.startswith(b"# Disk DescriptorFile"):
        vsize = _u64(head, 12) * SECTOR if head[:4] == b"KDMV" else 0
        return ("vmdk", "VMware VMDK disk image", vsize, 0,
                "Convert it (qemu-img convert -O raw) to read its partitions; a flat VMDK's "
                "data file is a raw image of its own.")
    if head[:8] == b"vhdxfile":
        return "vhdx", "Hyper-V VHDX disk image", 0, 0, "Convert it (qemu-img convert -O raw) first."
    if head[:8] == b"conectix":
        return "vhd", "Virtual PC VHD disk image (dynamic)", 0, 0, \
            "Convert it (qemu-img convert -O raw) first."
    if head[:8] == b"EVF\x09\x0d\x0a\xff\x00":
        return "ewf", "EnCase E01 evidence file", 0, 0, \
            "Read it with ewfmount (libewf) or convert it with ewfexport first."
    if tail[:8] == b"conectix":
        vsize = struct.unpack_from(">Q", tail, 48)[0] if len(tail) >= 56 else 0
        # A fixed VHD is a raw disk with a 512-byte footer.
        return "raw", "Virtual PC VHD disk image (fixed)", vsize, 0, ""
    return "", "", 0, 0, ""


# -- partition tables ---------------------------------------------------------------------


def _mbr_entries(sector: bytes) -> list[tuple[int, int, int, int]] | None:
    """The four entries (status, type, lba, sectors) of a valid MBR/EBR."""
    if len(sector) < 512 or sector[510:512] != b"\x55\xaa":
        return None
    entries = []
    for i in range(4):
        status, ptype, lba, count = struct.unpack_from("<B3xB3xII", sector, 446 + 16 * i)
        if status not in (0x00, 0x80):
            return None
        entries.append((status, ptype, lba, count))
    return entries


def _guid(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw)).upper()


def _gpt(reader: _Reader, info: ImageInfo, base: int) -> list[Partition] | None:
    for sector in (512, 4096):
        header = reader.read(base + sector, 92)
        if header[:8] == b"EFI PART":
            break
    else:
        return None
    info.sector_size = sector
    entries_lba, count, entry_size = _u64(header, 72), _u32(header, 80), _u32(header, 84)
    if not 128 <= entry_size <= 4096 or entry_size % 8:
        info.warnings.append(f"GPT: an entry size of {entry_size} bytes is not usable")
        return []
    if count > MAX_GPT_ENTRIES:
        info.warnings.append(f"GPT: {count} entries claimed; the first {MAX_GPT_ENTRIES} are read")
        count = MAX_GPT_ENTRIES
    table = reader.read(base + entries_lba * sector, count * entry_size)
    parts = []
    for i in range(count):
        e = table[i * entry_size:(i + 1) * entry_size]
        if len(e) < 128 or e[:16] == b"\0" * 16:
            continue
        type_id = _guid(e[:16])
        first, last = _u64(e, 32), _u64(e, 40)
        if last < first:
            info.warnings.append(f"GPT entry {i + 1}: ends before it starts")
            continue
        name = e[56:128].decode("utf-16-le", "replace").split("\0", 1)[0]
        parts.append(_partition(reader, i + 1, base + first * sector, (last - first + 1) * sector,
                                "gpt", type_id, GPT_TYPES.get(type_id, "Unknown"), name=name))
    return parts


def _mbr(reader: _Reader, info: ImageInfo, entries, base: int) -> list[Partition]:
    parts = []
    extended = None
    for i, (status, ptype, lba, count) in enumerate(entries):
        if ptype == 0 or count == 0:
            continue
        if ptype in EXTENDED_TYPES:
            extended = (lba, count)
            continue
        parts.append(_partition(reader, i + 1, base + lba * SECTOR, count * SECTOR, "mbr",
                                f"0x{ptype:02x}", MBR_TYPES.get(ptype, "Unknown"),
                                bootable=status == 0x80))
    if extended is not None:
        parts.extend(_logical(reader, info, extended[0], base))
    return parts


def _logical(reader: _Reader, info: ImageInfo, ext_lba: int, base: int) -> list[Partition]:
    parts = []
    seen = set()
    ebr = ext_lba
    number = 5
    # Bounded by links, not partitions: a chain of empty links costs a read
    # each (a round trip on a remote image) and would run through the image.
    while True:
        if len(seen) >= MAX_LOGICAL:
            info.warnings.append(f"MBR: more than {MAX_LOGICAL} links of logical partitions; "
                                 "the rest is not read")
            break
        if ebr in seen:
            info.warnings.append("MBR: the chain of logical partitions loops; it ends here")
            break
        seen.add(ebr)
        entries = _mbr_entries(reader.read(base + ebr * SECTOR, 512))
        if entries is None:
            break
        status, ptype, lba, count = entries[0]
        if ptype and count:
            parts.append(_partition(reader, number, base + (ebr + lba) * SECTOR, count * SECTOR,
                                    "mbr", f"0x{ptype:02x}", MBR_TYPES.get(ptype, "Unknown"),
                                    bootable=status == 0x80))
            number += 1
        _s, next_type, next_lba, _c = entries[1]
        if next_type not in EXTENDED_TYPES:
            break
        ebr = ext_lba + next_lba
    return parts


def _partition(reader: _Reader, number, start, size, scheme, type_id, type_name, *,
               name="", bootable=False) -> Partition:
    fs, label = probe_filesystem(reader.read(start, PROBE_BYTES))
    return Partition(number=number, start=start, size=size, scheme=scheme, type_id=type_id,
                     type_name=type_name, name=name, bootable=bootable, filesystem=fs,
                     label=label, beyond_end=start + size > reader.size)


# -- entry points -------------------------------------------------------------------------


def inspect(fh, size: int) -> ImageInfo:
    """Read what the image in *fh* (a binary file, *size* bytes) holds."""
    info = ImageInfo(size=size)
    if size <= 0:
        return info
    reader = _Reader(fh, size)
    head = reader.read(0, PROBE_BYTES)
    tail = reader.read(size - 512, 512) if size >= 512 else b""
    kind, description, vsize, offset, note = _container(head, tail)
    if kind and kind != "raw":
        info.kind, info.description, info.virtual_size, info.note = kind, description, vsize, note
        if not offset:
            return info
        info.data_offset = offset
    else:
        info.kind = "raw"
        info.description = description or "Raw disk image"
        info.virtual_size = vsize
    base = info.data_offset
    if base:
        head = reader.read(base, PROBE_BYTES)
    fs, label = probe_filesystem(head)
    # A FAT / NTFS / exFAT boot sector ends in 55 AA like an MBR: no table.
    entries = None if fs in ("vfat", "ntfs", "exfat") else _mbr_entries(head[:512])
    if entries is not None and any(t == 0xEE for _s, t, _l, _c in entries):
        parts = _gpt(reader, info, base)
        if parts is not None:
            info.scheme, info.partitions = "gpt", parts
            return info
    if entries is not None and any(t for _s, t, _l, c in entries if c):
        info.scheme = "mbr"
        info.partitions = _mbr(reader, info, entries, base)
        info.partitions.sort(key=lambda p: p.number)
        return info
    if fs:
        info.scheme, info.filesystem, info.label = "none", fs, label
        info.partitions = [Partition(0, base, size - base, "none", filesystem=fs, label=label)]
        return info
    if info.kind == "raw" and not description:
        info.kind, info.description, info.scheme = "unknown", "", ""
    return info


def inspect_path(path: str) -> ImageInfo:
    """inspect() on a local file."""
    with open(path, "rb") as fh:
        return inspect(fh, os.fstat(fh.fileno()).st_size)


def inspect_backend(backend, path: str) -> ImageInfo:
    """inspect() through a backend (local or remote); a stream that cannot
    seek is read from its head only."""
    size = int(getattr(backend.stat(path), "size", 0) or 0)
    with backend.open_read(path) as fh:
        return inspect(fh if hasattr(fh, "read") else io.BytesIO(fh), size)


#: Container kind -> the MIME type shared-mime-info gives its extension, so
#: a correctly named container is no mismatch. EnCase has none registered.
CONTAINER_MIME = {
    "qcow2": "application/x-qemu-disk",
    "vdi": "application/x-vdi-disk",
    "vmdk": "application/x-vmdk-disk",
    "vhd": "application/x-vhd-disk",
    "vhdx": "application/x-vhdx-disk",
    "ewf": "application/octet-stream",
}
RAW_DISK_MIME = "application/x-raw-disk-image"
#: MIME types that name a disk image (core.file_type, Qt's database).
DISK_IMAGE_MIMES = frozenset(
    {m for m in CONTAINER_MIME.values() if m != "application/octet-stream"}
    | {RAW_DISK_MIME, "application/x-cd-image", "application/x-iso9660-image",
       "application/x-qemu-disk", "application/x-virtualbox-vdi",
       "application/x-virtualbox-vmdk", "application/x-virtualbox-vhd",
       "application/x-virtualbox-vhdx", "application/x-apple-diskimage"}
)


def detect_container(head: bytes) -> tuple[str, str]:
    """``(mime, description)`` when *head* starts a virtual disk container
    or a GPT disk, else ``("", "")`` - for core.file_type."""
    kind, description, vsize, _offset, _note = _container(head, b"")
    if kind and kind != "raw":
        return (CONTAINER_MIME.get(kind, "application/octet-stream"),
                description + (f", {human_size(vsize)}" if vsize else ""))
    if head[512:520] == b"EFI PART":
        return RAW_DISK_MIME, "Disk image (GPT partition table)"
    # An MBR with partitions, unless a file system starts at 0: a FAT / NTFS
    # boot sector also ends in 55 AA, and a hybrid ISO carries an MBR too.
    entries = _mbr_entries(head[:512])
    if entries and any(t and c for _s, t, _l, c in entries) and not probe_filesystem(head)[0]:
        return RAW_DISK_MIME, "Disk image (MBR partition table)"
    return "", ""
