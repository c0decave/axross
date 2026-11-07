"""Fetch a target system's packages, verified, and unpack them into a folder.

The bundles (scripts/build_bundle.sh) take the system libraries PyInstaller
bundles from the build machine. scripts/build_dist.sh builds each glibc
variant with ONLY its target system's libraries on the library path; this
script makes those folders without a container, root or a package manager:

    python scripts/sysroot_fetch.py debian12    OUT [--list FILE]
    python scripts/sysroot_fetch.py almalinux9  OUT [--list FILE]

The package names come from build/sysroot/<system>.txt (or --list); each is
taken in the newest version the repositories have. What is checked:

* Debian 12: InRelease of bookworm, bookworm-updates and bookworm-security
  with gpgv against the Debian archive keyrings of /usr/share/keyrings; only
  the text gpgv verified is read (its Suite or Codename must be the suite
  asked for, a Valid-Until must lie ahead); the SHA-256 of
  main/binary-amd64/Packages.xz from it; each .deb's SHA-256 from that index.
* AlmaLinux 9: repomd.xml of BaseOS, AppStream and CRB with gpgv against
  the AlmaLinux 9 key - a key file holding exactly one primary key, with the
  fingerprint pinned here (:data:`ALMA9_KEY`); the primary index's SHA-256
  from repomd.xml; each .rpm's SHA-256 from it.

Unpacking writes inside OUT/root only: no absolute names, no ".."; a
symlink on the way is followed as in a chroot of the root (so lib64 ->
usr/lib64 works and nothing leads outside); files keep their permission bits (binutils must run);
absolute symlinks are made relative to the root, so nothing in it points
at this machine's files. Everything is unpacked into OUT/root (no scripts
run, no owners set);
OUT/PACKAGES.txt lists "name version" of what was taken. The standard
library does all of it except gpgv (in every Debian image) and zstd-packed
RPMs (``pip install zstandard``).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEBIAN_SUITES = (("https://deb.debian.org/debian", "bookworm"),
                 ("https://deb.debian.org/debian", "bookworm-updates"),
                 ("https://security.debian.org/debian-security", "bookworm-security"))
DEBIAN_KEYRINGS = ("debian-archive-keyring.gpg", "debian-archive-bookworm-stable.gpg",
                   "debian-archive-bookworm-automatic.gpg",
                   "debian-archive-bookworm-security-automatic.gpg")
ALMA9_REPOS = tuple(f"https://repo.almalinux.org/almalinux/9/{repo}/x86_64/os"
                    for repo in ("BaseOS", "AppStream", "CRB"))
ALMA9_KEY_URL = "https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9"
#: The AlmaLinux OS 9 signing key (almalinux.org/security): a key with
#: another fingerprint stops the fetch.
ALMA9_KEY = "BF18AC2876178908D6E71267D36CB86CB86B3716"
USER_AGENT = "axross-sysroot-fetch"


def get(url: str, attempts: int = 4) -> bytes:
    import http.client
    import time

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return response.read()
        except (OSError, http.client.HTTPException) as exc:
            if attempt == attempts - 1:
                raise SystemExit(f"{url}: {exc}") from None
            time.sleep(2 * (attempt + 1))  # a dropped connection: again
    raise AssertionError("unreachable")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def gpgv(signed: Path, keyrings, *, detached_data: Path | None = None,
         output: Path | None = None) -> None:
    """Check a signature; with *output*, gpgv writes the signed text there
    (of a clearsigned file: only what the signature covers)."""
    args = ["gpgv"]
    for keyring in keyrings:
        args += ["--keyring", str(keyring)]
    if output is not None:
        if output.exists():
            output.unlink()
        args += ["--output", str(output)]
    args.append(str(signed))
    if detached_data is not None:
        args.append(str(detached_data))
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"bad signature on {signed.name}:\n{result.stderr}")


# -- Debian ---------------------------------------------------------------------------------

def _stanzas(text: str):
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        key = None
        for line in block.splitlines():
            if line[:1].isspace() and key:
                fields[key] += "\n" + line.strip()
            elif ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        if fields:
            yield fields


def debian_index(work: Path) -> dict[str, dict]:
    keyrings = [Path("/usr/share/keyrings") / k for k in DEBIAN_KEYRINGS
                if (Path("/usr/share/keyrings") / k).exists()]
    if not keyrings:
        raise SystemExit("no Debian archive keyring in /usr/share/keyrings")
    best: dict[str, dict] = {}
    for base, suite in DEBIAN_SUITES:
        signed = work / f"{suite}.InRelease"
        signed.write_bytes(get(f"{base}/dists/{suite}/InRelease"))
        verified = work / f"{suite}.Release"
        gpgv(signed, keyrings, output=verified)
        release = verified.read_text(encoding="utf-8")  # the signed part, nothing around it
        _check_release(release, suite)
        want = "main/binary-amd64/Packages.xz"
        match = re.search(r"^SHA256:\n((?: .*\n)+)", release, re.M)
        sums = {line.split()[2]: line.split()[0] for line in match.group(1).splitlines()} \
            if match else {}
        data = get(f"{base}/dists/{suite}/{want}")
        if sums.get(want) != sha256(data):
            raise SystemExit(f"{suite}: {want} does not match its InRelease")
        for fields in _stanzas(lzma.decompress(data).decode("utf-8")):
            name = fields.get("Package")
            if not name:
                continue
            fields["_url"] = f"{base}/{fields['Filename']}"
            source = fields.get("Source", "") or name
            m = re.fullmatch(r"(\S+)(?:\s+\((\S+)\))?", source.strip())
            fields["_source"] = m.group(1) if m else name
            fields["_source_version"] = (m.group(2) if m and m.group(2) else fields["Version"])
            if name not in best or _deb_newer(fields["Version"], best[name]["Version"]):
                best[name] = fields
    return best


def _check_release(release: str, suite: str) -> None:
    """The verified Release is the suite asked for and not expired: no
    other suite's or an old signed file passed off as this one."""
    from email.utils import parsedate_to_datetime
    import datetime

    fields = next(_stanzas(release), {})
    if suite not in (fields.get("Suite"), fields.get("Codename")):
        raise SystemExit(f"{suite}: the signed Release is for "
                         f"{fields.get('Codename') or fields.get('Suite')!r}")
    until = fields.get("Valid-Until")
    if until:
        if parsedate_to_datetime(until) < datetime.datetime.now(datetime.timezone.utc):
            raise SystemExit(f"{suite}: the signed Release expired on {until}")


def _deb_newer(a: str, b: str) -> bool:
    return subprocess.run(["dpkg", "--compare-versions", a, "gt", b]).returncode == 0


def _member_name(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def _resolve_inside(dest: Path, parts: list[str], hops: int = 0) -> Path | None:
    """The folder *parts* names under *dest*, with every symlink on the way
    resolved as inside a chroot of *dest* (an absolute target counts from
    *dest*); None when the way leaves *dest* or loops."""
    here = dest
    for n, part in enumerate(parts):
        nxt = here / part
        if nxt.is_symlink():
            if hops > 32:
                return None
            link = os.readlink(nxt)
            base = [] if link.startswith("/") else list(here.relative_to(dest).parts)
            rest = [p for p in link.split("/") if p not in ("", ".")]
            joined: list[str] = []
            for p in base + rest:
                if p == "..":
                    if not joined:
                        return None  # above the root
                    joined.pop()
                else:
                    joined.append(p)
            resolved = _resolve_inside(dest, joined, hops + 1)
            if resolved is None:
                return None
            nxt = resolved
        here = nxt
    return here


def safe_target(dest: Path, name: str) -> Path | None:
    """Where archive member *name* goes under *dest*, or None when it would
    leave it: an absolute name or a ".." part is refused; a symlink on the
    way (lib64 -> usr/lib64 of a usrmerged system) is followed as in a
    chroot of *dest*, so it can never lead outside."""
    name = _member_name(name)
    if not name or name.startswith("/") or "\\" in name:
        return None
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    folder = _resolve_inside(dest, parts[:-1])
    if folder is None:
        return None
    return folder / parts[-1]


def _replace(target: Path) -> None:
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        target.unlink()


def _write_file(target: Path, data: bytes, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    _replace(target)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(target, (mode & 0o755) | 0o600)  # its x bits (binutils run), never set-id


def unpack_deb(path: Path, dest: Path) -> None:
    """A .deb's data.tar.* into *dest*: regular files with their permission
    bits, folders, symlinks, hard links as copies; devices and anything that
    would leave *dest* are skipped."""
    tar = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(path)], capture_output=True,
                         check=True).stdout
    with tempfile.TemporaryFile() as tmp:
        tmp.write(tar)
        tmp.seek(0)
        with tarfile.open(fileobj=tmp) as archive:
            for member in archive.getmembers():
                target = safe_target(dest, member.name)
                if target is None:
                    continue
                if member.isdir():
                    if target.is_symlink():
                        continue
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isreg():
                    data = archive.extractfile(member).read()
                    _write_file(target, data, member.mode)
                elif member.issym():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    _replace(target)
                    os.symlink(member.linkname, target)
                elif member.islnk():
                    source = safe_target(dest, member.linkname)
                    if source is not None and source.is_file() and not source.is_symlink():
                        _write_file(target, source.read_bytes(), source.stat().st_mode)


def relink_absolute(root: Path) -> int:
    """Absolute symlinks under *root* (libfoo.so -> /lib/x86_64-linux-gnu/...)
    point into *root* instead, relatively; the number changed."""
    changed = 0
    for folder, dirs, files in os.walk(root):
        for name in dirs + files:
            link = Path(folder) / name
            if not link.is_symlink():
                continue
            target = os.readlink(link)
            if not target.startswith("/"):
                continue
            inside = root / target.lstrip("/")
            link.unlink()
            os.symlink(os.path.relpath(inside, link.parent), link)
            changed += 1
    return changed


# -- AlmaLinux ------------------------------------------------------------------------------

def _dearmor(armored: str) -> bytes:
    body = armored.split("\n\n", 1)[1].split("-----END", 1)[0]
    lines = [line for line in body.strip().splitlines() if not line.startswith("=")]
    return base64.b64decode("".join(lines))


def packets(data: bytes):
    """(tag, body) of each OpenPGP packet in *data* (RFC 4880 4.2)."""
    i = 0
    while i < len(data):
        head = data[i]
        if not head & 0x80:
            raise SystemExit("not an OpenPGP key")
        if head & 0x40:  # new format
            tag = head & 0x3F
            first = data[i + 1]
            if first < 192:
                length, start = first, i + 2
            elif first < 224:
                length, start = ((first - 192) << 8) + data[i + 2] + 192, i + 3
            elif first == 255:
                length, start = struct.unpack(">I", data[i + 2:i + 6])[0], i + 6
            else:
                raise SystemExit("partial-length OpenPGP packets are not expected in a key")
        else:
            tag = (head >> 2) & 0x0F
            size = {0: 1, 1: 2, 2: 4}.get(head & 0x03)
            if size is None:
                raise SystemExit("indeterminate-length OpenPGP packet in a key")
            length = int.from_bytes(data[i + 1:i + 1 + size], "big")
            start = i + 1 + size
        if start + length > len(data):
            raise SystemExit("truncated OpenPGP key")
        yield tag, data[start:start + length]
        i = start + length


def _fingerprint(body: bytes) -> str:
    """The V4 fingerprint of a public-key packet body."""
    return hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).hexdigest().upper()


def pinned_key(key: bytes, fingerprint: str) -> bytes:
    """*key* when it holds exactly one primary key and that has *fingerprint*:
    a file with a second primary key appended would make gpgv trust it too."""
    primaries = [body for tag, body in packets(key) if tag == 6]
    if len(primaries) != 1:
        raise SystemExit(f"the key file holds {len(primaries)} primary keys, not 1")
    found = _fingerprint(primaries[0])
    if found != fingerprint:
        raise SystemExit(f"the key has fingerprint {found}, not {fingerprint}")
    return key


def alma_index(work: Path) -> dict[str, dict]:
    key = pinned_key(_dearmor(get(ALMA9_KEY_URL).decode("ascii")), ALMA9_KEY)
    keyring = work / "almalinux9.gpg"
    keyring.write_bytes(key)
    ns = {"r": "http://linux.duke.edu/metadata/repo", "c": "http://linux.duke.edu/metadata/common",
          "rpm": "http://linux.duke.edu/metadata/rpm"}
    best: dict[str, dict] = {}
    for n, base in enumerate(ALMA9_REPOS):
        repomd = work / f"repomd{n}.xml"
        repomd.write_bytes(get(f"{base}/repodata/repomd.xml"))
        signature = work / f"repomd{n}.xml.asc"
        signature.write_bytes(get(f"{base}/repodata/repomd.xml.asc"))
        gpgv(signature, [keyring], detached_data=repomd)
        primary = ET.parse(repomd).getroot().find("r:data[@type='primary']", ns)
        href = primary.find("r:location", ns).get("href")
        data = get(f"{base}/{href}")
        if sha256(data) != primary.find("r:checksum", ns).text:
            raise SystemExit(f"{base}: the primary index does not match repomd.xml")
        # AppStream's index is ~1 GB of XML unpacked: read it as a stream, one
        # package at a time, instead of a tree in memory
        package_tag = "{%s}package" % ns["c"]
        for _event, pkg in ET.iterparse(_stream(data), events=("end",)):
            if pkg.tag != package_tag:
                continue
            arch = pkg.find("c:arch", ns).text
            if arch not in ("x86_64", "noarch"):
                pkg.clear()
                continue
            name = pkg.find("c:name", ns).text
            v = pkg.find("c:version", ns)
            srpm = pkg.find("c:format/rpm:sourcerpm", ns)
            src_name, src_version = name, f"{v.get('ver')}-{v.get('rel')}"
            if srpm is not None and srpm.text:
                m = re.fullmatch(r"(.+)-([^-]+)-([^-]+)\.src\.rpm", srpm.text)
                if m:
                    src_name, src_version = m.group(1), f"{m.group(2)}-{m.group(3)}"
            entry = {"Version": f"{v.get('ver')}-{v.get('rel')}",
                     "_source": src_name, "_source_version": src_version,
                     "_evr": (int(v.get("epoch") or 0), v.get("ver"), v.get("rel")),
                     "SHA256": pkg.find("c:checksum", ns).text,
                     "_url": f"{base}/{pkg.find('c:location', ns).get('href')}"}
            if name not in best or _rpm_newer(entry["_evr"], best[name]["_evr"]):
                best[name] = entry
            pkg.clear()
    return best


def rpmvercmp(a: str, b: str) -> int:
    """rpm's version comparison (rpmio/rpmvercmp.c): -1, 0 or 1. Numbers
    beat letters, "~" sorts before anything (1.0~rc1 < 1.0), "^" after the
    end (1.0^1 > 1.0)."""
    if a == b:
        return 0

    def alnum(c: str) -> bool:
        return c.isascii() and c.isalnum()

    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not alnum(b[j]) and b[j] not in "~^":
            j += 1
        ta, tb = (a[i] if i < len(a) else ""), (b[j] if j < len(b) else "")
        if ta == "~" or tb == "~":
            if ta != "~":
                return 1
            if tb != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if ta == "^" or tb == "^":
            if not ta:
                return -1
            if not tb:
                return 1
            if ta != "^":
                return 1
            if tb != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if not ta or not tb:
            break
        digits = ta.isdigit()
        si, sj = i, j
        test = (lambda c: c.isascii() and c.isdigit()) if digits else \
            (lambda c: c.isascii() and c.isalpha())
        while i < len(a) and test(a[i]):
            i += 1
        while j < len(b) and test(b[j]):
            j += 1
        sa, sb = a[si:i], b[sj:j]
        if not sb:  # a number against letters: the number is newer
            return 1 if digits else -1
        if digits:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _rpm_newer(a, b) -> bool:
    """Epoch, then version, then release (each by rpmvercmp)."""
    if a[0] != b[0]:
        return a[0] > b[0]
    for x, y in ((a[1], b[1]), (a[2], b[2])):
        result = rpmvercmp(x, y)
        if result:
            return result > 0
    return False


def _stream(data: bytes):
    """A file object reading *data* decompressed (gzip, xz, zstd or plain)."""
    import io

    raw = io.BytesIO(data)
    if data[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=raw)
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(raw)
    if data[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard
        except ImportError:
            raise SystemExit("a zstd-packed file: pip install zstandard") from None
        return zstandard.ZstdDecompressor().stream_reader(raw)
    return raw


def _decompress(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(data)
    if data[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard
        except ImportError:
            raise SystemExit("a zstd-packed file: pip install zstandard") from None
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    return data


def unpack_rpm(path: Path, dest: Path) -> None:
    """An .rpm's payload (cpio newc) into *dest*."""
    data = path.read_bytes()
    offset = 96  # the lead
    for padded in (True, False):  # the signature header, then the header
        if data[offset:offset + 3] != b"\x8e\xad\xe8":
            raise ValueError(f"{path.name}: not an rpm header")
        count, size = struct.unpack(">II", data[offset + 8:offset + 16])
        offset += 16 + count * 16 + size
        if padded:
            offset += (-offset) % 8
    cpio = _decompress(data[offset:])
    pending: dict[tuple, tuple[list[Path], int]] = {}  # hard links waiting for their data
    i = 0
    while i + 110 <= len(cpio):
        if cpio[i:i + 6] not in (b"070701", b"070702"):
            raise ValueError(f"{path.name}: bad cpio header")
        fields = [int(cpio[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        ino, mode, nlink, filesize, dev_major, dev_minor, namesize = (
            fields[0], fields[1], fields[4], fields[6], fields[7], fields[8], fields[11])
        name = cpio[i + 110:i + 110 + namesize - 1].decode("utf-8", "surrogateescape")
        i = i + 110 + namesize
        i += (-i) % 4
        body = cpio[i:i + filesize]
        i += filesize
        i += (-i) % 4
        if name == "TRAILER!!!":
            break
        target = safe_target(dest, name)
        if target is None:
            continue
        kind = stat.S_IFMT(mode)
        if kind == stat.S_IFDIR:
            if not target.is_symlink():
                target.mkdir(parents=True, exist_ok=True)
        elif kind == stat.S_IFLNK:
            target.parent.mkdir(parents=True, exist_ok=True)
            _replace(target)
            os.symlink(body.decode("utf-8", "surrogateescape"), target)
        elif kind == stat.S_IFREG:
            key = (dev_major, dev_minor, ino)
            names = pending.pop(key, ([], mode))[0] + [target]
            if filesize or nlink <= 1:
                for t in names:  # newc carries a hard link's data with its last name
                    _write_file(t, body, mode)
            else:
                pending[key] = (names, mode)
    for names, mode in pending.values():  # hard links of an empty file
        for t in names:
            _write_file(t, b"", mode)


# -- main -----------------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] not in ("debian12", "almalinux9"):
        print(__doc__)
        return 2
    system, out = argv[1], Path(argv[2]).resolve()
    listing = Path(argv[argv.index("--list") + 1]) if "--list" in argv else \
        ROOT / "build" / "sysroot" / f"{system}.txt"
    names = [line.split()[0] for line in listing.read_text().splitlines()
             if line.strip() and not line.startswith("#")]
    work = out / "meta"
    packages = out / "packages"
    root = out / "root"
    for folder in (work, packages):
        folder.mkdir(parents=True, exist_ok=True)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    index = debian_index(work) if system == "debian12" else alma_index(work)
    missing = [n for n in names if n not in index]
    if missing:
        raise SystemExit(f"not in the repositories: {' '.join(missing)}")
    taken, records = [], []
    for name in names:
        entry = index[name]
        dest = packages / entry["_url"].rsplit("/", 1)[1]
        if not dest.exists() or sha256(dest.read_bytes()) != entry["SHA256"]:
            data = get(entry["_url"])
            if sha256(data) != entry["SHA256"]:
                raise SystemExit(f"{name}: the package does not match its index")
            dest.write_bytes(data)
        (unpack_deb if system == "debian12" else unpack_rpm)(dest, root)
        taken.append(f"{name} {entry['Version']}")
        # RPM versions with their epoch ("1:3.5.8-2.el9_8"), as OSV compares them
        epoch = entry.get("_evr", (0,))[0] if system == "almalinux9" else 0
        full = f"{epoch}:{entry['Version']}" if epoch else entry["Version"]
        src_full = f"{epoch}:{entry.get('_source_version', entry['Version'])}" if epoch else \
            entry.get("_source_version", entry["Version"])
        records.append({"name": name, "version": full, "source": entry.get("_source", name),
                        "source_version": src_full,
                        "sha256": entry["SHA256"], "file": dest.name})
    relink_absolute(root)
    (out / "PACKAGES.txt").write_text("\n".join(taken) + "\n")
    # for the supply-chain gate (security/supply_chain_gate.py check-system)
    ecosystem = "Debian:12" if system == "debian12" else "AlmaLinux:9"
    (out / "PACKAGES.json").write_text(json.dumps({"system": system, "ecosystem": ecosystem,
                                                   "packages": records}, indent=1) + "\n")
    print(f"{system}: {len(taken)} packages verified and unpacked into {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
