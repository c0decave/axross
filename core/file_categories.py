"""File categories: the type presets of Find Files.

"Find all my crypto wallets", "all my pictures", "every disk image of a
computer" - each preset is a :class:`Category` that decides by

1. the **name**: extensions, exact names and name globs;
2. the **path**: folders a program keeps its files in (an Electrum
   ``wallets`` folder, a browser extension's storage folder named by the
   extension's id);
3. the **content**, only for files whose extension no category claims
   (``blob``, ``wallet.dat``, ``UTC--...`` without ``.json``): a few
   magic bytes or markers in the first bytes of a local file. A file
   called ``notes.txt`` is never opened to look for image magic - that
   would read the head of every file in the tree.

``sift.detect`` (the optional ``sift`` package, ``axross[sift]``)
adds its kinds for local files when it is importable; the table here
works without it.

Which part belongs where: recognising what a file IS (magic, markers)
is sift's job in the long run - :func:`classify_content` is the piece to
move there. The presets, their labels and which kinds make up "Crypto
wallets" for a search are axross' (this table and the Find Files
dialog).

Nothing here looks for secrets inside files (passwords, API keys, seed
phrases): the categories name file *types*.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import stat as stat_module
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

#: Bytes the content rules read at most (wallet databases keep their
#: markers in the first pages).
MAX_HEAD_BYTES = 64 * 1024
#: What every content rule except ISO / UDF and the wallet markers needs.
_BASE_HEAD_BYTES = 4096
#: ISO 9660 / UDF volume descriptors start at sector 16.
_ISO_OFFSET = 0x8001
#: A raw disk / partition image is at least this big.
_MIN_RAW_DISK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Category:
    """One preset. Names are compared lower-case."""

    id: str
    label: str
    description: str
    extensions: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    globs: tuple[str, ...] = ()
    #: ``(ancestors, parent, extensions)``: every folder name in
    #: *ancestors* is somewhere on the path, the file's own folder is
    #: *parent* (``""`` = any) and its extension is in *extensions*
    #: (empty = any).
    path_rules: tuple[tuple[tuple[str, ...], str, tuple[str, ...]], ...] = ()
    #: Folder names that put every file below them in the category
    #: (browser extension ids, ``exodus.wallet``).
    folder_markers: frozenset[str] = field(default_factory=frozenset)


def _exts(*items: str) -> frozenset[str]:
    return frozenset("." + item.lstrip(".") for item in items)


# Browser extension ids of wallet extensions (Chrome / Brave / Edge store an
# extension's data in a folder named by its id).
_WALLET_EXTENSION_IDS = frozenset(
    {
        "nkbihfbeogaeaoehlefnkodbefgpgknn",  # MetaMask
        "ejbalbakoplchlghecdalmeeeajnimhm",  # MetaMask (Edge)
        "bfnaelmomeimhlpmgjnjophhpkkoljpa",  # Phantom
        "hnfanknocfeofbddgcijnmhnfnkdnaad",  # Coinbase Wallet
        "fhbohimaelbohpjbbldcngcnapndodjp",  # Binance Wallet
        "ibnejdfjmmkpcnlpebklmnkoeoihofec",  # TronLink
        "fnjhmkhhmkbjkkabndcnnogagogbneec",  # Ronin
        "dmkamcknogkgcdfhhbddcghachkejeap",  # Keplr
        "acmacodkjbdgmoleebolmdjonilkdbch",  # Rabby
        "egjidjbpglichdcondbcbdnbeeppgdph",  # Trust Wallet
        "mcohilncbfahbmgdjkbpemcciiolgcge",  # OKX Wallet
        "aholpfdialjgjfhomihkjbmgjidlcdno",  # Exodus Web3
        "webextension@metamask.io",  # MetaMask (Firefox)
    }
)

_ELECTRUM_HOMES = (".electrum", "electrum", ".electrum-ltc", "electrum-ltc", ".electron-cash",
                   "electroncash")

CATEGORIES: dict[str, Category] = {
    c.id: c
    for c in (
        Category(
            "images",
            "Images",
            "Photos and pictures: JPEG, PNG, GIF, HEIC, RAW camera files, PSD, SVG ...",
            _exts("jpg", "jpeg", "jpe", "png", "gif", "bmp", "tif", "tiff", "webp", "heic",
                  "heif", "avif", "ico", "svg", "psd", "xcf", "jxl", "jp2", "tga", "exr", "hdr",
                  "cr2", "cr3", "nef", "arw", "dng", "orf", "rw2", "raf", "srw", "pef"),
        ),
        Category(
            "videos",
            "Videos",
            "Films and clips: MP4, MKV, WebM, AVI, MOV, MPEG, ...",
            _exts("mp4", "m4v", "mkv", "webm", "avi", "mov", "wmv", "flv", "f4v", "mpg",
                  "mpeg", "m2v", "mts", "m2ts", "vob", "ogv", "3gp", "3g2", "rm", "rmvb", "asf",
                  "divx"),
        ),
        Category(
            "audio",
            "Audio",
            "Music and recordings: MP3, FLAC, WAV, Ogg, Opus, M4A, ...",
            _exts("mp3", "flac", "wav", "ogg", "oga", "opus", "m4a", "m4b", "aac", "wma",
                  "aif", "aiff", "alac", "ape", "mid", "midi", "amr", "wv", "mka", "dsf"),
        ),
        Category(
            "documents",
            "Documents",
            "PDF, Office and OpenDocument files, e-books and text documents",
            _exts("pdf", "doc", "docx", "docm", "dot", "dotx", "odt", "ott", "rtf", "txt",
                  "md", "markdown", "rst", "tex", "xls", "xlsx", "xlsm", "ods", "csv", "ppt",
                  "pptx", "pps", "ppsx", "odp", "epub", "mobi", "azw3", "djvu", "pages",
                  "numbers", "xps", "oxps", "one", "wpd"),
        ),
        Category(
            "archives",
            "Archives",
            "ZIP, tar, gzip / bzip2 / xz / zstd, 7z, RAR, cab, packages ...",
            _exts("zip", "tar", "gz", "tgz", "bz2", "tbz", "tbz2", "xz", "txz", "zst", "tzst",
                  "7z", "rar", "cab", "cpio", "lz", "lzma", "lz4", "z", "arj", "ace", "jar",
                  "war", "apk", "deb", "rpm", "xpi", "tar.gz", "tar.bz2", "tar.xz", "tar.zst",
                  "tar.lz", "tar.lzma"),
        ),
        Category(
            "disk_images",
            "Disk && VM images",
            "Disk, partition and virtual machine images: dd / raw / img, ISO, qcow2, VDI, "
            "VMDK, VHD(X), E01 / AFF evidence files, DMG, LUKS volumes ...",
            _exts("img", "raw", "dd", "iso", "qcow", "qcow2", "qed", "vdi", "vmdk", "vhd",
                  "vhdx", "avhd", "avhdx", "hdd", "hds", "e01", "ex01", "l01", "lx01", "s01",
                  "aff", "aff4", "ad1", "dmg", "sparseimage", "toast", "nrg", "mdf", "wim",
                  "ova", "vfd"),
            globs=("*.e[0-9][0-9]",),
        ),
        Category(
            "crypto_wallets",
            "Crypto wallets",
            "Wallet files of Bitcoin Core / Litecoin / Dogecoin (wallet.dat), Electrum, "
            "Ethereum keystores (UTC--...), Exodus, Monero, MultiBit / Armory / Coinomi, "
            "Wasabi, Atomic, Ledger Live and browser wallets (MetaMask, Phantom, ...)",
            _exts("wallet", "seco"),
            names=frozenset({"wallet.dat", "default_wallet", "wallet.aes.json", "electrum.dat"}),
            globs=("utc--*--*", "wallet*.dat", "wallet.dat.*", "*.wallet.aes"),
            path_rules=(
                *(((home,), "wallets", ()) for home in _ELECTRUM_HOMES),
                (("monero",), "", (".keys",)),
                ((".bitmonero",), "", (".keys",)),
                ((".ethereum",), "keystore", ()),
                (("ethereum",), "keystore", ()),
                (("walletwasabi", "client"), "wallets", (".json",)),
                (("atomic", "local storage"), "leveldb", ()),
                (("coinomi",), "wallets", ()),
                (("ledger live",), "", (".json",)),
                (("com.liberty.jaxx",), "", ()),
            ),
            folder_markers=_WALLET_EXTENSION_IDS | {"exodus.wallet"},
        ),
        Category(
            "keys_certs",
            "Keys && certificates",
            "Private keys, certificates and key stores: PEM / DER, PKCS#12 (.p12 / .pfx), "
            "Java key stores, SSH and PuTTY keys, KeePass databases, PGP keys",
            _exts("pem", "crt", "cer", "der", "csr", "p7b", "p7c", "p7s", "p12", "pfx", "jks",
                  "keystore", "jceks", "kdbx", "kdb", "ppk", "gpg", "pgp", "asc"),
            names=frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk",
                             "id_ed25519_sk", "identity"}),
        ),
        Category(
            "source_code",
            "Source code",
            "Programs and scripts: Python, C / C++, Java, Go, Rust, JavaScript, shell, ...",
            _exts("py", "pyw", "js", "mjs", "cjs", "ts", "tsx", "jsx", "java", "kt", "kts",
                  "c", "h", "cpp", "cc", "cxx", "hpp", "hh", "cs", "go", "rs", "rb", "php",
                  "swift", "scala", "sql", "sh", "bash", "zsh", "fish", "ps1", "psm1", "bat",
                  "cmd", "lua", "pl", "pm", "r", "m", "mm", "vue", "svelte", "html", "htm",
                  "css", "scss", "sass", "less", "dart", "ex", "exs", "erl", "hs", "ml", "clj",
                  "groovy", "gradle", "cmake", "asm", "s"),
            names=frozenset({"makefile", "gnumakefile", "dockerfile", "containerfile",
                             "cmakelists.txt", "rakefile", "gemfile", "vagrantfile",
                             "jenkinsfile", "justfile"}),
        ),
        Category(
            "email",
            "Email",
            "Mails and mailboxes: EML, MSG, mbox, Outlook PST / OST",
            _exts("eml", "emlx", "msg", "mbox", "mbx", "pst", "ost"),
        ),
        Category(
            "databases",
            "Databases",
            "SQLite, Access, dBASE and MySQL table files",
            _exts("sqlite", "sqlite3", "db", "db3", "s3db", "sdb", "mdb", "accdb", "dbf",
                  "frm", "ibd", "myd", "myi", "realm"),
        ),
    )
}

#: Extensions several categories could mean: decided by content only
#: (``server.key`` is a private key, ``talk.key`` a Keynote slide deck).
_AMBIGUOUS_EXTENSIONS = frozenset({".key"})

#: Compound extensions, longest first.
_COMPOUND = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lzma", ".tar.lz")

_KNOWN_EXTENSIONS = frozenset().union(*(c.extensions for c in CATEGORIES.values()))

#: sift.detect kinds -> categories.
_SIFT_KINDS = {
    "image": "images",
    "pdf": "documents",
    "docx": "documents",
    "odt": "documents",
    "rtf": "documents",
    "xlsx": "documents",
    "pptx": "documents",
    "ods": "documents",
    "odp": "documents",
    "epub": "documents",
    "office-legacy": "documents",
    "markdown": "documents",
    "archive": "archives",
    "sqlite": "databases",
    "email": "email",
    "source-code": "source_code",
    "shell": "source_code",
    "batch": "source_code",
    "powershell": "source_code",
}


def category_ids() -> list[str]:
    """Every category id, in display order."""
    return list(CATEGORIES)


def label(category_id: str) -> str:
    """The display label (``&&`` is a literal ampersand in a Qt label)."""
    cat = CATEGORIES.get(category_id)
    return cat.label.replace("&&", "&") if cat is not None else ""


def validate_categories(categories) -> tuple[str, ...]:
    """The ids as a tuple; ``ValueError`` for an unknown one or a non-list."""
    if isinstance(categories, (str, bytes)) or not isinstance(categories, (list, tuple, set,
                                                                             frozenset)):
        raise ValueError("categories must be a list of category ids")
    out: list[str] = []
    for cid in categories:
        if not isinstance(cid, str) or cid not in CATEGORIES:
            raise ValueError(f"unknown file category: {cid!r}")
        if cid not in out:
            out.append(cid)
    return tuple(out)


def extension_of(name: str) -> str:
    """Lower-case extension with the dot, compound tar extensions whole;
    ``""`` for none (a dot file like ``.bashrc`` has none)."""
    lower = name.lower()
    for ext in _COMPOUND:
        if lower.endswith(ext) and len(lower) > len(ext):
            return ext
    base, ext = os.path.splitext(lower)
    return ext if base else ""


def _components(path: str) -> list[str]:
    return [part for part in re.split(r"[\\/]+", path.lower()) if part]


def classify_name(name: str, path: str = "") -> set[str]:
    """Categories that *name* (and the folders of *path*, when given)
    put the file in. Never touches the file."""
    lower = name.lower()
    ext = extension_of(name)
    parts = _components(path)
    if parts and parts[-1] == lower:
        folders = parts[:-1]
    else:
        folders = parts
    parent = folders[-1] if folders else ""
    folder_set = set(folders)
    out: set[str] = set()
    for cat in CATEGORIES.values():
        if (
            (ext in cat.extensions and ext not in _AMBIGUOUS_EXTENSIONS)
            or lower in cat.names
            or any(fnmatch.fnmatchcase(lower, pattern) for pattern in cat.globs)
            or (cat.folder_markers and folder_set & cat.folder_markers)
        ):
            out.add(cat.id)
            continue
        for ancestors, wanted_parent, exts in cat.path_rules:
            if wanted_parent and parent != wanted_parent:
                continue
            if exts and ext not in exts:
                continue
            if all(a in folder_set for a in ancestors):
                out.add(cat.id)
                break
    return out


def needs_sniff(name: str) -> bool:
    """Whether the content may tell more than the name: true when no
    category claims the extension (or it is ambiguous)."""
    ext = extension_of(name)
    return ext in _AMBIGUOUS_EXTENSIONS or ext not in _KNOWN_EXTENSIONS


def head_bytes_needed(wanted=None) -> int:
    """How many leading bytes :func:`classify_content` needs for *wanted*
    (``None`` / empty = every category)."""
    wanted = set(wanted or CATEGORIES)
    need = _BASE_HEAD_BYTES
    if "disk_images" in wanted:
        need = max(need, _ISO_OFFSET + 5)
    if "crypto_wallets" in wanted:
        need = MAX_HEAD_BYTES
    return need


_PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----")
_HEADER_LINE_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9-]{1,40}: ")
_BDB_MAGIC = (b"\x62\x31\x05\x00", b"\x00\x05\x31\x62")
_WALLET_DB_MARKERS = (b"defaultkey", b"mkey", b"ckey", b"keymeta", b"bestblock", b"minversion",
                      b"hdchain", b"walletdescriptor")
_IMAGE_BRANDS = (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis")
_AUDIO_BRANDS = (b"M4A ", b"M4B ", b"M4P ")


def _media_kind(head: bytes) -> str:
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in _IMAGE_BRANDS:
            return "images"
        if brand in _AUDIO_BRANDS:
            return "audio"
        return "videos"
    if head[:4] == b"RIFF" and len(head) >= 12:
        return {b"WEBP": "images", b"WAVE": "audio", b"AVI ": "videos"}.get(head[8:12], "")
    if head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"):
        return "audio"
    return ""


def _is_raw_disk(head: bytes, size: int) -> bool:
    if size < _MIN_RAW_DISK_BYTES or size % 512:
        return False
    if head[512:520] == b"EFI PART" or head[512:520] == b"LABELONE":
        return True
    if head[3:11] == b"NTFS    " or head[1080:1082] == b"\x53\xef":
        return True
    if head[:4] == b"XFSB":
        return True
    if head[510:512] != b"\x55\xaa":
        return False
    if head[82:87] == b"FAT32" or head[54:59] in (b"FAT16", b"FAT12"):
        return True
    for entry in range(4):
        start = 446 + entry * 16
        status, kind = head[start], head[start + 4]
        if kind and status in (0x00, 0x80):
            return True
    return False


def classify_content(head: bytes, name: str = "", size: int = -1) -> set[str]:
    """Categories the first bytes *head* of a file show. *size* is the
    whole file's (``-1`` unknown: the raw-disk rule then stays silent)."""
    out: set[str] = set()
    if not head:
        return out
    if size < 0:
        size = len(head)
    start = head[:16]
    # Images
    if (start.startswith(b"\x89PNG\r\n\x1a\n") or start[:3] == b"\xff\xd8\xff"
            or start[:6] in (b"GIF87a", b"GIF89a") or start[:4] in (b"II*\x00", b"MM\x00*")
            or start[:4] == b"8BPS"):
        out.add("images")
    media = _media_kind(head)
    if media:
        out.add(media)
    # Video / audio containers
    if start[:4] == b"\x1a\x45\xdf\xa3" or start[:4] == b"FLV\x01" or start[:4] == b"\0\0\x01\xba":
        out.add("videos")
    if start[:16] == b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c":
        out.add("videos")
    if (start[:3] == b"ID3" or start[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")
            or start[:4] in (b"fLaC", b"OggS", b"MThd")):
        out.add("audio")
    # Documents
    if start[:5] == b"%PDF-" or start[:5] == b"{\\rtf" or start[:4] == b"\xd0\xcf\x11\xe0":
        out.add("documents")
    # Archives
    if (start[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"MSCF", b"\x28\xb5\x2f\xfd", b"LZIP",
                      b"\x04\x22\x4d\x18")
            or start[:2] == b"\x1f\x8b" or start[:3] == b"BZh" or start[:6] == b"\xfd7zXZ\x00"
            or start[:6] == b"7z\xbc\xaf\x27\x1c" or start[:4] == b"Rar!"
            or start[:6] == b"070701" or head[257:262] == b"ustar"):
        out.add("archives")
    # Disk and VM images
    if (start[:4] in (b"QFI\xfb", b"KDMV") or start[:8] in (b"vhdxfile", b"conectix")
            or start.startswith(b"EVF\x09\x0d\x0a\xff\x00") or start.startswith(b"EVF2\r\n\x81")
            or start.startswith(b"LVF\x09\x0d\x0a\xff\x00") or start[:6] == b"LUKS\xba\xbe"
            or head.startswith(b"# Disk DescriptorFile")
            or head[0x40:0x44] == b"\x7f\x10\xda\xbe"
            or head[_ISO_OFFSET:_ISO_OFFSET + 5] in (b"CD001", b"BEA01", b"NSR02", b"NSR03")
            or _is_raw_disk(head, size)):
        out.add("disk_images")
    # Crypto wallets
    lowered = head.lower()
    stripped = head.lstrip()
    if b'"crypto"' in lowered and b'"ciphertext"' in lowered and b'"kdf"' in lowered:
        out.add("crypto_wallets")
    if stripped.startswith(b"{") and b'"seed_version"' in head:
        out.add("crypto_wallets")
    if start.startswith(b"QklFMQ") or start[:4] == b"SECO":
        out.add("crypto_wallets")
    if head[12:16] in _BDB_MAGIC and any(m in head for m in _WALLET_DB_MARKERS):
        out.add("crypto_wallets")
    if (b'"keymetadata"' in lowered and b'"salt"' in lowered and b'"data"' in lowered
            and b'"iv"' in lowered):
        out.add("crypto_wallets")
    # Keys and certificates
    pem = _PEM_RE.search(head[:_BASE_HEAD_BYTES])
    if pem is not None:
        kind = pem.group(1)
        if b"PRIVATE KEY" in kind or b"CERTIFICATE" in kind or b"PUBLIC KEY" in kind or (
            b"PGP" in kind and b"KEY" in kind
        ):
            out.add("keys_certs")
    if (head.startswith(b"PuTTY-User-Key-File-") or start[:4] == b"\x03\xd9\xa2\x9a"
            or start[:4] in (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce")):
        out.add("keys_certs")
    # Email
    if start[:4] == b"!BDN":
        out.add("email")
    first_k = head[:_BASE_HEAD_BYTES]
    if first_k.startswith(b"From ") and b"\n" in first_k and (
        b"\nSubject:" in first_k or b"\nFrom:" in first_k
    ):
        out.add("email")
    elif _HEADER_LINE_RE.match(first_k) and b"From:" in first_k and b"Subject:" in first_k:
        out.add("email")
    # Databases
    if start == b"SQLite format 3\x00" or head[4:19] in (b"Standard Jet DB", b"Standard ACE DB"):
        out.add("databases")
    # Scripts
    if start[:2] == b"#!" and b"\0" not in first_k:
        out.add("source_code")
    return out


def _sift_detect():
    """``sift.detect.detect`` wrapped to take a path string, or ``None``
    when sift is not installed."""
    try:
        from pathlib import Path

        from sift import detect as sift_detect  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 - optional extra, any import failure means absent
        return None
    return lambda path: sift_detect.detect(Path(path))


def sift_available() -> bool:
    return _sift_detect() is not None


def sift_kind(path: str) -> str:
    """sift's kind of the local file *path* (``image``, ``pdf``,
    ``archive``, ...), ``""`` when sift is not installed or cannot tell.
    Never raises."""
    detect = _sift_detect()
    if detect is None:
        return ""
    try:
        return str(getattr(detect(path), "kind", "") or "")
    except Exception as exc:  # noqa: BLE001 - an optional analyser must not break a caller
        log.debug("file_categories: sift.detect(%s) failed: %s", path, exc)
        return ""


def classify_local(path: str, *, wanted=None, use_sift: bool = True,
                   name: str | None = None) -> set[str]:
    """Categories of the local file *path*: by name, then - when the name
    did not settle it and the extension is unclaimed - by the first bytes
    and by sift. Never raises; never opens anything but a regular file."""
    name = name if name is not None else os.path.basename(path)
    cats = classify_name(name, path)
    wanted_set = set(wanted or ())
    if wanted_set and cats & wanted_set:
        return cats
    if not needs_sniff(name):
        return cats
    try:
        st = os.stat(path)
    except OSError:
        return cats
    if not stat_module.S_ISREG(st.st_mode) or st.st_size == 0:
        return cats
    try:
        with open(path, "rb") as fh:
            head = fh.read(head_bytes_needed(wanted_set or None))
    except OSError as exc:
        log.debug("file_categories: cannot read %s: %s", path, exc)
        return cats
    cats |= classify_content(head, name=name, size=st.st_size)
    if not use_sift or (wanted_set and cats & wanted_set):
        return cats
    if wanted_set and not wanted_set & set(_SIFT_KINDS.values()):
        return cats
    detect = _sift_detect()
    if detect is None:
        return cats
    try:
        kind = getattr(detect(path), "kind", "")
    except Exception as exc:  # noqa: BLE001 - an optional analyser must not break a search
        log.debug("file_categories: sift.detect(%s) failed: %s", path, exc)
        return cats
    mapped = _SIFT_KINDS.get(kind)
    if mapped:
        cats.add(mapped)
    return cats


def primary_category(categories) -> str:
    """The first of *categories* in table order (the one a result row shows)."""
    for cid in CATEGORIES:
        if cid in categories:
            return cid
    return ""


__all__ = [
    "CATEGORIES",
    "Category",
    "category_ids",
    "classify_content",
    "classify_local",
    "classify_name",
    "extension_of",
    "head_bytes_needed",
    "label",
    "needs_sniff",
    "primary_category",
    "sift_available",
    "sift_kind",
    "validate_categories",
]
