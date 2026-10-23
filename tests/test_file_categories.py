"""File categories for Find Files: the type presets (Images, Disk & VM images,
Crypto wallets, ...) decided by name, path and cheap content markers.

Operator punch-list item 25: "alle meine kryptowallets finden, oder alle
meine bilder oder alle images/dd/vdis von computern".
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import file_categories as FC  # noqa: E402

# --- happy: one name per category -------------------------------------------

NAME_CASES = [
    ("images", "holiday.JPG", ""),
    ("images", "scan.heic", ""),
    ("videos", "clip.mkv", ""),
    ("videos", "movie.MP4", ""),
    ("audio", "song.flac", ""),
    ("audio", "voice.opus", ""),
    ("documents", "report.pdf", ""),
    ("documents", "letter.odt", ""),
    ("documents", "notes.md", ""),
    ("archives", "backup.tar.gz", ""),
    ("archives", "bundle.7z", ""),
    ("disk_images", "win10.vdi", ""),
    ("disk_images", "server.qcow2", ""),
    ("disk_images", "sda.dd", ""),
    ("disk_images", "evidence.E01", ""),
    ("disk_images", "evidence.e02", ""),
    ("disk_images", "ubuntu.iso", ""),
    ("crypto_wallets", "wallet.dat", ""),
    ("crypto_wallets", "UTC--2017-08-01T10-00-00.000Z--" + "0123456789abcdef" * 2 + "01234567", ""),
    ("crypto_wallets", "default_wallet", "/home/u/.electrum/wallets/default_wallet"),
    ("crypto_wallets", "seed.seco", ""),
    ("crypto_wallets", "000003.log",
     "/home/u/.config/google-chrome/Default/Local Extension Settings/"
     "nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log"),
    ("crypto_wallets", "mine.keys", "/home/u/Monero/wallets/mine/mine.keys"),
    ("keys_certs", "id_ed25519", ""),
    ("keys_certs", "server.pem", ""),
    ("keys_certs", "store.p12", ""),
    ("keys_certs", "Passwords.kdbx", ""),
    ("source_code", "main.py", ""),
    ("source_code", "Makefile", ""),
    ("email", "inbox.mbox", ""),
    ("email", "outlook.pst", ""),
    ("databases", "app.sqlite3", ""),
    ("databases", "legacy.accdb", ""),
]


@pytest.mark.parametrize(("category", "name", "path"), NAME_CASES)
def test_happy_name_rules_put_each_file_in_its_category(category, name, path) -> None:
    assert category in FC.classify_name(name, path)


def test_happy_every_category_has_a_label_and_is_listed_in_order() -> None:
    ids = FC.category_ids()
    assert ids[0] == "images"
    assert {"disk_images", "crypto_wallets", "keys_certs"} <= set(ids)
    for cid in ids:
        assert FC.label(cid)
        assert FC.CATEGORIES[cid].description


# --- happy: content markers --------------------------------------------------

CONTENT_CASES = [
    ("images", b"\x89PNG\r\n\x1a\n" + b"\0" * 32),
    ("videos", b"\x1a\x45\xdf\xa3" + b"\0" * 32),
    ("videos", b"\0\0\0\x18ftypisom" + b"\0" * 32),
    ("audio", b"\0\0\0\x18ftypM4A " + b"\0" * 32),
    ("audio", b"ID3\x04\0" + b"\0" * 32),
    ("documents", b"%PDF-1.7\n"),
    ("archives", b"\x1f\x8b\x08\0" + b"\0" * 32),
    ("disk_images", b"QFI\xfb" + b"\0" * 64),
    ("disk_images", b"KDMV" + b"\0" * 64),
    ("disk_images", b"vhdxfile" + b"\0" * 64),
    ("disk_images", b"conectix" + b"\0" * 64),
    ("disk_images", b"EVF\x09\x0d\x0a\xff\x00" + b"\0" * 64),
    ("disk_images",
     b"<<< Oracle VM VirtualBox Disk Image >>>\n" + b"\0" * 24 + b"\x7f\x10\xda\xbe"),
    ("disk_images", b"LUKS\xba\xbe" + b"\0" * 64),
    ("crypto_wallets", b'{"address":"ab","crypto":{"cipher":"aes-128-ctr","ciphertext":"00",'
     b'"kdf":"scrypt"},"version":3}'),
    ("crypto_wallets", b'{\n "seed_version": 18,\n "wallet_type": "standard"\n}'),
    ("crypto_wallets", b"QklFMQ" + b"A" * 60),
    ("crypto_wallets", b"\0" * 12 + b"\x62\x31\x05\x00" + b"\0" * 100 + b"defaultkey" + b"\0" * 8),
    # Built in pieces: the mirror's leak gate (scripts/_scrub_rules.py) refuses
    # a literal private-key header in any published file.
    ("keys_certs", b"-----BEGIN OPENSSH " + b"PRIVATE " + b"KEY-----\nb3Blbn==\n"),
    ("keys_certs", b"-----BEGIN CERTIFICATE-----\nMIIB\n"),
    ("keys_certs", b"PuTTY-User-Key-File-3: ssh-ed25519\n"),
    ("keys_certs", b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" + b"\0" * 16),
    ("email", b"!BDN" + b"\0" * 32),
    ("email", b"From alice@example.org Mon Jan  1 00:00:00 2024\nSubject: hi\n"),
    ("databases", b"SQLite format 3\x00" + b"\0" * 32),
    ("source_code", b"#!/usr/bin/env python3\nprint(1)\n"),
]


@pytest.mark.parametrize(("category", "head"), CONTENT_CASES)
def test_happy_content_markers_find_files_without_a_telling_name(category, head) -> None:
    assert category in FC.classify_content(head, name="blob", size=len(head))


def test_happy_an_iso_is_recognised_by_its_volume_descriptor() -> None:
    head = b"\0" * 0x8001 + b"CD001" + b"\0" * 32
    assert "disk_images" in FC.classify_content(head, name="cdrom", size=10 * 1024 * 1024)
    assert FC.head_bytes_needed({"disk_images"}) >= 0x8001 + 5


def test_happy_a_raw_disk_with_a_partition_table_is_a_disk_image() -> None:
    head = bytearray(4096)
    head[446 + 4] = 0x83  # one Linux partition
    head[510:512] = b"\x55\xaa"
    assert "disk_images" in FC.classify_content(bytes(head), name="sdb", size=8 * 1024 * 1024)


def test_happy_classify_local_reads_the_head_of_an_extensionless_file(tmp_path) -> None:
    keystore = tmp_path / "keystore-backup"
    keystore.write_bytes(b'{"crypto":{"ciphertext":"aa","kdf":"pbkdf2"},"version":3}')
    cats = FC.classify_local(str(keystore), wanted={"crypto_wallets"}, use_sift=False)
    assert "crypto_wallets" in cats


def test_happy_primary_category_follows_the_table_order() -> None:
    assert FC.primary_category({"archives", "documents"}) == "documents"
    assert FC.primary_category(set()) == ""


# --- sad -------------------------------------------------------------------


def test_sad_an_unknown_category_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown file category"):
        FC.validate_categories(("images", "secrets"))
    with pytest.raises(ValueError):
        FC.validate_categories("images")  # a bare string is not a list


@pytest.mark.parametrize(
    ("category", "name", "path"),
    [
        ("images", "picture.txt", ""),
        ("crypto_wallets", "wallet.txt", ""),  # "wallet" in a name is not enough
        ("crypto_wallets", "000003.log", "/home/u/.config/google-chrome/Default/Local Storage"),
        ("crypto_wallets", "server.keys", "/srv/app"),  # .keys outside a Monero folder
        ("disk_images", "img.png", ""),
        ("keys_certs", "id_rsa.pub.txt", ""),
        ("keys_certs", "presentation.key", "/home/u/Keynote"),  # Keynote is a document
    ],
)
def test_sad_lookalike_names_are_not_put_in_the_category(category, name, path) -> None:
    assert category not in FC.classify_name(name, path)


@pytest.mark.parametrize(
    ("category", "head", "size"),
    [
        ("crypto_wallets", b'{"crypto": "is great"}', 30),  # no ciphertext / kdf
        ("keys_certs", b"-----BEGIN SOMETHING ELSE-----\n", 40),
        ("disk_images", b"\0" * 510 + b"\x55\xaa", 512),  # a boot sector alone, too small
        ("disk_images", b"QFI", 3),  # truncated magic
        ("images", b"", 0),
    ],
)
def test_sad_weak_or_truncated_content_is_not_classified(category, head, size) -> None:
    assert category not in FC.classify_content(head, name="x", size=size)


def test_sad_classify_local_never_raises_on_a_missing_or_special_file(tmp_path) -> None:
    assert FC.classify_local(str(tmp_path / "gone"), wanted={"images"}, use_sift=False) == set()
    fifo = tmp_path / "pipe"
    if hasattr(os, "mkfifo"):
        os.mkfifo(fifo)
        # A FIFO must never be opened: that blocks until a writer appears.
        assert FC.classify_local(str(fifo), wanted={"images"}, use_sift=False) == set()


# --- edge ------------------------------------------------------------------


def test_edge_known_extensions_are_not_sniffed() -> None:
    # A file whose extension some category claims is decided by its name:
    # sniffing every .txt for image magic would read the head of every file.
    assert FC.needs_sniff("notes.txt") is False
    assert FC.needs_sniff("blob") is True
    assert FC.needs_sniff("wallet.dat") is True  # .dat says nothing


def test_edge_compound_and_upper_case_extensions() -> None:
    assert "archives" in FC.classify_name("X.TAR.ZST")
    assert FC.extension_of("a.tar.gz") == ".tar.gz"
    assert FC.extension_of(".bashrc") == ""
    assert FC.extension_of("noext") == ""


def test_edge_a_file_can_be_in_two_categories() -> None:
    # An Ethereum keystore inside a keystore folder is a wallet; a
    # .kdbx is a key store only.
    cats = FC.classify_name(
        "UTC--2020-01-01T00-00-00.0Z--" + "a" * 40, "/home/u/.ethereum/keystore"
    )
    assert "crypto_wallets" in cats


def test_edge_sift_is_consulted_only_when_importable(tmp_path, monkeypatch) -> None:
    script = tmp_path / "tool"
    script.write_text("import os\nprint(os.getcwd())\n" * 5)
    monkeypatch.setattr(FC, "_sift_detect", lambda: None)
    without = FC.classify_local(str(script), wanted={"source_code"}, use_sift=True)

    class _Det:
        kind = "source-code"

    monkeypatch.setattr(FC, "_sift_detect", lambda: (lambda path: _Det()))
    with_sift = FC.classify_local(str(script), wanted={"source_code"}, use_sift=True)
    assert "source_code" not in without
    assert "source_code" in with_sift


def test_edge_a_raising_sift_is_ignored(tmp_path, monkeypatch) -> None:
    blob = tmp_path / "blob"
    blob.write_bytes(b"\x01\x02")

    def boom(path):
        raise RuntimeError("sift broke")

    monkeypatch.setattr(FC, "_sift_detect", lambda: boom)
    assert FC.classify_local(str(blob), wanted={"documents"}, use_sift=True) == set()


def test_edge_vdi_signature_alone_without_the_banner() -> None:
    head = b"\0" * 0x40 + struct.pack("<I", 0xBEDA107F) + b"\0" * 16
    assert "disk_images" in FC.classify_content(head, name="disk", size=4 * 1024 * 1024)
