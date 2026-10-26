"""Signed self-updates (core.self_update, docs/plans entry 8).

A release carries ``SHA256SUMS.sig``: the raw 64-byte Ed25519 signature of
the exact bytes of its ``SHA256SUMS``. An installed binary pins the public
key (``TRUSTED_KEYS``) and refuses an update whose signature is missing,
oversized, malformed or does not verify - before it trusts any entry of
``SHA256SUMS``. Before this, the checksums and GitHub's digest came from the
same release, so whoever could change the release could change both.

Everything runs offline against tests/fake_github.py, whose releases are
signed with a key generated per test run (never the real release key).
"""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from axross._version import __version__  # noqa: E402
from core import self_update as SU  # noqa: E402
from tests.fake_github import (  # noqa: E402
    SIG,
    SUMS,
    TEST_PUBLIC_KEY,
    TEST_SIGNING_KEY,
    FakeGitHub,
    FakeHttpsHandler,
    FakeRelease,
    newer_than,
    public_key_b64,
    trust_test_key,
)

NEW = newer_than(__version__)
OLD_BYTES = b"\x7fELF old axross binary " * 100
NEW_BYTES = b"\x7fELF new axross binary " * 3000
EVIL_BYTES = b"\x7fELF evil axross binary" * 3000
#: The release key the operator published (raw 32 bytes, base64).
RELEASE_KEY = "rJX0yymA5/Mbw24qIpuLNaLqC/FbvugEREz1p0pSz68="
OTHER_KEY = Ed25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def _no_env_proxy(monkeypatch):
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy",
                 "ALL_PROXY", "no_proxy", "NO_PROXY", SU.NO_CHECK_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def trusted(monkeypatch):
    trust_test_key(monkeypatch)


@pytest.fixture
def fake():
    server = FakeGitHub(FakeRelease(NEW, {
        "axross-full": NEW_BYTES,
        "axross-slim": NEW_BYTES[:5000],
    }))
    yield server
    server.close()


@pytest.fixture
def binary(tmp_path):
    folder = tmp_path / "apps"
    folder.mkdir()
    exe = folder / "axross-full"
    exe.write_bytes(OLD_BYTES)
    exe.chmod(0o755)
    return exe


def opener_for(server):
    return SU.build_opener(handlers=[FakeHttpsHandler(server.port)])


def frozen_install(exe: Path) -> SU.Install:
    return SU.detect_install(frozen=True, executable=str(exe), bundle_dir=None,
                             platform="linux", machine="x86_64")


def paths(server) -> list[str]:
    """The release files asked for on github.com, in order."""
    return [p.rsplit("/", 1)[-1] for h, p in server.requests if h == "github.com"]


def leftovers(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir() if ".part" in p.name or ".update-" in p.name)


def update(server, exe):
    release = SU.check(opener=opener_for(server)).release
    return SU.update(release, frozen_install(exe), opener=opener_for(server))


def assert_refused_untouched(server, exe):
    assert exe.read_bytes() == OLD_BYTES
    assert leftovers(exe.parent) == []
    assert not exe.with_name(exe.name + ".previous").exists()
    assert "axross-full" not in paths(server)  # the binary was never fetched


SUMS_BYTES = b"%s  axross-full\n" % hashlib.sha256(NEW_BYTES).hexdigest().encode()


# --- the signature itself ------------------------------------------------------------


def test_happy_the_pinned_key_is_the_published_release_key():
    assert SU.TRUSTED_KEYS == (RELEASE_KEY,)
    assert len(base64.b64decode(SU.TRUSTED_KEYS[0], validate=True)) == 32
    assert SU.SIG_NAME == "SHA256SUMS.sig" and SU.SIG_BYTES == 64


def test_happy_a_signature_with_the_test_key_verifies():
    SU.verify_signature(SUMS_BYTES, TEST_SIGNING_KEY.sign(SUMS_BYTES), keys=(TEST_PUBLIC_KEY,))


def test_happy_the_module_constant_is_the_default(monkeypatch):
    trust_test_key(monkeypatch)
    SU.verify_signature(SUMS_BYTES, TEST_SIGNING_KEY.sign(SUMS_BYTES))
    monkeypatch.setattr(SU, "TRUSTED_KEYS", (RELEASE_KEY,))
    with pytest.raises(SU.SignatureError):
        SU.verify_signature(SUMS_BYTES, TEST_SIGNING_KEY.sign(SUMS_BYTES))


def test_sad_wrong_key_is_refused():
    with pytest.raises(SU.SignatureError, match="does not verify"):
        SU.verify_signature(SUMS_BYTES, OTHER_KEY.sign(SUMS_BYTES), keys=(TEST_PUBLIC_KEY,))


def test_sad_tampered_sums_is_refused():
    signature = TEST_SIGNING_KEY.sign(SUMS_BYTES)
    tampered = SUMS_BYTES.replace(b"axross-full", b"axross-fulL")
    with pytest.raises(SU.SignatureError, match="does not verify"):
        SU.verify_signature(tampered, signature, keys=(TEST_PUBLIC_KEY,))
    with pytest.raises(SU.SignatureError):  # one byte more: other bytes than were signed
        SU.verify_signature(SUMS_BYTES + b"\n", signature, keys=(TEST_PUBLIC_KEY,))


@pytest.mark.parametrize("bit", [0, 7, 255, 511])
def test_sad_tampered_signature_is_refused(bit):
    signature = bytearray(TEST_SIGNING_KEY.sign(SUMS_BYTES))
    signature[bit // 8] ^= 1 << (bit % 8)
    with pytest.raises(SU.SignatureError, match="does not verify"):
        SU.verify_signature(SUMS_BYTES, bytes(signature), keys=(TEST_PUBLIC_KEY,))


@pytest.mark.parametrize("signature", [
    b"",
    b"\0" * 63,
    b"\0" * 65,
    b"x" * 1000,
], ids=["empty", "63-bytes", "65-bytes", "1000-bytes"])
def test_sad_malformed_or_oversized_signature_is_refused(signature):
    with pytest.raises(SU.SignatureError, match="64 bytes"):
        SU.verify_signature(SUMS_BYTES, signature, keys=(TEST_PUBLIC_KEY,))


def test_sad_a_base64_text_signature_is_not_accepted():
    """The format is raw bytes; the base64 text of a valid signature is
    refused, not decoded on a guess."""
    text = base64.b64encode(TEST_SIGNING_KEY.sign(SUMS_BYTES))
    with pytest.raises(SU.SignatureError, match="64 bytes"):
        SU.verify_signature(SUMS_BYTES, text, keys=(TEST_PUBLIC_KEY,))


@pytest.mark.parametrize("bad", [None, 64, "sig"], ids=["none", "int", "str"])
def test_sad_a_signature_that_is_not_bytes_is_refused(bad):
    with pytest.raises(SU.SignatureError):
        SU.verify_signature(SUMS_BYTES, bad, keys=(TEST_PUBLIC_KEY,))


def test_happy_key_rotation_any_pinned_key_verifies():
    other = public_key_b64(OTHER_KEY)
    for keys in ((other, TEST_PUBLIC_KEY), (TEST_PUBLIC_KEY, other)):
        SU.verify_signature(SUMS_BYTES, TEST_SIGNING_KEY.sign(SUMS_BYTES), keys=keys)
        SU.verify_signature(SUMS_BYTES, OTHER_KEY.sign(SUMS_BYTES), keys=keys)


def test_sad_rotation_tuple_without_the_signing_key_refuses():
    third = public_key_b64(Ed25519PrivateKey.generate())
    with pytest.raises(SU.SignatureError):
        SU.verify_signature(SUMS_BYTES, TEST_SIGNING_KEY.sign(SUMS_BYTES),
                            keys=(public_key_b64(OTHER_KEY), third))


@pytest.mark.parametrize("broken", [
    "not base64!",
    base64.b64encode(b"\1" * 31).decode(),
    base64.b64encode(b"\1" * 33).decode(),
    "",
    None,
], ids=["not-base64", "31-bytes", "33-bytes", "empty", "none"])
def test_edge_an_unusable_pinned_key_is_skipped_never_trusted(broken):
    signature = TEST_SIGNING_KEY.sign(SUMS_BYTES)
    SU.verify_signature(SUMS_BYTES, signature, keys=(broken, TEST_PUBLIC_KEY))
    with pytest.raises(SU.SignatureError, match="no usable"):
        SU.verify_signature(SUMS_BYTES, signature, keys=(broken,))


def test_sad_no_pinned_key_refuses_everything():
    with pytest.raises(SU.SignatureError, match="no usable"):
        SU.verify_signature(SUMS_BYTES, TEST_SIGNING_KEY.sign(SUMS_BYTES), keys=())


def test_edge_a_signature_error_is_a_checksum_error():
    """Callers that refuse on ChecksumError refuse a bad signature too."""
    assert issubclass(SU.SignatureError, SU.ChecksumError)


# --- the update flow against a fake release --------------------------------------------


def test_happy_e2e_signed_release_updates(trusted, fake, binary):
    result = update(fake, binary)
    assert result.replaced and binary.read_bytes() == NEW_BYTES
    assert paths(fake) == [SUMS, SIG, "axross-full"]  # signature checked before the binary
    assert leftovers(binary.parent) == []


def test_sad_e2e_the_real_release_key_refuses_a_test_signed_release(fake, binary):
    assert SU.TRUSTED_KEYS == (RELEASE_KEY,)  # nothing patched
    with pytest.raises(SU.SignatureError, match="does not verify"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)


def test_sad_e2e_missing_signature_is_refused(trusted, fake, binary):
    fake.release.without_sig = True
    with pytest.raises(SU.SignatureError, match=r"no SHA256SUMS\.sig"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)
    assert paths(fake) == []  # refused before anything was downloaded


def test_sad_e2e_a_release_rewritten_after_signing_is_refused(trusted, fake, binary):
    """Whoever can change the release replaces the binary and writes a
    matching SHA256SUMS (GitHub's digests follow); only the signature of
    the original SHA256SUMS stays - it no longer covers the bytes served."""
    honest = fake.release.sums_text().encode()
    fake.release.files["axross-full"] = EVIL_BYTES
    fake.release.signed_sums = honest
    with pytest.raises(SU.SignatureError, match="does not verify"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)


def test_sad_e2e_tampered_signature_is_refused(trusted, fake, binary):
    signature = bytearray(fake.release.signature())
    signature[10] ^= 0x40
    fake.release.sig_override = bytes(signature)
    with pytest.raises(SU.SignatureError, match="does not verify"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)


def test_sad_e2e_wrong_key_is_refused(trusted, fake, binary):
    fake.release.signing_key = OTHER_KEY
    with pytest.raises(SU.SignatureError, match="does not verify"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)


def test_happy_e2e_rotation_accepts_the_new_key(monkeypatch, fake, binary):
    trust_test_key(monkeypatch, public_key_b64(OTHER_KEY))
    fake.release.signing_key = OTHER_KEY
    assert update(fake, binary).replaced and binary.read_bytes() == NEW_BYTES


def test_sad_e2e_an_oversized_signature_is_not_downloaded(trusted, fake, binary):
    fake.release.sig_override = fake.release.signature() + b"\0"
    with pytest.raises(SU.SignatureError, match="larger than 64 bytes"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)
    assert SIG not in paths(fake)


def test_sad_e2e_more_signature_bytes_than_stated_are_refused(trusted, fake, binary):
    fake.release.sig_override = fake.release.signature() + b"\0" * 100
    fake.release.size_override[SIG] = SU.SIG_BYTES
    fake.release.digest_override[SIG] = ""
    with pytest.raises(SU.UpdateError, match="larger"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)


@pytest.mark.parametrize("signature", [b"\0" * 63, b"x"], ids=["63-bytes", "1-byte"])
def test_sad_e2e_a_malformed_signature_is_refused(trusted, fake, binary, signature):
    fake.release.sig_override = signature
    with pytest.raises(SU.SignatureError, match="64 bytes"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)


def test_sad_e2e_a_signature_disagreeing_with_githubs_digest_is_refused(trusted, fake, binary):
    fake.release.digest_override[SIG] = "0" * 64
    with pytest.raises(SU.ChecksumError, match="digest"):
        update(fake, binary)
    assert_refused_untouched(fake, binary)


def test_sad_e2e_no_sums_entry_is_trusted_before_the_signature(trusted, fake, binary,
                                                                monkeypatch):
    parsed: list[str] = []
    real = SU.parse_sums
    monkeypatch.setattr(SU, "parse_sums", lambda text: parsed.append(text) or real(text))
    fake.release.signing_key = OTHER_KEY
    with pytest.raises(SU.SignatureError):
        update(fake, binary)
    assert parsed == []  # SHA256SUMS was never read for an entry
    fake.release.signing_key = TEST_SIGNING_KEY
    update(fake, binary)
    assert len(parsed) == 1


def test_sad_e2e_the_existing_checksum_checks_still_hold(trusted, fake, binary):
    """A correctly signed SHA256SUMS does not excuse a binary that differs
    from it."""
    fake.served_override["axross-full"] = NEW_BYTES[:-1] + b"X"
    with pytest.raises(SU.ChecksumError, match="SHA-256"):
        update(fake, binary)
    assert binary.read_bytes() == OLD_BYTES and leftovers(binary.parent) == []


# --- the signature asset is never taken for a binary -----------------------------------

PLATFORMS = [("linux", "x86_64", "full"), ("linux", "x86_64", "slim"),
             ("darwin", "arm64", "slim"), ("win32", "AMD64", "slim")]


@pytest.mark.parametrize("platform,machine,flavor", PLATFORMS)
def test_edge_the_signature_asset_is_never_picked_as_a_binary(tmp_path, platform, machine,
                                                              flavor):
    release = FakeRelease(NEW, {
        "axross-full.sig": b"s" * 64,
        "axross-slim.sig": b"s" * 64,
        "axross-full": b"full",
        "axross-slim": b"slim",
        "axross-slim-macos-arm64": b"mac",
        "axross-slim-windows-x64.exe": b"win",
    })
    data = release.json()
    data["assets"].sort(key=lambda a: not a["name"].endswith(".sig"))  # the .sig files first
    parsed = SU.parse_release(data)
    exe = tmp_path / f"axross-{flavor}"
    exe.write_bytes(b"x")
    inst = SU.detect_install(frozen=True, executable=str(exe), bundle_dir=None,
                             platform=platform, machine=machine)
    picked = parsed.asset(inst.asset)
    assert picked is not None and not picked.name.endswith(".sig")
    assert picked.name == inst.asset
    assert parsed.asset(SU.SUMS_NAME).name == SUMS


def test_edge_the_signature_asset_name_is_a_valid_release_asset():
    """Old binaries parse a release with SHA256SUMS.sig like any other: the
    name passes the asset filter, so the release is not refused for it."""
    parsed = SU.parse_release(FakeRelease(NEW, {"axross-full": b"x"}).json())
    assert {a.name for a in parsed.assets} == {"axross-full", SUMS, SIG}
