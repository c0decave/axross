"""At-rest encryption overlay for any FileBackend.

Stores AES-256-GCM encrypted blobs with ``.axenc`` suffix on whatever
backend you point it at. The key is derived from a user passphrase
via PBKDF2-HMAC-SHA256 with a per-file random salt, so two files
with the same passphrase + plaintext still produce different
ciphertexts (important for S3/WebDAV deduplication heuristics).

Two formats
-----------

**V1 (``AXXE1``) — single-shot GCM.** For blobs up to
:data:`MAX_ENCRYPTED_SIZE` (1 GiB). The whole ciphertext is pulled
into RAM and decrypted in one GCM call, so the authenticity tag is
checked before any plaintext is released.

    offset  0  ..  4   magic:    b"AXXE1" (5 bytes)
    offset  5  .. 21   salt:     16 bytes
    offset 21 .. 33    nonce:    12 bytes
    offset 33 .. end   ciphertext + 16-byte GCM tag (appended by AESGCM)

**V2 (``AXXE2``) — chunked GCM, streaming-safe.** For blobs above
the single-shot cap (or anywhere ``encrypt_stream`` /
``decrypt_stream`` is used explicitly). Each chunk is authenticated
independently with the chunk index and an ``is_final`` flag bound
into the AEAD's additional-data; readers only emit plaintext for
chunks whose tag verifies, truncation is detected by requiring a
final chunk, and reordering is detected by AD mismatch on the
per-chunk index.

    Header (25 bytes):
      magic         5 bytes  b"AXXE2"
      salt         16 bytes
      chunk_size    4 bytes  u32 LE (plaintext bytes per chunk)

    Per chunk, until a chunk with is_final = 1:
      ct_len        4 bytes  u32 LE (ciphertext length, incl. 16-byte tag)
      is_final      1 byte   0x00 for intermediate, 0x01 for final
      nonce        12 bytes  unique per chunk
      ciphertext ct_len bytes

    AD per chunk = MAGIC_V2 || u64_LE(chunk_index) || u8(is_final)

PBKDF2 iterations are pinned at ``ITERATIONS`` (currently 200_000)
for both formats. Raising this number is fine; lowering it silently
would be a security regression, so the constant is frozen here.

The overlay does NOT store the passphrase, salt-only verifier or
any hint — wrong-passphrase produces a clean
:class:`InvalidCiphertext` from the GCM tag check.
"""
from __future__ import annotations

import io
import logging
import os
import secrets
from typing import IO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

log = logging.getLogger("core.encrypted_overlay")

MAGIC = b"AXXE1"
MAGIC_V2 = b"AXXE2"
MAGIC_LEN = len(MAGIC)
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
ITERATIONS = 200_000
HEADER_LEN = MAGIC_LEN + SALT_LEN + NONCE_LEN
ENC_SUFFIX = ".axenc"

# Hard cap on ciphertext size we're willing to pull into RAM for
# single-shot GCM decryption. A malicious backend returning a multi-
# gigabyte .axenc file would otherwise OOM the client. 1 GiB is
# generous for the "sensitive note encrypted on S3" use case while
# still being well under any laptop's RAM. Callers above this cap
# should use :func:`encrypt_stream` / :func:`decrypt_stream` which
# frame the ciphertext as independently-authenticated chunks and
# never materialise the whole blob in RAM.
MAX_ENCRYPTED_SIZE = 1 * 1024 * 1024 * 1024

# Default plaintext bytes per chunk in the V2 streaming format.
# 4 MiB keeps per-chunk memory small enough to stream over a slow
# backend without stalling; chunks below 64 KiB multiply PBKDF2 and
# AEAD overhead to a point where the format pays for itself in
# bookkeeping. The encoder is free to pick any positive chunk_size
# up to ``STREAM_MAX_CHUNK_BYTES``; the decoder accepts whatever
# the file's header declares up to that safety bound.
DEFAULT_STREAM_CHUNK_SIZE = 4 * 1024 * 1024
# Hard ceiling on the chunk_size a V2 blob is allowed to declare.
# A malicious file could otherwise claim a 10-GiB chunk and force
# the decoder to try to allocate it before the tag check. 64 MiB
# is twelve orders of magnitude above any legitimate chunk size
# and well under "any laptop's RAM".
STREAM_MAX_CHUNK_BYTES = 64 * 1024 * 1024


class InvalidCiphertext(ValueError):
    """Raised when decryption fails: bad passphrase, corrupted blob,
    tampered tag, or non-axross data."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


# ---------------------------------------------------------------------------
# Pure bytes codec — useful in tests and anywhere else you already
# have the plaintext in memory.
# ---------------------------------------------------------------------------

def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    """Encrypt *data* with *passphrase*. Returns the full on-disk blob."""
    if not passphrase:
        raise ValueError("passphrase must be non-empty")
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, data, associated_data=MAGIC)
    return MAGIC + salt + nonce + ct


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    """Decrypt *blob*. Raises :class:`InvalidCiphertext` on any failure."""
    if len(blob) < HEADER_LEN + 16:  # +16 for GCM tag
        raise InvalidCiphertext("blob too short to be axross-encrypted")
    if blob[:MAGIC_LEN] != MAGIC:
        raise InvalidCiphertext("missing axross magic header")
    salt = blob[MAGIC_LEN:MAGIC_LEN + SALT_LEN]
    nonce = blob[MAGIC_LEN + SALT_LEN:HEADER_LEN]
    ct = blob[HEADER_LEN:]
    try:
        key = _derive_key(passphrase, salt)
    except Exception as exc:
        raise InvalidCiphertext(
            f"key derivation failed: {exc}"
        ) from exc
    try:
        return AESGCM(key).decrypt(nonce, ct, associated_data=MAGIC)
    except InvalidTag as exc:
        raise InvalidCiphertext(
            "authentication failed — wrong passphrase or tampered blob"
        ) from exc


# ---------------------------------------------------------------------------
# Backend-attached helpers
# ---------------------------------------------------------------------------

def _ensure_enc_suffix(path: str) -> str:
    if path.endswith(ENC_SUFFIX):
        return path
    return path + ENC_SUFFIX


def write_encrypted(backend, path: str, data: bytes,
                    passphrase: str) -> str:
    """Encrypt *data* and write it to *path* on *backend*.

    Appends ``.axenc`` if missing. Returns the final path.
    """
    final = _ensure_enc_suffix(path)
    blob = encrypt_bytes(data, passphrase)
    handle = backend.open_write(final)
    try:
        handle.write(blob)
    finally:
        handle.close()
    return final


def read_encrypted(backend, path: str, passphrase: str) -> bytes:
    """Read and decrypt *path*. Raises :class:`InvalidCiphertext` on
    bad passphrase / corruption, :class:`OSError` on IO failure."""
    handle = backend.open_read(path)
    # Pre-bind so the post-finally access is safe even if read raises.
    raw: bytes | str = b""
    try:
        # Bounded read: a malicious backend could otherwise return a
        # 50-GiB "encrypted" blob and OOM the client before we've even
        # had a chance to verify the GCM tag. Read one byte past the
        # cap so we can distinguish "exactly MAX" from "too big".
        raw = handle.read(MAX_ENCRYPTED_SIZE + 1)
    finally:
        try:
            handle.close()
        except Exception as close_exc:
            log.debug("encrypted_overlay: handle close failed: %s", close_exc)
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    if len(raw) > MAX_ENCRYPTED_SIZE:
        raise InvalidCiphertext(
            f"encrypted blob at {path} exceeds "
            f"{MAX_ENCRYPTED_SIZE // (1024 * 1024)} MiB cap"
        )
    return decrypt_bytes(raw, passphrase)


def is_encrypted_blob(raw: bytes) -> bool:
    """Cheap sniffer — does this blob LOOK like our format?
    Doesn't try to decrypt (no passphrase here). False positives are
    possible for attacker-controlled data; for authenticity use
    :func:`decrypt_bytes` and catch :class:`InvalidCiphertext`."""
    return len(raw) >= HEADER_LEN + 16 and raw[:MAGIC_LEN] == MAGIC


def is_encrypted_path(path: str) -> bool:
    """Fast filename check."""
    return path.endswith(ENC_SUFFIX)


# ---------------------------------------------------------------------------
# Streaming handle — lets callers plug the overlay into code that
# expects a file-like object without materialising huge plaintexts in
# one shot. We still have to hold the whole blob in memory because
# GCM is single-shot, but at least the reader sees a uniform API.
# ---------------------------------------------------------------------------

def open_encrypted_read(backend, path: str, passphrase: str) -> IO[bytes]:
    """Return an in-memory ``BytesIO`` holding the decrypted content."""
    plaintext = read_encrypted(backend, path, passphrase)
    return io.BytesIO(plaintext)


# ---------------------------------------------------------------------------
# V2 streaming format — chunked, independently-authenticated chunks.
# Safe for multi-gigabyte blobs without holding the whole ciphertext
# in memory.
# ---------------------------------------------------------------------------

def encrypt_stream(
    reader: IO[bytes], writer: IO[bytes], passphrase: str,
    *, chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
) -> None:
    """Encrypt bytes from *reader* into the V2 ``AXXE2`` framed format
    and write them to *writer*. Neither side is closed.

    Peak memory is about ``2 × chunk_size`` — the encoder always holds
    the current chunk plus the look-ahead chunk so it can set the
    ``is_final`` flag before encrypting (otherwise a receiver couldn't
    detect truncation of the last chunk).
    """
    if not passphrase:
        raise ValueError("passphrase must be non-empty")
    if chunk_size <= 0 or chunk_size > STREAM_MAX_CHUNK_BYTES:
        raise ValueError(
            f"chunk_size must be in (0, {STREAM_MAX_CHUNK_BYTES}]; "
            f"got {chunk_size}",
        )
    salt = secrets.token_bytes(SALT_LEN)
    key = _derive_key(passphrase, salt)
    aead = AESGCM(key)
    writer.write(MAGIC_V2 + salt + chunk_size.to_bytes(4, "little"))

    index = 0
    pending = reader.read(chunk_size)
    while pending:
        # Read-ahead so the current chunk's ``is_final`` can be set
        # correctly — otherwise a reader can't distinguish "the file
        # ends here" from "the attacker truncated here".
        lookahead = reader.read(chunk_size)
        is_final = 0 if lookahead else 1
        nonce = secrets.token_bytes(NONCE_LEN)
        ad = (MAGIC_V2 + index.to_bytes(8, "little")
              + bytes([is_final]))
        ct = aead.encrypt(nonce, pending, associated_data=ad)
        writer.write(
            len(ct).to_bytes(4, "little")
            + bytes([is_final])
            + nonce
            + ct,
        )
        pending = lookahead
        index += 1
    # Empty-plaintext case: emit exactly one empty final chunk so
    # truncation-to-zero attacks on the outer storage are still
    # detectable (no final chunk in a zero-length stream ≠ "empty
    # plaintext"; a valid empty plaintext still has one final chunk).
    if index == 0:
        nonce = secrets.token_bytes(NONCE_LEN)
        ad = MAGIC_V2 + b"\x00" * 8 + b"\x01"
        ct = aead.encrypt(nonce, b"", associated_data=ad)
        writer.write(
            len(ct).to_bytes(4, "little")
            + b"\x01"
            + nonce
            + ct,
        )


def decrypt_stream(
    reader: IO[bytes], writer: IO[bytes], passphrase: str,
) -> None:
    """Decrypt a V2 ``AXXE2`` framed stream from *reader*, writing the
    recovered plaintext to *writer*. Neither side is closed.

    The decoder never emits plaintext for a chunk whose tag failed,
    raises :class:`InvalidCiphertext` on any authenticity / framing /
    truncation failure, and refuses to return until the stream's
    final chunk is reached. Trailing bytes after the final chunk are
    rejected as tampering.
    """
    if not passphrase:
        raise ValueError("passphrase must be non-empty")
    header = _read_exact(reader, MAGIC_LEN + SALT_LEN + 4)
    if header is None:
        raise InvalidCiphertext("stream too short for AXXE2 header")
    if header[:MAGIC_LEN] != MAGIC_V2:
        raise InvalidCiphertext("missing AXXE2 magic")
    salt = header[MAGIC_LEN:MAGIC_LEN + SALT_LEN]
    chunk_size = int.from_bytes(header[-4:], "little")
    if chunk_size <= 0 or chunk_size > STREAM_MAX_CHUNK_BYTES:
        raise InvalidCiphertext(
            f"header declares chunk_size {chunk_size} outside "
            f"(0, {STREAM_MAX_CHUNK_BYTES}]",
        )
    try:
        key = _derive_key(passphrase, salt)
    except Exception as exc:
        raise InvalidCiphertext(
            f"key derivation failed: {exc}",
        ) from exc
    aead = AESGCM(key)

    index = 0
    max_ct_len = chunk_size + 16  # +16 for GCM tag
    while True:
        frame_head = _read_exact(reader, 4 + 1 + NONCE_LEN)
        if frame_head is None:
            raise InvalidCiphertext(
                f"stream truncated — missing chunk {index} header",
            )
        ct_len = int.from_bytes(frame_head[:4], "little")
        is_final = frame_head[4]
        nonce = frame_head[5:17]
        if is_final not in (0, 1):
            raise InvalidCiphertext(
                f"chunk {index} is_final byte {is_final} invalid",
            )
        if ct_len > max_ct_len:
            raise InvalidCiphertext(
                f"chunk {index} ct_len {ct_len} exceeds "
                f"max_ct_len {max_ct_len}",
            )
        ct = _read_exact(reader, ct_len)
        if ct is None:
            raise InvalidCiphertext(
                f"stream truncated in chunk {index} body",
            )
        ad = (MAGIC_V2 + index.to_bytes(8, "little")
              + bytes([is_final]))
        try:
            pt = aead.decrypt(nonce, ct, associated_data=ad)
        except InvalidTag as exc:
            raise InvalidCiphertext(
                f"chunk {index} authentication failed — "
                f"wrong passphrase or tampered blob",
            ) from exc
        writer.write(pt)
        if is_final:
            trailing = reader.read(1)
            if trailing:
                raise InvalidCiphertext(
                    "trailing bytes after final chunk",
                )
            return
        index += 1


def _read_exact(stream: IO[bytes], want: int) -> bytes | None:
    """Read exactly *want* bytes from *stream*, concatenating across
    short reads. Returns None if the stream ends before ``want``
    bytes have been read. The V2 decoder uses this instead of a
    plain ``read(want)`` because some backends (pipes, slow SFTP
    connections) short-read mid-stream even when more bytes are
    coming, and the decoder's safety invariants depend on the
    chunk header arriving intact."""
    buf = b""
    while len(buf) < want:
        got = stream.read(want - len(buf))
        if not got:
            return None
        if isinstance(got, str):
            got = got.encode("utf-8", errors="replace")
        buf += got
    return buf


def is_streaming_blob(raw: bytes) -> bool:
    """Cheap sniffer for the V2 ``AXXE2`` framed format."""
    return len(raw) >= len(MAGIC_V2) and raw[:len(MAGIC_V2)] == MAGIC_V2


__all__ = [
    "DEFAULT_STREAM_CHUNK_SIZE",
    "ENC_SUFFIX",
    "InvalidCiphertext",
    "MAGIC_V2",
    "STREAM_MAX_CHUNK_BYTES",
    "decrypt_bytes",
    "decrypt_stream",
    "encrypt_bytes",
    "encrypt_stream",
    "is_encrypted_blob",
    "is_encrypted_path",
    "is_streaming_blob",
    "open_encrypted_read",
    "read_encrypted",
    "write_encrypted",
]
