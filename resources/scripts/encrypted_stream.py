"""encrypted_stream.py — encrypt/decrypt big files via the streaming
codec in ``core.encrypted_overlay``.

The all-in-memory ``axross.encrypt`` / ``axross.decrypt`` helpers
work for files up to a few hundred MB; for genuinely large blobs
(VM images, archives) use ``encrypt_stream`` / ``decrypt_stream``
which pipe a file-like through 256 KiB AEAD frames so the
plaintext never has to fit in RAM.

Usage::

    src = axross.open("source-vault")
    dst = axross.open("encrypted-target")
    seal_stream(src, "/iso/ubuntu.iso",
                dst, "/backups/ubuntu.iso.axenc",
                passphrase="vault-2026")
"""
from __future__ import annotations

from core.encrypted_overlay import decrypt_stream, encrypt_stream


def seal_stream(src_backend, src_path: str,
                dst_backend, dst_path: str,
                passphrase: str,
                frame_size: int = 256 * 1024) -> int:
    """Encrypt a file backend → backend in fixed-size AEAD frames.
    Returns the resulting ciphertext size on the destination. The
    on-wire size is a few bytes larger than the plaintext per frame
    (AEAD tag + nonce); the exact overhead is set by ``frame_size``."""
    with src_backend.open_read(src_path) as src_fh, \
         dst_backend.open_write(dst_path) as dst_fh:
        # core.encrypted_overlay.encrypt_stream calls the parameter
        # ``chunk_size``; we expose the friendlier ``frame_size``
        # name because that's the wire-level concept.
        encrypt_stream(src_fh, dst_fh, passphrase=passphrase,
                       chunk_size=frame_size)
    return dst_backend.stat(dst_path).size


def unseal_stream(src_backend, src_path: str,
                  dst_backend, dst_path: str,
                  passphrase: str) -> int:
    """Decrypt a sealed stream backend → backend. Returns the
    plaintext length on the destination."""
    with src_backend.open_read(src_path) as src_fh, \
         dst_backend.open_write(dst_path) as dst_fh:
        decrypt_stream(src_fh, dst_fh, passphrase=passphrase)
    return dst_backend.stat(dst_path).size
