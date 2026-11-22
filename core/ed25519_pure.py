"""Ed25519 (RFC 8032) in pure Python: what an update needs to check the
signature of a release's SHA256SUMS without a crypto package
(core.markdown_update - axross-markdown depends on no ``cryptography``).

:func:`verify` is the strict check: a public key and a point R that are no
canonical encoding of a curve point (y >= p, an x that does not exist) and an
S that is not below the group order L are refused before any arithmetic;
the equation is the cofactorless one, [S]B == R + [k]A, compared as points.
:func:`sign` and :func:`public_key` are here for the tests and for
scripts/sign_release.py's own check - a release is signed with the
``cryptography`` package on the maintainer's machine.

Not constant time: verification works on public data only. Signing here is
for tests, never for a release key.
"""

from __future__ import annotations

import hashlib

_P = 2 ** 255 - 19
#: The order of the base point's group.
L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

#: The sizes of a public key and of a signature.
KEY_BYTES = 32
SIGNATURE_BYTES = 64


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
#: The base point in extended coordinates (X, Y, Z, T).
_G = (_GX, _GY, 1, _GX * _GY % _P)
_ZERO = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _mul(scalar: int, point):
    result = _ZERO
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _compress(point) -> bytes:
    zinv = pow(point[2], _P - 2, _P)
    x, y = point[0] * zinv % _P, point[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data: bytes):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return x, y, 1, x * y % _P


def _hash_int(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Whether *signature* is a valid Ed25519 signature of exactly *message*
    by the key *public* (its raw 32 bytes). Anything malformed is False."""
    if not isinstance(public, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)) \
            or not isinstance(message, (bytes, bytearray)):
        return False
    public, signature, message = bytes(public), bytes(signature), bytes(message)
    if len(public) != KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    a = _decompress(public)
    if a is None:
        return False
    r_bytes = signature[:32]
    r = _decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = _hash_int(r_bytes, public, message) % L
    return _equal(_mul(s, _G), _add(r, _mul(k, a)))


def _secret_scalar(secret: bytes) -> tuple[int, bytes]:
    if len(secret) != 32:
        raise ValueError("an Ed25519 secret key is 32 bytes")
    digest = hashlib.sha512(secret).digest()
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, digest[32:]


def public_key(secret: bytes) -> bytes:
    """The raw public key of the raw 32-byte *secret* (tests)."""
    a, _prefix = _secret_scalar(secret)
    return _compress(_mul(a, _G))


def sign(secret: bytes, message: bytes) -> bytes:
    """*message* signed with the raw 32-byte *secret* (tests - not constant time)."""
    a, prefix = _secret_scalar(secret)
    public = _compress(_mul(a, _G))
    r = _hash_int(prefix, message) % L
    r_bytes = _compress(_mul(r, _G))
    k = _hash_int(r_bytes, public, message) % L
    return r_bytes + int.to_bytes((r + k * a) % L, 32, "little")


__all__ = ["KEY_BYTES", "L", "SIGNATURE_BYTES", "public_key", "sign", "verify"]
