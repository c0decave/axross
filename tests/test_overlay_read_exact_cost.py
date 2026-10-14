"""``_read_exact`` collects short reads without re-copying the buffer.

Measured before: ``buf += got`` on ``bytes`` copied everything read so
far on every short read, so a 4 MiB chunk arriving in 16 KiB reads took
33.7 ms instead of ~4 ms (quadratic in reads per chunk).

The reference below is a verbatim copy of the function before the
change; the tests hold new == old, including str chunks and early EOF.
"""

from __future__ import annotations

import io
import random
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import encrypted_overlay as EO  # noqa: E402


def _old_read_exact(stream, want: int):
    buf = b""
    while len(buf) < want:
        got = stream.read(want - len(buf))
        if not got:
            return None
        if isinstance(got, str):
            got = got.encode("utf-8", errors="replace")
        buf += got
    return buf


class _Stepped:
    """Returns at most the next step's worth per read (str or bytes)."""

    def __init__(self, data, steps):
        self._data, self._steps, self._pos, self._i = data, steps, 0, 0

    def read(self, n):
        step = self._steps[self._i % len(self._steps)]
        self._i += 1
        out = self._data[self._pos : self._pos + min(n, step)]
        self._pos += len(out)
        return out


class ReadExactTest(unittest.TestCase):
    def test_happy_equals_the_old_function(self) -> None:
        rng = random.Random(11)
        for _ in range(300):
            data = rng.randbytes(rng.randint(0, 3000))
            want = rng.randint(0, 3500)
            steps = [rng.randint(1, 900) for _ in range(rng.randint(1, 5))]
            new = EO._read_exact(_Stepped(data, steps), want)
            old = _old_read_exact(_Stepped(data, steps), want)
            self.assertEqual(new, old)
            self.assertIs(type(new), type(old))

    def test_sad_str_chunks_and_early_eof(self) -> None:
        for want in (0, 3, 9, 10):
            with self.subTest(want=want):
                self.assertEqual(
                    EO._read_exact(_Stepped("abcdéfgh", [2, 3]), want),
                    _old_read_exact(_Stepped("abcdéfgh", [2, 3]), want),
                )
        self.assertIsNone(EO._read_exact(io.BytesIO(b"abc"), 4))

    def test_edge_a_full_first_read_is_returned_as_is(self) -> None:
        data = b"z" * 1000
        self.assertEqual(EO._read_exact(io.BytesIO(data), 1000), data)
        self.assertEqual(EO._read_exact(io.BytesIO(b""), 0), b"")

    def test_edge_bytearray_and_memoryview_reads_still_give_bytes(self) -> None:
        for wrap in (bytearray, memoryview):
            for steps in ([100], [3, 4]):
                with self.subTest(wrap=wrap.__name__, steps=steps):
                    stream = _Stepped(wrap(b"0123456789"), steps)
                    got = EO._read_exact(stream, 10)
                    self.assertIs(type(got), bytes)
                    self.assertEqual(got, _old_read_exact(_Stepped(wrap(b"0123456789"), steps), 10))

    def test_happy_many_short_reads_stay_linear(self) -> None:
        data = b"x" * (4 * 1024 * 1024)
        start = time.perf_counter()
        got = EO._read_exact(_Stepped(data, [4096]), len(data))
        elapsed = time.perf_counter() - start
        self.assertEqual(len(got), len(data))
        self.assertLess(elapsed, 0.1)  # before: ~0.3 s with 4 KiB reads


if __name__ == "__main__":
    unittest.main()
