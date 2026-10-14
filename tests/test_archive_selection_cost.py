"""Partial extraction picks its members in O(path depth) per member.

Measured before: ``_is_selected`` compared each archive member against
every requested name, so selecting half of a 10 000-member archive took
2.7 s just to decide what to extract (``_resolve_selection`` had the
same shape). A member is a descendant of a requested directory iff one
of its own ``/``-prefixes is that name, so the check walks the member's
prefixes instead of the request list.

The reference functions below are verbatim copies of the code before
the change; the corpus test holds new == old.
"""

from __future__ import annotations

import random
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import archive as A  # noqa: E402


# --- verbatim reference (before the change) --------------------------------
def _old_is_selected(member_name: str, requested_norm: set[str]) -> bool:
    norm = A._norm_member(member_name)
    if norm in requested_norm:
        return True
    return any(norm.startswith(req + "/") for req in requested_norm)


def _old_resolve_selection(all_member_names, members):
    norm_all = {A._norm_member(n) for n in all_member_names}
    requested_norm = {A._norm_member(m) for m in members}

    def _matches(req_norm: str) -> bool:
        return req_norm in norm_all or any(other.startswith(req_norm + "/") for other in norm_all)

    missing = [m for m in members if not _matches(A._norm_member(m))]
    if missing:
        raise KeyError(f"requested member(s) not found in archive: {missing!r}")
    return requested_norm


def _rand_name(rng: random.Random) -> str:
    parts = [rng.choice(["a", "b", "ab", "a.b", "", "..", "d2"]) for _ in range(rng.randint(1, 4))]
    name = rng.choice(["/", "\\"]).join(parts)
    return rng.choice(["", "/"]) + name + rng.choice(["", "/", "//", "\\"])


class SelectionEquivalenceTest(unittest.TestCase):
    def test_happy_is_selected_equals_the_old_function(self) -> None:
        rng = random.Random(5)
        for _ in range(400):
            members = [_rand_name(rng) for _ in range(rng.randint(1, 15))]
            requested = {A._norm_member(_rand_name(rng)) for _ in range(rng.randint(1, 6))}
            for m in members:
                self.assertEqual(
                    A._is_selected(m, requested), _old_is_selected(m, requested), (m, requested)
                )

    def test_happy_resolve_selection_equals_the_old_function(self) -> None:
        rng = random.Random(6)
        for _ in range(400):
            members = [_rand_name(rng) for _ in range(rng.randint(1, 15))]
            requests = [_rand_name(rng) for _ in range(rng.randint(1, 4))]
            requests += rng.sample(members, k=min(2, len(members)))
            try:
                old = _old_resolve_selection(members, requests)
            except KeyError as exc:
                with self.assertRaises(KeyError) as cm:
                    A._resolve_selection(members, requests)
                self.assertEqual(str(cm.exception), str(exc))
            else:
                self.assertEqual(A._resolve_selection(members, requests), old)

    def test_sad_a_string_prefix_sibling_is_not_selected(self) -> None:
        self.assertFalse(A._is_selected("d2.txt", {"d"}))
        self.assertFalse(A._is_selected("dd/x", {"d"}))
        with self.assertRaises(KeyError):
            A._resolve_selection(["d2.txt"], ["d"])

    def test_edge_nested_and_root_like_requests(self) -> None:
        self.assertTrue(A._is_selected("a/b/c/d.txt", {"a/b"}))
        self.assertTrue(A._is_selected("a\\b\\c", {"a"}))
        self.assertTrue(A._is_selected("/abs/x", {""}))  # "/" normalises to ""
        self.assertFalse(A._is_selected("rel/x", {""}))
        self.assertEqual(A._resolve_selection(["a/b/c.txt"], ["a/", "a/b"]), {"a", "a/b"})


class SelectionCostTest(unittest.TestCase):
    def test_happy_half_of_a_large_archive_is_picked_quickly(self) -> None:
        names = [f"dir{i % 50}/f{i:06d}.txt" for i in range(10_000)]
        start = time.perf_counter()
        requested = A._resolve_selection(names, names[::2])
        picked = [n for n in names if A._is_selected(n, requested)]
        elapsed = time.perf_counter() - start
        self.assertEqual(len(picked), 5_000)
        self.assertLess(elapsed, 0.5)  # before: ~2.7 s


if __name__ == "__main__":
    unittest.main()
