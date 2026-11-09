"""The sdist must not carry operator-only documents.

``recursive-include docs *.md`` picked up every Markdown file in the work
tree, tracked or not: an untracked docs/FEEDBACK_HANDOFF_2026-10-31.md
reached an sdist built from a working copy, as only HANDOFF, BACKLOG, the
plans and the review report were excluded by name. docs/ is an allow-list
in MANIFEST.in now, held against the tracked public documents below.

setuptools also adds every ``tests/test*.py`` by default
(``_distutils/command/sdist.py``), so a private test file reached every
sdist up to 0.7.6. ``BuiltSdistTest`` builds the real sdist and holds it
against the mirror's own exclude list.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: no lock, and no parallel builds to guard against
    fcntl = None

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPORT_SCRIPT = REPO_ROOT / "scripts" / "export-public.py"
SCRUB_RULES = REPO_ROOT / "scripts" / "_scrub_rules.py"
IDENTITY_RULES = {"operator-email", "operator-handle"}
PRIVATE = (
    "docs/HANDOFF.md",
    "docs/BACKLOG.md",
    "docs/plans/2026-roadmap.md",
    "docs/SECURITY-REVIEW-2026-10.md",
    # Untracked notes of any name, as an operator leaves them in docs/.
    "docs/FEEDBACK_HANDOFF_2026-10-31.md",
    "docs/NOTES.md",
    "docs/USAGE_notes.md",
    "docs/patterns/draft.md",
    "docs/private/anything.md",
)
PUBLIC = ("docs/USAGE.md", "docs/PROXY_SUPPORT.md", "docs/mcp-tools.json")
#: Tracked documents that are operator-only (the public mirror drops them too).
OPERATOR_DOCS = {"docs/HANDOFF.md", "docs/BACKLOG.md", "docs/SECURITY-REVIEW-2026-10.md"}


def _manifest_lines() -> list[list[str]]:
    lines = (REPO_ROOT / "MANIFEST.in").read_text().splitlines()
    return [line.split() for line in lines if line.strip() and not line.lstrip().startswith("#")]


#: The docs/ lines of MANIFEST.in (argv[1]) applied to the files under the
#: current folder; prints what they take.
_DOCS_FILTER = """
import os
import sys
from setuptools._distutils.filelist import FileList
files = FileList()
files.findall()
for line in open(sys.argv[1], encoding="utf-8").read().splitlines():
    line = line.strip()
    if line.startswith(("recursive-include docs", "prune docs", "exclude docs",
                        "include docs", "graft docs", "global-")):
        files.process_template_line(line)
print("\\n".join(f.replace(os.sep, "/") for f in files.files))
"""


def _sdist_docs() -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        for rel in (*PRIVATE, *PUBLIC):
            path = Path(tmp, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")
        # In a child: setuptools' distutils shim asserts when the stdlib
        # distutils was imported first in this process (some test modules
        # of the suite do; seen in a full -n run), as in test_pypi_packaging.
        out = subprocess.run(
            [sys.executable, "-c", _DOCS_FILTER, str(REPO_ROOT / "MANIFEST.in")],
            cwd=tmp, capture_output=True, text=True, check=True, timeout=120,
        ).stdout
        return set(out.split())


class SdistManifestTest(unittest.TestCase):
    def test_public_docs_are_included(self) -> None:
        included = _sdist_docs()
        for rel in PUBLIC:
            self.assertIn(rel, included)

    def test_operator_only_docs_are_excluded(self) -> None:
        included = _sdist_docs()
        for rel in PRIVATE:
            self.assertNotIn(rel, included)

    def test_happy_the_allow_list_is_every_tracked_public_document(self) -> None:
        """A tracked docs/ file is listed in MANIFEST.in, or operator-only."""
        try:
            out = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "ls-files", "-z", "docs"],
                capture_output=True, check=True, timeout=60,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            self.skipTest("not a git checkout (an unpacked sdist)")
        public = {
            rel for rel in out.decode("utf-8").split("\0")
            if rel.endswith((".md", ".json")) and not rel.startswith("docs/plans/")
            and rel not in OPERATOR_DOCS
        }
        if not public:
            self.skipTest("not a git checkout (an unpacked sdist)")
        listed = {
            word for words in _manifest_lines() if words[0] == "include"
            for word in words[1:] if word.startswith("docs/")
        }
        self.assertEqual(sorted(public - listed), [], "public docs missing from MANIFEST.in")
        self.assertEqual(sorted(listed - public), [], "MANIFEST.in names untracked or private docs")

    def test_sad_no_pattern_over_docs_is_back(self) -> None:
        """A glob over docs/ would take an operator's untracked notes again."""
        for words in _manifest_lines():
            command, args = words[0], words[1:]
            if command in ("recursive-include", "graft"):
                self.assertFalse(args[0].startswith("docs"), " ".join(words))
            elif command == "include":
                for word in args:
                    if word.startswith("docs"):
                        self.assertNotRegex(word, r"[*?\[]", " ".join(words))
            self.assertNotEqual(command, "global-include", " ".join(words))

    def test_mirror_excludes_the_security_report(self) -> None:
        script = REPO_ROOT / "scripts" / "export-public.py"
        if not script.exists():
            self.skipTest("export tooling is not part of the public tree")
        text = script.read_text()
        self.assertIn('"docs/SECURITY-REVIEW-2026-10.md"', text)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private_members(members: list[str], prefixes: tuple[str, ...]) -> list[str]:
    """Members (``<name>-<version>/<path>``) the public mirror would drop.

    Same matching as ``export-public.py``: exact path or prefix.
    """
    rels = (m.split("/", 1)[1] for m in members if "/" in m)
    return sorted(r for r in rels if any(r == p or r.startswith(p) for p in prefixes))


@unittest.skipUnless(EXPORT_SCRIPT.exists(), "export tooling is not part of the public tree")
class BuiltSdistTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # PyPA build (dev-requirements.txt). Not this tree's build/ folder,
        # which a bare "build" also finds: it has no __main__.
        if importlib.util.find_spec("build.__main__") is None:
            raise unittest.SkipTest("PyPA build is not installed (dev-requirements.txt)")
        cls.prefixes = _load(EXPORT_SCRIPT, "export_public").MIRROR_EXCLUDE_PREFIXES
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        # --no-isolation: this environment's setuptools builds it, so it has
        # to meet pyproject's build-system floor (dev-requirements.txt).
        # One build of this tree at a time: setuptools assembles the sdist in
        # an axross-<version>/ folder inside the tree, and pytest-xdist runs
        # this class's tests on several workers, each with its own
        # setUpClass - two builds at once deleted each other's files.
        lock_path = Path(tempfile.gettempdir()) / (
            "axross-sdist-" + hashlib.sha256(str(REPO_ROOT).encode()).hexdigest()[:16] + ".lock")
        with open(lock_path, "w") as lock:
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_EX)
            built = subprocess.run(
                [sys.executable, "-m", "build", "--sdist", "--no-isolation",
                 "--outdir", tmp.name, str(REPO_ROOT)],
                capture_output=True,
                text=True,
            )
        if built.returncode:
            raise AssertionError(f"the sdist build failed:\n{built.stdout[-3000:]}"
                                 f"{built.stderr[-3000:]}")
        (sdist,) = Path(tmp.name).glob("*.tar.gz")
        cls.sdist = sdist
        with tarfile.open(sdist) as tar:
            cls.members = tar.getnames()
            cls.texts = {
                m.name: tar.extractfile(m).read().decode("utf-8", "replace")
                for m in tar.getmembers()
                if m.isfile() and m.size < 4_000_000
            }

    def test_happy_no_mirror_excluded_file_is_in_the_sdist(self) -> None:
        self.assertEqual(_private_members(self.members, self.prefixes), [])

    def test_happy_public_tests_are_still_shipped(self) -> None:
        rels = {m.split("/", 1)[1] for m in self.members if "/" in m}
        self.assertIn("tests/test_sdist_manifest.py", rels)
        self.assertIn("tests/test_packaging.py", rels)

    def test_happy_the_suite_ships_with_what_it_imports_and_reads(self) -> None:
        """Every tracked file of tests/ the mirror publishes - helper modules,
        fixtures, tests/integration, the lab files - plus the scripts,
        Dockerfiles and workflows the tests read. Without the helpers,
        collecting the sdist's suite failed in 238 modules. build/ cannot be
        in an sdist (setuptools prunes its build_base): its tests skip."""
        rels = {m.split("/", 1)[1] for m in self.members if "/" in m}
        tracked = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z", "--", "tests", "scripts",
             "Dockerfile.*", ".github/workflows"],
            capture_output=True, check=True,
        ).stdout.decode().split("\0")
        wanted = {
            p for p in tracked
            if p and not any(p == e or p.startswith(e) for e in self.prefixes)
        }
        self.assertIn("tests/fixtures/mcp/registry_time.json", wanted)
        self.assertEqual(sorted(wanted - rels), [])
        self.assertFalse([r for r in rels if r.startswith("build/")])

    @unittest.skipUnless(os.environ.get("AXROSS_TEST_SDIST_COLLECT"),
                         "set AXROSS_TEST_SDIST_COLLECT=1 to collect the sdist's suite (~2 min)")
    def test_happy_the_sdist_suite_collects(self) -> None:
        """``pytest --collect-only`` in the unpacked sdist: no errors."""
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(self.sdist) as tar:
                tar.extractall(tmp, filter="data")
            (root,) = Path(tmp).iterdir()
            done = subprocess.run(
                [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--collect-only",
                 "-q"],
                cwd=root, capture_output=True, text=True, timeout=1800,
            )
        errors = [line for line in done.stdout.splitlines() if line.startswith("ERROR")]
        self.assertEqual(errors, [], done.stdout[-3000:])
        self.assertEqual(done.returncode, 0, done.stdout[-3000:])

    @unittest.skipUnless(SCRUB_RULES.exists(), "scrub rules are not part of the public tree")
    def test_sad_no_operator_identity_in_any_sdist_file(self) -> None:
        find_leaks = _load(SCRUB_RULES, "scrub_rules").find_leaks
        hits = {
            name: found
            for name, text in self.texts.items()
            if (found := IDENTITY_RULES & set(find_leaks(text, include_paths=False)))
        }
        self.assertEqual(hits, {})

    def test_sad_the_checker_reports_private_members(self) -> None:
        members = [
            "axross-1.0/tests/test_internal_tool.py",
            "axross-1.0/docs/plans/x.md",
            "axross-1.0/core/ram_fs.py",
            "axross-1.0/",
        ]
        self.assertEqual(
            _private_members(members, ("tests/test_internal_tool.py", "docs/plans/")),
            ["docs/plans/x.md", "tests/test_internal_tool.py"],
        )

    def test_edge_every_private_test_path_is_excluded_even_when_untracked(self) -> None:
        """Each ``tests/`` entry of the mirror list, present as a file, stays out.

        The real build only sees files that exist here; this covers the
        others, through the same defaults + MANIFEST.in processing.
        """
        from setuptools._distutils.filelist import FileList

        private = [
            p + "x.py" if p.endswith("_") else p for p in self.prefixes if p.startswith("tests/")
        ]
        public = ["tests/test_packaging.py", "tests/test_peers.py"]
        self.assertTrue(private)
        with tempfile.TemporaryDirectory() as tmp:
            for rel in (*private, *public):
                Path(tmp, rel).parent.mkdir(parents=True, exist_ok=True)
                Path(tmp, rel).write_text("x")
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                files = FileList()
                files.findall()
                files.process_template_line("include tests/test*.py")  # setuptools default
                # In order, as setuptools reads it: a graft of tests/ comes
                # before the exclusions.
                for line in (REPO_ROOT / "MANIFEST.in").read_text().splitlines():
                    commands = ("graft", "exclude", "prune", "global-exclude",
                                "recursive-exclude")
                    if line.strip().startswith(commands):
                        files.process_template_line(line.strip())
                included = {f.replace(os.sep, "/") for f in files.files}
            finally:
                os.chdir(cwd)
        self.assertEqual(sorted(set(private) & included), [])
        self.assertEqual(sorted(set(public) & included), sorted(public))

    def test_edge_the_checker_matches_like_the_mirror_export(self) -> None:
        members = ["a-1/tests/test_ops_x.py", "a-1/tests/test_opsx.py", "a-1/tests/test_op.py"]
        self.assertEqual(_private_members(members, ("tests/test_ops_",)), ["tests/test_ops_x.py"])
        self.assertEqual(_private_members([], self.prefixes), [])


if __name__ == "__main__":
    unittest.main()
