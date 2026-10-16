"""The lab test runner installs what pyproject names - minus what PyPI lacks.

tests/docker/Dockerfile.testrunner derives its pip requirement list from
pyproject.toml (every dependency, every optional extra). The ``sift``
extra names ``sift-summarizer``, which was not on PyPI until sift 0.1.95:
pip then stopped the image build with "No matching distribution found for
sift-summarizer>=0.1.86", and once a stranger registers such a name the
build would install the stranger's package instead. The derivation lives
in tests/docker/testrunner_requirements.py and leaves unpublished
packages out; these tests hold that rule and its wiring.
"""

from __future__ import annotations

import importlib.util
import tomllib
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCKER = REPO / "tests" / "docker"
SCRIPT = DOCKER / "testrunner_requirements.py"
EXPORT_SCRIPT = REPO / "scripts" / "export-public.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _meta() -> dict:
    with open(REPO / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]


class TestrunnerRequirementsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tr = _load("testrunner_requirements", SCRIPT)

    # -- happy -------------------------------------------------------------

    def test_happy_every_published_dependency_is_installed(self) -> None:
        meta = _meta()
        reqs = self.tr.requirements(meta)
        for dep in meta["dependencies"]:
            self.assertIn(dep, reqs)
        for extra, deps in meta["optional-dependencies"].items():
            for dep in deps:
                if self.tr.project_name(dep) in self.tr.UNPUBLISHED_DEPENDENCIES:
                    continue
                self.assertIn(dep, reqs, f"extra {extra!r}")

    def test_happy_base_dependencies_come_first_without_duplicates(self) -> None:
        meta = _meta()
        reqs = self.tr.requirements(meta)
        self.assertEqual(reqs[: len(meta["dependencies"])], list(meta["dependencies"]))
        self.assertEqual(len(reqs), len(set(reqs)))

    # -- sad ---------------------------------------------------------------

    def test_happy_the_published_sift_extra_is_installed(self) -> None:
        names = {self.tr.project_name(r) for r in self.tr.requirements(_meta())}
        self.assertIn("sift-summarizer", names)

    def test_sad_an_unpublished_package_is_never_installed(self) -> None:
        meta = dict(_meta())
        extras = dict(meta["optional-dependencies"], extra=["axross-unclaimed-helper>=1"])
        meta["optional-dependencies"] = extras
        reqs = self.tr.requirements(meta, unpublished=frozenset({"axross-unclaimed-helper"}))
        names = {self.tr.project_name(r) for r in reqs}
        self.assertNotIn("axross-unclaimed-helper", names)
        self.assertIn("pyqt6", names)  # only the unpublished one is left out

    def test_sad_main_refuses_a_missing_pyproject(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.tr.main([str(DOCKER / "no-such-pyproject.toml")])

    # -- edge --------------------------------------------------------------

    def test_edge_any_pep503_spelling_of_an_unpublished_name_is_dropped(self) -> None:
        meta = {
            "dependencies": ["PyQt6>=6.5"],
            "optional-dependencies": {
                "a": ["Sift_Summarizer[x]>=1", "sift.summarizer ; python_version>'3'"],
                "b": ["SIFT-summarizer==2", "requests>=2"],
                "all": ["requests>=2"],
            },
        }
        unpublished = frozenset({"sift-summarizer"})
        self.assertEqual(self.tr.requirements(meta, unpublished=unpublished),
                         ["PyQt6>=6.5", "requests>=2"])

    def test_edge_project_name_normalises_like_pep503(self) -> None:
        self.assertEqual(self.tr.project_name("psycopg[binary]>=3.1"), "psycopg")
        self.assertEqual(self.tr.project_name("Foo__Bar.baz ~= 1.0"), "foo-bar-baz")
        self.assertEqual(self.tr.project_name("x; sys_platform == 'win32'"), "x")

    def test_edge_dockerfile_derives_its_list_through_the_script(self) -> None:
        text = (DOCKER / "Dockerfile.testrunner").read_text(encoding="utf-8")
        self.assertIn("COPY tests/docker/testrunner_requirements.py", text)
        self.assertIn("python /tmp/testrunner_requirements.py pyproject.toml", text)

    @unittest.skipUnless(EXPORT_SCRIPT.exists(), "export tooling is not part of the public tree")
    def test_edge_unpublished_set_matches_the_public_mirror_gate(self) -> None:
        ep = _load("export_public", EXPORT_SCRIPT)
        self.assertEqual(self.tr.UNPUBLISHED_DEPENDENCIES, ep.UNPUBLISHED_DEPENDENCIES)


if __name__ == "__main__":
    unittest.main()
