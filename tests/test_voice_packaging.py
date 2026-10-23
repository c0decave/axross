"""Packaging of the voice feature: the pip extra, the resources, and the
axross-full bundle - which ships piper-tts (GPL-3.0-or-later, with
espeak-ng) and so carries the GPL-3 text and a written source offer.

Builds are not run here (disk); these tests hold the build files together.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import features as F  # noqa: E402

DOCKERFILE = (ROOT / "Dockerfile.build").read_text(encoding="utf-8")
SPEC = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
BUNDLE = (ROOT / "scripts" / "build_bundle.sh").read_text(encoding="utf-8")
LICENSES = (ROOT / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")
OFFER = ROOT / "build" / "licenses" / "voice" / "SOURCE-OFFER.txt"
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PINS = {"piper-tts": "1.8.0", "onnxruntime": "1.31.0", "faster-whisper": "1.2.1",
        "ctranslate2": "4.8.3"}


def _full_block() -> str:
    match = re.search(r'# Voice \(axross-full\).*?\n(?=# ---|\Z)', SPEC, re.S)
    assert match, "no voice block in the spec"
    return match.group(0)


def test_happy_the_builder_installs_the_pinned_voice_packages():
    for name, version in PINS.items():
        assert f'"{name}=={version}"' in DOCKERFILE, name


def test_happy_the_pins_meet_the_extras_floors():
    floors = dict(r.split(">=") for r in F.EXTRAS["voice"])
    assert floors == PINS


def test_happy_the_full_preflight_requires_piper_and_whisper():
    full = re.search(r"FULL_MODS=\((.*?)\n\)", BUNDLE, re.S).group(1)
    assert '"piper:' in full and '"faster_whisper:' in full


def test_happy_the_full_spec_collects_the_voice_packages_and_their_data():
    block = _full_block()
    assert 'if FLAVOR == "full":' in block
    for module in ("piper", "faster_whisper"):
        assert f'collect_submodules("{module}")' in block, module
    assert 'collect_data_files("piper"' in block and 'collect_data_files("faster_whisper")' in block
    assert 'collect_dynamic_libs("ctranslate2")' in block
    assert '"licenses/voice"' in block


def test_sad_slim_excludes_the_voice_packages():
    slim = re.search(r'if FLAVOR == "slim":\n    excludes \+= \[(.*?)\n    \]', SPEC, re.S)
    for module in ("piper", "faster_whisper", "ctranslate2", "onnxruntime"):
        assert f'"{module}"' in slim.group(1), module


def test_sad_a_full_build_without_the_gpl_text_stops():
    """The bundle may not ship piper without its licence: fail closed."""
    block = _full_block()
    assert "COPYING" in block and "raise SystemExit" in block


def test_happy_the_source_offer_names_exact_sources():
    text = OFFER.read_text(encoding="utf-8")
    assert "piper-tts 1.8.0" in text and "GPL-3.0-or-later" in text
    assert "https://github.com/OHF-voice/piper1-gpl/tree/v1.8.0" in text
    assert "724808c5a83f9ef95fdd0db886ba7ba537ff224a" in text
    assert "830588aded347df579c91a32703e0fc2a3685d84f1e3533b14f2de69135d4904" in text
    assert "three years" in text


def test_happy_the_licence_file_lists_the_voice_components():
    for line in ("| `[voice]` | piper-tts | GPL-3.0-or-later |",
                 "| `[voice]` | faster-whisper | MIT |",
                 "| `[voice]` | onnxruntime | MIT |",
                 "| `[voice]` | ctranslate2 | MIT |"):
        assert line in LICENSES, line
    assert "espeak-ng" in LICENSES and "SOURCE-OFFER.txt" in LICENSES


def test_edge_the_licence_file_names_the_pinned_versions():
    for name, version in PINS.items():
        assert f"{name} {version}" in LICENSES, name


def test_happy_the_lexicon_ships_with_pip_installs():
    tool = PYPROJECT["tool"]["setuptools"]
    assert "resources.voice" in tool["packages"]
    assert tool["package-data"]["resources.voice"] == ["*.txt"]
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include resources/voice *.txt" in manifest
    assert (ROOT / "resources" / "voice" / "__init__.py").exists()
