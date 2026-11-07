"""What the supply-chain review of the dependencies found and axross guards
against (security/supply_chain_baseline/):

* onnxruntime carries Microsoft's telemetry client, on by default
  (mobile.events.data.microsoft.com): axross turns it off in every process
  that can load onnxruntime.
* impacket: importing ``impacket.examples`` replaces
  ``ssl.create_default_context`` for the whole process with one that checks
  no certificate; axross must never import it.
"""

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_happy_the_voice_child_starts_with_onnx_telemetry_off(monkeypatch):
    from core import voice_worker as VW

    captured = {}

    class FakePopen:
        def __init__(self, cmd, **kw):
            captured.update(kw["env"])
            self.stdin = self.stdout = None
            self.pid = 1

        def poll(self):
            return None

    monkeypatch.setattr(VW.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(VW, "_LineReader", lambda: None)
    worker = VW.VoiceWorker.__new__(VW.VoiceWorker)
    worker._command = ["python"]
    VW.VoiceWorker._start(worker)
    assert captured["ORT_DISABLE_TELEMETRY"] == "1"


def test_happy_the_child_calls_onnxruntimes_own_switch(monkeypatch):
    from core import voice_worker as VW

    calls = []
    monkeypatch.setitem(sys.modules, "onnxruntime",
                        types.SimpleNamespace(disable_telemetry_events=lambda: calls.append(1)))
    monkeypatch.delenv("ORT_DISABLE_TELEMETRY", raising=False)
    VW.disable_onnx_telemetry()
    assert calls == [1]
    import os
    assert os.environ["ORT_DISABLE_TELEMETRY"] == "1"


def test_happy_main_turns_onnx_telemetry_off_first():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    body = source[source.index("def main() -> int:"):]
    assert body.index('os.environ["ORT_DISABLE_TELEMETRY"] = "1"') < body.index("QApplication")


def test_sad_no_module_imports_impacket_examples():
    hits = []
    for top in ("core", "ui", "resources", "models", "axross"):
        for path in sorted((ROOT / top).rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names = []
                if isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
                elif isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                if any(n == "impacket.examples" or n.startswith("impacket.examples.") for n in names):
                    hits.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert hits == [], hits
