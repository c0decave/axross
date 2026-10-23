"""Fetch models shows a drop-down with size, parameters, quantisation and
which model is loaded.

Operator: *„man kann zwar fetch models machen, bekommt aber keine drop down
auswahliste, mit größe und sieht auch nicht welches modell aktuell geladen
ist, bitte fixen"*

Before: ``_on_models`` (ui/llm_settings_dialog.py) put the bare names into
the editable model combo without opening it and said only "N model(s) on
the server" - no list in sight, no size, no load state.

The server shapes below follow the APIs' own documentation: Ollama
``/api/tags`` (size, details.parameter_size, details.quantization_level)
and ``/api/ps``; LM Studio ``/api/v1/models`` (key, size_bytes,
params_string, quantization.name, loaded_instances, max_context_length)
and ``/api/v0/models`` (id, state, quantization, max_context_length, no
size); llama.cpp ``/v1/models`` (meta.n_params, meta.size,
meta.n_ctx_train); a plain OpenAI-compatible ``/v1/models`` (ids only).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent as A  # noqa: E402
from core import llm_profiles as LP  # noqa: E402

GB = 1 << 30


class _Routes:
    """An HTTP server answering GET per path: {path: (status, json object)};
    any other path is a 404."""

    def __init__(self, routes: dict, headers: dict | None = None):
        self.routes = routes
        self.headers = headers or {}
        self.seen: list[tuple[str, dict]] = []

    def __enter__(self):
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                state.seen.append((self.path, dict(self.headers)))
                status, obj = state.routes.get(self.path, (404, {"error": "not found"}))
                body = json.dumps(obj).encode()
                self.send_response(status)
                for k, v in state.headers.get(self.path, {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()
        return False

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_address[1]}"

    def paths(self) -> list[str]:
        return [p for p, _h in self.seen]


def _ollama_routes(ps=(200, None)):
    tags = {"models": [
        {"name": "qwen2.5:7b", "model": "qwen2.5:7b", "size": 4_683_087_332,
         "details": {"family": "qwen2", "parameter_size": "7.6B", "quantization_level": "Q4_K_M"}},
        {"name": "llama3.2:1b", "model": "llama3.2:1b", "size": 1_321_098_329,
         "details": {"family": "llama", "parameter_size": "1.2B", "quantization_level": "Q8_0"}},
    ]}
    status, body = ps
    if body is None:
        body = {"models": [{"name": "qwen2.5:7b", "model": "qwen2.5:7b", "size": 6_000_000_000,
                            "size_vram": 6_000_000_000, "context_length": 8192}]}
    return {"/api/tags": (200, tags), "/api/ps": (status, body)}


def _ollama(url):
    return LP.LLMProfile(name="o", provider="ollama", endpoint=url)


def _compat(url, provider="lmstudio"):
    return LP.LLMProfile(name="l", provider=provider, endpoint=url + "/v1")


V1_IDS = {"/v1/models": (200, {"object": "list", "data": [
    {"id": "qwen/qwen3-4b", "object": "model"},
    {"id": "google/gemma-3-12b", "object": "model"},
]})}

LMSTUDIO_V1 = {"/api/v1/models": (200, {"models": [
    {"type": "llm", "publisher": "qwen", "key": "qwen/qwen3-4b", "display_name": "Qwen3 4B",
     "quantization": {"name": "Q4_K_M", "bits_per_weight": 4}, "size_bytes": 2_497_281_920,
     "params_string": "4B", "loaded_instances": [{"id": "qwen/qwen3-4b",
                                                 "config": {"context_length": 4096}}],
     "max_context_length": 262144, "format": "gguf"},
    {"type": "llm", "publisher": "google", "key": "google/gemma-3-12b",
     "quantization": {"name": "Q3_K_L", "bits_per_weight": 3}, "size_bytes": 6_960_000_000,
     "params_string": "12B", "loaded_instances": [], "max_context_length": 131072,
     "format": "gguf"},
]})}

LMSTUDIO_V0 = {"/api/v0/models": (200, {"object": "list", "data": [
    {"id": "qwen/qwen3-4b", "object": "model", "type": "llm", "publisher": "qwen",
     "arch": "qwen3", "compatibility_type": "gguf", "quantization": "Q4_K_M",
     "state": "loaded", "max_context_length": 262144},
    {"id": "google/gemma-3-12b", "object": "model", "type": "llm", "publisher": "google",
     "arch": "gemma3", "compatibility_type": "gguf", "quantization": "Q3_K_L",
     "state": "not-loaded", "max_context_length": 131072},
]})}

LLAMA_CPP = {"/v1/models": (200, {"object": "list", "data": [
    {"id": "qwen2.5-1.5b-instruct-q4_k_m.gguf", "object": "model", "owned_by": "llamacpp",
     "meta": {"vocab_type": 2, "n_vocab": 151936, "n_ctx_train": 32768, "n_embd": 1536,
              "n_params": 1_543_714_304, "size": 1_117_320_736}},
]})}


class ModelInventoryTest(unittest.TestCase):
    def test_happy_ollama_sizes_parameters_quantisation_and_the_loaded_one(self) -> None:
        with _Routes(_ollama_routes()) as srv:
            got = A.model_inventory(_ollama(srv.url), "")
        self.assertEqual([e.id for e in got], ["qwen2.5:7b", "llama3.2:1b"])
        qwen, llama = got
        self.assertEqual((qwen.size, qwen.parameters, qwen.quantization, qwen.loaded),
                         (4_683_087_332, "7.6B", "Q4_K_M", True))
        self.assertEqual((llama.size, llama.parameters, llama.quantization, llama.loaded),
                         (1_321_098_329, "1.2B", "Q8_0", False))
        self.assertEqual(srv.paths(), ["/api/tags", "/api/ps"])

    def test_happy_lmstudio_api_v1_gives_size_and_loaded_instances(self) -> None:
        with _Routes({**V1_IDS, **LMSTUDIO_V1, **LMSTUDIO_V0}) as srv:
            got = A.model_inventory(_compat(srv.url), "sk-1")
        qwen, gemma = got
        self.assertEqual((qwen.id, qwen.size, qwen.parameters, qwen.quantization, qwen.loaded,
                          qwen.context),
                         ("qwen/qwen3-4b", 2_497_281_920, "4B", "Q4_K_M", True, 262144))
        self.assertEqual((gemma.size, gemma.loaded, gemma.parameters), (6_960_000_000, False, "12B"))
        # v1 says everything: v0 is not asked; the key went with each request.
        self.assertNotIn("/api/v0/models", srv.paths())
        self.assertTrue(all(h.get("Authorization") == "Bearer sk-1" for _p, h in srv.seen))

    def test_happy_lmstudio_without_api_v1_falls_back_to_v0_state(self) -> None:
        with _Routes({**V1_IDS, **LMSTUDIO_V0}) as srv:
            got = A.model_inventory(_compat(srv.url), "")
        qwen, gemma = got
        self.assertEqual((qwen.loaded, qwen.quantization, qwen.context, qwen.size),
                         (True, "Q4_K_M", 262144, None))
        self.assertEqual((gemma.loaded, gemma.quantization), (False, "Q3_K_L"))
        self.assertEqual(srv.paths(), ["/v1/models", "/api/v1/models", "/api/v0/models"])

    def test_happy_lmstudio_run_as_provider_openai_is_asked_too(self) -> None:
        # The "openai" provider's default endpoint is LM Studio's port.
        with _Routes({**V1_IDS, **LMSTUDIO_V1}) as srv:
            got = A.model_inventory(_compat(srv.url, provider="openai"), "")
        self.assertEqual(got[0].size, 2_497_281_920)

    def test_happy_llama_cpp_meta_gives_size_and_parameter_count(self) -> None:
        with _Routes(LLAMA_CPP) as srv:
            (entry,) = A.model_inventory(_compat(srv.url, provider="openai"), "")
        self.assertEqual((entry.size, entry.parameters, entry.context, entry.loaded),
                         (1_117_320_736, "1.5B", 32768, None))

    def test_edge_lmstudio_v1_naming_none_of_the_models_falls_back_to_v0(self) -> None:
        other = {"/api/v1/models": (200, {"models": [{"key": "something/else",
                                                      "size_bytes": 1, "loaded_instances": []}]})}
        with _Routes({**V1_IDS, **other, **LMSTUDIO_V0}) as srv:
            got = A.model_inventory(_compat(srv.url), "")
        self.assertEqual([(e.loaded, e.size) for e in got], [(True, None), (False, None)])

    def test_edge_a_remote_openai_api_is_not_asked_lm_studio_endpoints(self) -> None:
        with _Routes({**V1_IDS, **LMSTUDIO_V1}) as srv, \
                mock.patch.object(LP.LLMProfile, "is_remote", return_value=True):
            got = A.model_inventory(_compat(srv.url, provider="openai"), "sk-1")
        self.assertEqual(srv.paths(), ["/v1/models"])
        self.assertEqual([e.size for e in got], [None, None])

    def test_edge_small_parameter_counts_are_not_rounded_to_zero(self) -> None:
        body = {"/v1/models": (200, {"data": [
            {"id": "tiny", "meta": {"n_params": 135_000_000}},
            {"id": "toy", "meta": {"n_params": 400_000}},
        ]})}
        with _Routes(body) as srv:
            got = A.model_inventory(_compat(srv.url, provider="openai"), "")
        self.assertEqual([e.parameters for e in got], ["135M", "400000"])

    def test_edge_plain_openai_server_reports_ids_only(self) -> None:
        with _Routes(V1_IDS) as srv:
            got = A.model_inventory(_compat(srv.url, provider="openai"), "")
        self.assertEqual([(e.id, e.size, e.loaded, e.parameters) for e in got],
                         [("qwen/qwen3-4b", None, None, ""), ("google/gemma-3-12b", None, None, "")])

    def test_sad_ollama_without_api_ps_keeps_the_sizes_and_says_unknown(self) -> None:
        with _Routes(_ollama_routes(ps=(500, {"error": "boom"}))) as srv:
            got = A.model_inventory(_ollama(srv.url), "")
        self.assertEqual([e.loaded for e in got], [None, None])
        self.assertEqual(got[0].size, 4_683_087_332)

    def test_sad_lmstudio_v1_answering_an_error_falls_back_to_v0(self) -> None:
        routes = {**V1_IDS, **LMSTUDIO_V0,
                  "/api/v1/models": (200, {"error": "Unexpected endpoint or method."})}
        with _Routes(routes) as srv:
            got = A.model_inventory(_compat(srv.url), "")
        self.assertEqual([e.loaded for e in got], [True, False])

    def test_sad_the_listing_itself_failing_is_an_error_as_before(self) -> None:
        p = LP.LLMProfile(name="x", provider="openai", endpoint="http://127.0.0.1:9/v1")
        with self.assertRaisesRegex(A.AgentError, "cannot reach"):
            A.model_inventory(p, "")

    def test_sad_a_redirect_on_an_extra_request_is_not_followed(self) -> None:
        with _Routes({}) as trap:
            routes = {**V1_IDS, "/api/v1/models": (302, {}), "/api/v0/models": (302, {})}
            headers = {"/api/v1/models": {"Location": trap.url + "/steal"},
                       "/api/v0/models": {"Location": trap.url + "/steal"}}
            with _Routes(routes, headers) as srv:
                got = A.model_inventory(_compat(srv.url), "sk-secret")
            self.assertEqual(trap.seen, [])
        self.assertEqual([e.loaded for e in got], [None, None])

    def test_edge_nonsense_numbers_and_types_are_not_shown_as_sizes(self) -> None:
        tags = {"models": [
            {"name": "a", "size": True, "details": {"parameter_size": 7, "quantization_level": 4}},
            {"name": "b", "size": -5, "details": "junk"},
            {"name": "c", "size": "big"},
            {"name": "d", "size": 0},
        ]}
        with _Routes({"/api/tags": (200, tags), "/api/ps": (200, {"models": "junk"})}) as srv:
            got = A.model_inventory(_ollama(srv.url), "")
        self.assertEqual([(e.size, e.parameters, e.quantization, e.loaded) for e in got],
                         [(None, "", "", None), (None, "", "", None), (None, "", "", None),
                          (0, "", "", None)])

    def test_edge_ollama_loaded_matches_by_name_or_model(self) -> None:
        ps = {"models": [{"model": "llama3.2:1b"}]}
        with _Routes(_ollama_routes(ps=(200, ps))) as srv:
            got = A.model_inventory(_ollama(srv.url), "")
        self.assertEqual([e.loaded for e in got], [False, True])

    def test_edge_list_models_still_returns_names(self) -> None:
        with _Routes(_ollama_routes()) as srv:
            self.assertEqual(A.list_models(_ollama(srv.url), ""), ["qwen2.5:7b", "llama3.2:1b"])


class ModelLabelTest(unittest.TestCase):
    def test_happy_label_has_size_parameters_quantisation_and_loaded(self) -> None:
        from ui.llm_settings_dialog import model_label

        text = model_label(A.ModelEntry("qwen2.5:7b", size=4_683_087_332, parameters="7.6B",
                                        quantization="Q4_K_M", loaded=True))
        self.assertTrue(text.startswith("qwen2.5:7b"))
        for part in ("4.4 GB", "7.6B", "Q4_K_M", "loaded"):
            self.assertIn(part, text)

    def test_edge_no_size_says_so_and_never_invents_one(self) -> None:
        from ui.llm_settings_dialog import model_label

        text = model_label(A.ModelEntry("m"))
        self.assertIn("size not reported", text)
        self.assertNotIn("loaded", text)
        self.assertNotIn("GB", text)


class FetchModelsDialogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def _wait(self, cond, seconds=10.0) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if cond():
                return
            time.sleep(0.02)
        self.fail("condition not reached")

    def _dialog(self, provider: str, endpoint: str):
        from ui.llm_settings_dialog import LLMSettingsDialog

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patch = mock.patch.object(LP, "get_api_key", return_value="")
        patch.start()
        self.addCleanup(patch.stop)
        d = LLMSettingsDialog(settings_path=Path(tmp.name) / "llm.json")
        self.addCleanup(d.deleteLater)
        d.show()
        d.add_profile()
        d.name_edit.setText("local")
        d.provider_combo.setCurrentText(provider)
        d.endpoint_edit.setText(endpoint)
        return d

    def _close_popup(self, d) -> None:
        d.model_combo.hidePopup()
        self.app.processEvents()

    def test_e2e_fetch_opens_the_drop_down_with_sizes_and_the_loaded_model(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        from ui.llm_settings_dialog import MODEL_LABEL_ROLE

        with _Routes(_ollama_routes()) as srv:
            d = self._dialog("ollama", srv.url)
            QTest.mouseClick(d.fetch_button, Qt.MouseButton.LeftButton)
            self._wait(lambda: d.model_combo.count() == 2)
        combo = d.model_combo
        self.assertTrue(combo.view().isVisible(), "the drop-down did not open")
        self.assertEqual([combo.itemText(i) for i in range(2)], ["qwen2.5:7b", "llama3.2:1b"])
        first = combo.itemData(0, MODEL_LABEL_ROLE)
        self.assertIn("4.4 GB", first)
        self.assertIn("loaded", first)
        self.assertNotIn("loaded", combo.itemData(1, MODEL_LABEL_ROLE))
        status = d.status_label.text()
        self.assertIn("2 model(s)", status)
        self.assertIn("qwen2.5:7b", status.split("Loaded now:")[1])
        # A click in the list picks the model id, not the label.
        view = combo.view()
        rect = view.visualRect(view.model().index(1, 0))
        QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
        self._wait(lambda: not view.isVisible())
        self.assertEqual(combo.currentText(), "llama3.2:1b")
        self.assertEqual(d._current.model, "llama3.2:1b")

    def test_e2e_the_drop_down_paints_the_label(self) -> None:
        from PyQt6.QtWidgets import QStyleOptionViewItem

        with _Routes(_ollama_routes()) as srv:
            d = self._dialog("ollama", srv.url)
            d.fetch_models()
            self._wait(lambda: d.model_combo.count() == 2)
        self._close_popup(d)
        view = d.model_combo.view()
        option = QStyleOptionViewItem()
        view.itemDelegate().initStyleOption(option, view.model().index(0, 0))
        self.assertIn("Q4_K_M", option.text)
        self.assertIn("7.6B", option.text)

    def test_e2e_ids_only_server_says_size_not_reported(self) -> None:
        from ui.llm_settings_dialog import MODEL_LABEL_ROLE

        with _Routes(V1_IDS) as srv:
            d = self._dialog("openai", srv.url + "/v1")
            d.fetch_models()
            self._wait(lambda: d.model_combo.count() == 2)
        self._close_popup(d)
        self.assertIn("size not reported", d.model_combo.itemData(0, MODEL_LABEL_ROLE))
        status = d.status_label.text()
        self.assertIn("does not report which model is loaded", status)
        self.assertIn("does not report sizes", status)

    def test_sad_a_failed_fetch_opens_nothing_and_keeps_the_model(self) -> None:
        d = self._dialog("openai", "http://127.0.0.1:9/v1")
        d.model_combo.setEditText("kept-model")
        d.fetch_models()
        self._wait(lambda: "cannot reach" in d.status_label.text())
        self.assertFalse(d.model_combo.view().isVisible())
        self.assertEqual(d.model_combo.currentText(), "kept-model")

    def test_edge_an_empty_list_opens_no_drop_down(self) -> None:
        with _Routes({"/v1/models": (200, {"data": []})}) as srv:
            d = self._dialog("openai", srv.url + "/v1")
            d.fetch_models()
            self._wait(lambda: "0 model(s)" in d.status_label.text())
        self.assertFalse(d.model_combo.view().isVisible())

    def test_edge_the_typed_model_stays_after_the_fetch(self) -> None:
        with _Routes(_ollama_routes()) as srv:
            d = self._dialog("ollama", srv.url)
            d.model_combo.setEditText("llama3.2:1b")
            d.fetch_models()
            self._wait(lambda: d.model_combo.count() == 2)
        self._close_popup(d)
        self.assertEqual(d.model_combo.currentText(), "llama3.2:1b")
        self.assertEqual(d._current.model, "llama3.2:1b")


if __name__ == "__main__":
    unittest.main()
