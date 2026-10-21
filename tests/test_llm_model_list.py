"""Listing a server's models needs no sift: the agent and the profile
dialog ask the server themselves. Reported: a build without sift said
"sift is not installed" when listing models for the agent."""

from __future__ import annotations

import json
import os
import sys
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
from tests.fake_llm_server import FakeOllama  # noqa: E402

#: sys.modules entries that make ``import sift`` fail, as in a build without it.
NO_SIFT = {"sift": None, "sift.config": None, "sift.llm": None}


class _Server:
    """An HTTP server answering GET with a fixed (status, body, headers)."""

    def __init__(self, status=200, body=b"", headers=()):
        self.status, self.body, self.headers = status, body, list(headers)
        self.seen: list[tuple[str, dict]] = []

    def __enter__(self):
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                state.seen.append((self.path, dict(self.headers)))
                self.send_response(state.status)
                for k, v in state.headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(state.body)))
                self.end_headers()
                self.wfile.write(state.body)

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


def _json(obj) -> bytes:
    return json.dumps(obj).encode()


class ListModelsTest(unittest.TestCase):
    def test_happy_ollama_models_without_sift(self) -> None:
        with FakeOllama() as srv, mock.patch.dict(sys.modules, NO_SIFT):
            names = A.list_models(LP.LLMProfile(name="o", endpoint=srv.url), "")
        self.assertEqual(names, ["demo:latest", "other:7b"])

    def test_happy_openai_compatible_models_and_the_key_is_sent(self) -> None:
        body = _json({"data": [{"id": "qwen2.5"}, {"id": "llama3"}]})
        with _Server(body=body) as srv, mock.patch.dict(sys.modules, NO_SIFT):
            p = LP.LLMProfile(name="l", provider="lmstudio", endpoint=srv.url + "/v1")
            names = A.list_models(p, "sk-1")
        self.assertEqual(names, ["qwen2.5", "llama3"])
        path, headers = srv.seen[0]
        self.assertEqual(path, "/v1/models")
        self.assertEqual(headers.get("Authorization"), "Bearer sk-1")

    def test_edge_ollama_endpoint_given_with_v1_still_asks_api_tags(self) -> None:
        with FakeOllama() as srv:
            names = A.list_models(LP.LLMProfile(name="o", endpoint=srv.url + "/v1/"), "")
        self.assertEqual(names, ["demo:latest", "other:7b"])

    def test_edge_no_key_sends_no_authorization(self) -> None:
        with _Server(body=_json({"data": []})) as srv:
            p = LP.LLMProfile(name="l", provider="openai", endpoint=srv.url + "/v1")
            self.assertEqual(A.list_models(p, ""), [])
        self.assertNotIn("Authorization", srv.seen[0][1])

    def test_edge_entries_without_a_name_are_skipped(self) -> None:
        body = _json({"data": [{"id": ""}, {"object": "model"}, {"id": "m"}, "junk"]})
        with _Server(body=body) as srv:
            p = LP.LLMProfile(name="l", provider="openai", endpoint=srv.url + "/v1")
            self.assertEqual(A.list_models(p, ""), ["m"])

    def test_sad_unreachable_server(self) -> None:
        p = LP.LLMProfile(name="x", provider="openai", endpoint="http://127.0.0.1:9/v1")
        with self.assertRaisesRegex(A.AgentError, "cannot reach"):
            A.list_models(p, "")

    def test_sad_http_error_names_the_status(self) -> None:
        with _Server(status=500, body=b"boom") as srv:
            p = LP.LLMProfile(name="x", provider="openai", endpoint=srv.url + "/v1")
            with self.assertRaisesRegex(A.AgentError, "HTTP 500"):
                A.list_models(p, "")

    def test_sad_not_json(self) -> None:
        with _Server(body=b"<html>hi</html>") as srv:
            p = LP.LLMProfile(name="x", provider="openai", endpoint=srv.url + "/v1")
            with self.assertRaisesRegex(A.AgentError, "did not answer JSON"):
                A.list_models(p, "")

    def test_sad_a_200_carrying_an_error_is_an_error(self) -> None:
        # LM Studio on a wrong path answers 200 {"error": "Unexpected endpoint ..."}.
        body = _json({"error": "Unexpected endpoint or method. (GET /models)"})
        with _Server(body=body) as srv:
            p = LP.LLMProfile(name="x", provider="lmstudio", endpoint=srv.url)
            with self.assertRaisesRegex(A.AgentError, "Unexpected endpoint"):
                A.list_models(p, "")

    def test_sad_a_redirect_is_not_followed(self) -> None:
        with _Server(status=302, headers=[("Location", "http://127.0.0.1:9/steal")]) as srv:
            p = LP.LLMProfile(name="x", provider="openai", endpoint=srv.url + "/v1")
            with self.assertRaisesRegex(A.AgentError, "redirect"):
                A.list_models(p, "sk-secret")


class DialogWithoutSiftTest(unittest.TestCase):
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

    def _dialog(self, tmp: Path):
        from ui.llm_settings_dialog import LLMSettingsDialog

        d = LLMSettingsDialog(settings_path=tmp / "llm.json")
        self.addCleanup(d.deleteLater)
        d.add_profile()
        d.name_edit.setText("local")
        return d

    def test_happy_fetch_models_works_without_sift(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp, FakeOllama() as srv:
            with mock.patch.dict(sys.modules, NO_SIFT), mock.patch.object(
                LP, "get_api_key", return_value=""
            ):
                d = self._dialog(Path(tmp))
                d.provider_combo.setCurrentText("ollama")
                d.endpoint_edit.setText(srv.url)
                d.fetch_models()
                self._wait(lambda: d.model_combo.count() >= 2 or "sift" in d.status_label.text())
        self.assertNotIn("sift", d.status_label.text())
        names = sorted(d.model_combo.itemText(i) for i in range(d.model_combo.count()))
        self.assertEqual(names, ["demo:latest", "other:7b"])

    def test_sad_fetch_models_reports_an_unreachable_server(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            LP, "get_api_key", return_value=""
        ):
            d = self._dialog(Path(tmp))
            d.provider_combo.setCurrentText("openai")
            d.endpoint_edit.setText("http://127.0.0.1:9/v1")
            d.fetch_models()
            self._wait(lambda: "cannot reach" in d.status_label.text())


if __name__ == "__main__":
    unittest.main()
