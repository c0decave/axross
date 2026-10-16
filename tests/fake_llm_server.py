"""A small Ollama stand-in over a real socket, for the Analysis dock's LLM tests.

Endpoints as Ollama's: GET /api/tags, GET /api/ps, POST /api/chat (a
newline-delimited JSON stream when asked). Asking for a model that is not
resident is refused and recorded, so a test can assert nothing was loaded.
The last line of a chat reports its counts as Ollama documents them.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNTS = {
    "prompt_eval_count": 26,
    "eval_count": 12,
    "prompt_eval_duration": 130_000_000,
    "eval_duration": 480_000_000,
    "load_duration": 5_000_000,
    "total_duration": 640_000_000,
}


class FakeOllama:
    def __init__(
        self,
        reply: str = "TYPE: Test table\nSUMMARY: A table of two people.",
        installed=("demo:latest", "other:7b"),
        resident=("demo:latest",),
        chunk: int = 4,
        delay: float = 0.0,
    ):
        self.reply = reply
        self.installed = list(installed)
        self.resident = list(resident)
        self.chunk = chunk
        #: Seconds between two streamed pieces: a model generating slowly.
        self.delay = delay
        self.requests: list[dict] = []
        self.headers: list[dict] = []
        self.refused_loads: list[str] = []

    def __enter__(self) -> "FakeOllama":
        state = self

        class Handler(_Handler):
            fake = state

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> bool:
        self._srv.shutdown()
        self._srv.server_close()
        return False

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    fake: FakeOllama = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.rstrip("/")
        if path == "/api/tags":
            self._send(
                200,
                {
                    "models": [
                        {
                            "name": n,
                            "model": n,
                            "details": {"families": ["llama"]},
                            "context_length": 8192,
                        }
                        for n in self.fake.installed
                    ]
                },
            )
        elif path == "/api/ps":
            self._send(200, {"models": [{"name": n, "model": n} for n in self.fake.resident]})
        else:
            self._send(404, {"error": "no such endpoint"})

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        self.fake.headers.append(dict(self.headers))
        if self.path.rstrip("/") != "/api/chat":
            self._send(404, {"error": "no such endpoint"})
            return
        model = payload.get("model", "")
        if model not in self.fake.resident:
            self.fake.refused_loads.append(model)
            self._send(400, {"error": f"loading {model} would unload the resident model"})
            return
        self.fake.requests.append(payload)
        if not payload.get("stream"):
            self._send(
                200,
                {
                    "model": model,
                    "done": True,
                    "done_reason": "stop",
                    "message": {"role": "assistant", "content": self.fake.reply},
                    **COUNTS,
                },
            )
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        text = self.fake.reply
        for i in range(0, len(text), self.fake.chunk):
            if self.fake.delay:
                time.sleep(self.fake.delay)
            self._chunk(
                {
                    "model": model,
                    "done": False,
                    "message": {"role": "assistant", "content": text[i : i + self.fake.chunk]},
                }
            )
        self._chunk(
            {
                "model": model,
                "done": True,
                "done_reason": "stop",
                "message": {"role": "assistant", "content": ""},
                **COUNTS,
            }
        )
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _chunk(self, obj) -> None:
        body = (json.dumps(obj) + "\n").encode()
        self.wfile.write(f"{len(body):X}\r\n".encode() + body + b"\r\n")
        self.wfile.flush()
