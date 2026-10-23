"""Speech recognition on a server: an OpenAI-compatible transcription
endpoint (``POST {endpoint}/audio/transcriptions``, multipart: ``file`` as
WAV, ``model``, optional ``language``) - the profile's own endpoint or the
one its ``stt_endpoint`` names.

The recording is sent from memory: no temporary file, nothing on disk. The
API key goes in the Authorization header, never in the URL, argv or the
environment. Local recognition (faster-whisper) runs in core.voice_worker.
"""

from __future__ import annotations

import json
import secrets
import struct
import urllib.error
import urllib.request

from core.llm_profiles import LLMProfile

RATE = 16000
#: Largest answer read from the server.
MAX_ANSWER_BYTES = 1 << 20


class TranscriptionError(Exception):
    pass


def wav_bytes(pcm: bytes, rate: int = RATE) -> bytes:
    """16-bit mono PCM with a WAV header."""
    pcm = pcm[: len(pcm) // 2 * 2]
    header = b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE"
    header += b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16)
    header += b"data" + struct.pack("<I", len(pcm))
    return header + pcm


def _multipart(fields: dict[str, str], wav: bytes) -> tuple[bytes, str]:
    boundary = "axross-" + secrets.token_hex(12)
    parts = []
    for name, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
                     f"{value}\r\n".encode())
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="speech.wav"\r\nContent-Type: audio/wav\r\n\r\n')
    parts.append(head.encode() + wav + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def transcribe_server(
    profile: LLMProfile, api_key: str, pcm: bytes, *, language: str | None = None,
    opener=None,
) -> str:
    """The text of *pcm* (16 kHz mono int16) as the profile's server hears it."""
    fields = {"model": profile.stt_server_model(), "response_format": "json"}
    if language in ("de", "en"):
        fields["language"] = language
    body, content_type = _multipart(fields, wav_bytes(pcm))
    request = urllib.request.Request(profile.transcription_url(), data=body, method="POST")
    request.add_header("Content-Type", content_type)
    if api_key:
        request.add_header("Authorization", f"Bearer {api_key}")
    opener = opener or urllib.request.urlopen
    try:
        with opener(request, timeout=profile.timeout) as response:
            raw = response.read(MAX_ANSWER_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise TranscriptionError(f"the transcription server answered HTTP {exc.code}") from exc
    except (OSError, ValueError) as exc:
        raise TranscriptionError(f"the transcription server is not reachable: {exc}") from exc
    if len(raw) > MAX_ANSWER_BYTES:
        raise TranscriptionError("the transcription server's answer is too large")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise TranscriptionError("the transcription server's answer is no JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("text"), str):
        raise TranscriptionError("the transcription server's answer has no text")
    return data["text"].strip()
