"""The voices (Piper) and speech recognition models (faster-whisper) the
Agent dock downloads on first use (Help > Features…).

Every file is pinned: an https URL at a fixed commit of its Hugging Face
repository, its size and its SHA-256, computed from the downloaded file
(and equal to the repository's LFS id where there is one). A download goes
into a hidden folder beside the target, every byte through SHA-256; only
when every file matches does the folder take the model's place
(``~/.local/share/axross/voice/<id>/``, or under ``$XDG_DATA_HOME``). A
mismatch, a file larger or smaller than pinned, an error or Cancel leaves
nothing behind.

Licences: the Piper voices are from rhasspy/piper-voices (MIT, per-voice
dataset terms in each MODEL_CARD); the Whisper models are Systran's
CTranslate2 conversions (MIT).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import threading
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_PIPER = ("https://huggingface.co/rhasspy/piper-voices/resolve/"
          "375a0fe641dea077c2a47b4e9a056d6da521eed3")  # = tag v1.0.0
_WHISPER_BASE = ("https://huggingface.co/Systran/faster-whisper-base/resolve/"
                 "ebe41f70d5b6dfa9166e2c581c45c9c0cfc57b66")
_WHISPER_SMALL = ("https://huggingface.co/Systran/faster-whisper-small/resolve/"
                  "536b0662742c02347bc0e980a01041f333bce120")
_CHUNK = 1 << 20


class DownloadError(Exception):
    """A model could not be downloaded, or what came is not what is pinned."""


class DownloadCancelled(DownloadError):
    pass


@dataclass(frozen=True)
class ModelFile:
    name: str
    url: str
    sha256: str
    size: int


@dataclass(frozen=True)
class VoiceModel:
    id: str
    title: str
    kind: str  # "voice" (Piper) or "whisper" (faster-whisper)
    language: str  # "de", "en"; "" for a model of every language
    gender: str  # "male", "female"; "" for a recognition model
    files: tuple[ModelFile, ...]

    @property
    def size(self) -> int:
        return sum(f.size for f in self.files)


def _voice(model_id, title, lang, gender, path, onnx_sha, onnx_size, json_sha, json_size):
    name = path.rsplit("/", 1)[1]
    return VoiceModel(model_id, title, "voice", lang, gender, (
        ModelFile(f"{name}.onnx", f"{_PIPER}/{path}.onnx", onnx_sha, onnx_size),
        ModelFile(f"{name}.onnx.json", f"{_PIPER}/{path}.onnx.json", json_sha, json_size),
    ))


def _whisper(model_id, title, base, model_sha, model_size, config_sha, config_size):
    return VoiceModel(model_id, title, "whisper", "", "", (
        ModelFile("model.bin", f"{base}/model.bin", model_sha, model_size),
        ModelFile("config.json", f"{base}/config.json", config_sha, config_size),
        ModelFile("tokenizer.json", f"{base}/tokenizer.json",
                  "fb7b63191e9bb045082c79fd742a3106a12c99513ab30df4a0d47fa6cb6fd0ab", 2203239),
        ModelFile("vocabulary.txt", f"{base}/vocabulary.txt",
                  "34ce3fe1c5041027b3f8d42912270993f986dbc4bb34cf27f951e34a1e453913", 459861),
    ))


MODELS: tuple[VoiceModel, ...] = (
    _voice("piper-de-thorsten", "German male voice (Thorsten, high)", "de", "male",
           "de/de_DE/thorsten/high/de_DE-thorsten-high",
           "9df1c43c61149ef9b39e618e2b861fbe41e1fcea9390b2dac62e8761573ea4f1", 113895201,
           "6de734444e4c3f9e33b7ebe2746dbc19b71e85f613e79c65acf623200b99a76a", 4875),
    # Kerstin exists in "low" quality only (piper-voices v1.0.0).
    _voice("piper-de-kerstin", "German female voice (Kerstin, low)", "de", "female",
           "de/de_DE/kerstin/low/de_DE-kerstin-low",
           "d352a7641892cebf2903859af94e9ba81a141110215fe3943bcda7f7da401b7a", 63104526,
           "56e708556b7b9b7a53c4f8957e021421e69f11a600962bba554cffbe72cf2d47", 4158),
    _voice("piper-en-ryan", "English male voice (Ryan, medium)", "en", "male",
           "en/en_US/ryan/medium/en_US-ryan-medium",
           "abf4c274862564ed647ba0d2c47f8ee7c9b717d27bdad9219100eb310db4047a", 63201294,
           "44034c056cb15681b2ad494307c7f3f2e4499d1253c700c711fa0a4607ffe78d", 4883),
    _voice("piper-en-lessac", "English female voice (Lessac, medium)", "en", "female",
           "en/en_US/lessac/medium/en_US-lessac-medium",
           "5efe09e69902187827af646e1a6e9d269dee769f9877d17b16b1b46eeaaf019f", 63201294,
           "efe19c417bed055f2d69908248c6ba650fa135bc868b0e6abb3da181dab690a0", 4885),
    _whisper("whisper-base", "Speech recognition, Whisper base (local)", _WHISPER_BASE,
             "d01c3014881c9c6f3133c182f3d2887eb6ca1c789a7538c5c007196857a0a6a9", 145217532,
             "56a6d8110d311f19c8f0471e562832c7527f146b567275bfca59fcf7c184da9a", 2309),
    _whisper("whisper-small", "Speech recognition, Whisper small (local, more accurate)",
             _WHISPER_SMALL,
             "3e305921506d8872816023e4c273e75d2419fb89b24da97b4fe7bce14170d671", 483546902,
             "b55496ac7940a7ae47d2c01eab40edfd8701feec1229d9cce3b40014383fb828", 2370),
)
#: The local recognition models a profile may name ("" = the first).
WHISPER_MODELS = tuple(m.id.removeprefix("whisper-") for m in MODELS if m.kind == "whisper")


def model(model_id: str) -> VoiceModel | None:
    return next((m for m in MODELS if m.id == model_id), None)


def whisper_model(name: str) -> VoiceModel | None:
    """The local recognition model of a profile's ``stt_model`` ("" = base)."""
    return model(f"whisper-{name or WHISPER_MODELS[0]}")


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local",
                                                           "share")
    return Path(base) / "axross" / "voice"


def model_dir(m: VoiceModel) -> Path:
    return data_dir() / m.id


def installed(m: VoiceModel) -> bool:
    """Every file is there with its pinned size (the SHA-256 was checked
    when it came)."""
    folder = model_dir(m)
    try:
        return all((folder / f.name).stat().st_size == f.size for f in m.files)
    except OSError:
        return False


def voice_paths(m: VoiceModel) -> tuple[Path, Path]:
    """(model .onnx, its .onnx.json) of an installed voice."""
    folder = model_dir(m)
    onnx = next(f.name for f in m.files if f.name.endswith(".onnx"))
    return folder / onnx, folder / f"{onnx}.json"


def download(
    m: VoiceModel,
    *,
    opener: Callable | None = None,
    progress: Callable[[int, int], None] | None = None,
    cancel: threading.Event | None = None,
    timeout: float = 60.0,
) -> Path:
    """Fetch *m*'s files, check each against its pin, then put the folder
    in place. Raises DownloadError (DownloadCancelled on *cancel*)."""
    for f in m.files:
        if not f.url.startswith("https://"):
            raise DownloadError(f"{f.name}: only https downloads are allowed")
    opener = opener or urllib.request.urlopen
    root = data_dir()
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    tmp = root / f".{m.id}.part-{secrets.token_hex(4)}"
    tmp.mkdir(mode=0o700)
    total, done = m.size, 0
    try:
        for f in m.files:
            done = _fetch(f, tmp / f.name, opener, timeout, cancel, progress, done, total)
        final = model_dir(m)
        if final.exists():
            old = root / f".{m.id}.old-{secrets.token_hex(4)}"
            os.rename(final, old)
            shutil.rmtree(old, ignore_errors=True)
        os.rename(tmp, final)
        return final
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _fetch(f: ModelFile, target: Path, opener, timeout, cancel, progress, done, total) -> int:
    digest = hashlib.sha256()
    got = 0
    try:
        response = opener(f.url, timeout=timeout)
        with response, open(target, "wb") as out:
            while True:
                if cancel is not None and cancel.is_set():
                    raise DownloadCancelled("cancelled")
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                got += len(chunk)
                if got > f.size:
                    raise DownloadError(f"{f.name} is larger than the pinned {f.size} bytes")
                digest.update(chunk)
                out.write(chunk)
                if progress is not None:
                    progress(done + got, total)
    except DownloadError:
        raise
    except (OSError, ValueError) as exc:
        raise DownloadError(f"{f.name}: {exc}") from exc
    if got != f.size:
        raise DownloadError(f"{f.name} has {got} bytes, pinned are {f.size}")
    if digest.hexdigest() != f.sha256:
        raise DownloadError(f"{f.name}: the SHA-256 differs from the pinned one - refused")
    return done + got
