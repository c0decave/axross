"""LLM profiles for the Analysis dock: which server sift's LLM mode talks to.

A profile is a provider, an endpoint and a model, plus generation limits.
Profiles live in ``~/.config/axross/llm.json`` (0600) **without** API
keys; a key lives in the system keyring (``core.credentials``) under its
own entry. A profile whose endpoint is not on this machine or a private
network is *remote*: analysing a file with it sends the file's content
there, and the dock asks before it does. So is one that urllib would reach
through the proxy of the environment (``http_proxy`` and friends, minus
``no_proxy``): the content goes to that proxy first, whatever the host.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import urllib.request
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit

from core import credentials
from core.secure_storage import keep_unreadable_copy

log = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".config" / "axross"
SETTINGS_FILE = CONFIG_DIR / "llm.json"

#: sift's providers, minus "auto" (a profile names its server) and "none".
PROVIDERS = ("ollama", "lmstudio", "openai", "mlx-lm")
#: The endpoint sift uses when a profile leaves it empty (sift.config);
#: tests/test_llm_profiles.py holds these to sift's own resolver.
DEFAULT_ENDPOINTS = {
    "ollama": "http://localhost:11434",
    "lmstudio": "http://localhost:1234/v1",
    "openai": "http://localhost:1234/v1",
    "mlx-lm": "http://localhost:8080/v1",
}


@dataclass
class LLMProfile:
    name: str
    provider: str = "ollama"
    endpoint: str = ""
    model: str = ""
    temperature: float = 0.2
    timeout: float = 180.0
    max_output_tokens: int = 2000
    allow_model_load: bool = False
    #: Where the user agreed to send file content: scheme://host:port, plus
    #: the proxy in between, if any (see consent_key). Pointing the profile
    #: elsewhere - another host, scheme, port or proxy - asks again. The
    #: consent of an older version (``confirmed_host``, the host alone) is
    #: not read: it did not say for which scheme and port it was given.
    confirmed_origin: str = ""
    #: Speech recognition for the Agent dock's microphone: "local"
    #: (faster-whisper in a worker, nothing leaves the machine) or "server"
    #: (an OpenAI-compatible ``POST {endpoint}/audio/transcriptions``).
    stt_engine: str = "local"
    #: The transcription server; "" = this profile's own endpoint.
    stt_endpoint: str = ""
    #: local: a Whisper model of core.voice_models ("" = base); server: the
    #: model name it expects ("" = whisper-1).
    stt_model: str = ""

    def resolved_endpoint(self) -> str:
        """The endpoint in use: the typed one, or the provider's default. An
        OpenAI-compatible server typed without a path means its ``/v1``
        (LM Studio answers ``/models`` with an error object)."""
        typed = self.endpoint.strip()
        if not typed:
            return DEFAULT_ENDPOINTS.get(self.provider, "")
        return typed if self.provider == "ollama" else with_api_path(typed)

    def is_remote(self) -> bool:
        endpoint = self.resolved_endpoint()
        return is_remote_endpoint(endpoint) or bool(proxy_for(endpoint))

    def host(self) -> str:
        """Where the content goes, for a person: the host, and the proxy it
        passes on the way (never the proxy's credentials)."""
        endpoint = self.resolved_endpoint()
        try:
            host = (urlsplit(endpoint).hostname or "").lower()
        except ValueError:
            return ""
        proxy = proxy_for(endpoint)
        return f"{host} via the proxy {proxy}" if proxy and host else host

    def consent_key(self) -> str:
        """scheme://host:port of the endpoint and the proxy in between; ""
        when the endpoint names no host (such an endpoint always asks)."""
        endpoint = self.resolved_endpoint()
        try:
            parts = urlsplit(endpoint)
            host, port = (parts.hostname or "").lower(), parts.port
        except ValueError:
            return ""
        if not host or parts.scheme not in ("http", "https"):
            return ""
        port = port or (443 if parts.scheme == "https" else 80)
        key = f"{parts.scheme}://{host}:{port}"
        proxy = proxy_for(endpoint)
        return f"{key} via {proxy}" if proxy else key

    def needs_consent(self) -> bool:
        if not self.is_remote():
            return False
        key = self.consent_key()
        return not key or self.confirmed_origin != key

    def consent(self) -> None:
        self.confirmed_origin = self.consent_key()

    # -- speech recognition --------------------------------------------------

    def stt_resolved_endpoint(self) -> str:
        typed = self.stt_endpoint.strip()
        return with_api_path(typed) if typed else self.resolved_endpoint()

    def transcription_url(self) -> str:
        return self.stt_resolved_endpoint().rstrip("/") + "/audio/transcriptions"

    def stt_server_model(self) -> str:
        return self.stt_model.strip() or "whisper-1"

    def stt_needs_consent(self) -> bool:
        """A recording would go to a remote server (or through a proxy)
        whose origin has no consent: the LLM's consent counts when the
        transcription server is the same origin."""
        if self.stt_engine != "server":
            return False
        probe = LLMProfile(name=self.name, provider="openai",
                           endpoint=self.stt_resolved_endpoint(),
                           confirmed_origin=self.confirmed_origin)
        return probe.needs_consent()

    def stt_host(self) -> str:
        return LLMProfile(name=self.name, provider="openai",
                          endpoint=self.stt_resolved_endpoint()).host()

    def stt_problems(self) -> list[str]:
        from core.voice_models import WHISPER_MODELS

        out = []
        if self.stt_engine not in STT_ENGINES:
            out.append(f"unknown speech recognition {self.stt_engine!r}")
        if self.stt_endpoint.strip() and not _http_url(self.stt_endpoint):
            out.append("the transcription endpoint is not an http(s) URL")
        if self.stt_engine == "local" and self.stt_model.strip() not in ("", *WHISPER_MODELS):
            out.append(f"unknown local Whisper model {self.stt_model!r}")
        return out

    def problems(self) -> list[str]:
        out = []
        if not self.name.strip():
            out.append("the name is empty")
        if self.provider not in PROVIDERS:
            out.append(f"unknown provider {self.provider!r}")
        if self.endpoint.strip() and not _http_url(self.endpoint):
            out.append("the endpoint is not an http(s) URL")
        if not 0 < self.timeout <= 3600:
            out.append("the timeout must be 1 s to 1 h")
        if not 0 <= self.temperature <= 2:
            out.append("the temperature must be 0 to 2")
        if not 1 <= self.max_output_tokens <= 1_000_000:
            out.append("max output tokens out of range")
        return out + self.stt_problems()


#: Speech recognition of a profile (core.voice_worker / core.voice_stt).
STT_ENGINES = ("local", "server")


def with_api_path(endpoint: str) -> str:
    """*endpoint* with ``/v1`` when it names no path at all (``http://h:1234``
    or ``http://h:1234/``) - where every OpenAI-compatible server (LM Studio,
    llama.cpp, vLLM, mlx-lm, OpenAI itself) serves its API. A path that is
    given is kept as it is, and so is anything that is no http(s) URL."""
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return endpoint
    if parts.scheme not in ("http", "https") or parts.path.strip("/") or parts.query:
        return endpoint
    return parts._replace(path="/v1", fragment="").geturl()


def endpoint_problem(url: str) -> str:
    """Why *url* cannot be an LLM endpoint ("" when it can)."""
    if _http_url(url):
        return ""
    return (f"the endpoint {url!r} is not an http(s) URL; type it with http:// or https://, "
            "e.g. http://192.168.1.10:1234/v1")


def _http_url(text: str) -> bool:
    try:
        parts = urlsplit(text.strip())
        valid = parts.scheme in ("http", "https") and bool(parts.hostname)
        parts.port  # noqa: B018 - raises ValueError for a port that is no number
    except ValueError:  # "http://[::1:1234", "http://h:99999"
        return False
    return valid


#: Addresses that are this machine or its own network. Deliberately not
#: ``ipaddress.is_private``: that also covers Teredo (2001::/32, reachable
#: over the internet), the documentation ranges and 198.18.0.0/15.
_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def is_remote_endpoint(url: str) -> bool:
    """False only for loopback, RFC 1918 / unique-local and link-local
    addresses and localhost.

    A host name other than localhost counts as remote: telling where it
    resolves would take a lookup, and the safe answer is to ask.
    """
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return True
    if not host:
        return True
    if host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return not any(addr in net for net in _LOCAL_NETWORKS)


def proxy_for(url: str) -> str:
    """host:port of the proxy urllib would send a request for ``url`` to,
    or "" when it connects directly.

    The decision of urllib's ProxyHandler, which sift's clients go through:
    the environment's proxy for the URL's scheme, unless no_proxy bypasses
    the host. The proxy's credentials are never returned.
    """
    try:
        parts = urlsplit(url.strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    proxy = urllib.request.getproxies().get(parts.scheme)
    if not proxy:
        return ""
    if urllib.request.proxy_bypass(f"{host}:{port}" if port else host):
        return ""
    unreadable = "an unreadable proxy setting"
    try:
        p = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        name, proxy_port = p.hostname or "", p.port
    except ValueError:
        return unreadable
    if not name:
        return unreadable
    return f"{name}:{proxy_port}" if proxy_port else name


_TYPES = {f.name: f.type for f in fields(LLMProfile)}


def _profile_from(raw) -> LLMProfile | None:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        return None
    kw = {"name": raw["name"]}
    for f in fields(LLMProfile):
        if f.name == "name" or f.name not in raw:
            continue
        value = raw[f.name]
        expected = {"str": str, "float": (int, float), "int": int, "bool": bool}[f.type]
        if isinstance(value, bool) and f.type in ("float", "int"):
            continue
        if isinstance(value, expected):
            kw[f.name] = float(value) if f.type == "float" else value
    profile = LLMProfile(**kw)
    if profile.stt_problems():
        # The voice settings came later than the profile: an odd value
        # there falls back to local recognition, it never drops the profile.
        profile.stt_engine, profile.stt_endpoint, profile.stt_model = "local", "", ""
    return None if profile.problems() else profile


@dataclass
class LLMSettings:
    profiles: list[LLMProfile] = field(default_factory=list)
    active: str = ""
    #: True when load() could not take in the whole file (unreadable, not
    #: an object, profiles dropped). save() would replace that file with
    #: only what is in memory, so it keeps a copy of it first.
    file_not_fully_loaded: bool = field(default=False, repr=False, compare=False)

    def active_profile(self) -> LLMProfile | None:
        return next((p for p in self.profiles if p.name == self.active), None)

    def profile(self, name: str) -> LLMProfile | None:
        return next((p for p in self.profiles if p.name == name), None)

    @classmethod
    def load(cls, path: Path | None = None) -> LLMSettings:
        path = path or SETTINGS_FILE
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.warning("LLM settings: cannot read %s (%s), using none", path, exc)
            return cls(file_not_fully_loaded=True)
        if not isinstance(raw, dict) or not isinstance(raw.get("profiles"), list):
            log.warning("LLM settings: %s holds no profile list, using none", path)
            return cls(file_not_fully_loaded=True)
        profiles: list[LLMProfile] = []
        dropped = 0
        for item in raw["profiles"]:
            profile = _profile_from(item)
            if profile is not None and all(p.name != profile.name for p in profiles):
                profiles.append(profile)
            else:
                dropped += 1
        if dropped:
            log.warning("LLM settings: skipped %d invalid profile(s) in %s", dropped, path)
        active = raw.get("active") if isinstance(raw.get("active"), str) else ""
        settings = cls(profiles, active, file_not_fully_loaded=bool(dropped))
        if settings.active_profile() is None:
            settings.active = ""
        return settings

    def save(self, path: Path | None = None) -> None:
        path = Path(path or SETTINGS_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        if self.file_not_fully_loaded and not keep_unreadable_copy(path):
            raise OSError(f"Not saving: the unreadable {path} could not be kept as a copy")
        data = {"profiles": [asdict(p) for p in self.profiles], "active": self.active}
        tmp = path.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        self.file_not_fully_loaded = False


def worker_request(profile: LLMProfile, api_key: str) -> dict:
    """What core.analysis_worker needs to talk to this profile's server."""
    return {
        "provider": profile.provider,
        "endpoint": profile.resolved_endpoint(),
        "model": profile.model,
        "api_key": api_key,
        "temperature": profile.temperature,
        "timeout": profile.timeout,
        "max_output_tokens": profile.max_output_tokens,
        "allow_model_load": profile.allow_model_load,
    }


# -- API keys: the keyring, never the settings file -------------------------
def _key_entry(profile_name: str) -> str:
    return f"{credentials.LLM_API_KEY_PREFIX}{profile_name}:api-key"


def store_api_key(profile_name: str, key: str) -> bool:
    return credentials.store_password(_key_entry(profile_name), key)


def get_api_key(profile_name: str) -> str:
    return credentials.get_password(_key_entry(profile_name)) or ""


def delete_api_key(profile_name: str) -> bool:
    return credentials.delete_password(_key_entry(profile_name))
