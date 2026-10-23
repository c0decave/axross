"""Whether an Agent tab's LLM is reachable: the state of the dock's lamp.

The state is evidence, never a guess:

* ``online`` (green) - the last request to the profile's endpoint
  succeeded: the model listing of a check (:func:`probe`) or a chat request
  of a task (the agent's ``connection`` events).
* ``trying`` (orange) - a check or a chat request is on its way.
* ``offline`` (red) - the last one failed, there is no profile, or nothing
  was asked yet.

A check never reaches a remote endpoint that has no consent: the listing
would carry the API key there, and the user has not agreed to talk to it
yet (the first task asks).
"""

from __future__ import annotations

from core import agent as A
from core.i18n import tr
from core.llm_profiles import LLMProfile, endpoint_problem

OFFLINE, TRYING, ONLINE = "offline", "trying", "online"
STATES = (OFFLINE, TRYING, ONLINE)
#: The agent's ``connection`` event states and the lamp state each means.
_EVENT_STATES = {"trying": TRYING, "connected": ONLINE, "failed": OFFLINE}


def profile_key(profile: LLMProfile) -> tuple:
    """What makes a profile another connection: a change forgets the state."""
    return (profile.name, profile.provider, profile.resolved_endpoint(), profile.model,
            profile.consent_key(), profile.needs_consent())


def probe(profile: LLMProfile, api_key: str) -> tuple[bool, str]:
    """(reachable, detail) of *profile*'s endpoint: its model listing,
    bounded by core.agent.MODELS_TIMEOUT. Blocks - call it off the GUI
    thread. Asks nothing when the endpoint is broken or remote without
    consent; the detail then says why."""
    problem = endpoint_problem(profile.resolved_endpoint())
    if problem:
        return False, problem
    if profile.needs_consent():
        return False, tr(
            "not checked: {host} is reached only after your consent, which the first task asks for"
        ).format(host=profile.host() or profile.resolved_endpoint())
    try:
        models = A.list_models(profile, api_key)
    except A.AgentError as exc:
        return False, str(exc)
    if profile.model and not _listed(profile, models):
        return True, tr("the server does not list the model {model}").format(model=profile.model)
    return True, ""


def _listed(profile: LLMProfile, models: list[str]) -> bool:
    """Whether the server's list names the profile's model as the server
    resolves it: LM Studio ignores the case, Ollama adds ":latest"."""
    model = profile.model
    if profile.provider == "ollama":
        return (model if ":" in model else f"{model}:latest") in models or model in models
    return model.lower() in {m.lower() for m in models}


class LinkTracker:
    """The lamp state of one tab, from its checks and its requests."""

    def __init__(self) -> None:
        self.state = OFFLINE
        self.detail = tr("not checked yet")
        self.endpoint = ""
        self.model = ""
        self.key: tuple | None = None
        self._has_profile = False
        #: Counts every change; a check's result counts only when nothing
        #: happened after it began.
        self._serial = 0
        self._check: int | None = None
        #: (state, detail) before the request on its way, for a Stop.
        self._before: tuple[str, str] | None = None

    def _set(self, state: str, detail: str) -> None:
        self.state, self.detail = state, detail
        self._serial += 1

    def reset(self, profile: LLMProfile) -> bool:
        """Follow *profile*; True when it is another connection than before
        (its state is then forgotten)."""
        key = profile_key(profile)
        if key == self.key:
            return False
        self.key, self._has_profile = key, True
        self.endpoint, self.model = profile.resolved_endpoint(), profile.model
        self._check = self._before = None
        self._set(OFFLINE, tr("not checked yet"))
        return True

    def no_profile(self) -> None:
        self.key, self._has_profile = None, False
        self.endpoint = self.model = ""
        self._check = self._before = None
        self._set(OFFLINE, tr("No LLM profile is active: set one up with LLM…"))

    def needs_check(self) -> bool:
        """Whether a check would tell something: a profile that is not
        known to be reachable, and nothing on its way."""
        return self._has_profile and self.state == OFFLINE

    def begin_check(self) -> int:
        self._set(TRYING, tr("checking"))
        self._check = self._serial
        return self._serial

    def end_check(self, token: int, ok: bool, detail: str) -> bool:
        """Take a check's result, unless something newer came meanwhile.
        True when it was taken."""
        if token != self._check or token != self._serial:
            return False
        self._check = None
        self._set(ONLINE if ok else OFFLINE, detail)
        return True

    def on_event(self, event: dict) -> bool:
        """Take an agent ``connection`` event; True when the state changed."""
        if not isinstance(event, dict) or event.get("type") != "connection":
            return False
        state = event.get("state")
        detail = event.get("detail")
        detail = detail if isinstance(detail, str) else ""
        if state == "cancelled":
            if self.state != TRYING:
                return False
            # Stopped before the server answered: as it was before.
            self._set(*(self._before or (OFFLINE, tr("not checked yet"))))
            self._before = None
            return True
        if state not in _EVENT_STATES:
            return False
        if state == "trying":
            if self.state != TRYING:
                self._before = (self.state, self.detail)
            elif self._before is None:
                # A check was on its way: its answer no longer counts.
                self._before = (OFFLINE, tr("not checked yet"))
            self._set(TRYING, tr("waiting for the model"))
        else:
            self._before = None
            self._set(_EVENT_STATES[state], detail)
        self._check = None
        return True

    def tooltip(self) -> str:
        where = self.endpoint + (f" · {tr('model')} {self.model}" if self.model else "")
        if not self._has_profile and self.state == OFFLINE:
            return tr("Not connected to the LLM: {detail}").format(detail=self.detail)
        if self.state == ONLINE:
            text = tr("Connected to the LLM: {where}").format(where=where)
            return f"{text} - {self.detail}" if self.detail else text
        if self.state == TRYING:
            return tr("Connecting to the LLM ({detail}): {where}").format(
                detail=self.detail, where=where)
        return tr("Not connected to the LLM: {where} - {detail}. Click to check again.").format(
            where=where, detail=self.detail)
