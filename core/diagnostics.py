"""Connection/profile/backend diagnostics."""

from __future__ import annotations

import socket
import uuid
from dataclasses import dataclass
from typing import Callable

from core.path_policy import safe_join


@dataclass(frozen=True)
class DiagnosticCheck:
    name: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class DiagnosticReport:
    subject: str
    checks: list[DiagnosticCheck]

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def to_text(self) -> str:
        from core.redaction import redact_text

        lines = [f"Diagnostics: {redact_text(str(self.subject))}"]
        for check in self.checks:
            mark = "OK" if check.ok else "FAIL"
            suffix = f" — {redact_text(str(check.detail))}" if check.detail else ""
            lines.append(f"[{mark}] {check.name}{suffix}")
        return "\n".join(lines)


def _check(name: str, fn: Callable[[], str]) -> DiagnosticCheck:
    try:
        return DiagnosticCheck(name, True, fn())
    except Exception as exc:  # noqa: BLE001
        return DiagnosticCheck(name, False, str(exc))


def diagnose_profile(profile) -> DiagnosticReport:
    """Validate cheap profile properties without opening a session."""
    checks: list[DiagnosticCheck] = []

    def backend_available() -> str:
        from core.backend_registry import get, init_registry

        init_registry()
        info = get(profile.protocol)
        if info is None:
            raise OSError(f"unknown protocol {profile.protocol!r}")
        if not info.available:
            raise OSError(f"missing optional dependency for {info.display_name}")
        return info.display_name

    checks.append(_check("backend available", backend_available))

    host = getattr(profile, "host", "") or ""
    if host:
        checks.append(
            _check(
                "dns resolution",
                lambda: ", ".join(sorted({i[4][0] for i in socket.getaddrinfo(host, None)}))[:200],
            )
        )

    ptype = getattr(profile, "proxy_type", "none") or "none"
    phost = getattr(profile, "proxy_host", "") or ""
    if ptype != "none" and phost:

        def proxy_check() -> str:
            from core.proxy import build_requests_proxies
            from core.redaction import redact

            proxy_password = ""
            if hasattr(profile, "get_proxy_password"):
                proxy_password = profile.get_proxy_password() or ""
            return str(
                redact(
                    build_requests_proxies(
                        ptype,
                        phost,
                        int(getattr(profile, "proxy_port", 0) or 0),
                        getattr(profile, "proxy_username", "") or "",
                        proxy_password,
                    )
                )
            )

        checks.append(_check("proxy configuration", proxy_check))

    return DiagnosticReport(subject=getattr(profile, "name", "") or profile.protocol, checks=checks)


def diagnose_backend(
    backend,
    *,
    root: str | None = None,
    write_test: bool = False,
) -> DiagnosticReport:
    """Run live checks against an already-open backend."""
    subject = getattr(backend, "name", type(backend).__name__)
    checks: list[DiagnosticCheck] = []
    checks.append(_check("home", lambda: backend.home()))
    probe_root = root or "/"
    if root is None:
        try:
            probe_root = backend.home()
        except Exception:
            pass
    checks.append(_check("list root", lambda: f"{len(backend.list_dir(probe_root))} entries"))
    checks.append(_check("stat root", lambda: "dir" if backend.stat(probe_root).is_dir else "file"))

    if write_test:

        def cleanup(path: str) -> None:
            try:
                if backend.exists(path):
                    backend.remove(path)
            except Exception as exc:  # noqa: BLE001
                raise OSError(f"write probe cleanup failed for {path}: {exc}") from exc

        def write_probe() -> str:
            token = uuid.uuid4().hex[:10]
            src = safe_join(backend, probe_root, f".axross-diagnostic-{token}.tmp")
            dst = safe_join(backend, probe_root, f".axross-diagnostic-{token}.renamed")
            with backend.open_write(src) as handle:
                handle.write(b"axross diagnostic\n")
            try:
                backend.rename(src, dst)
                backend.remove(dst)
            except Exception as exc:
                cleanup_errors: list[str] = []
                for candidate in (src, dst):
                    try:
                        cleanup(candidate)
                    except OSError as cleanup_exc:
                        cleanup_errors.append(str(cleanup_exc))
                if cleanup_errors:
                    raise OSError("; ".join(cleanup_errors)) from exc
                raise
            return "write/rename/delete ok"

        checks.append(_check("write/rename/delete probe", write_probe))

    return DiagnosticReport(subject=subject, checks=checks)


__all__ = ["DiagnosticCheck", "DiagnosticReport", "diagnose_backend", "diagnose_profile"]
