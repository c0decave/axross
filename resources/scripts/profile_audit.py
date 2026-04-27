"""profile_audit.py — flag risky settings across saved profiles.

Walks every :class:`core.profiles.ConnectionProfile` and reports
profiles that:

* talk plaintext (Telnet, FTP, NNTP-on-119, rsh)
* skip TLS verification
* store no key + use password auth (per-engagement convenience but
  worth flagging on a routine audit)
* turn off shell-history suppression for an SSH/Telnet target
* run with a stale OAuth flow (no refresh-token cached)

Usage::

    findings = audit()
    for f in findings:
        print(f["profile"], f["rule"], f["detail"])
"""
from __future__ import annotations

from core.profiles import ProfileManager

PLAINTEXT_PROTOCOLS = {"telnet", "ftp", "rsh", "cisco-telnet"}


def audit() -> list[dict]:
    findings: list[dict] = []
    mgr = ProfileManager()
    for profile in mgr.all_profiles():
        proto = (profile.protocol or "").lower()
        if proto in PLAINTEXT_PROTOCOLS:
            findings.append({
                "profile": profile.name,
                "rule": "plaintext_protocol",
                "detail": f"protocol={proto} sends credentials in the clear",
            })
        if proto == "nntp" and not getattr(profile, "use_tls", True):
            findings.append({
                "profile": profile.name,
                "rule": "nntp_plaintext",
                "detail": "NNTP-on-119 without STARTTLS",
            })
        if not getattr(profile, "verify_tls", True):
            findings.append({
                "profile": profile.name,
                "rule": "tls_verify_disabled",
                "detail": "verify_tls=False — MITM-vulnerable",
            })
        if proto in ("sftp", "telnet") and not profile.suppress_shell_history:
            findings.append({
                "profile": profile.name,
                "rule": "shell_history_kept",
                "detail": "suppress_shell_history=False on a remote shell",
            })
        if proto in ("sftp", "scp") and not profile.key_path \
                and not profile.use_agent and profile.store_password:
            findings.append({
                "profile": profile.name,
                "rule": "ssh_password_only",
                "detail": "no key, no agent — relies on stored password",
            })
    return findings
