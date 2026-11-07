"""core.mail_dns: SPF evaluation, DKIM verification (against RFC 8463's
signed example, as dkimpy ships it), DMARC alignment - on a scripted DNS,
no network."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mail_dns as D  # noqa: E402
from core.mail_message import parse_eml  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mail" / "rfc8463-signed.eml"
KEYS = {
    "brisbane._domainkey.football.example.com": '"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="',
    "test._domainkey.football.example.com": '"v=DKIM1; g=*; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"',
}


def dns(records: dict):
    calls = []

    def lookup(name, rtype):
        calls.append((name, rtype))
        value = records.get((name, rtype), records.get(name) if rtype == "TXT" else None)
        if value is None:
            return []
        return value if isinstance(value, list) else [value]
    lookup.calls = calls
    return lookup


def _raw() -> bytes:
    return FIXTURE.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


@pytest.mark.parametrize("which", ["ed25519-sha256", "rsa-sha256"])
def test_happy_the_rfc_8463_signatures_verify(which):
    msg = parse_eml(_raw())
    sig = next(s for s in msg.header_all("DKIM-Signature") if f"a={which}" in s.replace(" ", ""))
    result, domain, why = D.dkim_verify(msg.raw, sig, dns(KEYS))
    assert (result, domain) == ("pass", "football.example.com"), why


def test_sad_a_changed_body_or_header_fails():
    raw = _raw()
    for changed in (raw.replace(b"hungry", b"angry"), raw.replace(b"Is dinner ready?", b"Is lunch ready?")):
        msg = parse_eml(changed)
        results = {D.dkim_verify(msg.raw, s, dns(KEYS))[0] for s in msg.header_all("DKIM-Signature")}
        assert results == {"fail"}, results


def test_sad_a_missing_key_is_a_permerror():
    msg = parse_eml(_raw())
    assert D.dkim_verify(msg.raw, msg.header_all("DKIM-Signature")[0], dns({}))[0] == "permerror"


SPF = {
    "example.org": '"v=spf1 ip4:192.0.2.0/24 include:_spf.mailer.example mx -all"',
    "_spf.mailer.example": '"v=spf1 ip6:2001:db8::/32 ~all"',
    ("example.org", "MX"): ["10 mx.example.org."],
    ("mx.example.org", "A"): ["198.51.100.25"],
    "soft.example": '"v=spf1 ~all"',
    "redir.example": '"v=spf1 redirect=example.org"',
    "loop.example": '"v=spf1 include:loop.example"',
    "two.example": ['"v=spf1 -all"', '"v=spf1 +all"'],
}


@pytest.mark.parametrize("ip,domain,result", [
    ("192.0.2.77", "example.org", "pass"),           # ip4 range
    ("198.51.100.25", "example.org", "pass"),        # mx
    ("2001:db8::5", "example.org", "pass"),          # matched inside the include
    ("2001:db9::5", "example.org", "fail"),          # the include ends ~all: no match there; -all here
    ("203.0.113.9", "example.org", "fail"),
    ("203.0.113.9", "soft.example", "softfail"),
    ("192.0.2.1", "redir.example", "pass"),
    ("192.0.2.1", "nothing.example", "none"),
    ("192.0.2.1", "loop.example", "permerror"),
    ("192.0.2.1", "two.example", "permerror"),
])
def test_spf_evaluation(ip, domain, result):
    got, why = D.spf_check(ip, domain, dns(SPF))
    assert got == result, why


# a public address (the documentation ranges count as private and are skipped)
PUBLIC = "93.184.216.34"


def test_happy_dns_check_names_spf_dkim_and_dmarc():
    raw = _raw().replace(b"From: Joe", b"Received: from out.football.example.com (out.football.example.com ["
                         + PUBLIC.encode() + b"])\r\n\tby mx.shopping.example.net; Fri, 11 Jul 2003 21:00:40 -0700"
                         b"\r\nFrom: Joe", 1)
    records = dict(KEYS)
    records["football.example.com"] = f'"v=spf1 ip4:{PUBLIC}/32 -all"'
    records["_dmarc.football.example.com"] = '"v=DMARC1; p=reject"'
    findings, result = D.dns_check(parse_eml(raw), dns(records))
    assert result["spf"] == "pass" and result["spf_ip"] == PUBLIC
    assert {d["result"] for d in result["dkim"]} == {"pass"}
    assert result["dmarc"]["p"] == "reject"
    assert not [f for f in findings if f.severity == "high"]
    assert any("DMARC policy of football.example.com: p=reject; passes" in f.text for f in findings)


SPOOF = (b"Received: from evil.example (unknown [" + PUBLIC.encode() + b"])\r\n\tby mx.victim.example; "
         b"Tue, 04 Nov 2026 10:00:00 +0000\r\nFrom: Bank <alerts@bank.example>\r\nSubject: x\r\n"
         b"DKIM-Signature: v=1; a=rsa-sha256; d=evil.example; s=s1; h=from; bh=AAAA; b=AAAA\r\n\r\nbody\r\n")


def test_sad_a_spoofed_sender_fails_spf_and_dmarc():
    records = {"bank.example": '"v=spf1 ip4:192.0.2.0/24 -all"', "_dmarc.bank.example": '"v=DMARC1; p=quarantine"'}
    findings, result = D.dns_check(parse_eml(SPOOF), dns(records))
    assert result["spf"] == "fail" and result["spf_ip"] == PUBLIC
    assert result["dkim"][0]["result"] == "permerror"         # evil.example publishes no key
    high = " | ".join(f.text for f in findings if f.severity == "high")
    assert "SPF (looked up now) fail" in high and "neither SPF nor DKIM passes aligned with bank.example" in high


def test_happy_a_mail_project_checks_dns_only_when_asked(tmp_path):
    from core.mail_project import MailProject

    (tmp_path / "s.eml").write_bytes(SPOOF)
    records = {"bank.example": '"v=spf1 ip4:192.0.2.0/24 -all"', "_dmarc.bank.example": '"v=DMARC1; p=reject"'}
    lookup = dns(records)
    with MailProject(tmp_path / "off") as p:
        p.import_paths([str(tmp_path / "s.eml")])
        assert "dns" not in p.report(p.messages()[0]["sha256"])
    with MailProject(tmp_path / "on", dns=lookup) as p:
        p.import_paths([str(tmp_path / "s.eml")])
        rep = p.report(p.messages()[0]["sha256"])
    assert rep["dns"]["spf"] == "fail" and lookup.calls
    assert any(f["area"] == "dns" and f["severity"] == "high" for f in rep["findings"])


def test_happy_a_dock_s_mail_analyse_checks_dns_when_its_setting_says_so():
    from core import mail_dock as MD
    from core.ram_fs import RamFsSession

    box = RamFsSession()
    box.mkdir("/INBOX")
    with box.open_write("/INBOX/1.eml") as f:
        f.write(SPOOF)
    for on in (False, True):
        dock = MD.MailDockConfig(name="d", dns_checks=on)
        mailbox = MD.Mailbox(box, "INBOX", Path("/nonexistent/seen.json"))
        tools = MD.MailTools(dock, mailbox, ask_send=lambda o, s: False, smtp=lambda: None,
                             drafts_dir=Path("/nonexistent"))
        tools.dns_lookup = dns({"bank.example": '"v=spf1 -all"'})
        mid = mailbox.recent()[0]["id"]
        result = tools.analyse({"id": mid})
        assert ("dns" in result) is on
        assert bool(tools.dns_lookup.calls) is on
