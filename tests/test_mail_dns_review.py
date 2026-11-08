"""core.mail_dns after a review: SPF dual-cidr, IPv6 address literals,
redirect loops, broken DKIM tags, Outlook files and DMARC's strict
alignment and subdomain policy - all on a scripted DNS, no network.

What was wrong:

* SPF ``a/NN`` / ``mx/NN`` took the last ``/NN`` for both address families
  and did not parse RFC 7208's dual-cidr: ``a/24`` passed a foreign IPv6
  sender, ``a/24//64`` failed a matching IPv4 one.
* ``[IPv6:2a00:1450:4864:20::22b]`` in a Received line was read as the
  address ``6:2a00:1450:...`` (which parses): SPF was checked for a wrong
  address. core.mail_analyse's hop addresses had the same expression.
* ``redirect=`` counted no lookups: ``v=spf1 redirect=loop.example`` made
  ~990 lookups and a RecursionError, which threw away the DKIM and DMARC
  findings too.
* ``int(tags["l"])`` outside any try: one DKIM signature with ``l=abc``
  aborted the whole DNS check.
* An Outlook .msg's raw bytes are the compound file and a PST message is
  rebuilt - a validly signed mail showed "DKIM fail".
* DMARC compared organisational domains always (adkim / aspf ``s`` read,
  unused) and ignored ``sp=``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import mail_dns as D  # noqa: E402
from core.mail_analyse import analyse  # noqa: E402
from core.mail_message import parse_any, parse_eml  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mail" / "rfc8463-signed.eml"
KEY = '"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="'
PUBLIC4, PUBLIC6 = "93.184.216.34", "2a00:1450:4864:20::22b"


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


def texts(findings, severity=None):
    return " | ".join(f.text for f in findings if severity is None or f.severity == severity)


# --- 4. SPF a/NN, mx/NN, dual-cidr ----------------------------------------------------------

DUAL = {
    ("example.com", "A"): "192.0.2.10", ("example.com", "AAAA"): "2001:db8::10",
    ("example.com", "MX"): "10 mx.example.com.",
    ("mx.example.com", "A"): "198.51.100.25", ("mx.example.com", "AAAA"): "2001:db8::25",
    ("other.example", "A"): "203.0.113.5",
}


@pytest.mark.parametrize("record,ip,result", [
    ("a/24", "2001:db8:ffff::666", "fail"),        # /24 is the IPv4 prefix only: IPv6 stays /128
    ("a/24", "192.0.2.99", "pass"),
    ("a/24", "2001:db8::10", "pass"),
    ("a/24//64", "192.0.2.99", "pass"),           # dual-cidr: the IPv4 sender is in the /24
    ("a/24//64", "2001:db8::ffff", "pass"),       # ... and the IPv6 one in the /64
    ("a/24//64", "2001:db8:1::1", "fail"),
    ("a//64", "192.0.2.99", "fail"),              # IPv4 default /32
    ("a//64", "192.0.2.10", "pass"),
    ("mx/24", "2001:db8:abcd::1", "fail"),
    ("mx/24", "198.51.100.200", "pass"),
    ("mx/24//48", "2001:db8:0:1::1", "pass"),
    ("mx:example.com/24//48", "2001:db8:0:1::1", "pass"),
    ("a:other.example/24", "203.0.113.77", "pass"),
    ("a:other.example", "203.0.113.77", "fail"),
    ("A/24", "192.0.2.99", "pass"),
])
def test_spf_dual_cidr(record, ip, result):
    records = dict(DUAL)
    records["example.com"] = f'"v=spf1 {record} -all"'
    got, why = D.spf_check(ip, "example.com", dns(records))
    assert got == result, why


@pytest.mark.parametrize("record", ["a/33", "a//129", "mx/24//200", "a:", "a/x"])
def test_sad_a_bad_prefix_length_is_a_permerror(record):
    records = dict(DUAL)
    records["example.com"] = f'"v=spf1 {record} -all"'
    assert D.spf_check("192.0.2.10", "example.com", dns(records))[0] == "permerror"


# --- 5. [IPv6:...] in Received ----------------------------------------------------------------

V6_RECEIVED = (f"Received: from mx.sender.example (mx.sender.example [IPv6:{PUBLIC6}]) by mx.rcpt.example; "
               "Tue, 04 Nov 2026 10:00:00 +0000\r\nFrom: a@sender.example\r\n\r\nx\r\n").encode()


def test_happy_an_ipv6_address_literal_is_the_sending_address():
    msg = parse_eml(V6_RECEIVED)
    assert D.sending_ip(msg) == PUBLIC6
    findings, result = D.dns_check(msg, dns({"sender.example": '"v=spf1 ip6:2a00:1450:4864::/48 -all"'}))
    assert result["spf"] == "pass" and result["spf_ip"] == PUBLIC6, texts(findings)


def test_happy_the_offline_analysis_reads_the_same_address():
    assert analyse(parse_eml(V6_RECEIVED)).hops[0].from_ip == PUBLIC6
    raw = (b"Received: from h (h [IPv6:2001:db8::1] helo=x) by mx; Tue, 04 Nov 2026 10:00:00 +0000\r\n"
           b"Received: from h2 (h2 [" + PUBLIC4.encode() + b"]) by h; Tue, 04 Nov 2026 09:59:00 +0000\r\n\r\nx")
    hops = analyse(parse_eml(raw)).hops
    assert [h.from_ip for h in hops] == [PUBLIC4, "2001:db8::1"]


def test_edge_a_bare_ipv6_tag_and_the_newest_public_hop():
    raw = (f"Received: from a (a IPv6:{PUBLIC6}) by b; Tue, 04 Nov 2026 10:00:00 +0000\r\n"
           "Received: from c (c [10.0.0.1]) by a; Tue, 04 Nov 2026 09:00:00 +0000\r\n\r\nx").encode()
    assert D.sending_ip(parse_eml(raw)) == PUBLIC6


# --- 6. redirect loops ------------------------------------------------------------------------

def test_sad_a_redirect_loop_is_a_permerror_within_the_lookup_limit():
    lookup = dns({"loop.example": '"v=spf1 redirect=loop.example"'})
    result, why = D.spf_check("192.0.2.1", "loop.example", lookup)
    assert result == "permerror", why
    assert len(lookup.calls) <= D.MAX_LOOKUPS + 2


def test_sad_a_redirect_loop_keeps_the_dkim_and_dmarc_findings():
    raw = (b"Return-Path: <x@loop.example>\r\nReceived: from h (h [" + PUBLIC4.encode() + b"]) by mx; "
           b"Tue, 04 Nov 2026 10:00:00 +0000\r\nFrom: Bank <ceo@loop.example>\r\n"
           b"DKIM-Signature: v=1; a=rsa-sha256; d=loop.example; s=s; h=from; bh=AAAA; b=AAAA\r\n\r\nbody\r\n")
    records = {"loop.example": '"v=spf1 redirect=loop.example"', "_dmarc.loop.example": '"v=DMARC1; p=reject"'}
    findings, result = D.dns_check(parse_eml(raw), dns(records))
    assert result["spf"] == "permerror"
    assert result["dkim"] and result["dmarc"]["p"] == "reject"
    assert "DMARC policy of loop.example" in texts(findings)


def test_edge_a_redirect_to_a_domain_without_spf_is_a_permerror():
    assert D.spf_check("192.0.2.1", "r.example", dns({"r.example": '"v=spf1 redirect=none.example"'}))[0] \
        == "permerror"


# --- 7. one broken DKIM signature ------------------------------------------------------------

BANK = (b"Return-Path: <x@attacker.example>\r\nReceived: from h (h [" + PUBLIC4.encode() + b"]) by mx; "
        b"Tue, 04 Nov 2026 10:00:00 +0000\r\nFrom: Bank <ceo@bank.example>\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=bank.example; s=s; h=from; l=abc; bh=AAAA; b=AAAA\r\n"
        b"Subject: x\r\n\r\nbody\r\n")
BANK_DNS = {"_dmarc.bank.example": '"v=DMARC1; p=reject"', "s._domainkey.bank.example": '"v=DKIM1; p=AAAA"',
            "attacker.example": '"v=spf1 -all"'}


@pytest.mark.parametrize("length", ["abc", "-1", "1e3", "1 2", "0x10", "9" * 80])
def test_sad_a_bad_body_length_is_a_permerror_of_that_signature(length):
    sig = f"v=1; a=rsa-sha256; d=bank.example; s=s; h=from; l={length}; bh=AAAA; b=AAAA"
    result, domain, why = D.dkim_verify(BANK, sig, dns(BANK_DNS))
    assert (result, domain) == ("permerror", "bank.example"), why


def test_sad_a_bad_body_length_does_not_drop_spf_or_dmarc():
    findings, result = D.dns_check(parse_eml(BANK), dns(BANK_DNS))
    assert result["spf"] == "fail" and result["dkim"][0]["result"] == "permerror"
    assert "neither SPF nor DKIM passes aligned with bank.example" in texts(findings, "high")


def test_sad_a_signature_check_that_raises_is_one_finding(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(D, "dkim_verify", boom)
    findings, result = D.dns_check(parse_eml(BANK), dns(BANK_DNS))
    assert result["dkim"][0]["result"] == "permerror" and "unexpected" in result["dkim"][0]["why"]
    assert result["spf"] == "fail" and result["dmarc"]["p"] == "reject"


def test_sad_an_spf_check_that_raises_is_one_finding(monkeypatch):
    def boom(*_a, **_k):
        raise RecursionError("too deep")
    monkeypatch.setattr(D, "spf_check", boom)
    findings, result = D.dns_check(parse_eml(BANK), dns(BANK_DNS))
    assert result["spf"] == "temperror" and "too deep" in texts(findings)
    assert result["dmarc"]["p"] == "reject" and result["dkim"]


# --- 8. Outlook .msg and PST ------------------------------------------------------------------

def _signed() -> bytes:
    return FIXTURE.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


SIGNED_DNS = {"brisbane._domainkey.football.example.com": KEY,
              "_dmarc.football.example.com": '"v=DMARC1; p=reject"'}


def test_sad_a_signed_msg_is_not_verifiable_and_no_fail():
    import cfb_writer

    raw = _signed()
    head, body = raw.split(b"\r\n\r\n", 1)
    data = cfb_writer.msg_file("x", "Joe", "joe@football.example.com", body.decode(),
                               headers=head.decode() + "\r\n")
    msg = parse_any(data, "x.msg")
    findings, result = D.dns_check(msg, dns(SIGNED_DNS))
    assert {d["result"] for d in result["dkim"]} == {"unverifiable"}
    assert "not verifiable from this file format" in texts(findings)
    assert not [f for f in findings if f.severity in ("high", "warn")], texts(findings)


def test_sad_a_message_rebuilt_from_a_pst_is_not_verifiable(tmp_path):
    from core.mail_project import MailProject

    with MailProject(tmp_path / "p", dns=dns(SIGNED_DNS)) as project:
        sha = project.add_bytes(_signed(), f"{tmp_path}/archive.pst#Inbox/0x200024")
        rep = project.report(sha)
    assert {d["result"] for d in rep["dns"]["dkim"]} == {"unverifiable"}
    assert not [f for f in rep["findings"] if f["area"] == "dns" and f["severity"] != "info"]


def test_edge_the_same_message_as_eml_still_verifies():
    findings, result = D.dns_check(parse_eml(_signed(), "/mail/x.eml"), dns(SIGNED_DNS))
    # the ed25519 signature passes (the RSA one's key is not in this DNS)
    assert "pass" in {d["result"] for d in result["dkim"]}
    assert "unverifiable" not in {d["result"] for d in result["dkim"]}
    # and dkim_verify on an .msg's bytes says so itself
    assert D.dkim_verify(bytes.fromhex("d0cf11e0a1b11ae1") + b"\0" * 504, "d=x.example; s=s",
                         dns({}))[0] == "unverifiable"


# --- 9. DMARC strict alignment and sp= --------------------------------------------------------

def _from(from_addr: str, env: str) -> bytes:
    return (f"Return-Path: <b@{env}>\r\nReceived: from h (h [{PUBLIC4}]) by mx; Tue, 04 Nov 2026 10:00:00 +0000"
            f"\r\nFrom: Bank <{from_addr}>\r\nSubject: x\r\n\r\nbody\r\n").encode()


@pytest.mark.parametrize("aspf,severity", [("r", "info"), ("s", "high")])
def test_dmarc_strict_spf_alignment(aspf, severity):
    records = {"_dmarc.bank.example": f'"v=DMARC1; p=reject; aspf={aspf}"',
               "mail.bank.example": f'"v=spf1 ip4:{PUBLIC4} -all"'}
    findings, result = D.dns_check(parse_eml(_from("ceo@bank.example", "mail.bank.example")), dns(records))
    assert result["spf"] == "pass"
    dmarc = [f for f in findings if f.text.startswith("DMARC")]
    assert [f.severity for f in dmarc] == [severity], texts(findings)


@pytest.mark.parametrize("adkim,severity", [("r", "info"), ("s", "high")])
def test_dmarc_strict_dkim_alignment(adkim, severity, monkeypatch):
    monkeypatch.setattr(D, "dkim_verify", lambda raw, sig, lookup: ("pass", "mail.bank.example", "signed"))
    raw = _from("ceo@bank.example", "attacker.example").replace(
        b"Subject: x", b"DKIM-Signature: v=1; d=mail.bank.example; s=s; h=from; bh=A; b=A\r\nSubject: x")
    records = {"_dmarc.bank.example": f'"v=DMARC1; p=reject; adkim={adkim}"', "attacker.example": '"v=spf1 -all"'}
    findings, _result = D.dns_check(parse_eml(raw), dns(records))
    dmarc = [f for f in findings if f.text.startswith("DMARC")]
    assert [f.severity for f in dmarc] == [severity], texts(findings)


def test_sad_the_subdomain_policy_applies_to_a_subdomain():
    records = {"_dmarc.bank.example": '"v=DMARC1; p=none; sp=reject"', "attacker.example": '"v=spf1 -all"'}
    findings, result = D.dns_check(parse_eml(_from("ceo@alerts.bank.example", "attacker.example")), dns(records))
    assert result["dmarc"]["applied"] == "reject"
    assert "DMARC policy of bank.example: sp=reject" in texts(findings, "high")


def test_edge_the_subdomain_policy_does_not_apply_to_the_domain_itself():
    records = {"_dmarc.bank.example": '"v=DMARC1; p=reject; sp=none"', "attacker.example": '"v=spf1 -all"'}
    findings, _result = D.dns_check(parse_eml(_from("ceo@bank.example", "attacker.example")), dns(records))
    assert "DMARC policy of bank.example: p=reject" in texts(findings, "high")
    findings, result = D.dns_check(parse_eml(_from("ceo@alerts.bank.example", "attacker.example")), dns(records))
    assert result["dmarc"]["applied"] == "none"
    assert "DMARC policy of bank.example: sp=none" in texts(findings, "warn")


# --- include: of a domain without SPF (RFC 7208 5.2) -----------------------------------------

def test_sad_include_of_a_domain_without_spf_is_a_permerror():
    """Counted as "no match" before, so ``include:gone.example ~all`` fell
    through to the softfail of the next term."""
    records = {"example.com": '"v=spf1 include:gone.example ~all"'}
    result, why = D.spf_check("192.0.2.10", "example.com", dns(records))
    assert result == "permerror" and "include:gone.example" in why


def test_happy_include_of_a_domain_with_spf_still_matches():
    records = {"example.com": '"v=spf1 include:spf.partner.example -all"',
               "spf.partner.example": '"v=spf1 ip4:192.0.2.0/24 -all"'}
    assert D.spf_check("192.0.2.10", "example.com", dns(records))[0] == "pass"


# --- review 3: the hop where the mail entered the receiving organisation -----------------------

O365 = b"""Received: from AM0PR02MB1234.eurprd02.prod.outlook.com (2603:10a6:208:12::34)
 by DB9PR02MB5678.eurprd02.prod.outlook.com with HTTPS; Mon, 2 Nov 2026 10:00:03 +0000
Received: from AM6PR0502CA0001.eurprd05.prod.outlook.com (2603:10a6:20b:2e::14)
 by AM0PR02MB1234.eurprd02.prod.outlook.com (2603:10a6:208:12::34) with Microsoft SMTP Server; Mon, 2 Nov 2026 10:00:02 +0000
Received: from AM3PEPF0000A78F.eurprd04.prod.outlook.com (2603:10a6:207:1::3) by AM6PR0502CA0001.outlook.office365.com
 (2603:10a6:20b:2e::14) with Microsoft SMTP Server; Mon, 2 Nov 2026 10:00:02 +0000
Received: from mail-wm1-f41.google.com (209.85.128.41) by
 AM3PEPF0000A78F.mail.protection.outlook.com (10.167.16.104) with Microsoft SMTP Server; Mon, 2 Nov 2026 10:00:01 +0000
Return-Path: alice@gmail.com
From: Alice <alice@gmail.com>
To: bob@contoso.com
Subject: hi

body
"""


def test_sad_microsoft_365_internal_hops_are_not_the_sending_address():
    """sending_ip took the newest Received hop with any public address - in
    Microsoft 365 that is one of its own outlook.com servers (public IPv6),
    so a gmail mail was checked against Microsoft's address and showed
    "SPF fail" at high severity. The receiver's own hops (from and by in its
    organisations, outlook.com and office365.com) are passed over now."""
    msg = parse_eml(O365)
    assert D.sending_ip(msg) == "209.85.128.41"
    findings, result = D.dns_check(msg, dns({"gmail.com": '"v=spf1 ip4:209.85.128.0/17 -all"',
                                             "_dmarc.gmail.com": '"v=DMARC1; p=none"'}))
    assert result["spf"] == "pass", texts(findings)
    assert not texts(findings, "high"), texts(findings)


def test_happy_the_address_the_receiver_recorded_above_the_entry_hop_wins():
    """A filter in front of the receiver (another organisation, public
    address) was taken as the sender. The client address the receiver wrote
    into Authentication-Results above the entry hop is used; one in a header
    below it (the sender could have written it) is not."""
    raw = (b"Authentication-Results: mx.contoso.example; spf=pass smtp.mailfrom=gmail.com "
           b"smtp.remote-ip=209.85.128.41\r\n"
           b"Received: from scan.cloudav.example (scan.cloudav.example [93.184.216.34]) by mx.contoso.example; "
           b"Mon, 2 Nov 2026 10:00:02 +0000\r\n"
           b"Received: from mail-wm1-f41.google.com (209.85.128.41) by scan.cloudav.example; "
           b"Mon, 2 Nov 2026 10:00:01 +0000\r\nFrom: a@gmail.com\r\n\r\nx\r\n")
    assert D.sending_ip(parse_eml(raw)) == "209.85.128.41"
    forged = (b"Received: from mail.attacker.example (mail.attacker.example [6.6.6.6]) by mx.contoso.example; "
              b"Mon, 2 Nov 2026 10:00:02 +0000\r\n"
              b"Authentication-Results: mx.contoso.example; spf=pass smtp.remote-ip=209.85.128.41\r\n"
              b"Received-SPF: pass client-ip=209.85.128.41\r\nFrom: a@gmail.com\r\n\r\nx\r\n")
    assert D.sending_ip(parse_eml(forged)) == "6.6.6.6"


def test_edge_a_mail_from_inside_the_organisation_keeps_the_newest_public_hop():
    """Every hop inside the receiver's organisation, none from outside:
    the newest public address, as before - and the Received-SPF client-ip
    of a Gmail-style receiver above an outside hop is read too."""
    inside = (b"Received: from a.contoso.example (a.contoso.example [93.184.216.34]) by b.contoso.example; "
              b"Mon, 2 Nov 2026 10:00:02 +0000\r\n"
              b"Received: from c.contoso.example (c.contoso.example [93.184.216.35]) by a.contoso.example; "
              b"Mon, 2 Nov 2026 10:00:01 +0000\r\n\r\nx\r\n")
    assert D.sending_ip(parse_eml(inside)) == "93.184.216.34"
    gmail = (b"Received-SPF: softfail (google.com: domain of transitioning a@b.example does not designate "
             b"198.51.200.9 as permitted sender) client-ip=198.51.200.9;\r\n"
             b"Received: by 2002:a05:6000:1::1 with SMTP id x; Mon, 2 Nov 2026 10:00:03 +0000\r\n"
             b"Received: from relay.mx.google.com (relay.mx.google.com [64.233.160.10]) by mx.google.com; "
             b"Mon, 2 Nov 2026 10:00:02 +0000\r\n"
             b"Received: from out.b.example (out.b.example [198.51.200.9]) by relay.mx.google.com; "
             b"Mon, 2 Nov 2026 10:00:01 +0000\r\n\r\nx\r\n")
    assert D.sending_ip(parse_eml(gmail)) == "198.51.200.9"


def test_sad_a_failed_dmarc_lookup_is_a_finding():
    """dmarc_policy turned a resolver error (a timeout) into None, and
    dns_check said nothing about DMARC at all - as if it had not been
    looked at. It is an info finding "DMARC: lookup failed" now."""
    raw = (b"Received: from mx.example.net (mx.example.net [93.184.216.34]) by mx.me; "
           b"Mon, 2 Nov 2026 10:00:01 +0000\r\nFrom: a@example.net\r\n\r\nb\r\n")

    def lookup(name, rtype):
        if name.startswith("_dmarc."):
            raise TimeoutError("DNS timed out")
        return ['"v=spf1 ip4:93.184.216.34 -all"'] if (name, rtype) == ("example.net", "TXT") else []
    findings, result = D.dns_check(parse_eml(raw), lookup)
    failed = [f for f in findings if f.text.startswith("DMARC: lookup failed")]
    assert len(failed) == 1 and failed[0].severity == "info" and "timed out" in failed[0].text
    assert result["dmarc"] is None and result["spf"] == "pass"
