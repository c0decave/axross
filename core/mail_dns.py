"""Live DNS checks of a message - opt-in, because every lookup tells the
DNS servers (and whoever watches them) which domains are being looked at.

* **SPF** (RFC 7208): the record of the envelope sender's domain (Return-Path,
  else From), evaluated for the address of the server that handed the
  message to the receiving side (the first Received hop from outside) -
  ip4, ip6, a, mx, include, redirect, exists, all; at most 10 lookups.
* **DKIM** (RFC 6376): every DKIM-Signature verified against the key its
  selector publishes - relaxed/simple canonicalisation, the body hash,
  rsa-sha256 and ed25519-sha256 (cryptography).
* **DMARC** (RFC 7489): the policy of the From domain (or its organisational
  domain) and whether SPF or DKIM pass aligned with it.

:func:`dns_check` returns findings in core.mail_analyse's shape and a dict
of results; ``lookup(name, rtype) -> [text]`` is injectable (tests).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from email.utils import parseaddr

from core.cfb import MAGIC as _CFB_MAGIC
from core.mail_analyse import Finding, _org, ip_literals
from core.mail_message import MailMessage

MAX_LOOKUPS = 10


def _lookup_default(name: str, rtype: str) -> list[str]:
    from core.net_helpers import dns_records

    return dns_records(name, rtype, timeout=4.0)


def _txt(lookup, name: str) -> list[str]:
    out = []
    for rec in lookup(name, "TXT"):
        # dnspython gives '"v=spf1 " "ip4:..."': join the quoted pieces
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', rec)
        out.append("".join(parts) if parts else rec)
    return out


# --- SPF -------------------------------------------------------------------------------

class _SpfError(Exception):
    def __init__(self, result: str, why: str):
        super().__init__(why)
        self.result = result


def _ips(lookup, name: str) -> list[ipaddress._BaseAddress]:
    out = []
    for rtype in ("A", "AAAA"):
        for rec in lookup(name, rtype):
            try:
                out.append(ipaddress.ip_address(rec.strip()))
            except ValueError:
                pass
    return out


_DOMAIN_CIDR = re.compile(r"(?::([^/]+))?(?:/(\d{1,2}))?(?://(\d{1,3}))?")


def _domain_cidr(rest: str, domain: str) -> tuple[str, int, int]:
    """'' | ':example.com' | '/24' | '//64' | ':example.com/24//64' after
    'a' or 'mx' -> (domain, ip4-cidr, ip6-cidr) - RFC 7208 5.6 dual-cidr,
    each family with its own prefix (default /32 and /128)."""
    m = _DOMAIN_CIDR.fullmatch(rest)
    if not m:
        raise ValueError(f"not a domain and prefix lengths: {rest!r}")
    v4, v6 = int(m.group(2) or 32), int(m.group(3) or 128)
    if v4 > 32 or v6 > 128:
        raise ValueError(f"a prefix length too long: {rest!r}")
    return m.group(1) or domain, v4, v6


def _in_net(ip, v4: int, v6: int, base_ips) -> bool:
    prefix = v4 if ip.version == 4 else v6
    for b in base_ips:
        if ip.version != b.version:
            continue
        if ip in ipaddress.ip_network(f"{b}/{prefix}", strict=False):
            return True
    return False


def spf_check(ip: str, domain: str, lookup=_lookup_default, *, _count=None, _depth=0) -> tuple[str, str]:
    """(result, why): pass / fail / softfail / neutral / none / permerror / temperror."""
    count = _count if _count is not None else [0]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "none", f"no sending address to check ({ip!r})"
    try:
        records = [r for r in _txt(lookup, domain) if r.lower().startswith("v=spf1")]
    except OSError as exc:
        return "temperror", str(exc)
    if not records:
        return "none", f"{domain} publishes no SPF record"
    if len(records) > 1:
        return "permerror", f"{domain} publishes {len(records)} SPF records"
    redirect = None
    for term in records[0].split()[1:]:
        qual = "+"
        if term[0] in "+-~?":
            qual, term = term[0], term[1:]
        mech, _, arg = term.partition(":")
        mech_l = mech.lower()
        if "=" in term and not arg:
            key, _, value = term.partition("=")
            if key.lower() == "redirect":
                redirect = value
            continue
        name = re.match(r"[a-z0-9]*", mech_l).group(0)
        if name in ("a", "mx"):                 # a, a:host, a/24, a//64, mx:host/24//64
            mech_l = name
        matched = False
        try:
            if mech_l == "all":
                matched = True
            elif mech_l in ("ip4", "ip6"):
                matched = addr in ipaddress.ip_network(arg, strict=False)
            elif mech_l == "a":
                count[0] += 1
                target, v4, v6 = _domain_cidr(term[1:], domain)
                matched = _in_net(addr, v4, v6, _ips(lookup, target))
            elif mech_l == "mx":
                count[0] += 1
                target, v4, v6 = _domain_cidr(term[2:], domain)
                hosts = [r.split()[-1].rstrip(".") for r in lookup(target, "MX")]
                matched = any(_in_net(addr, v4, v6, _ips(lookup, h)) for h in hosts[:10])
            elif mech_l == "include":
                count[0] += 1
                if count[0] > MAX_LOOKUPS or _depth > 10:
                    return "permerror", "more than 10 DNS lookups"
                result, _why = spf_check(ip, arg, lookup, _count=count, _depth=_depth + 1)
                if result in ("temperror", "permerror"):
                    return result, f"include:{arg}: {_why}"
                if result == "none":            # RFC 7208 5.2: no record to include
                    return "permerror", f"include:{arg}: {_why}"
                matched = result == "pass"
            elif mech_l == "exists":
                count[0] += 1
                matched = bool(lookup(arg, "A"))
            elif mech_l == "ptr":
                continue                         # deprecated; not evaluated
        except (ValueError, OSError) as exc:
            return "permerror" if isinstance(exc, ValueError) else "temperror", f"{term}: {exc}"
        if count[0] > MAX_LOOKUPS:
            return "permerror", "more than 10 DNS lookups"
        if matched:
            result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qual]
            return result, f"{ip} matches {qual}{term} of {domain}"
    if redirect:
        # a lookup like include's (RFC 7208 4.6.4): a redirect loop ends at the limit
        count[0] += 1
        if count[0] > MAX_LOOKUPS or _depth > MAX_LOOKUPS:
            return "permerror", "more than 10 DNS lookups"
        result, why = spf_check(ip, redirect, lookup, _count=count, _depth=_depth + 1)
        if result == "none":                    # RFC 7208 6.1
            return "permerror", f"redirect={redirect}: {why}"
        return result, why
    return "neutral", f"nothing in {domain}'s SPF record matches {ip}"


# --- DKIM ------------------------------------------------------------------------------

def _tags(text: str) -> dict:
    out = {}
    for part in text.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            out[key.strip().lower()] = re.sub(r"\s+", "", value) if key.strip().lower() in ("b", "bh", "p") \
                else value.strip()
    return out


def _relaxed_header(name: str, value: str) -> str:
    value = re.sub(r"\r?\n[ \t]", " ", value)
    value = re.sub(r"[ \t]+", " ", value).strip()
    return f"{name.lower().strip()}:{value}\r\n"


def _body(raw: bytes) -> bytes:
    sep = raw.find(b"\r\n\r\n")
    if sep >= 0:
        return raw[sep + 4:]
    sep = raw.find(b"\n\n")
    return raw[sep + 2:] if sep >= 0 else b""


def _canon_body(body: bytes, relaxed: bool) -> bytes:
    body = body.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    if relaxed:
        lines = [re.sub(rb"[ \t]+", b" ", line).rstrip(b" \t") for line in body.split(b"\r\n")]
        body = b"\r\n".join(lines)
    body = body.rstrip(b"\r\n")
    return body + b"\r\n" if body or not relaxed else b""


def _raw_headers(raw: bytes) -> list[tuple[str, str]]:
    """The header fields as they are in the message (folding kept)."""
    text = raw.split(b"\r\n\r\n", 1)[0] if b"\r\n\r\n" in raw else raw.split(b"\n\n", 1)[0]
    lines = text.decode("utf-8", "surrogateescape").replace("\r\n", "\n").split("\n")
    fields: list[list[str]] = []
    for line in lines:
        if line[:1] in (" ", "\t") and fields:
            fields[-1][1] += "\r\n" + line
        elif ":" in line:
            name, _, value = line.partition(":")
            fields.append([name, value])
    return [(n, v) for n, v in fields]


def dkim_verify(raw: bytes, signature: str, lookup=_lookup_default) -> tuple[str, str, str]:
    """(result, domain, why) for one DKIM-Signature value: pass / fail / permerror / temperror
    (unverifiable: *raw* is an Outlook .msg, not the message's bytes)."""
    tags = _tags(signature)
    domain, selector = tags.get("d", ""), tags.get("s", "")
    if raw[:8] == _CFB_MAGIC:
        return "unverifiable", domain, "not verifiable from this file format (an Outlook .msg)"
    algo = tags.get("a", "rsa-sha256").lower()
    if not domain or not selector or "b" not in tags or "bh" not in tags or "h" not in tags:
        return "permerror", domain, "the signature lacks d=, s=, h=, b= or bh="
    if algo not in ("rsa-sha256", "ed25519-sha256"):
        return "permerror", domain, f"algorithm {algo} is not verified here"
    head_c, _, body_c = tags.get("c", "simple/simple").lower().partition("/")
    body_c = body_c or "simple"
    try:
        keys = [_tags(t) for t in _txt(lookup, f"{selector}._domainkey.{domain}")]
    except OSError as exc:
        return "temperror", domain, str(exc)
    key = next((k for k in keys if k.get("p")), None)
    if key is None:
        return "permerror", domain, f"no key published at {selector}._domainkey.{domain}"
    body = _canon_body(_body(raw), body_c == "relaxed")
    if "l" in tags:
        if not re.fullmatch(r"\d{1,76}", tags["l"]):
            return "permerror", domain, f"the body length l={tags['l'][:40]!r} is not a number"
        body = body[:int(tags["l"])]
    if base64.b64encode(hashlib.sha256(body).digest()).decode() != tags["bh"]:
        return "fail", domain, "the body was changed after signing (body hash differs)"
    fields = _raw_headers(raw)
    used: dict[str, int] = {}
    data = ""
    for name in [h.strip() for h in tags["h"].split(":") if h.strip()]:
        matches = [f for f in fields if f[0].strip().lower() == name.lower()]
        n = used.get(name.lower(), 0)
        if n < len(matches):
            fname, fvalue = matches[-1 - n]
            used[name.lower()] = n + 1
            data += _relaxed_header(fname, fvalue) if head_c == "relaxed" else f"{fname}:{fvalue}\r\n"
    sig_field = next((f for f in fields if f[0].strip().lower() == "dkim-signature"
                      and re.sub(r"\s+", "", f[1]).find(re.sub(r"\s+", "", tags["b"])[:40]) >= 0), None)
    if sig_field is None:
        return "permerror", domain, "the signature's header field was not found"
    unsigned = re.sub(r"(\bb\s*=)[^;]*", r"\1", sig_field[1])
    data += (_relaxed_header(sig_field[0], unsigned) if head_c == "relaxed" else f"{sig_field[0]}:{unsigned}").rstrip("\r\n")
    try:
        signature_bytes = base64.b64decode(tags["b"])
        public = base64.b64decode(key["p"])
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding

        if algo == "rsa-sha256":
            pub = serialization.load_der_public_key(public)
            pub.verify(signature_bytes, data.encode("utf-8", "surrogateescape"), padding.PKCS1v15(), hashes.SHA256())
        else:
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(
                signature_bytes, hashlib.sha256(data.encode("utf-8", "surrogateescape")).digest())
    except InvalidSignature:
        return "fail", domain, "the signature does not match the headers"
    except (ValueError, TypeError) as exc:
        return "permerror", domain, f"unusable key or signature: {exc}"
    return "pass", domain, f"signed by {domain} (selector {selector})"


# --- DMARC -----------------------------------------------------------------------------

def dmarc_policy(domain: str, lookup=_lookup_default) -> dict | None:
    for name in (domain, _org(domain)):
        try:
            recs = [r for r in _txt(lookup, f"_dmarc.{name}") if r.lower().startswith("v=dmarc1")]
        except OSError:
            return None
        if recs:
            tags = _tags(recs[0])
            return {"domain": name, "p": tags.get("p", "none").lower(), "sp": tags.get("sp", "").lower(),
                    "adkim": tags.get("adkim", "r").lower(), "aspf": tags.get("aspf", "r").lower()}
    return {}


def _aligned(domain: str, from_dom: str, mode: str) -> bool:
    """RFC 7489 3.1: strict ("s") is the same domain, relaxed the same
    organisational domain."""
    domain, from_dom = domain.lower().rstrip("."), from_dom.lower().rstrip(".")
    return domain == from_dom if mode == "s" else _org(domain) == _org(from_dom)


def _applied(policy: dict, from_dom: str) -> tuple[str, str]:
    """('p' | 'sp', its value): sp= is the policy of the subdomains of the
    domain that publishes the record (RFC 7489 6.3)."""
    if policy.get("sp") and from_dom.lower().rstrip(".") != policy["domain"]:
        return "sp", policy["sp"]
    return "p", policy["p"]


# --- all of it -----------------------------------------------------------------------------

def sending_ip(msg: MailMessage) -> str:
    """The address the receiving side saw: the newest Received hop whose
    'from' address is public ("[IPv6:2001:db8::1]" is 2001:db8::1)."""
    for value in msg.header_all("Received"):
        m = re.search(r"\bfrom\s+\S+\s+\(([^)]*)\)", " ".join(value.split()), re.I)
        if not m:
            continue
        for addr in ip_literals(m.group(1)):
            if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                return str(addr)
    return ""


def unverifiable_dkim(msg: MailMessage) -> str:
    """Why *msg.raw* cannot carry a DKIM signature's proof ('' when it can):
    an Outlook .msg is a compound file of properties and a PST message is
    rebuilt from them (core.pst.to_eml) - neither keeps the bytes signed."""
    if msg.kind == "msg":
        return "not verifiable from this file format (an Outlook .msg keeps no original message bytes)"
    if msg.rebuilt == "pst":
        return "not verifiable from this file format (a PST message is rebuilt from its properties)"
    return ""


def dns_check(msg: MailMessage, lookup=_lookup_default) -> tuple[list[Finding], dict]:
    """SPF, every DKIM signature, DMARC: each one on its own - one that cannot
    be checked (a broken record or signature, a resolver error) is a finding,
    the others are still made."""
    findings: list[Finding] = []
    from_dom = parseaddr(msg.header("From") or msg.from_)[1].rpartition("@")[2].lower()
    env_dom = parseaddr(msg.header("Return-Path"))[1].rpartition("@")[2].lower() or from_dom
    ip = sending_ip(msg)
    try:
        spf, spf_why = spf_check(ip, env_dom, lookup) if env_dom and ip else ("none", "no sender domain or address")
    except Exception as exc:  # noqa: BLE001 - this check fails, the others go on
        spf, spf_why = "temperror", f"could not be checked: {type(exc).__name__}: {exc}"[:300]
    sev = {"fail": "high", "softfail": "warn", "permerror": "warn"}.get(spf, "info")
    findings.append(Finding(sev, "dns", f"SPF (looked up now) {spf}: {spf_why}"))
    dkim = []
    no_proof = unverifiable_dkim(msg)
    for sig in msg.header_all("DKIM-Signature"):
        if no_proof:
            dkim.append({"result": "unverifiable", "domain": _tags(sig).get("d", ""), "why": no_proof})
            findings.append(Finding("info", "dns", f"DKIM: {no_proof}"))
            continue
        try:
            result, domain, why = dkim_verify(msg.raw, sig, lookup)
        except Exception as exc:  # noqa: BLE001 - one signature, not the whole check
            result, domain, why = "permerror", "", f"could not be checked: {type(exc).__name__}: {exc}"[:300]
        dkim.append({"result": result, "domain": domain, "why": why})
        findings.append(Finding({"fail": "high", "permerror": "warn"}.get(result, "info"), "dns",
                                f"DKIM (verified now) {result}: {why}"))
    if not dkim:
        findings.append(Finding("info", "dns", "no DKIM signature to verify"))
    try:
        policy = dmarc_policy(from_dom, lookup) if from_dom else None
    except Exception as exc:  # noqa: BLE001
        policy = None
        findings.append(Finding("info", "dns", f"DMARC could not be checked: {type(exc).__name__}: {exc}"[:300]))
    if policy:
        aligned_spf = bool(spf == "pass" and env_dom and _aligned(env_dom, from_dom, policy["aspf"]))
        aligned_dkim = any(d["result"] == "pass" and _aligned(d["domain"], from_dom, policy["adkim"]) for d in dkim)
        which, applied = _applied(policy, from_dom)
        policy["applied"] = applied
        ok = aligned_spf or aligned_dkim
        head = f"DMARC policy of {policy['domain']}: {which}={applied}; "
        strict = [f"{k}=s" for k in ("aspf", "adkim") if policy[k] == "s"]
        if ok:
            findings.append(Finding("info", "dns", head + "passes (aligned " + ("SPF" if aligned_spf else "DKIM") + ")"))
        elif any(d["result"] == "unverifiable" for d in dkim):
            findings.append(Finding("info", "dns", head + "no verdict: SPF does not pass aligned with " + from_dom
                                    + " and DKIM is not verifiable from this file format"))
        else:
            sev = "high" if applied in ("reject", "quarantine") else "warn"
            findings.append(Finding(sev, "dns", head + "neither SPF nor DKIM passes aligned with " + from_dom
                                    + (f" (strict alignment: {', '.join(strict)})" if strict else "")))
    elif policy == {}:
        findings.append(Finding("info", "dns", f"{from_dom} publishes no DMARC policy"))
    return findings, {"spf": spf, "spf_ip": ip, "dkim": dkim, "dmarc": policy}
