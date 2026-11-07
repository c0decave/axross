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

from core.mail_analyse import Finding, _org
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


def _in_net(ip, spec: str, base_ips) -> bool:
    for b in base_ips:
        if ip.version != b.version:
            continue
        default = 32 if ip.version == 4 else 128
        m = re.search(r"/(\d+)\Z", spec)
        prefix = int(m.group(1)) if m else default
        try:
            if ip in ipaddress.ip_network(f"{b}/{prefix}", strict=False):
                return True
        except ValueError:
            continue
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
        if "/" in mech_l and not arg:          # a/24, mx/24
            mech_l, _, cidr = mech_l.partition("/")
            arg = f"{domain}/{cidr}"
        matched = False
        try:
            if mech_l == "all":
                matched = True
            elif mech_l in ("ip4", "ip6"):
                matched = addr in ipaddress.ip_network(arg, strict=False)
            elif mech_l == "a":
                count[0] += 1
                target = (arg or domain).split("/")[0]
                matched = _in_net(addr, arg or "", _ips(lookup, target))
            elif mech_l == "mx":
                count[0] += 1
                target = (arg or domain).split("/")[0]
                hosts = [r.split()[-1].rstrip(".") for r in lookup(target, "MX")]
                matched = any(_in_net(addr, arg or "", _ips(lookup, h)) for h in hosts[:10])
            elif mech_l == "include":
                count[0] += 1
                if count[0] > MAX_LOOKUPS or _depth > 10:
                    return "permerror", "more than 10 DNS lookups"
                result, _why = spf_check(ip, arg, lookup, _count=count, _depth=_depth + 1)
                if result in ("temperror", "permerror"):
                    return result, f"include:{arg}: {_why}"
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
        count[0] += 1
        return spf_check(ip, redirect, lookup, _count=count, _depth=_depth + 1)
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
    """(result, domain, why) for one DKIM-Signature value: pass / fail / permerror / temperror."""
    tags = _tags(signature)
    domain, selector = tags.get("d", ""), tags.get("s", "")
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
            return {"domain": name, "p": tags.get("p", "none"), "sp": tags.get("sp", ""),
                    "adkim": tags.get("adkim", "r"), "aspf": tags.get("aspf", "r")}
    return {}


# --- all of it -----------------------------------------------------------------------------

def sending_ip(msg: MailMessage) -> str:
    """The address the receiving side saw: the newest Received hop whose
    'from' address is public."""
    for value in msg.header_all("Received"):
        m = re.search(r"\bfrom\s+\S+\s+\(([^)]*)\)", " ".join(value.split()), re.I)
        if not m:
            continue
        for cand in re.findall(r"\[?([0-9a-fA-F:.]{7,})\]?", m.group(1)):
            try:
                addr = ipaddress.ip_address(cand.strip("[]"))
            except ValueError:
                continue
            if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                return str(addr)
    return ""


def dns_check(msg: MailMessage, lookup=_lookup_default) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    from_dom = parseaddr(msg.header("From") or msg.from_)[1].rpartition("@")[2].lower()
    env_dom = parseaddr(msg.header("Return-Path"))[1].rpartition("@")[2].lower() or from_dom
    ip = sending_ip(msg)
    spf, spf_why = spf_check(ip, env_dom, lookup) if env_dom and ip else ("none", "no sender domain or address")
    sev = {"fail": "high", "softfail": "warn", "permerror": "warn"}.get(spf, "info")
    findings.append(Finding(sev, "dns", f"SPF (looked up now) {spf}: {spf_why}"))
    dkim = []
    for sig in msg.header_all("DKIM-Signature"):
        result, domain, why = dkim_verify(msg.raw, sig, lookup)
        dkim.append({"result": result, "domain": domain, "why": why})
        findings.append(Finding({"fail": "high", "permerror": "warn"}.get(result, "info"), "dns",
                                f"DKIM (verified now) {result}: {why}"))
    if not dkim:
        findings.append(Finding("info", "dns", "no DKIM signature to verify"))
    policy = dmarc_policy(from_dom, lookup) if from_dom else None
    aligned_spf = spf == "pass" and env_dom and _org(env_dom) == _org(from_dom)
    aligned_dkim = any(d["result"] == "pass" and _org(d["domain"]) == _org(from_dom) for d in dkim)
    if policy:
        ok = aligned_spf or aligned_dkim
        sev = "info" if ok else ("high" if policy["p"] in ("reject", "quarantine") else "warn")
        findings.append(Finding(sev, "dns", f"DMARC policy of {policy['domain']}: p={policy['p']}; "
                                + ("passes (aligned " + ("SPF" if aligned_spf else "DKIM") + ")" if ok else
                                   "neither SPF nor DKIM passes aligned with " + from_dom)))
    elif policy == {}:
        findings.append(Finding("info", "dns", f"{from_dom} publishes no DMARC policy"))
    return findings, {"spf": spf, "spf_ip": ip, "dkim": dkim, "dmarc": policy}
