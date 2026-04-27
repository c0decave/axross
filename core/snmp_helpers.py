"""SNMP polling helpers — slice 7 of API_GAPS.

Built on top of ``pysnmp.hlapi.v3arch.asyncio`` (the only public API
surface pysnmp 7+ ships). We wrap each asyncio call in
``asyncio.run()`` so the helpers stay synchronous from the caller's
point of view — a REPL user doing
``axross.snmp_get("10.0.0.1", "1.3.6.1.2.1.1.1.0")``
shouldn't have to know about event loops.

Why no global SnmpEngine: the SnmpEngine is cheap-ish to construct
(~5 ms) but holds open UDP sockets if reused across calls. Since
these helpers are one-shot polls from the REPL or a script, we
construct + tear down per call. For high-rate polling the caller
should drop down to pysnmp directly.

SNMP version notes:
* SNMPv1 / SNMPv2c use a community string (``community="public"``).
* SNMPv3 uses USM with a username + auth/priv keys; pass
  ``user=...``, ``auth_key=...``, ``priv_key=...``,
  ``auth_proto=...`` and ``priv_proto=...``. Defaults to v2c.

OID notes:
* OIDs may be passed as dotted strings (``"1.3.6.1.2.1.1.1.0"``)
  or as MIB-resolved (``"SNMPv2-MIB::sysDescr.0"``). pysnmp handles
  both — the latter requires the MIB module to be importable.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SnmpVar:
    """One OID/value pair returned from a GET / WALK."""
    oid: str
    type: str
    value: Any

    def __repr__(self) -> str:
        return f"SnmpVar(oid={self.oid!r}, type={self.type!r}, value={self.value!r})"


def _build_auth(community: str | None,
                user: str | None,
                auth_key: str | None,
                priv_key: str | None,
                auth_proto: str | None,
                priv_proto: str | None):
    """Choose CommunityData (v1/v2c) or UsmUserData (v3)."""
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore
        CommunityData, UsmUserData,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmAesCfb128Protocol, usmDESPrivProtocol,
    )
    if user:
        proto_map_a = {
            "md5": usmHMACMD5AuthProtocol,
            "sha": usmHMACSHAAuthProtocol,
        }
        proto_map_p = {
            "aes": usmAesCfb128Protocol,
            "des": usmDESPrivProtocol,
        }
        return UsmUserData(
            user,
            auth_key, priv_key,
            authProtocol=proto_map_a.get((auth_proto or "sha").lower(),
                                         usmHMACSHAAuthProtocol),
            privProtocol=proto_map_p.get((priv_proto or "aes").lower(),
                                         usmAesCfb128Protocol),
        )
    return CommunityData(community or "public")


def _to_var(varbind) -> SnmpVar:
    """Normalise a (oid, value) varbind into our SnmpVar."""
    oid_obj, value = varbind
    oid_str = str(oid_obj)
    type_name = type(value).__name__
    # Most pysnmp values stringify to the readable form (OctetString
    # decodes printable ASCII automatically; Counter32 etc. give ints).
    return SnmpVar(oid=oid_str, type=type_name, value=value.prettyPrint())


def snmp_get(host: str, oid: str, *,
             community: str = "public",
             port: int = 161,
             timeout: float = 3.0,
             retries: int = 1,
             user: str | None = None,
             auth_key: str | None = None,
             priv_key: str | None = None,
             auth_proto: str | None = None,
             priv_proto: str | None = None) -> SnmpVar:
    """Issue a single SNMP GET request. Returns one ``SnmpVar`` for
    the OID. Raises ``OSError`` on transport failure.

    For v3, supply ``user`` (and optionally ``auth_key`` / ``priv_key``).
    For v2c (the default), the ``community`` string is enough.
    """
    return asyncio.run(_snmp_get_async(
        host, oid,
        community=community, port=port, timeout=timeout, retries=retries,
        user=user, auth_key=auth_key, priv_key=priv_key,
        auth_proto=auth_proto, priv_proto=priv_proto,
    ))


async def _snmp_get_async(host, oid, *, community, port, timeout, retries,
                          user, auth_key, priv_key, auth_proto, priv_proto):
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore
        SnmpEngine, ContextData, ObjectType, ObjectIdentity,
        UdpTransportTarget, get_cmd,
    )
    auth = _build_auth(community, user, auth_key, priv_key,
                       auth_proto, priv_proto)
    transport = await UdpTransportTarget.create(
        (host, int(port)),
        timeout=float(timeout), retries=int(retries),
    )
    error_indication, error_status, error_index, var_binds = await get_cmd(
        SnmpEngine(),
        auth,
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    if error_indication:
        raise OSError(f"SNMP GET {host}:{port} {oid}: {error_indication}")
    if error_status:
        raise OSError(
            f"SNMP GET {host}:{port} {oid}: {error_status.prettyPrint()} "
            f"(index {error_index})"
        )
    if not var_binds:
        raise OSError(f"SNMP GET {host}:{port} {oid}: empty varbinds")
    return _to_var(var_binds[0])


def snmp_walk(host: str, base_oid: str, *,
              community: str = "public",
              port: int = 161,
              timeout: float = 3.0,
              retries: int = 1,
              max_vars: int = 10_000,
              user: str | None = None,
              auth_key: str | None = None,
              priv_key: str | None = None,
              auth_proto: str | None = None,
              priv_proto: str | None = None) -> list[SnmpVar]:
    """Walk an OID subtree, returning every leaf as an ``SnmpVar``.
    ``max_vars`` caps the result at a sane number — a walk of ``1.3``
    on a packed device returns thousands of varbinds.
    """
    return asyncio.run(_snmp_walk_async(
        host, base_oid,
        community=community, port=port, timeout=timeout, retries=retries,
        max_vars=max_vars,
        user=user, auth_key=auth_key, priv_key=priv_key,
        auth_proto=auth_proto, priv_proto=priv_proto,
    ))


async def _snmp_walk_async(host, base_oid, *, community, port, timeout,
                           retries, max_vars, user, auth_key, priv_key,
                           auth_proto, priv_proto):
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore
        SnmpEngine, ContextData, ObjectType, ObjectIdentity,
        UdpTransportTarget, walk_cmd,
    )
    auth = _build_auth(community, user, auth_key, priv_key,
                       auth_proto, priv_proto)
    transport = await UdpTransportTarget.create(
        (host, int(port)),
        timeout=float(timeout), retries=int(retries),
    )
    out: list[SnmpVar] = []
    async for (error_indication, error_status, error_index, var_binds) in walk_cmd(
        SnmpEngine(),
        auth,
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,
    ):
        if error_indication:
            raise OSError(
                f"SNMP WALK {host}:{port} {base_oid}: {error_indication}"
            )
        if error_status:
            raise OSError(
                f"SNMP WALK {host}:{port} {base_oid}: "
                f"{error_status.prettyPrint()} (index {error_index})"
            )
        for vb in var_binds:
            out.append(_to_var(vb))
            if len(out) >= max_vars:
                return out
    return out


def snmp_set(host: str, oid: str, value: Any, *,
             value_type: str = "OctetString",
             community: str = "private",
             port: int = 161,
             timeout: float = 3.0,
             retries: int = 1) -> SnmpVar:
    """Issue an SNMP SET. ``value_type`` is the pysnmp type-class name
    (``OctetString`` / ``Integer`` / ``Counter32`` / …).

    Default community is ``"private"`` — most devices distinguish
    read-only ``"public"`` from read-write ``"private"``. Override
    explicitly when your device uses a different community.
    """
    return asyncio.run(_snmp_set_async(
        host, oid, value,
        value_type=value_type, community=community,
        port=port, timeout=timeout, retries=retries,
    ))


async def _snmp_set_async(host, oid, value, *,
                          value_type, community, port, timeout, retries):
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore
        SnmpEngine, ContextData, ObjectType, ObjectIdentity,
        UdpTransportTarget, set_cmd,
    )
    import pysnmp.hlapi.v3arch.asyncio as _h
    type_cls = getattr(_h, value_type, None)
    if type_cls is None:
        raise ValueError(
            f"snmp_set: unknown value_type {value_type!r}; expected one of "
            "OctetString / Integer / Counter32 / Gauge32 / TimeTicks / IpAddress / Bits"
        )
    auth = _h.CommunityData(community)
    transport = await UdpTransportTarget.create(
        (host, int(port)),
        timeout=float(timeout), retries=int(retries),
    )
    error_indication, error_status, error_index, var_binds = await set_cmd(
        SnmpEngine(),
        auth,
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(oid), type_cls(value)),
    )
    if error_indication:
        raise OSError(f"SNMP SET {host}:{port} {oid}: {error_indication}")
    if error_status:
        raise OSError(
            f"SNMP SET {host}:{port} {oid}: {error_status.prettyPrint()} "
            f"(index {error_index})"
        )
    return _to_var(var_binds[0])


__all__ = ["snmp_get", "snmp_walk", "snmp_set", "SnmpVar"]
