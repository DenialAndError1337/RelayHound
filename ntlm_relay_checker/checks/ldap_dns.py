"""
ADIDNS-spoofing prerequisite checks for NTLM Relay → LDAP (AD-integrated DNS write).

Relaying a coerced account's NTLM authentication to LDAP lets the attacker create
a new DNS A record (a dnsNode child object) in an AD-integrated DNS zone, pointing
an attacker-chosen hostname at the attacker's IP. Any client that subsequently
resolves that name connects to the attacker instead of the legitimate host —
enabling further coercion/capture or onward relay (e.g. poisoning beyond the local
subnet, or registering a `wpad` record).

What makes this distinct from RBCD / Shadow Credentials: the relay channel is the
same (LDAP), but the write target is a *new child object* in the DNS zone rather
than an attribute on an existing computer object. The post-exploitation outcome is
DNS hijacking rather than delegation abuse or certificate theft.

Prerequisites:
  [REQ]  LDAP signing not enforced       — shared with RBCD/Shadow Creds (LDAP relay)
  [REQ]  LDAP channel binding not required — same
  [REQ]  An AD-integrated DNS zone exists (a dnsZone object reachable via LDAP)
  [OPT]  `Authenticated Users` (or `Everyone`) holds CreateChild on the zone DACL.
         This is the key signal: when present (the AD default), *any* relayed
         account can create a record. When hardened away, the attack is not dead —
         it now depends on relaying a principal that does hold CreateChild — so the
         absence is a PARTIAL/soft-blocker, not NOT VIABLE (mirrors how the
         operator-rights checks in RBCD/Shadow Creds are treated as optional).

Tooling notes (for the attack-chain commands in output.py):
  - ntlmrelayx ships an `--add-dns-record <name> <ip>` LDAP attack (impacket
    PR #1289) that creates the A record directly during the relay.
  - dnstool.py (dirkjanm/krbrelayx) is the credentialed / post-relay alternative:
    `dnstool.py -u 'DOMAIN\\user' -p '<pass>' --action add --record <name>
    --data <attacker-ip> <dc>`.
  - nxc `ldap --module get-network` exists but has crashed on binary DNS record
    data (pyasn1 decode bug), so all zone enumeration here uses ldap3 directly.
"""
from __future__ import annotations
import struct
from typing import Optional

from .base import BaseCheck, CheckResult, Status, ldap_or_relay_viability
from ..config import TargetEnv
from ..utils import LdapSigningCheck, LdapChannelBindingCheck

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    from ldap3.protocol.microsoft import security_descriptor_control
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False

try:
    from impacket.ldap import ldaptypes
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


# ── access-mask / ACE constants ─────────────────────────────────────────────
# Identical across every AD environment.
ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
GENERIC_ALL               = 0x10000000
GENERIC_WRITE             = 0x40000000

ACE_TYPE_ALLOWED        = 0x00
ACE_TYPE_ALLOWED_OBJECT = 0x05
ACE_OBJECT_TYPE_PRESENT = 0x01

# Trustees that make the attack work for *any* relayed account when granted
# CreateChild on the zone.
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_EVERYONE            = "S-1-1-0"
OPEN_TRUSTEES = {SID_AUTHENTICATED_USERS: "Authenticated Users",
                 SID_EVERYONE:            "Everyone"}

# DNS zone types (MS-DNSP DSPROPERTY_ZONE_TYPE / dnsProperty Data DWORD).
# Only PRIMARY zones are AD-integrated zones the DC is authoritative for and can
# hold attacker-created dnsNode records. Forwarder/stub/secondary/cache zones are
# also stored as dnsZone objects but have no writable record container, so they
# are NOT ADIDNS-spoofing targets (lab-proven on GOAD: a cross-forest conditional
# forwarder `essos.local` was enumerated but a record write returned noSuchObject).
DNS_ZONE_TYPE_PRIMARY = 1   # CACHE=0, SECONDARY=2, STUB=3, FORWARDER=4


def _dns_zone_type(dnsproperty_raw_values) -> Optional[int]:
    """Decode the zone type from a dnsZone object's multi-valued dnsProperty.

    Each dnsProperty value is an MS-DNSP property blob:
        DataLength(4) NameLength(4) Flag(4) Version(4) Id(4) Data(DataLength) Name(1)
    The zone-type property has Id == 0x01; its Data is a DWORD zone type
    (0=Cache, 1=Primary, 2=Secondary, 3=Stub, 4=Forwarder).

    Returns the zone-type int, or None if it cannot be cleanly determined — so
    callers treat "unknown" as do-not-exclude (conservative: never hide a real
    primary zone just because its property blob was unreadable).
    """
    if not dnsproperty_raw_values:
        return None
    for blob in dnsproperty_raw_values:
        try:
            if len(blob) < 20:
                continue
            data_length, _name_len, _flag, _version, prop_id = struct.unpack_from("<IIIII", blob, 0)
            if prop_id == 0x01:  # DSPROPERTY_ZONE_TYPE
                if data_length >= 4 and len(blob) >= 24:
                    (zone_type,) = struct.unpack_from("<I", blob, 20)
                    return int(zone_type)
                return None  # zero/short Data → unknown, keep zone
        except Exception:
            continue
    return None


# ── helpers ──────────────────────────────────────────────────────────────────


def _dns_partition_bases(server) -> list[str]:
    """
    Return the LDAP search bases that can hold AD-integrated DNS zones.

    AD-integrated zones live in one of three partitions:
      DC=DomainDnsZones,<domain NC>   — domain-wide replication (default)
      DC=ForestDnsZones,<forest NC>   — forest-wide replication
      CN=MicrosoftDNS,CN=System,<domain NC>  — legacy domain-NC storage

    The DomainDnsZones / ForestDnsZones application partitions are read from
    RootDSE namingContexts (rather than constructed from the domain name) so
    this stays correct in child domains and multi-domain forests. The legacy
    System container is derived from the default NC as a fallback.
    """
    bases: list[str] = []
    other = {}
    try:
        other = getattr(server.info, "other", {}) or {}
    except Exception:
        other = {}

    # namingContexts is a standard RFC 4512 attribute that ldap3 parses into
    # server.info.naming_contexts (NOT server.info.other — that only holds
    # AD-specific extensions like defaultNamingContext).
    ncs = []
    try:
        ncs = [str(v) for v in (getattr(server.info, "naming_contexts", None) or [])]
    except Exception:
        ncs = []
    for nc in ncs:
        low = nc.lower()
        if low.startswith("dc=domaindnszones,") or low.startswith("dc=forestdnszones,"):
            bases.append(nc)

    # Legacy / fallback: CN=MicrosoftDNS,CN=System,<defaultNC>
    default_nc = None
    try:
        vals = other.get("defaultNamingContext")
        if vals:
            default_nc = str(vals[0])
    except Exception:
        default_nc = None
    if default_nc:
        bases.append(f"CN=MicrosoftDNS,CN=System,{default_nc}")

    # Deduplicate, preserve order
    return list(dict.fromkeys(bases))


def _discover_dns_zones(env: TargetEnv) -> Optional[list[dict]]:
    """
    Discover AD-integrated DNS zones and (where readable) their DACLs.

    Returns a list of {"name", "dn", "partition", "raw_sd"} dicts, or None if
    the probe was inconclusive (ldap3 missing, bind failed, no partition found).
    An empty list is a *definitive* "no AD-integrated zone" answer.

    Cached in env.shared_cache["adidns_zones"] so the zone-existence check and
    the CreateChild-ACE check share a single LDAP pass (one query per partition).
    """
    if "adidns_zones" in env.shared_cache:
        return env.shared_cache["adidns_zones"]

    if not LDAP3_AVAILABLE:
        return None

    if env.cred.nt_hash:
        nh = env.cred.nt_hash.split(":")[-1]
        auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
    else:
        auth_password = env.cred.password

    # Try plain LDAP first; fall back to LDAPS/TLS when signing is enforced (3a).
    import ssl as _ssl
    server = conn = None
    for _port, _ssl_flag in ((389, False), (636, True)):
        try:
            from ldap3 import Tls as _Tls
            _tls = _Tls(validate=_ssl.CERT_NONE) if _ssl_flag else None
            server = Server(env.dc_ip, port=_port, use_ssl=_ssl_flag, tls=_tls,
                            get_info=ALL, connect_timeout=env.timeout)
            conn = Connection(server, user=env.cred.upn, password=auth_password,
                              authentication=NTLM, auto_bind=True)
            break
        except Exception:
            server = conn = None
    if conn is None:
        return None  # bind refused/failed → inconclusive (do NOT cache)

    bases = _dns_partition_bases(server)
    if not bases:
        try:
            conn.unbind()
        except Exception:
            pass
        return None  # couldn't read RootDSE NCs → inconclusive

    # DACL-only security descriptor control (sdflags=0x04). Reading the DACL
    # does not require SeSecurityPrivilege (that is only for the SACL).
    sd_control = None
    if IMPACKET_AVAILABLE:
        try:
            sd_control = security_descriptor_control(sdflags=0x04)
        except Exception:
            sd_control = None

    zones: list[dict] = []
    search_completed = False
    for base in bases:
        attrs = ["name", "nTSecurityDescriptor", "dnsProperty"]
        # First try requesting the SD via the control; fall back to a plain
        # search if the control errors (so zone *existence* is still detected).
        ran = False
        if sd_control is not None:
            try:
                conn.search(search_base=base,
                            search_filter="(objectClass=dnsZone)",
                            search_scope=SUBTREE, attributes=attrs,
                            controls=sd_control)
                ran = True
            except Exception:
                ran = False
        if not ran:
            try:
                conn.search(search_base=base,
                            search_filter="(objectClass=dnsZone)",
                            search_scope=SUBTREE, attributes=["name", "dnsProperty"])
                ran = True
            except Exception:
                ran = False
        if not ran:
            continue
        search_completed = True
        for e in conn.entries:
            raw_sd = None
            try:
                if "nTSecurityDescriptor" in e and e["nTSecurityDescriptor"].raw_values:
                    raw_sd = e["nTSecurityDescriptor"].raw_values[0]
            except Exception:
                raw_sd = None
            zname = str(e["name"]) if "name" in e and e["name"] else e.entry_dn.split(",")[0]
            ztype = None
            try:
                if "dnsProperty" in e and e["dnsProperty"].raw_values:
                    ztype = _dns_zone_type(e["dnsProperty"].raw_values)
            except Exception:
                ztype = None
            zones.append({"name": zname, "dn": e.entry_dn,
                          "partition": base, "raw_sd": raw_sd, "zone_type": ztype})

    try:
        conn.unbind()
    except Exception:
        pass

    if not search_completed:
        return None  # every partition search errored → inconclusive

    # Filter out zones that are not useful spoofing targets:
    # - Reverse-lookup zones (in-addr.arpa, ip6.arpa)
    # - Root-hints and pseudo-zones (RootDNSServers, ..RootHints)
    # - _msdcs zones: these are DC-locator zones — writing records there breaks
    #   domain functionality (SRV/NS corruption) rather than enabling useful MITM.
    #   Keep them in the existence check but exclude from the "write target" list.
    # - Non-primary zones (forwarder/stub/secondary/cache): enumerated as dnsZone
    #   objects but the DC isn't authoritative for them and they have no writable
    #   record container, so they can't be ADIDNS-spoofed. zone_type None = unknown
    #   → keep (conservative; never hide a real primary zone we couldn't classify).
    spoofable = [z for z in zones
                 if not z["name"].lower().endswith("in-addr.arpa")
                 and not z["name"].lower().endswith("ip6.arpa")
                 and z["name"].lower() not in ("rootdnsservers", "..roothints")
                 and not z["name"].lower().startswith("_msdcs.")
                 and z.get("zone_type") in (DNS_ZONE_TYPE_PRIMARY, None)]
    # Fallback when nothing is clearly spoofable: surface only zones whose type we
    # could NOT read (zone_type is None), never ones we positively classified as
    # non-primary. Falling back to the *full* list re-admitted forwarder/stub
    # zones — a forwarder-only result then false-PASSed the existence gatekeeper
    # even though the DC can't write a record there (the essos.local case). An
    # unparseable-type zone stays surfaced so a real primary zone we simply
    # couldn't classify is never hidden.
    result = spoofable or [z for z in zones if z.get("zone_type") is None]

    env.shared_cache["adidns_zones"] = result
    return result


# ── individual checks ──────────────────────────────────────────────────────

class AdIntegratedDnsZoneCheck(BaseCheck):
    """
    An AD-integrated DNS zone must exist as the write target.

    Gatekeeper: with no dnsZone object reachable over LDAP there is nothing to
    write a record into, so the remaining ADIDNS checks are pointless — this
    breaks_on_fail. SKIP (tool/bind/RootDSE inconclusive) does not break the
    chain; only a definitive empty result FAILs.
    """

    name = "AD-integrated DNS zone exists"
    breaks_on_fail = True

    def _run(self) -> CheckResult:
        if not LDAP3_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="ldap3 not installed — cannot enumerate DNS zones. "
                                      "Install with: pip install ldap3")
        zones = _discover_dns_zones(self.env)
        if zones is None:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP bind/search inconclusive — could not enumerate "
                                      "DNS partitions (check credentials/connectivity).")
        if not zones:
            return CheckResult(name=self.name, status=Status.FAIL,
                               detail="No AD-integrated DNS zone (dnsZone object) found in the "
                                      "DomainDnsZones/ForestDnsZones/System partitions — no zone "
                                      "to write a spoofed record into.")
        names = ", ".join(z["name"] for z in zones[:5])
        more = f" (+{len(zones) - 5} more)" if len(zones) > 5 else ""
        return CheckResult(name=self.name, status=Status.PASS,
                           detail=f"AD-integrated DNS zone(s) present: {names}{more}. "
                                  "Relayed LDAP write can create a new A record (dnsNode) here.")


class DnsZoneCreateChildAceCheck(BaseCheck):
    """
    Does the zone DACL grant CreateChild to Authenticated Users / Everyone?

    This is the key, hardenable signal:
      PASS — an open trustee holds CreateChild (the AD default). *Any* relayed
             account can create a record → broadest viability.
      FAIL — zone read but no open-trustee CreateChild ACE. The attack is not
             impossible: it now requires relaying a principal that *does* hold
             CreateChild (DnsAdmins, a privileged machine/user account, etc.).
             Reported optional so this yields PARTIAL, not NOT VIABLE — mirrors
             how RBCD/Shadow Creds treat identity-dependent write rights.
      SKIP — impacket missing (no SD parser), or the SD was not readable.

    required=False: never blocks viability; it characterises *which* relayed
    identities work, which is impact/accuracy context, not a hard prerequisite.
    """

    name = "DNS zone allows record creation by any account (CreateChild for Authenticated Users)"
    required = False

    def _run(self) -> CheckResult:
        if not IMPACKET_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="impacket not installed — cannot parse the zone "
                                      "nTSecurityDescriptor. Install with: pip install impacket")
        zones = _discover_dns_zones(self.env)
        if not zones:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="No DNS zone DACL available to evaluate "
                                      "(zone enumeration inconclusive or empty).")

        with_sd = [z for z in zones if z.get("raw_sd")]
        if not with_sd:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="DNS zone(s) found but their nTSecurityDescriptor could not "
                                      "be read (insufficient rights or SD control rejected). "
                                      "Verify the zone DACL manually.")

        open_grants: list[str] = []   # "zone (Trustee[, scoped])"
        for z in with_sd:
            for trustee, label, scoped in _zone_createchild_trustees(z["raw_sd"]):
                note = f"{z['name']} ({label}{', object-scoped' if scoped else ''})"
                open_grants.append(note)

        if open_grants:
            uniq = list(dict.fromkeys(open_grants))
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=("Open CreateChild on zone DACL — any relayed account can create "
                        f"records: {', '.join(uniq[:6])}. This is the AD default and is the "
                        "broadest ADIDNS-spoofing condition."),
            )

        scanned = ", ".join(z["name"] for z in with_sd[:5])
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=(f"No CreateChild ACE for Authenticated Users/Everyone on the scanned "
                    f"zone(s): {scanned}. The default DACL appears hardened — record creation "
                    "is restricted to privileged principals (e.g. DnsAdmins, SYSTEM, a "
                    "specific machine/user account). The attack is still viable if you relay "
                    "a principal that holds CreateChild; it just no longer works for an "
                    "arbitrary relayed account."),
        )


def _zone_createchild_trustees(raw_sd: bytes) -> list[tuple[str, str, bool]]:
    """
    Parse a zone nTSecurityDescriptor DACL and return open trustees (Authenticated
    Users / Everyone) that hold CreateChild (or GenericAll/GenericWrite, which
    subsume it). Returns list of (sid, label, object_scoped) tuples.
    """
    out: list[tuple[str, str, bool]] = []
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
        if not sd["Dacl"]:
            return out
        for ace in sd["Dacl"].aces:
            ace_type = ace["AceType"]
            if ace_type not in (ACE_TYPE_ALLOWED, ACE_TYPE_ALLOWED_OBJECT):
                continue
            try:
                sid_str = ace["Ace"]["Sid"].formatCanonical()
            except Exception:
                continue
            if sid_str not in OPEN_TRUSTEES:
                continue
            mask = ace["Ace"]["Mask"]["Mask"]
            grants = bool(mask & (ADS_RIGHT_DS_CREATE_CHILD | GENERIC_ALL | GENERIC_WRITE))
            if not grants:
                continue
            scoped = False
            if ace_type == ACE_TYPE_ALLOWED_OBJECT:
                try:
                    scoped = bool(ace["Ace"]["Flags"] & ACE_OBJECT_TYPE_PRESENT)
                except Exception:
                    scoped = False
            out.append((sid_str, OPEN_TRUSTEES[sid_str], scoped))
    except Exception:
        pass
    return out


# ── attack check list ──────────────────────────────────────────────────────

# OR relay-path verdict (signing OR channel-binding OR NTLMv1). Attached by the
# engine via AttackResult.viability_fn.
module_viability = ldap_or_relay_viability


def get_checks(env: TargetEnv) -> list[BaseCheck]:
    # Deferred import avoids a utils ↔ checks import cycle (same pattern the
    # other plain-LDAP modules use). NTLMv1 acceptance is what lets a coerced
    # SMB auth relay to plain ldap:// even when LDAP signing is enforced, so it
    # belongs here exactly as in rbcd/shadowcreds/laps.
    from ..utils import NtlmV1AuthProbeCheck
    return [
        LdapSigningCheck(env),
        LdapChannelBindingCheck(env),
        AdIntegratedDnsZoneCheck(env),
        DnsZoneCreateChildAceCheck(env),
        NtlmV1AuthProbeCheck(env),
    ]


ATTACK_NAME = "NTLM Relay → LDAP (ADIDNS Spoofing)"
