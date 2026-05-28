"""
Relay target finder — inbound ACL analysis.

Instead of authenticating as candidate accounts, this module queries
nTSecurityDescriptor on high-value AD objects using the enumeration
credential, then identifies which principals have write (or read, for LAPS)
rights that would make them valuable relay targets.

The output answers: "If I can coerce X into authenticating, which relay
attack should I chain it with, and what's the target object?"

Attacks covered:
  RBCD         — principals with GenericWrite / WriteDACL / GenericAll
                  on computer objects (can write msDS-AllowedToActOnBehalfOf...)
  Shadow Creds — same ACL check (msDS-KeyCredentialLink same targets)
  LAPS         — principals with read rights on ms-Mcs-AdmPwd
                  on LAPS-managed computer objects
  ACL Abuse    — principals with WriteDACL / GenericAll on domain root
                  or high-value groups (Domain Admins, etc.)

All queries run as the enumeration credential — no candidate passwords needed.

Requires: impacket (from impacket.ldap import ldaptypes)
          ldap3
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from ..config import TargetEnv

try:
    import ldap3
    from ldap3 import Server, Connection, NTLM, SUBTREE, BASE, ALL
    from ldap3.protocol.microsoft import security_descriptor_control
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False

try:
    from impacket.ldap import ldaptypes
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


# ── attribute / right GUIDs ────────────────────────────────────────────────
# Fixed schema GUIDs, identical across all AD environments.

GUID_RBCD       = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"  # msDS-AllowedToActOnBehalfOfOtherIdentity
GUID_SHADOWCRED = "5b47d60f-6090-40b2-9f37-2a4de88f3063"  # msDS-KeyCredentialLink
GUID_LAPS_PWD   = "54bafdd2-36a8-4147-8d5c-be6d79fc6e84"  # ms-Mcs-AdmPwd (read)
GUID_LAPS_EXP   = "125c6e93-1512-4de2-ae6b-fd4d350853be"  # ms-Mcs-AdmPwdExpirationTime

# Access mask bits
GENERIC_ALL    = 0x10000000
GENERIC_WRITE  = 0x40000000
WRITE_DACL     = 0x00040000
WRITE_OWNER    = 0x00080000
ADS_WRITE_PROP = 0x00000020   # ADS_RIGHT_DS_WRITE_PROP
ADS_READ_PROP  = 0x00000010   # ADS_RIGHT_DS_READ_PROP

# ACE type constants
ACE_TYPE_ALLOWED        = 0x00
ACE_TYPE_ALLOWED_OBJECT = 0x05
ACE_OBJECT_TYPE_PRESENT = 0x01

# Well-known SIDs to always filter from results — expected rights by design.
# S-1-5-10 = SELF (the object itself) — not an exploitable trustee.
BUILTIN_NOISE_SIDS = {
    "S-1-5-10",       # SELF
    "S-1-5-18",       # SYSTEM
    "S-1-5-32-544",   # BUILTIN\Administrators
    "S-1-5-32-548",   # Account Operators
    "S-1-5-32-549",   # Server Operators
    "S-1-5-32-550",   # Print Operators
    "S-1-3-0",        # Creator Owner
    "S-1-3-4",        # Owner Rights
}

# Well-known RIDs — used to label cross-domain SIDs that can't be resolved
# via the local domain's SID map.
WELL_KNOWN_RIDS: dict[int, str] = {
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    553: "RAS and IAS Servers",
}

HIGH_VALUE_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Schema Admins",
    "Group Policy Creator Owners",
    "Domain Controllers",
]

# The DACL security info control — requests owner + group + DACL (flags=0x07)
_DACL_CONTROL = None   # populated lazily after ldap3 import confirmed


def _get_dacl_control():
    global _DACL_CONTROL
    if _DACL_CONTROL is None:
        _DACL_CONTROL = security_descriptor_control(sdflags=0x07)
    return _DACL_CONTROL


# ── result dataclasses ─────────────────────────────────────────────────────

@dataclass
class RelayTargetEntry:
    """A single (account, attack, target_object) finding."""
    account:       str   # sAMAccountName, or labelled SID if cross-domain
    attack:        str   # "RBCD", "ShadowCreds", "LAPS", "ACLAbuse"
    target_object: str   # CN of the object the account can write/read
    right:         str   # e.g. "GenericWrite", "WriteDACL"


@dataclass
class RelayTargetSummary:
    entries: list[RelayTargetEntry] = field(default_factory=list)
    error:   str = ""
    skipped: str = ""

    @property
    def by_account(self) -> dict[str, list[RelayTargetEntry]]:
        result: dict[str, list[RelayTargetEntry]] = defaultdict(list)
        for e in self.entries:
            result[e.account].append(e)
        return dict(result)

    @property
    def attacks_for(self) -> dict[str, set[str]]:
        result: dict[str, set[str]] = defaultdict(set)
        for e in self.entries:
            result[e.account].add(e.attack)
        return dict(result)


# ── LDAP connection ────────────────────────────────────────────────────────

def _ldap_connect(env: TargetEnv):
    if not LDAP3_AVAILABLE:
        return None
    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        conn = Connection(
            server,
            user=env.cred.upn,
            password=env.cred.password,
            authentication=NTLM,
            auto_bind=True,
        )
        return conn
    except Exception:
        return None


# ── SID helpers ────────────────────────────────────────────────────────────

def _build_sid_map(conn, domain_dn: str) -> dict[str, str]:
    """
    Build a SID → sAMAccountName map for the local domain.
    ldap3 returns objectSid as a formatted 'S-1-5-...' string directly.
    """
    sid_map: dict[str, str] = {}
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(|(objectClass=user)(objectClass=computer)(objectClass=group))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "objectSid"],
            paged_size=500,
        )
        for entry in conn.entries:
            try:
                sid_str = str(entry["objectSid"].value)
                name    = str(entry["sAMAccountName"])
                sid_map[sid_str] = name
            except Exception:
                continue
    except Exception:
        pass
    return sid_map


def _build_noise_sids(domain_sid: str) -> set[str]:
    """
    Build the full noise SID set: builtins + domain high-privilege groups.
    These SIDs having ACL rights is expected and not actionable for relay.
    """
    noise = set(BUILTIN_NOISE_SIDS)
    # High-privilege domain groups by RID
    for rid in (512, 516, 518, 519, 521):
        noise.add(f"{domain_sid}-{rid}")
    return noise


def _get_domain_sid(conn, domain_dn: str) -> str:
    """Retrieve the domain SID from the domain root object."""
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(objectClass=domain)",
            search_scope=BASE,
            attributes=["objectSid"],
        )
        if conn.entries:
            return str(conn.entries[0]["objectSid"].value)
    except Exception:
        pass
    return ""


def _resolve_sid(
    sid_str: str,
    sid_map: dict[str, str],
    known_domain_sids: dict[str, str],
) -> Optional[str]:
    """
    Resolve a SID string to a human-readable name.

    Resolution order:
      1. Local domain sid_map (covers all local users/groups/computers)
      2. Well-known RID suffix (e.g. -512 = Domain Admins) combined with
         a known domain prefix — labels cross-domain SIDs meaningfully
      3. Return None → caller will skip or show raw SID

    Cross-domain SIDs (from trusted domains) won't be in the local sid_map.
    We label them as "<DomainName>/<GroupName>" using the RID if known,
    or "<DomainName>/<SID>" if not — always more readable than a raw SID.
    """
    # Local resolution
    if sid_str in sid_map:
        return sid_map[sid_str]

    # Try RID-based resolution for cross-domain SIDs
    # SID format: S-1-5-21-<sub1>-<sub2>-<sub3>-<RID>
    parts = sid_str.split("-")
    if len(parts) >= 2:
        try:
            rid = int(parts[-1])
            domain_prefix = "-".join(parts[:-1])

            domain_label = known_domain_sids.get(domain_prefix, "")
            rid_label    = WELL_KNOWN_RIDS.get(rid, "")

            if domain_label and rid_label:
                return f"{domain_label}\\{rid_label}"
            elif domain_label:
                return f"{domain_label}\\{rid}"
            elif rid_label:
                # Domain unknown but RID is well-known — label with just the group name
                return rid_label
        except ValueError:
            pass

    return None   # unresolvable — caller decides whether to skip or show raw


# ── ACE parsing ────────────────────────────────────────────────────────────

def _format_guid(raw: bytes) -> str:
    """
    Convert a 16-byte GUID in Windows wire format (mixed-endian) to the
    standard xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx string.
    """
    if len(raw) != 16:
        return raw.hex()
    p1 = raw[0:4][::-1].hex()
    p2 = raw[4:6][::-1].hex()
    p3 = raw[6:8][::-1].hex()
    p4 = raw[8:10].hex()
    p5 = raw[10:16].hex()
    return f"{p1}-{p2}-{p3}-{p4}-{p5}"


def _parse_dacl(
    raw_sd: bytes,
    noise_sids: set[str],
    sid_map: dict[str, str],
    known_domain_sids: dict[str, str],
) -> list[tuple[str, int, Optional[str]]]:
    """
    Parse a raw nTSecurityDescriptor DACL.

    Returns list of (account_name, access_mask, object_type_guid_or_None)
    for all non-noise ALLOW ACEs where the SID can be resolved.
    Unresolvable SIDs are silently dropped.
    """
    results = []
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
        if not sd["Dacl"]:
            return results

        for ace in sd["Dacl"].aces:
            ace_type = ace["AceType"]
            if ace_type not in (ACE_TYPE_ALLOWED, ACE_TYPE_ALLOWED_OBJECT):
                continue

            try:
                sid_str = ace["Ace"]["Sid"].formatCanonical()
            except Exception:
                continue

            if sid_str in noise_sids:
                continue

            account = _resolve_sid(sid_str, sid_map, known_domain_sids)
            if account is None:
                # Unresolvable SID — skip rather than show raw SID noise
                continue

            mask = ace["Ace"]["Mask"]["Mask"]

            if ace_type == ACE_TYPE_ALLOWED_OBJECT:
                flags = ace["Ace"]["Flags"]
                if flags & ACE_OBJECT_TYPE_PRESENT:
                    try:
                        guid_str = _format_guid(bytes(ace["Ace"]["ObjectType"]))
                        results.append((account, mask, guid_str))
                    except Exception:
                        results.append((account, mask, None))
                else:
                    results.append((account, mask, None))
            else:
                results.append((account, mask, None))

    except Exception:
        pass

    return results


# ── ACE right classifiers ──────────────────────────────────────────────────

def _ace_grants_write(mask: int, guid: Optional[str]) -> Optional[str]:
    """Right label if the ACE grants write access useful for RBCD/Shadow Creds."""
    if mask & GENERIC_ALL:   return "GenericAll"
    if mask & GENERIC_WRITE: return "GenericWrite"
    if mask & WRITE_DACL:    return "WriteDACL"
    if mask & WRITE_OWNER:   return "WriteOwner"
    if mask & ADS_WRITE_PROP:
        if guid is None:                           return "WriteProperty(all)"
        if guid.lower() == GUID_RBCD.lower():      return "WriteProperty(msDS-AllowedToActOnBehalfOfOtherIdentity)"
        if guid.lower() == GUID_SHADOWCRED.lower(): return "WriteProperty(msDS-KeyCredentialLink)"
    return None


def _ace_grants_laps_read(mask: int, guid: Optional[str]) -> bool:
    """True if the ACE grants read access to ms-Mcs-AdmPwd."""
    if mask & GENERIC_ALL: return True
    if mask & ADS_READ_PROP:
        if guid is None: return True
        if guid.lower() in (GUID_LAPS_PWD.lower(), GUID_LAPS_EXP.lower()): return True
    return False


def _ace_grants_acl_abuse(mask: int, guid: Optional[str]) -> Optional[str]:
    """Right label if the ACE grants rights useful for ACL abuse."""
    if mask & GENERIC_ALL:   return "GenericAll"
    if mask & WRITE_DACL:    return "WriteDACL"
    if mask & WRITE_OWNER:   return "WriteOwner"
    if mask & GENERIC_WRITE: return "GenericWrite"
    if mask & ADS_WRITE_PROP and guid is None: return "WriteProperty(all)"
    return None


# ── per-attack scanners ────────────────────────────────────────────────────

def _ldap_search_with_sd(conn, base, filter_, attrs):
    """
    Run an LDAP search requesting nTSecurityDescriptor via the DACL control.
    Falls back to a plain search if the control causes an error.
    """
    try:
        conn.search(
            search_base=base,
            search_filter=filter_,
            search_scope=SUBTREE,
            attributes=attrs,
            controls=_get_dacl_control(),
        )
        return True
    except Exception:
        pass
    try:
        conn.search(
            search_base=base,
            search_filter=filter_,
            search_scope=SUBTREE,
            attributes=attrs,
        )
        return True
    except Exception:
        return False


def _scan_rbcd_shadowcreds(
    conn,
    domain_dn: str,
    noise_sids: set[str],
    sid_map: dict[str, str],
    known_domain_sids: dict[str, str],
) -> list[RelayTargetEntry]:
    """Find accounts with write rights on computer objects (RBCD + Shadow Creds)."""
    entries: list[RelayTargetEntry] = []

    if not _ldap_search_with_sd(
        conn, domain_dn, "(objectClass=computer)",
        ["sAMAccountName", "nTSecurityDescriptor"],
    ):
        return entries

    for obj in conn.entries:
        try:
            computer_name = str(obj["sAMAccountName"])
            raw_sd = obj["nTSecurityDescriptor"].raw_values[0]
        except Exception:
            continue

        aces = _parse_dacl(raw_sd, noise_sids, sid_map, known_domain_sids)
        seen: dict[str, set[str]] = defaultdict(set)

        for account, mask, guid in aces:
            right = _ace_grants_write(mask, guid)
            if not right or right in seen[account]:
                continue
            seen[account].add(right)

            if "AllowedToActOnBehalf" in right:
                entries.append(RelayTargetEntry(account, "RBCD", computer_name, right))
            elif "KeyCredentialLink" in right:
                entries.append(RelayTargetEntry(account, "ShadowCreds", computer_name, right))
            else:
                # Generic right covers both attacks
                entries.append(RelayTargetEntry(account, "RBCD",         computer_name, right))
                entries.append(RelayTargetEntry(account, "ShadowCreds",  computer_name, right))

    return entries


def _scan_laps(
    conn,
    domain_dn: str,
    noise_sids: set[str],
    sid_map: dict[str, str],
    known_domain_sids: dict[str, str],
) -> list[RelayTargetEntry]:
    """Find accounts with read access to ms-Mcs-AdmPwd on LAPS-managed computers."""
    entries: list[RelayTargetEntry] = []

    if not _ldap_search_with_sd(
        conn, domain_dn, "(ms-Mcs-AdmPwdExpirationTime=*)",
        ["sAMAccountName", "nTSecurityDescriptor"],
    ):
        return entries

    for obj in conn.entries:
        try:
            computer_name = str(obj["sAMAccountName"])
            raw_sd = obj["nTSecurityDescriptor"].raw_values[0]
        except Exception:
            continue

        aces = _parse_dacl(raw_sd, noise_sids, sid_map, known_domain_sids)
        seen: set[str] = set()
        for account, mask, guid in aces:
            if account not in seen and _ace_grants_laps_read(mask, guid):
                seen.add(account)
                entries.append(RelayTargetEntry(
                    account, "LAPS", computer_name, "ReadProperty(ms-Mcs-AdmPwd)",
                ))

    return entries


def _scan_acl_abuse(
    conn,
    domain_dn: str,
    noise_sids: set[str],
    sid_map: dict[str, str],
    known_domain_sids: dict[str, str],
) -> list[RelayTargetEntry]:
    """Find accounts with WriteDACL/GenericAll on domain root or high-value groups."""
    entries: list[RelayTargetEntry] = []

    # Domain root — needs BASE scope, not SUBTREE
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(objectClass=domain)",
            search_scope=BASE,
            attributes=["distinguishedName", "nTSecurityDescriptor"],
            controls=_get_dacl_control(),
        )
        if conn.entries:
            raw_sd = conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
            aces   = _parse_dacl(raw_sd, noise_sids, sid_map, known_domain_sids)
            seen: set[str] = set()
            for account, mask, guid in aces:
                right = _ace_grants_acl_abuse(mask, guid)
                if right and account not in seen:
                    seen.add(account)
                    entries.append(RelayTargetEntry(
                        account, "ACLAbuse", "Domain Root (DCSync path)", right,
                    ))
    except Exception:
        pass

    # High-value groups
    for group_cn in HIGH_VALUE_GROUPS:
        try:
            conn.search(
                search_base=domain_dn,
                search_filter=f"(&(objectClass=group)(cn={group_cn}))",
                search_scope=SUBTREE,
                attributes=["cn", "nTSecurityDescriptor"],
                controls=_get_dacl_control(),
            )
            if not conn.entries:
                continue
            raw_sd = conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
            aces   = _parse_dacl(raw_sd, noise_sids, sid_map, known_domain_sids)
            seen_g: set[str] = set()
            for account, mask, guid in aces:
                right = _ace_grants_acl_abuse(mask, guid)
                if right and account not in seen_g:
                    seen_g.add(account)
                    entries.append(RelayTargetEntry(
                        account, "ACLAbuse", group_cn, right,
                    ))
        except Exception:
            continue

    return entries


# ── public entry point ─────────────────────────────────────────────────────

def run_relay_target_finder(env: TargetEnv) -> RelayTargetSummary:
    """
    Run the inbound ACL scan using the enumeration credential.
    No candidate account passwords needed.
    """
    summary = RelayTargetSummary()

    if not IMPACKET_AVAILABLE:
        summary.skipped = (
            "impacket not available — install with: pip install impacket. "
            "Needed for nTSecurityDescriptor ACE parsing."
        )
        return summary

    if not LDAP3_AVAILABLE:
        summary.skipped = "ldap3 not available — install with: pip install ldap3"
        return summary

    conn = _ldap_connect(env)
    if not conn:
        summary.skipped = (
            f"LDAP connection to {env.dc_ip} failed — "
            "check credentials and network connectivity."
        )
        return summary

    try:
        domain_dn  = ",".join(f"DC={p}" for p in env.domain.split("."))
        domain_sid = _get_domain_sid(conn, domain_dn)

        if not domain_sid:
            summary.skipped = "Could not retrieve domain SID — ACL scan aborted."
            return summary

        noise_sids = _build_noise_sids(domain_sid)
        sid_map    = _build_sid_map(conn, domain_dn)

        # Build a domain SID prefix → short name map for labelling cross-domain SIDs.
        # Seed with the local domain; additional domains can be added if needed.
        domain_label = env.domain.split(".")[0].upper()
        known_domain_sids: dict[str, str] = {domain_sid: domain_label}

        summary.entries += _scan_rbcd_shadowcreds(conn, domain_dn, noise_sids, sid_map, known_domain_sids)
        summary.entries += _scan_laps(conn, domain_dn, noise_sids, sid_map, known_domain_sids)
        summary.entries += _scan_acl_abuse(conn, domain_dn, noise_sids, sid_map, known_domain_sids)

    except Exception as e:
        summary.error = f"ACL scan failed: {e}"
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    return summary
