"""
LDAPS ACL abuse prerequisite checks for NTLM Relay → LDAPS (ACL Abuse).

Relaying NTLM to LDAPS allows modifying ACLs on AD objects if the relayed
account has WriteDACL or GenericAll rights on them. Common targets are user
objects (add DCSync rights), group objects (add members), or computer objects
(RBCD/Shadow Credentials).

Unlike the Add Computer relay (which needs MAQ > 0), ACL abuse only needs
a target object where the relayed account has write permissions.

Prerequisites:
  [REQ]  LDAPS reachable (port 636)
  [REQ]  LDAPS channel binding (EPA) not enforced
  [REQ]  At least one target object exists with weak ACLs
         (WriteDACL / GenericAll / GenericWrite on a valuable object)
  [OPT]  Domain object itself writable (allows granting DCSync rights)
  [OPT]  High-value groups with weak ACLs (Domain Admins, etc.)
"""
from __future__ import annotations

from .base import BaseCheck, CheckResult, Status, ldap_or_relay_viability
from ..config import TargetEnv
from .relay_target_finder import relay_target_principals_note
from ..utils import LdapSigningCheck

try:
    from ldap3 import SUBTREE
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
from ..utils import _ldap_connect, _port_open, _run_bloodyad, ldaps_cb_fanout, _dc_list_label


# ── helpers ────────────────────────────────────────────────────────────────


# ── individual checks ──────────────────────────────────────────────────────

class LdapsPortCheck(BaseCheck):
    """LDAPS reachable on port 636 — the LDAPS/TLS relay sub-path.

    Under the OR relay-path model this is an alternative channel, not a hard gate:
    with LDAPS unreachable, ACL writes still succeed over plain ldap:// when LDAP
    signing is off. So required=False and viability is decided by module_viability.
    """

    name = "LDAPS reachable (port 636)"
    required = False

    def _run(self) -> CheckResult:
        if _port_open(self.env.dc_ip, 636, timeout=self.env.timeout):
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"LDAPS port 636 reachable on {self.env.dc_ip}.",
            )
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=f"LDAPS port 636 not reachable on {self.env.dc_ip}.",
        )


class LdapsChannelBindingCheck(BaseCheck):
    """LDAPS channel binding (EPA) not enforced — opens the ldaps:// relay path.

    Under the OR model this is one alternative channel (CB=Never → TLS relay
    viable), not a hard requirement: required=False so a CB FAIL alone does not
    veto the attack when the plain-ldap:// (signing-off) or NTLMv1 path is open.
    """

    name = "LDAPS channel binding (EPA) not enforced"
    required = False

    def _run(self) -> CheckResult:
        # Fan out over dc_targets() — CB=Never on ANY DC opens the ldaps:// path.
        status, open_dcs, blocked_dcs, soft_dcs, unknown_dcs = ldaps_cb_fanout(self.env)
        multi = len(open_dcs) + len(blocked_dcs) + len(soft_dcs) + len(unknown_dcs) > 1

        if status is Status.PASS:
            note = ""
            if multi:
                other = blocked_dcs + soft_dcs + unknown_dcs
                note = (f" (enforced/undetermined on {_dc_list_label(self.env, other)}, "
                        "relay to the permissive DC still succeeds)") if other else ""
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"LDAPS channel binding NOT required (Never) on "
                       f"{_dc_list_label(self.env, open_dcs)} — relay viable.{note}",
            )
        if status is Status.FAIL:
            scope = "all probed DCs" if multi else _dc_list_label(self.env, blocked_dcs)
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    f"LDAPS channel binding enforced (Always / When Supported) on {scope} "
                    "— ldaps:// relay path blocked (relayed no-CBT bind fails with "
                    "SEC_E_BAD_BINDINGS). Plain ldap:// path (signing off) or NTLMv1 may "
                    "still allow ACL writes — check those results."
                ),
            )
        if status is Status.WARN:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"LDAPS channel binding unconfirmed on {_dc_list_label(self.env, soft_dcs)} "
                    "— cannot confirm CB=Never vs When Supported, so the ldaps:// relay path "
                    "is unconfirmed. Check the plain-LDAP signing result; verify "
                    "LdapEnforceChannelBinding (0=Never, 1=When Supported, 2=Always)."
                ),
            )
        # SKIP
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Channel binding could not be determined on "
                f"{_dc_list_label(self.env, unknown_dcs)} — nxc timed out / unavailable and "
                "the direct LDAPS probe was inconclusive. Plain ldap:// (signing off) or "
                "NTLMv1 may still allow ACL writes — check those results."
            ),
        )


class WeakAclObjectsCheck(BaseCheck):
    """
    At least one high-value AD object must have weak ACLs that the relayed
    account can exploit. Common targets:
      - Domain object itself (WriteDACL → grant DCSync rights)
      - Domain Admins group (GenericWrite → add members)
      - Computer objects (GenericWrite → RBCD/Shadow Creds)
      - User objects (GenericWrite → set SPN, reset password)

    Method: bloodyAD get writable (lists objects current account can write to)
            Fallback: enumerate computer/group objects and note manual ACL check needed.

    Note: Full ACL enumeration is done by BloodHound — this check gives a
    lightweight indicator. Use BloodHound for comprehensive ACL analysis.
    """

    name = "Writable high-value AD objects exist"
    # Optional/informational: probes the OPERATOR's current write rights. ACL abuse
    # is carried out via the relayed victim's rights, so "nothing writable by me"
    # must NOT make the attack NOT VIABLE — viability is driven by the protocol
    # prerequisites (LDAPS reachable / channel binding) checked above.
    required = False

    def _run(self) -> CheckResult:
        result = self._run_base()
        note = relay_target_principals_note(self.env, "ACLAbuse")
        if note:
            result.detail = (result.detail or "") + note
        return result

    def _run_base(self) -> CheckResult:
        # Try bloodyAD writable check
        rc, out, err = _run_bloodyad(["get", "writable"], self.env)
        if rc == 0 and out.strip():
            import re
            # bloodyAD output: "distinguishedName: CN=..., permission: WRITE"
            # Extract just the CN portion for clean display
            dn_matches = re.findall(r"CN=([^,\n]+)", out)
            perm_matches = re.findall(r"permission:[\s]*([^\n,]+)", out, re.IGNORECASE)

            # AD container/system objects writable by default for privileged accounts
            # but not meaningful ACL abuse targets
            ad_containers = {
                "users", "computers", "system", "lostandfound", "infrastructure",
                "foreignsecurityprincipals", "program data", "managed service accounts",
                "keys", "tpm devices", "builtin", "microsoft", "ntds quotas",
                "s-1-5-11", "s-1-5-9", "s-1-5-32", "wellknown security principals",
                "ras and ias servers", "cert publishers", "read-only domain controllers",
            }

            # Build clean object list: "CN (permission)", skipping noise containers
            # and the operator's own account (users always have self-write on their
            # own object; it's not an ACL-abuse target).
            own_cn = self.env.cred.username.lower()
            objects = []
            for i, cn in enumerate(dn_matches[:12]):
                cn_clean = cn.strip()
                if cn_clean.lower() in ad_containers:
                    continue
                if cn_clean.lower() == own_cn:
                    continue  # self-write, not a relay target
                perm = perm_matches[i].strip() if i < len(perm_matches) else "WRITE"
                objects.append(f"{cn_clean} ({perm.strip()})")
                if len(objects) >= 8:
                    break

            high_value_keywords = [
                "domain admins", "enterprise admins", "administrators",
                "domain controllers", "schema admins", "group policy",
                "dns admins", "account operators",
            ]
            high_value = [o for o in objects
                          if any(kw in o.lower() for kw in high_value_keywords)]

            # Also check domain root here so we don't miss the highest-impact path
            domain_root_writable = False
            rc_dr, out_dr, _ = _run_bloodyad(
                ["get", "writable", "--otype", "DOMAIN"], self.env
            )
            if rc_dr == 0 and out_dr.strip():
                domain_root_writable = True

            if high_value or domain_root_writable:
                parts = []
                if domain_root_writable:
                    parts.append("domain root (DCSync path via --escalate-user)")
                if high_value:
                    extra = (f" (+{len(objects)-len(high_value)} other)"
                             if len(objects) > len(high_value) else "")
                    parts.append(f"{', '.join(high_value[:3])}{extra}")
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"High-value writable objects: {'; '.join(parts)}. "
                        "Relay this account → LDAPS → modify ACL or group membership."
                    ),
                    raw=out[:400],
                )
            if objects:
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        f"Writable objects found: {', '.join(objects[:5])}. "
                        "Review whether any are high-value targets for ACL abuse."
                    ),
                    raw=out[:400],
                )
            # bloodyAD returned output but all entries were noise containers
            if out.strip():
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        "bloodyAD found only default system containers — "
                        "no meaningful writable objects for ACL abuse with this account. "
                        "Does not block the attack — a higher-privileged relayed account "
                        "may have write access. Verify with BloodHound for inherited or "
                        "delegated rights."
                    ),
                )

        # Fallback: check domain object ACL via ldap3
        if LDAP3_AVAILABLE:
            conn = _ldap_connect(self.env)
            if conn:
                try:
                    domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
                    # Enumerate computer and group objects as potential targets
                    conn.search(
                        search_base=domain_dn,
                        search_filter="(|(objectClass=computer)(objectClass=group))",
                        search_scope=SUBTREE,
                        attributes=["sAMAccountName", "objectClass"],
                        paged_size=20,
                    )
                    objects = [str(e["sAMAccountName"]) for e in conn.entries]
                    conn.unbind()

                    if objects:
                        return CheckResult(
                            name=self.name, status=Status.WARN,
                            detail=(
                                f"Found {len(objects)} computer/group object(s). "
                                "Use BloodHound or impacket-dacledit to identify "
                                "objects with weak ACLs for the relayed account. "
                                f"Sample objects: {', '.join(objects[:5])}"
                            ),
                        )
                except Exception:
                    pass
                finally:
                    try:
                        conn.unbind()
                    except Exception:
                        pass

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "Could not enumerate writable objects automatically. "
                "Run BloodHound for full ACL analysis, or: "
                "`bloodyAD --host <dc> -d <domain> -u <user> -p <pass> get writable`"
            ),
        )


class HighValueGroupsCheck(BaseCheck):
    """
    Optional: check for high-value groups with weak ACLs.
    GenericWrite on Domain Admins → add members → domain compromise.
    """

    name = "High-value groups with weak ACLs (optional)"
    required = False

    def _run(self) -> CheckResult:
        if not LDAP3_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="ldap3 not installed.")

        conn = _ldap_connect(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed.")

        try:
            domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
            conn.search(
                search_base=domain_dn,
                search_filter=(
                    "(|(cn=Domain Admins)(cn=Enterprise Admins)"
                    "(cn=Administrators)(cn=Schema Admins))"
                ),
                search_scope=SUBTREE,
                attributes=["cn", "distinguishedName"],
            )
            groups = [(str(e["cn"]), str(e["distinguishedName"])) for e in conn.entries]
            conn.unbind()

            if groups:
                names = [g[0] for g in groups]
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        f"High-value groups found: {', '.join(names)}. "
                        "Check ACLs manually — GenericWrite on any of these "
                        "allows adding members via relay. "
                        "Use: `bloodyAD get object '<group_dn>' --attr nTSecurityDescriptor`"
                    ),
                )
        except Exception as e:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail=f"Query failed: {e}")
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return CheckResult(name=self.name, status=Status.SKIP,
                           detail="Could not enumerate groups.")


# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    # ACL modifications (WriteDACL to grant DCSync, group-membership adds) are
    # ordinary SD/attribute writes — they relay over ANY one open channel:
    #   • ldaps:// (LdapsChannelBindingCheck PASS)  — the original path
    #   • plain ldap:// (LdapSigningCheck PASS)      — signing off; NEW path
    #   • NTLMv1 (NtlmV1AuthProbeCheck PASS)         — SMB→LDAP relay enabler; NEW
    # module_viability (ldap_or_relay_viability) ORs these; the LDAPS reachability
    # and channel-binding checks are alternative channels (required=False), so an
    # EPA-enforced / LDAPS-unreachable DC is no longer a false NOT VIABLE when
    # plain-ldap signing is off.
    from ..utils import NtlmV1AuthProbeCheck
    return [
        LdapsPortCheck(env),
        LdapsChannelBindingCheck(env),
        LdapSigningCheck(env),
        WeakAclObjectsCheck(env),
        HighValueGroupsCheck(env),
        NtlmV1AuthProbeCheck(env),
    ]


# Attribute-write OR relay-path verdict (same shape as Shadow / LAPS / ADIDNS):
# VIABLE if any one relay channel is open, then the (optional) target-object
# prerequisites decide. base._ldap_relay_paths recognizes this module's LDAPS-
# native channel-binding name as a TLS opener.
module_viability = ldap_or_relay_viability

ATTACK_NAME = "NTLM Relay → LDAPS (ACL Abuse)"
