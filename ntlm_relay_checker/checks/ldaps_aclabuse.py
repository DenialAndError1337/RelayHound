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
import socket
import subprocess

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv

try:
    import ldap3
    from ldap3 import Server, Connection, NTLM, SUBTREE, BASE, ALL
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


# ── helpers ────────────────────────────────────────────────────────────────

def _port_open(host: str, port: int, timeout: int = 5) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _run_nxc_ldap(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    try:
        auth = (["-H", env.cred.nt_hash] if env.cred.nt_hash
                else ["-p", env.cred.password])
        cmd = ["nxc", "ldap", env.dc_ip,
               "-u", env.cred.username,
               "-d", env.domain] + auth + args
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        try:
            cmd[0] = "crackmapexec"
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", "nxc not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def _run_bloodyad(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    try:
        cmd = ["bloodyAD", "--host", env.dc_ip, "-d", env.domain,
               "-u", env.cred.username, *((["-H", env.cred.nt_hash] if env.cred.nt_hash else ["-p", env.cred.password]))] + args
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", "bloodyAD not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


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


# ── individual checks ──────────────────────────────────────────────────────

class LdapsPortCheck(BaseCheck):
    """LDAPS must be reachable on port 636."""

    name = "LDAPS reachable (port 636)"

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
    """LDAPS channel binding (EPA) must not be enforced."""

    name = "LDAPS channel binding (EPA) not enforced"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "ldap-checker"], self.env)
        combined = (out + err).lower()

        if rc == -1:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="nxc not available to check channel binding.")

        if "channel binding is set to: never" in combined or "channel binding is not required" in combined:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="LDAPS channel binding NOT required — relay viable.",
            )
        if "channel binding is set to: always" in combined or "channel binding is required" in combined:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="LDAPS channel binding REQUIRED — relay blocked.",
            )
        if "channel binding is set to: when supported" in combined:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail="Channel binding set to: When Supported — relay may work.",
            )
        return CheckResult(name=self.name, status=Status.WARN,
                           detail="Channel binding status unclear.")


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

    def _run(self) -> CheckResult:
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
            objects = []
            for i, cn in enumerate(dn_matches[:12]):
                cn_clean = cn.strip()
                if cn_clean.lower() in ad_containers:
                    continue
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
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "bloodyAD found only default system containers — "
                        "no meaningful writable objects for ACL abuse. "
                        "Verify with BloodHound for inherited or delegated rights."
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
    return [
        LdapsPortCheck(env),
        LdapsChannelBindingCheck(env),
        WeakAclObjectsCheck(env),
        HighValueGroupsCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → LDAPS (ACL Abuse)"
