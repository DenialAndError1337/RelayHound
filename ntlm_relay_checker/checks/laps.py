"""
LAPS dump prerequisite checks for NTLM Relay → LDAP (LAPS Password Dump).

LAPS stores randomised local admin passwords on computer objects. Legacy
"Microsoft LAPS" uses the ms-Mcs-AdmPwd attribute (cleartext); Windows LAPS
(built-in since Win11/Server 2025, backportable) uses msLAPS-Password
(cleartext) or msLAPS-EncryptedPassword (DPAPI-encrypted). If a relayed account
has read access, passwords for managed computers can be extracted without
further exploitation.

Prerequisites:
  [REQ]  LDAP signing not enforced
  [REQ]  LDAP channel binding not required
  [REQ]  LAPS deployed (legacy ms-Mcs-AdmPwd or Windows LAPS msLAPS-* schema)
  [REQ]  Relayed account has read access to the LAPS password attribute
  [OPT]  Number of LAPS-managed computers (scope)

nxc ldap --module laps output formats (GOAD-confirmed 2026-07-04):
  Readable:     "LAPS … [*] Getting LAPS Passwords"
                "LAPS … Computer:BRAAVOS$ User:  Password:L@KUNBc4GJF27E"
  Not readable: "LAPS … [*] Getting LAPS Passwords"
                "LAPS … [-] No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !"
  No LAPS:      "LAPS … [*] Getting LAPS Passwords"
                "LAPS … [-] No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !"
  NOTE: "Getting LAPS Passwords" and "No result found" are IDENTICAL in the
  not-readable and no-LAPS cases — nxc cannot distinguish them. Only a real
  Computer/Password pair confirms deployment; everything else falls through to
  the ldap3 schema check.
"""
from __future__ import annotations

from .base import BaseCheck, CheckResult, Status, ldap_or_relay_viability
from ..config import TargetEnv

try:
    from ldap3 import SUBTREE, BASE
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
from ..utils import (LdapSigningCheck, LdapChannelBindingCheck,
                     _ldap_connect_with_tls_fallback, _run_nxc_ldap)


# ── helpers ────────────────────────────────────────────────────────────────


# ── individual checks ──────────────────────────────────────────────────────

class LapsDeployedCheck(BaseCheck):
    """
    LAPS must be deployed — ms-Mcs-AdmPwd or msLAPS-Password attribute
    must exist in the schema.

    Method: nxc ldap --module laps
            OR ldap3 schema check for the attribute
    """

    name = "LAPS deployed (legacy ms-Mcs-AdmPwd or Windows LAPS schema)"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "laps"], self.env)
        combined = out + err
        lower = combined.lower()

        if rc != -1 and combined.strip():
            # The ONLY reliable nxc signal that LAPS is both deployed AND readable
            # is a real Computer/Password pair in the output (Run 1 capture:
            # "LAPS … Computer:BRAAVOS$ User: Password:L@KUNBc4GJF27E").
            # Two previously-accepted signals are NOT reliable (GOAD-confirmed
            # 2026-07-04 against sevenkingdoms.local, which has no LAPS):
            #   "Getting LAPS Passwords" — printed by nxc before querying,
            #     regardless of whether LAPS is deployed.
            #   "No result found with attribute ms-MCS-AdmPwd or msLAPS-Password"
            #     — printed both when LAPS is deployed-but-unreadable AND when
            #     LAPS is not deployed at all. Using it as PASS "schema confirmed"
            #     false-PASSed this REQUIRED check on a LAPS-free domain, which
            #     with LDAP signing off renders the LAPS module VIABLE — a
            #     cardinal-rule false positive.
            # Both ambiguous signals now fall through to the ldap3 schema check,
            # which queries the schema directly and is unambiguous.
            if "computer:" in lower and "password:" in lower:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="LAPS deployed and readable — password attribute present and populated.",
                    raw=out[:300],
                )

        # Fallback: ldap3 schema check
        if not LDAP3_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="ldap3 not installed. Run: pip install ldap3")

        conn, _via_tls = _ldap_connect_with_tls_fallback(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed (tried plain and TLS).")

        try:
            domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
            # Check schema for legacy LAPS attribute
            schema_dn = (
                f"CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,{domain_dn}"
            )
            conn.search(
                search_base=schema_dn,
                search_filter="(objectClass=attributeSchema)",
                search_scope=BASE,
                attributes=["cn"],
            )
            if conn.entries:
                conn.unbind()
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="ms-Mcs-AdmPwd attribute found in schema — LAPS deployed.",
                )

            # Check Windows LAPS attribute
            wlaps_dn = (
                f"CN=ms-LAPS-Password,CN=Schema,CN=Configuration,{domain_dn}"
            )
            conn.search(
                search_base=wlaps_dn,
                search_filter="(objectClass=attributeSchema)",
                search_scope=BASE,
                attributes=["cn"],
            )
            if conn.entries:
                conn.unbind()
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        "ms-LAPS-Password attribute found — Windows LAPS (new) deployed. "
                        "Note: Windows LAPS uses encrypted storage."
                    ),
                )

            conn.unbind()
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="LAPS schema attributes not found — LAPS not deployed.",
            )

        except Exception as e:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail=f"Schema query failed: {e}")
        finally:
            try:
                conn.unbind()
            except Exception:
                pass


class LapsReadableCheck(BaseCheck):
    """
    The relayed account must be able to read ms-Mcs-AdmPwd.

    nxc laps output when readable:
      "Computer:BRAAVOS$  User:  Password:7zNNeEb#BF4,f4"
    nxc laps output when not readable:
      "[-] No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !"
    """

    name = "LAPS password readable by current account (legacy or Windows LAPS)"
    # Optional/informational: this probes the OPERATOR's current rights. The
    # relay uses the (privileged) relayed victim's read rights, so "not readable
    # by me" must NOT make the attack NOT VIABLE — viability is driven by the
    # protocol prerequisites (LDAP signing / channel binding) checked above.
    required = False

    def _run(self) -> CheckResult:
        import re

        rc, out, err = _run_nxc_ldap(["--module", "laps"], self.env)
        combined = out + err
        lower = combined.lower()

        if rc != -1 and "[+]" in out:
            # Readable: parse Computer/Password pairs
            readable = re.findall(
                r"Computer:([^\s]+)\s+User:[^\s]*\s+Password:([^\s\r\n]+)",
                combined, re.IGNORECASE,
            )
            if readable:
                computers = [c[0] for c in readable[:3]]
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"LAPS passwords readable for {len(readable)} computer(s): "
                        f"{', '.join(computers)}. "
                        "Relay this account to LDAP to dump all accessible LAPS passwords."
                    ),
                    raw=out[:400],
                )
            # Not readable
            if "no result found with attribute" in lower:
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        "LAPS deployed but ms-Mcs-AdmPwd not readable with this account. "
                        "Does not block the attack — relay a higher-privileged account "
                        "(delegated LAPS reader, Domain Admin, or local admin of target)."
                    ),
                )

        # Fallback: ldap3 with wildcard attributes
        if not LDAP3_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="ldap3 not installed.")

        conn, _via_tls = _ldap_connect_with_tls_fallback(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed (tried plain and TLS).")

        try:
            domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
            conn.search(
                search_base=domain_dn,
                search_filter="(objectClass=computer)",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "*"],
                paged_size=20,
            )
            readable_computers = []
            laps_managed = []
            for entry in conn.entries:
                name = str(entry["sAMAccountName"])
                entry_str = str(entry).lower()
                # Check if any LAPS password attribute has a non-empty value
                has_laps_value = any(
                    attr in entry_str
                    and entry_str.split(attr)[-1][:30].strip().lstrip(":").strip() not in ("", "none", "[]")
                    for attr in ["ms-mcs-admpwd:", "mslaps-password:", "mslaps-encryptedpassword:"]
                )
                if has_laps_value:
                    readable_computers.append(name)
                elif "ms-mcs-admpwdexpirationtime" in entry_str:
                    laps_managed.append(name)

            conn.unbind()

            if readable_computers:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"LAPS password readable for {len(readable_computers)} computer(s): "
                        f"{', '.join(readable_computers[:5])}. "
                        "Relay this account to LDAP to dump all accessible LAPS passwords."
                    ),
                )
            if laps_managed:
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        f"LAPS managed computers found ({', '.join(laps_managed[:5])}) "
                        "but ms-Mcs-AdmPwd not readable with this account. "
                        "Does not block the attack — relay a higher-privileged account "
                        "for password access."
                    ),
                )

        except Exception as e:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail=f"LDAP query failed: {e}")
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "Could not confirm LAPS read access. "
                "The value of this relay depends on whether the relayed account "
                "has been granted LAPS read rights."
            ),
        )


class LapsManagedComputersCheck(BaseCheck):
    """
    Optional: count how many computers are LAPS-managed.
    Higher count = broader attack surface if read access is confirmed.
    """

    name = "LAPS-managed computers in scope (optional scope check)"
    required = False

    def _run(self) -> CheckResult:
        if not LDAP3_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="ldap3 not installed.")

        conn, _via_tls = _ldap_connect_with_tls_fallback(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed (tried plain and TLS).")

        try:
            domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
            # Check for both legacy and Windows LAPS managed computers
            conn.search(
                search_base=domain_dn,
                search_filter=(
                    "(|(ms-Mcs-AdmPwdExpirationTime=*)"
                    "(msLAPS-PasswordExpirationTime=*))"
                ),
                search_scope=SUBTREE,
                attributes=["sAMAccountName"],
            )
            count = len(conn.entries)
            all_computers = [str(e["sAMAccountName"]) for e in conn.entries]
            computers = all_computers[:5]
            conn.unbind()

            if count > 0:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"{count} LAPS-managed computer(s): "
                        f"{', '.join(computers)}{'...' if count > 5 else ''}. "
                        "Each managed computer has a unique local admin password."
                    ),
                    raw="\n".join(all_computers),
                )
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "No LAPS-managed computers found. "
                    "LAPS may be deployed in schema but not applied via GPO."
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


class LapsAclReadersCheck(BaseCheck):
    """
    Enumerate which accounts have LAPS read permissions on managed computers.
    Even if the current account can't read passwords, knowing which accounts
    CAN read them identifies valuable coercion targets.

    Uses impacket-dacledit filtering on two fixed GUIDs for legacy LAPS v1:
      54bafdd2-36a8-4147-8d5c-be6d79fc6e84 — ms-Mcs-AdmPwd (password)
      125c6e93-1512-4de2-ae6b-fd4d350853be — ms-Mcs-AdmPwdExpirationTime

    These GUIDs are standardised and identical across all AD environments.
    """

    name = "Accounts with LAPS read permissions (coercion target candidates)"
    required = False

    LAPS_PWD_GUID        = "54bafdd2-36a8-4147-8d5c-be6d79fc6e84"
    LAPS_EXPIRY_GUID     = "125c6e93-1512-4de2-ae6b-fd4d350853be"

    def _run(self) -> CheckResult:
        # First find LAPS-managed computers to target
        managed = self._get_managed_computers()
        if not managed:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No LAPS-managed computers found — skipping ACL check.",
            )

        readers: dict[str, list[str]] = {}  # computer → [accounts with read]

        for computer in managed[:3]:  # check up to 3 to keep runtime reasonable
            trustees = self._get_laps_readers(computer)
            if trustees:
                readers[computer] = trustees

        if readers:
            lines = []
            for computer, trustees in readers.items():
                lines.append(f"{computer}: {', '.join(trustees)}")
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Accounts with LAPS read permissions — {'; '.join(lines)}. "
                    "Relay any of these accounts to LDAP to dump LAPS passwords."
                ),
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "Could not enumerate LAPS ACL readers automatically. "
                "Run manually: `impacket-dacledit -action read -target '<computer$>' "
                f"-dc-ip {self.env.dc_ip} '<domain>/<user>:<pass>' "
                f"2>/dev/null | grep -A6 \"54bafdd2|125c6e93\" | grep Trustee`"
            ),
        )

    def _get_managed_computers(self) -> list[str]:
        """Return sAMAccountNames of LAPS-managed computers."""
        if not LDAP3_AVAILABLE:
            return []
        conn, _via_tls = _ldap_connect_with_tls_fallback(self.env)
        if not conn:
            return []
        try:
            domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
            conn.search(
                search_base=domain_dn,
                search_filter="(ms-Mcs-AdmPwdExpirationTime=*)",
                search_scope=SUBTREE,
                attributes=["sAMAccountName"],
            )
            return [str(e["sAMAccountName"]) for e in conn.entries]
        except Exception:
            return []
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    def _get_laps_readers(self, computer: str) -> list[str]:
        """Run impacket-dacledit and filter for LAPS GUIDs."""
        try:
            import subprocess
            result = subprocess.run(
                [
                    "impacket-dacledit",
                    "-action", "read",
                    "-target", computer,
                    "-dc-ip", self.env.dc_ip,
                    *((
                        [f"{self.env.domain}/{self.env.cred.username}",
                         "-hashes", f"aad3b435b51404eeaad3b435b51404ee:{self.env.cred.nt_hash.split(chr(58))[-1]}"]
                        if self.env.cred.nt_hash
                        else [f"{self.env.domain}/{self.env.cred.username}:{self.env.cred.password}"]
                    )),
                ],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr
            if not output.strip():
                return []

            # Filter lines containing either LAPS GUID then extract Trustee
            import re
            trustees = set()
            lines = output.splitlines()
            for i, line in enumerate(lines):
                if self.LAPS_PWD_GUID.lower() in line.lower() or                    self.LAPS_EXPIRY_GUID.lower() in line.lower():
                    # Look for Trustee in surrounding lines
                    for j in range(max(0, i-2), min(len(lines), i+7)):
                        m = re.search(r"Trustee[^:]*:\s*([^(\n]+)", lines[j], re.IGNORECASE)
                        if m:
                            trustee = m.group(1).strip()
                            if trustee and trustee not in ("", "None") \
                                    and "principal self" not in trustee.lower():
                                trustees.add(trustee)
            return sorted(trustees)

        except FileNotFoundError:
            return []
        except Exception:
            return []


class LapsWebClientCoercionCheck(BaseCheck):
    """
    Optional: WebClient service running on target machines enables WebDAV
    coercion to force a privileged account to authenticate — useful when
    the current account can't read LAPS but a domain account with LAPS
    read rights can be coerced via WebDAV.

    This is the same check as the WebDAV module but included here as a
    reminder that WebDAV coercion is the reliable path to LAPS relay.
    """

    name = "WebClient running on target (WebDAV coercion for LAPS relay)"
    required = False

    def _run(self) -> CheckResult:
        webclient_hosts = []
        for host in self.env.all_targets:
            try:
                import subprocess
                rc, out, err = (lambda r: (r.returncode, r.stdout, r.stderr))(
                    subprocess.run(
                        ["nxc", "smb", host,
                         "-u", self.env.cred.username,
                         *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                         "-d", self.env.domain,
                         "--module", "webdav"],
                        capture_output=True, text=True,
                        timeout=self.env.timeout + 10,
                    )
                )
                combined = (out + err).lower()
                if rc != -1 and (
                    "webclient service enabled" in combined or
                    "webdav: true" in combined or
                    "running" in combined
                ):
                    webclient_hosts.append(host)
                else:
                    # Fallback: check via --services if --module webdav was ambiguous
                    import subprocess as _sp2
                    r2 = _sp2.run(
                        ["nxc", "smb", host,
                         "-u", self.env.cred.username,
                         *(([ "-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                         "-d", self.env.domain,
                         "--services"],
                        capture_output=True, text=True,
                        timeout=self.env.timeout + 10,
                    )
                    combined2 = (r2.stdout + r2.stderr).lower()
                    if "webclient" in combined2 and ("running" in combined2 or "started" in combined2):
                        webclient_hosts.append(host)
            except Exception:
                pass

        if webclient_hosts:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"WebClient running on: {', '.join(webclient_hosts)}. "
                    "WebDAV coercion can force a LAPS-reader account to authenticate "
                    "— relay that auth to LDAP to dump LAPS passwords."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "WebClient not confirmed on targets. "
                "Without WebClient, coercion relies on PrinterBug/PetitPotam "
                "which produce SMB auth (check SMB signing status)."
            ),
        )


# ── attack check list ──────────────────────────────────────────────────────

# OR relay-path verdict (signing OR channel-binding OR NTLMv1). Attached by the
# engine via AttackResult.viability_fn.
module_viability = ldap_or_relay_viability


def get_checks(env: TargetEnv) -> list[BaseCheck]:
    from ..utils import NtlmV1AuthProbeCheck
    return [
        LdapSigningCheck(env),
        LdapChannelBindingCheck(env),
        LapsDeployedCheck(env),
        LapsReadableCheck(env),
        LapsManagedComputersCheck(env),
        LapsAclReadersCheck(env),
        LapsWebClientCoercionCheck(env),
        NtlmV1AuthProbeCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → LDAP (LAPS Password Dump)"
