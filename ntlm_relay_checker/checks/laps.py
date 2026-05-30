"""
LAPS dump prerequisite checks for NTLM Relay → LDAP (LAPS Password Dump).

LAPS stores randomised local admin passwords in ms-Mcs-AdmPwd on computer
objects. If a relayed account has read access, passwords for managed
computers can be extracted without further exploitation.

Prerequisites:
  [REQ]  LDAP signing not enforced
  [REQ]  LDAP channel binding not required
  [REQ]  LAPS deployed (ms-Mcs-AdmPwd attribute exists in schema)
  [REQ]  Relayed account has read access to ms-Mcs-AdmPwd
  [OPT]  Number of LAPS-managed computers (scope)

nxc laps output formats:
  Not readable: "[-] No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !"
  Readable:     "Computer:BRAAVOS$  User:  Password:7zNNeEb#BF4,f4"
"""
from __future__ import annotations
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

class LdapSigningCheck(BaseCheck):
    """LDAP signing must not be enforced for relay to succeed."""

    name = "LDAP signing not enforced"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "ldap-checker"], self.env)
        combined = (out + err).lower()

        if rc != -1:
            if "ldap signing not enforced" in combined or "signing: false" in combined:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="LDAP signing NOT enforced — relay viable.",
                )
            if "ldap signing enforced" in combined or "signing: true" in combined:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail="LDAP signing REQUIRED — relay rejected.",
                )

        if LDAP3_AVAILABLE:
            try:
                from ldap3 import ANONYMOUS
                server = Server(self.env.dc_ip, connect_timeout=self.env.timeout)
                conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
                if conn.bound:
                    conn.unbind()
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail="Anonymous LDAP bind succeeded — signing not enforced.",
                    )
            except Exception as e:
                if "stronger" in str(e).lower() or "sign" in str(e).lower():
                    return CheckResult(
                        name=self.name, status=Status.FAIL,
                        detail=f"LDAP requires signing: {e}",
                    )

        return CheckResult(name=self.name, status=Status.SKIP,
                           detail="Could not determine LDAP signing status.")


class LdapChannelBindingCheck(BaseCheck):
    """LDAP channel binding must not be required."""

    name = "LDAP channel binding not required"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "ldap-checker"], self.env)
        combined = (out + err).lower()

        if rc == -1:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="nxc not available.")

        if "channel binding is set to: never" in combined or "channel binding is not required" in combined:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="LDAP channel binding NOT required — relay viable.",
            )
        if "channel binding is set to: always" in combined or "channel binding is required" in combined:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="LDAP channel binding REQUIRED — relay blocked.",
            )
        if "channel binding is set to: when supported" in combined:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail="Channel binding set to: When Supported — relay may work.",
            )
        return CheckResult(name=self.name, status=Status.WARN,
                           detail="Channel binding status unclear. Review manually.")


class LapsDeployedCheck(BaseCheck):
    """
    LAPS must be deployed — ms-Mcs-AdmPwd or msLAPS-Password attribute
    must exist in the schema.

    Method: nxc ldap --module laps
            OR ldap3 schema check for the attribute
    """

    name = "LAPS deployed (ms-Mcs-AdmPwd attribute exists)"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "laps"], self.env)
        combined = out + err
        lower = combined.lower()

        if rc != -1 and combined.strip():
            # Readable: "Computer:HOST$  User:  Password:xxx"
            if "computer:" in lower and "password:" in lower:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="LAPS deployed and passwords readable with this account.",
                    raw=out[:300],
                )
            # Not readable but schema present:
            # "[-] No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !"
            if "no result found with attribute ms-mcs-admpwd" in lower or \
               "no result found with attribute mslaps" in lower:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        "LAPS schema confirmed (nxc queried ms-MCS-AdmPwd/msLAPS-Password). "
                        "Account cannot read passwords — relay a more privileged account."
                    ),
                    raw=(out + err)[:300],
                )
            # nxc ran and mentioned LAPS
            if "getting laps passwords" in lower:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="LAPS detected via nxc — ms-Mcs-AdmPwd attribute present.",
                    raw=out[:300],
                )

        # Fallback: ldap3 schema check
        if not LDAP3_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="ldap3 not installed. Run: pip install ldap3")

        conn = _ldap_connect(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed.")

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

    name = "ms-Mcs-AdmPwd readable by current account"

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
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "LAPS deployed but ms-Mcs-AdmPwd not readable with this account. "
                        "Relay a higher-privileged account (delegated LAPS reader, "
                        "Domain Admin, or local admin of target)."
                    ),
                )

        # Fallback: ldap3 with wildcard attributes
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
                    name=self.name, status=Status.FAIL,
                    detail=(
                        f"LAPS managed computers found ({', '.join(laps_managed[:5])}) "
                        "but ms-Mcs-AdmPwd not readable with this account. "
                        "Relay a higher-privileged account for password access."
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

        conn = _ldap_connect(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed.")

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
    CAN read them identifies valuable relay targets.

    Uses impacket-dacledit filtering on two fixed GUIDs for legacy LAPS v1:
      54bafdd2-36a8-4147-8d5c-be6d79fc6e84 — ms-Mcs-AdmPwd (password)
      125c6e93-1512-4de2-ae6b-fd4d350853be — ms-Mcs-AdmPwdExpirationTime

    These GUIDs are standardised and identical across all AD environments.
    """

    name = "Accounts with LAPS read permissions (relay target candidates)"
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
        conn = _ldap_connect(self.env)
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

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        LdapSigningCheck(env),
        LdapChannelBindingCheck(env),
        LapsDeployedCheck(env),
        LapsReadableCheck(env),
        LapsManagedComputersCheck(env),
        LapsAclReadersCheck(env),
        LapsWebClientCoercionCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → LDAP (LAPS Password Dump)"
