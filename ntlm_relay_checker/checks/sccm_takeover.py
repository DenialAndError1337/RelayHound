"""
SCCM prerequisite checks for NTLM Relay → SCCM Site Takeover.

Covers two relay paths against SCCM infrastructure (TAKEOVER-1 and TAKEOVER-2
from Misconfiguration Manager):

  TAKEOVER-1: Coerce site server → relay to site DB via MSSQL (TCP 1433)
    Site server machine account has db_owner on the site DB → grant any domain
    account SCCM Full Administrator → arbitrary code execution on all managed
    clients as SYSTEM.

  TAKEOVER-2: Coerce site server → relay to site DB via SMB (TCP 445)
    Same outcome via SMB relay instead of MSSQL relay. Requires SMB signing
    disabled on the site DB server.

Discovery:
  SCCM publishes infrastructure to AD. The System Management container
  (CN=System Management,CN=System,<domain_dn>) is present when SCCM is
  installed. Site servers hold GenericAll on this container. Management
  points publish mSMSManagementPoint objects inside it, containing the
  site DB hostname and site code.

Prerequisites:
  [REQ]  SCCM detected in AD (System Management container + site server)
  [REQ]  Site server (coercion target) is reachable / identifiable
  [REQ]  Site database is on a separate host from the site server
  [REQ]  Site database server is reachable (MSSQL 1433 or SMB 445)
  [OPT]  MSSQL on site DB accepts NTLM auth (TAKEOVER-1 path)
  [OPT]  SMB signing disabled on site DB server (TAKEOVER-2 path)
  [OPT]  Coercion available on site server (Print Spooler / PetitPotam)
  [OPT]  EPA not enforced on MSSQL (default — TAKEOVER-1 hardening check)
"""
from __future__ import annotations

import re
import socket
import subprocess
from typing import Optional

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv

try:
    from ldap3 import Server, Connection, NTLM, SUBTREE, ALL, MODIFY_ADD
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


def _resolve(hostname: str) -> Optional[str]:
    """Resolve a hostname to an IPv4 address. Returns None on failure."""
    try:
        return socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]
    except (socket.gaierror, IndexError):
        return None


def _ldap_connect(env: TargetEnv) -> Optional[object]:
    if not LDAP3_AVAILABLE:
        return None
    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        if env.cred.nt_hash:
            nh = env.cred.nt_hash.split(":")[-1]
            auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
        else:
            auth_password = env.cred.password
        conn = Connection(
            server,
            user=env.cred.upn,
            password=auth_password,
            authentication=NTLM,
            auto_bind=True,
        )
        return conn
    except Exception:
        return None


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


# ── LDAP discovery ─────────────────────────────────────────────────────────

class SCCMDiscovery:
    """
    Holds SCCM infrastructure discovered from LDAP.

    Populated once and shared across all checks in this module.
    """
    def __init__(self):
        self.present: bool = False              # System Management container found
        self.site_servers: list[str] = []       # hostnames with GenericAll on container
        self.management_points: list[str] = []  # dNSHostName of MP objects
        self.site_db_host: Optional[str] = None # resolved from mSMSManagementPoint
        self.site_code: Optional[str] = None    # e.g. "P01"
        self.error: Optional[str] = None

    @classmethod
    def from_ldap(cls, env: TargetEnv) -> "SCCMDiscovery":
        disc = cls()
        if not LDAP3_AVAILABLE:
            disc.error = "ldap3 not available"
            return disc

        conn = _ldap_connect(env)
        if not conn:
            disc.error = "LDAP connection failed"
            return disc

        domain_dn = ",".join(f"DC={p}" for p in env.domain.split("."))
        sys_mgmt_dn = f"CN=System Management,CN=System,{domain_dn}"

        # ── Check System Management container exists ───────────────────────
        try:
            conn.search(
                search_base=sys_mgmt_dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["distinguishedName"],
            )
            disc.present = len(conn.entries) > 0
        except Exception:
            disc.present = False

        if not disc.present:
            # Authoritative fallback: search from CN=System (which always exists
            # in a domain) for the container. This distinguishes a clean
            # "not found" (-> FAIL: SCCM not deployed) from a search that did
            # not complete (-> SKIP via disc.error), so a transient LDAP error
            # can't masquerade as "SCCM not deployed". ldap3 here runs with
            # raise_exceptions=False, so a failed op returns False with the
            # code in conn.result rather than raising.
            try:
                ok = conn.search(
                    search_base=f"CN=System,{domain_dn}",
                    search_filter="(cn=System Management)",
                    search_scope=SUBTREE,
                    attributes=["distinguishedName"],
                )
                result_code = (conn.result or {}).get("result")
                disc.present = len(conn.entries) > 0
                if disc.present:
                    sys_mgmt_dn = str(conn.entries[0]["distinguishedName"])
                elif not ok and result_code not in (0, 32):
                    # 0 = success (genuinely 0 entries), 32 = noSuchObject (base
                    # absent — still a definitive negative). Anything else means
                    # the lookup did not complete; don't call that "no SCCM".
                    disc.error = (
                        f"System Management lookup did not complete "
                        f"(LDAP result {result_code}); cannot confirm SCCM presence."
                    )
            except Exception as exc:
                disc.error = f"System Management container lookup failed: {exc}"

        if not disc.present:
            conn.unbind()
            return disc

        # ── Find site servers: computers with GenericAll on the container ──
        try:
            conn.search(
                search_base=sys_mgmt_dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["nTSecurityDescriptor"],
                get_operational_attributes=True,
            )
            # nTSecurityDescriptor parsing requires ldap3 extras; use a
            # simpler keyword search as fallback if ACE parsing unavailable
        except Exception:
            pass

        # ── Find Management Points published in the container ──────────────
        try:
            conn.search(
                search_base=sys_mgmt_dn,
                search_filter="(objectClass=mSSMSManagementPoint)",
                search_scope=SUBTREE,
                attributes=["dNSHostName", "mSSMSSiteCode", "mSSMSMPName",
                            "mSSMSDefaultMP"],
            )
            for entry in conn.entries:
                try:
                    fqdn = str(entry["dNSHostName"]).strip()
                    if fqdn and fqdn.lower() not in ("none", ""):
                        disc.management_points.append(fqdn)
                except Exception:
                    pass
                try:
                    sc = str(entry["mSSMSSiteCode"]).strip()
                    if sc and sc.lower() not in ("none", ""):
                        disc.site_code = sc
                except Exception:
                    pass
        except Exception:
            pass

        # ── Site DB host: MSSQLSvc SPN lookup (most reliable cross-version) ─
        # mSSMSSQLServerName is not published by all SCCM versions.
        # Instead, query for the MSSQLSvc SPN registered by the SQL service
        # account — this is always present when SQL is domain-joined.
        # e.g. MSSQLSvc/MSSQL.sccm.lab:1433 → db host is MSSQL.sccm.lab
        if not disc.site_db_host:
            try:
                conn.search(
                    search_base=domain_dn,
                    search_filter="(servicePrincipalName=MSSQLSvc/*)",
                    search_scope=SUBTREE,
                    attributes=["servicePrincipalName", "dNSHostName", "cn"],
                )
                for entry in conn.entries:
                    for spn in entry["servicePrincipalName"].values:
                        spn_str = str(spn).strip()
                        # MSSQLSvc/hostname:port or MSSQLSvc/hostname
                        if spn_str.lower().startswith("mssqlsvc/"):
                            host_part = spn_str.split("/", 1)[1].split(":")[0]
                            if host_part and host_part.lower() not in ("none", ""):
                                disc.site_db_host = host_part
                                break
                    if disc.site_db_host:
                        break
            except Exception:
                pass

        # ── Fuzzy search: computer objects with SCCM/MECM in name ─────────
        try:
            for kw in ("*sccm*", "*mecm*", "*smsserver*", "*configmgr*"):
                conn.search(
                    search_base=domain_dn,
                    search_filter=f"(&(objectClass=computer)(cn={kw}))",
                    search_scope=SUBTREE,
                    attributes=["dNSHostName", "cn"],
                )
                for entry in conn.entries:
                    try:
                        fqdn = str(entry["dNSHostName"]).strip()
                        if fqdn and fqdn.lower() not in ("none", ""):
                            disc.site_servers.append(fqdn)
                    except Exception:
                        pass
        except Exception:
            pass

        # ── If MP hostnames found, use them as site servers if no others ──
        if not disc.site_servers and disc.management_points:
            disc.site_servers = list(disc.management_points)

        # ── Deduplicate ────────────────────────────────────────────────────
        disc.site_servers = list(dict.fromkeys(disc.site_servers))
        disc.management_points = list(dict.fromkeys(disc.management_points))

        conn.unbind()
        return disc


# ── Shared discovery instance (populated by first check, reused by rest) ──

_disc_cache: dict[str, SCCMDiscovery] = {}


def _get_discovery(env: TargetEnv) -> SCCMDiscovery:
    key = env.dc_ip
    if key not in _disc_cache:
        _disc_cache[key] = SCCMDiscovery.from_ldap(env)
    return _disc_cache[key]


# ── Check classes ──────────────────────────────────────────────────────────

class SCCMDetectedCheck(BaseCheck):
    """Detect SCCM in the domain via the System Management container in AD."""

    name = "SCCM detected in AD (System Management container)"
    breaks_on_fail = True  # no SCCM = skip all downstream checks

    def _run(self) -> CheckResult:
        if not LDAP3_AVAILABLE:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="ldap3 not available — cannot query AD for SCCM. "
                       "Install with: pip install ldap3",
            )

        disc = _get_discovery(self.env)

        if disc.error:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=f"LDAP query failed: {disc.error}",
            )

        if not disc.present:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="CN=System Management container not found in AD. "
                       "SCCM does not appear to be deployed in this domain.",
            )

        detail_parts = ["System Management container found in AD — SCCM is deployed."]
        if disc.site_servers:
            detail_parts.append(
                f"Potential site server(s): {', '.join(disc.site_servers[:3])}"
                + ("..." if len(disc.site_servers) > 3 else "")
            )
        if disc.management_points:
            detail_parts.append(
                f"Management point(s): {', '.join(disc.management_points[:3])}"
            )
        if disc.site_code:
            detail_parts.append(f"Site code: {disc.site_code}")
        if disc.site_db_host:
            detail_parts.append(f"Site DB host: {disc.site_db_host} (via MSSQLSvc SPN)")

        return CheckResult(
            name=self.name, status=Status.PASS,
            detail=" ".join(detail_parts),
        )

    def run(self) -> CheckResult:
        result = super().run()
        if result.status == Status.FAIL:
            self.env.shared_cache["sccm_present"] = False
        elif result.status == Status.PASS:
            self.env.shared_cache["sccm_present"] = True
        return result


class SiteServerReachableCheck(BaseCheck):
    """Check that at least one site server is identifiable and network-reachable."""

    name = "Site server identifiable and reachable (coercion target)"

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        candidates = list(disc.site_servers)

        # Also check extra_targets in case a site server was passed manually
        for t in self.env.extra_targets:
            if t not in candidates:
                candidates.append(t)

        if not candidates:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail="SCCM detected but no site server hostname found in AD. "
                       "Use --extra-targets to specify the site server IP/hostname manually.",
            )

        reachable = []
        for host in candidates:
            ip = _resolve(host) or (host if re.match(r"\d+\.\d+\.\d+\.\d+", host) else None)
            if ip and (_port_open(ip, 445, self.env.timeout) or
                       _port_open(ip, 135, self.env.timeout)):
                reachable.append(host)

        if not reachable:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"Site server candidate(s) {', '.join(candidates)} not reachable "
                       f"(checked ports 445 and 135). Cannot coerce authentication.",
            )

        return CheckResult(
            name=self.name, status=Status.PASS,
            detail=f"Site server(s) reachable: {', '.join(reachable)}. "
                   "These are the coercion targets — coerce their machine account auth "
                   "and relay to the site DB.",
        )


class SiteDBRemoteCheck(BaseCheck):
    """
    Verify that the site database is hosted on a separate host from the site server.

    This is a hard requirement for both TAKEOVER-1 and TAKEOVER-2.
    The attack works by coercing NTLM auth FROM the site server and relaying
    it TO the site database server. If both roles are on the same host,
    the relay loops back to the coercion source, which does not work.

    Per Misconfiguration Manager: 'The site database is not hosted on the
    coercion target' is listed as an explicit prerequisite for TAKEOVER-1
    and TAKEOVER-2.
    """

    name = "Site database hosted on separate server from site server (remote DB required)"

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)

        site_servers = {s.lower().split(".")[0] for s in disc.site_servers}
        db_host = disc.site_db_host

        if not db_host:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    "Site database hostname not found — MSSQLSvc SPN lookup returned "
                    "no results and the attribute is not published in AD. "
                    "If the SQL server is not domain-joined or has no SPN registered, "
                    "pass the DB host manually via --extra-targets."
                ),
            )

        if not site_servers:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="Site server hostname not found in AD — cannot compare "
                       "against site DB host to verify topology.",
            )

        db_shortname = db_host.lower().split(".")[0].split("\\")[0]

        if db_shortname in site_servers:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    f"Site database ({db_host}) appears to be co-located on the site server. "
                    "TAKEOVER-1 and TAKEOVER-2 require a remote site database — relaying "
                    "the site server's auth back to itself does not work."
                ),
            )

        return CheckResult(
            name=self.name, status=Status.PASS,
            detail=(
                f"Site database ({db_host}) is on a separate host from the site server(s) "
                f"({', '.join(disc.site_servers[:3])}). "
                "Remote DB topology confirmed — relay from site server to DB is viable."
            ),
        )


class SiteDBMSSQLCheck(BaseCheck):
    """Check MSSQL reachability and NTLM auth on the site DB (TAKEOVER-1 path)."""

    name = "Site DB MSSQL reachable and accepts NTLM (TAKEOVER-1)"

    @property
    def required(self) -> bool:
        return False

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        # Determine site DB host
        db_host = disc.site_db_host
        if not db_host and disc.management_points:
            db_host = disc.management_points[0].split(".")[0]
        if not db_host:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    "Site database hostname not found — MSSQLSvc SPN lookup returned no results. "
                    "If the SQL server has no SPN registered, pass the DB host via --extra-targets."
                ),
            )

        db_ip = _resolve(db_host)
        if not db_ip:
            # Try as-is in case it's already an IP
            db_ip = db_host if re.match(r"\d+\.\d+\.\d+\.\d+", db_host) else None

        if not db_ip:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"Site DB host '{db_host}' does not resolve. "
                       "Cannot verify MSSQL reachability.",
            )

        if not _port_open(db_ip, 1433, self.env.timeout):
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"MSSQL port 1433 not reachable on site DB {db_host} ({db_ip}). "
                       "TAKEOVER-1 (relay to MSSQL) not viable.",
            )

        # Check NTLM auth via nxc
        auth = (["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash
                else ["-p", self.env.cred.password])
        rc, out, err = _run_nxc_mssql(
            [db_ip, "-u", self.env.cred.username, "-d", self.env.domain] + auth,
            self.env,
        )
        combined = out + err
        ntlm_ok = rc != -1 and (
            "windows auth" in combined.lower() or
            "ntlm" in combined.lower() or
            "[+]" in combined
        )

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=f"MSSQL port 1433 open on {db_host} ({db_ip}) but nxc not available "
                       "to confirm NTLM auth — could not test. TAKEOVER-1 relay path may "
                       "still be viable; install nxc (netexec) to confirm.",
                raw=combined[:300],
            )

        if ntlm_ok:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"MSSQL reachable on {db_host} ({db_ip}) and accepts NTLM auth. "
                       "Relay site server machine account auth here for TAKEOVER-1.",
                raw=out[:300],
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=f"MSSQL port 1433 open on {db_host} ({db_ip}) but NTLM auth status "
                   "unclear from nxc output. Verify manually.",
            raw=combined[:300],
        )


class SiteDBSMBSigningCheck(BaseCheck):
    """Check SMB signing on the site DB server (TAKEOVER-2 path)."""

    name = "SMB signing disabled on site DB server (TAKEOVER-2)"

    @property
    def required(self) -> bool:
        return False

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        db_host = disc.site_db_host
        if not db_host and disc.management_points:
            db_host = disc.management_points[0].split(".")[0]
        if not db_host:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    "Site database hostname not found — MSSQLSvc SPN lookup returned no results. "
                    "If the SQL server has no SPN registered, pass the DB host via --extra-targets."
                ),
            )

        db_ip = _resolve(db_host)
        if not db_ip:
            db_ip = db_host if re.match(r"\d+\.\d+\.\d+\.\d+", db_host) else None

        if not db_ip or not _port_open(db_ip, 445, self.env.timeout):
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"SMB not reachable on site DB {db_host}. TAKEOVER-2 path not viable.",
            )

        rc, out, err = _run_nxc_smb(
            [db_ip, "-u", self.env.cred.username,
             "-d", self.env.domain,
             *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash
               else ["-p", self.env.cred.password]))],
            self.env,
        )
        combined = out + err

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=f"SMB reachable on {db_host} but nxc unavailable to check signing.",
            )

        signing_required = (
            "signing:true" in combined.lower() or
            "smb signing: true" in combined.lower() or
            "signing required" in combined.lower()
        )
        signing_disabled = (
            "signing:false" in combined.lower() or
            "smb signing: false" in combined.lower() or
            "signing not required" in combined.lower()
        )

        if signing_disabled:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"SMB signing not required on site DB {db_host} ({db_ip}). "
                       "TAKEOVER-2 (relay to SMB) viable.",
                raw=out[:300],
            )

        if signing_required:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"SMB signing enforced on site DB {db_host} ({db_ip}). "
                       "TAKEOVER-2 (relay to SMB) blocked. Use TAKEOVER-1 (MSSQL relay) instead.",
                raw=out[:300],
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=f"SMB reachable on {db_host} but signing status unclear. Verify manually.",
            raw=combined[:300],
        )


class SiteDBRelayPathCheck(BaseCheck):
    """
    Required gate: at least one relay path to the site DB must be viable.

    TAKEOVER-1 (MSSQL) and TAKEOVER-2 (SMB) are alternative paths to the same
    outcome. SiteDBMSSQLCheck and SiteDBSMBSigningCheck are both required=False,
    so if both FAIL the viability engine would still show PARTIAL rather than
    NOT VIABLE. This check closes that gap: it re-evaluates both paths and emits
    a required FAIL if neither is viable, making the attack correctly NOT VIABLE.

    If the DB host is unknown (SKIP), this check also SKIPs — we can't rule out
    viability without knowing the target.
    """

    name = "At least one relay path to site DB viable (TAKEOVER-1 or TAKEOVER-2)"

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        db_host = disc.site_db_host
        if not db_host and disc.management_points:
            db_host = disc.management_points[0].split(".")[0]
        if not db_host:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="Site DB hostname unknown — cannot evaluate relay path viability.",
            )

        db_ip = _resolve(db_host)
        if not db_ip:
            db_ip = db_host if re.match(r"\d+\.\d+\.\d+\.\d+", db_host) else None
        if not db_ip:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"Site DB host '{db_host}' does not resolve. "
                       "Neither TAKEOVER-1 nor TAKEOVER-2 viable.",
            )

        # ── Check TAKEOVER-2: SMB signing ────────────────────────────────
        smb_viable = False
        if _port_open(db_ip, 445, self.env.timeout):
            auth = (["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash
                    else ["-p", self.env.cred.password])
            rc, out, err = _run_nxc_smb(
                [db_ip, "-u", self.env.cred.username, "-d", self.env.domain] + auth,
                self.env,
            )
            combined = out + err
            if rc != -1 and (
                "signing:false" in combined.lower() or
                "smb signing: false" in combined.lower() or
                "signing not required" in combined.lower()
            ):
                smb_viable = True

        # ── Check TAKEOVER-1: MSSQL reachable ───────────────────────────
        mssql_viable = _port_open(db_ip, 1433, self.env.timeout)

        if smb_viable and mssql_viable:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"Both relay paths viable on {db_host}: "
                       "TAKEOVER-1 (MSSQL port 1433 open) and TAKEOVER-2 (SMB signing disabled).",
            )
        if smb_viable:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"TAKEOVER-2 (SMB relay) viable on {db_host} — SMB signing disabled. "
                       "TAKEOVER-1 (MSSQL) not available.",
            )
        if mssql_viable:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"TAKEOVER-1 (MSSQL relay) viable on {db_host} — port 1433 open. "
                       "TAKEOVER-2 (SMB) blocked or signing enforced.",
            )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=f"Neither relay path viable on site DB {db_host} ({db_ip}): "
                   "MSSQL port 1433 not reachable and SMB signing enforced or not reachable. "
                   "TAKEOVER-1 and TAKEOVER-2 both blocked.",
        )


class SiteServerCoercionCheck(BaseCheck):
    """
    Check whether coercion is available on SCCM coercion targets.

    Per Misconfiguration Manager, valid coercion targets for TAKEOVER-1/2 are:
      - TAKEOVER-x.1: Primary site server
      - TAKEOVER-x.2: SMS Provider (if on a separate host)
      - TAKEOVER-x.3: Passive site server (if HA is configured)

    All of these machine accounts have db_owner on the site DB, so coercing
    any of them and relaying to the site DB achieves Full Administrator.
    Currently only the primary site server is checked — SMS Provider and
    passive site server discovery is a future improvement.
    """

    name = "Coercion available on site server / SMS Provider (PrinterBug / PetitPotam)"

    @property
    def required(self) -> bool:
        return False

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        candidates = disc.site_servers or disc.management_points
        if not candidates:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No site server hostname found — cannot check coercion.",
            )

        spooler_hosts = []
        rpc_hosts = []

        for host in candidates:
            ip = _resolve(host) or (host if re.match(r"\d+\.\d+\.\d+\.\d+", host) else None)
            if not ip:
                continue

            if _port_open(ip, 135, self.env.timeout):
                rpc_hosts.append(host)

            # Check Print Spooler via nxc
            auth = (["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash
                    else ["-p", self.env.cred.password])
            rc, out, err = _run_nxc_smb(
                [ip, "-u", self.env.cred.username, "-d", self.env.domain]
                + auth + ["-M", "spooler"],
                self.env,
                timeout=15,
            )
            if rc != -1 and "spooler" in (out + err).lower() and (
                "enabled" in (out + err).lower() or "[+]" in out
            ):
                spooler_hosts.append(host)

        parts = []
        if spooler_hosts:
            parts.append(f"Print Spooler running on: {', '.join(spooler_hosts)}. "
                         "PrinterBug coercion available (TAKEOVER-x.1).")
        if rpc_hosts:
            parts.append(f"RPC (port 135) open on: {', '.join(rpc_hosts)}. "
                         "PetitPotam coercion viable. "
                         "Note: SMS Provider (TAKEOVER-x.2) and passive site server "
                         "(TAKEOVER-x.3) are also valid coercion targets if present.")

        if parts:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=" ".join(parts),
            )

        if not rpc_hosts and not spooler_hosts:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"No coercion paths confirmed on site server(s) "
                       f"{', '.join(candidates[:3])}. "
                       "Ports 135/445 may be filtered. Also check SMS Provider and "
                       "passive site server as alternative coercion targets.",
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail="RPC reachable but Print Spooler status unclear. "
                   "PetitPotam coercion may still work. "
                   "SMS Provider and passive site server are also valid coercion targets.",
        )


class MSSQLEPACheck(BaseCheck):
    """Check whether EPA (Extended Protection for Auth) is enforced on MSSQL site DB."""

    name = "MSSQL EPA not enforced on site DB (TAKEOVER-1 hardening)"

    @property
    def required(self) -> bool:
        return False

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        db_host = disc.site_db_host
        if not db_host:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="Site DB hostname not available — cannot check EPA.",
            )

        db_ip = _resolve(db_host)
        if not db_ip:
            db_ip = db_host if re.match(r"\d+\.\d+\.\d+\.\d+", db_host) else None

        if not db_ip or not _port_open(db_ip, 1433, self.env.timeout):
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="MSSQL not reachable — cannot check EPA.",
            )

        # EPA on MSSQL is not easily detectable without a successful relay attempt.
        # The mitigation described in Misconfiguration Manager is to configure EPA
        # on the MSSQL instance. We can note whether MSSQL is reachable and
        # advise manual verification.
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=f"MSSQL reachable on {db_host} ({db_ip}). EPA (Extended Protection for "
                   "Authentication) on MSSQL cannot be confirmed remotely — it is NOT enforced "
                   "by default. If KB15599094 is unpatched and EPA is not configured, "
                   "TAKEOVER-1 relay to MSSQL is viable.",
        )


# ── Module entry point ─────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        SCCMDetectedCheck(env),
        SiteServerReachableCheck(env),
        SiteDBRemoteCheck(env),
        SiteDBMSSQLCheck(env),
        SiteDBSMBSigningCheck(env),
        SiteDBRelayPathCheck(env),
        SiteServerCoercionCheck(env),
        MSSQLEPACheck(env),
    ]
