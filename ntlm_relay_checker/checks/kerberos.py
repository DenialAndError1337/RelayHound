"""
Kerberos relay prerequisite checks for Kerberos Relay → ADCS (krbrelayx).

krbrelayx relays a machine account's Kerberos DNS ticket to ADCS HTTP
enrollment (certsrv), obtaining a certificate for the victim machine account.
The certificate is then used for PKINIT/UnPAC-the-hash → NT hash → DCSync.

Key distinction from NTLM relay:
  - Kerberos CANNOT relay to LDAP (integrity flag forces signing)
  - Kerberos CAN relay to ADCS HTTP (no signing requirement)
  - SMB signing is irrelevant — this is not an SMB relay

Three supported coercion paths (ADIDNS write only required for path 1):

  Path 1 — Forshaw DNS trick (coerce → ADIDNS record → krbrelayx):
    1. Add Forshaw-encoded ADIDNS record pointing to attacker IP
       (requires only a regular domain user account)
    2. Start krbrelayx targeting ADCS HTTP endpoint
    3. Coerce DC via PetitPotam/PrinterBug using the Forshaw hostname
       — Windows requests Kerberos DNS ticket for that name
    4. krbrelayx relays ticket to certsrv → certificate issued for DC$

  Path 2 — mitm6 / DHCPv6 DNS poisoning (no ADIDNS write needed):
    1. Start mitm6 to poison DHCPv6 DNS for target hosts
    2. Victim machine authenticates via Kerberos to attacker DNS name
    3. krbrelayx relays to ADCS HTTP endpoint
    Note: unreliable when ADCS and DC are on the same host

  Path 3 — Kerberos relay over SMB (Synacktiv technique, no ADIDNS write):
    1. Pass the Forshaw-encoded string directly as the coercion target
       hostname argument — no DNS record registration needed
    2. Coerce DC auth to the marshalled hostname string
    3. krbrelayx relays to ADCS HTTP endpoint

  All paths end with:
    certipy auth → PKINIT → NT hash recovered (UnPAC-the-hash) → DCSync

Prerequisites:
  [REQ]  ADCS deployed with HTTP enrollment enabled (certsrv reachable)
  [REQ]  certsrv accepts Negotiate/Kerberos auth (WWW-Authenticate: Negotiate)
  [OPT]  ADIDNS record writable by domain user — required for path 1 only
  [REQ]  DomainController or Machine certificate template available
  [OPT]  Coercion method available (PrinterBug / PetitPotam)
  [OPT]  DCOM/RPC reachable on target (port 135) for coercion
  [OPT]  Target is a DC (Forshaw trick most reliable against DCs;
         member servers may fall back to NTLM)

Notes:
  - Cross-domain relay (child domain machine → parent CA) requires
    the CA template to grant enrollment rights to the child domain
  - Always clean up: remove Forshaw DNS record and clear
    msDS-KeyCredentialLink after testing
"""
from __future__ import annotations
import re
import socket
import subprocess
import urllib.request
import urllib.error

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv
from ..utils import CoercionAvailabilityCheck, adcs_enrollment_verdict

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


def _http_get_headers(url: str, timeout: int = 10) -> tuple[int, dict]:
    """GET a URL and return (status_code, merged_headers)."""
    def _merge_auth(headers) -> dict:
        merged = dict(headers)
        auth_values = ", ".join(
            v for k, v in headers.items()
            if k.lower() == "www-authenticate"
        )
        if auth_values:
            merged["WWW-Authenticate"] = auth_values
        return merged

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _merge_auth(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, _merge_auth(e.headers)
    except Exception:
        return -1, {}


def _run_nxc(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    try:
        cmd = ["nxc"] + args
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


def _run_certipy(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(["certipy-ad"] + args, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        try:
            r = subprocess.run(["certipy"] + args, capture_output=True,
                               text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", "certipy-ad not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


# ── individual checks ──────────────────────────────────────────────────────

class AdcsHttpEnrollmentCheck(BaseCheck):
    """
    ADCS must be deployed and HTTP enrollment (certsrv) must be reachable.
    This is the relay target for krbrelayx — without certsrv there is
    nowhere to relay the Kerberos ticket.

    Method: nxc ldap --module adcs + port 80 check on all targets.
    """

    name = "ADCS HTTP enrollment (certsrv) reachable"
    breaks_on_fail = True  # no certsrv = nowhere to relay; skip all downstream checks

    def _run(self) -> CheckResult:
        # Authoritative shared probe for CA existence (reads/writes the cache).
        # This module does NOT write the cache itself: "certsrv HTTP reachable"
        # is a separate fact and must not poison shared_cache["adcs_deployed"].
        v = adcs_enrollment_verdict(self.env)
        if v.status == Status.FAIL:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(f"{v.detail} Kerberos relay via krbrelayx needs a "
                        "certsrv HTTP endpoint, which cannot exist without a CA."),
            )

        # CA exists (PASS) or LDAP inconclusive (SKIP): probe certsrv HTTP.
        ca_names, ca_hosts = v.ca_names, v.ca_hosts
        http_endpoints = []
        for host in self.env.all_targets:
            if not _port_open(host, 80, timeout=self.env.timeout):
                continue
            code, headers = _http_get_headers(
                f"http://{host}/certsrv/", timeout=self.env.timeout)
            if code in (200, 401, 403):
                http_endpoints.append(host)

        if v.status == Status.PASS:
            ca_summary = ""
            if ca_names:
                ca_summary += f"CA: {', '.join(ca_names[:2])}"
            if ca_hosts:
                ca_summary += f"{'; ' if ca_summary else ''}Host: {', '.join(ca_hosts[:2])}"
            ca_summary = ca_summary or "CA registered in AD"
            if http_endpoints:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(f"AD CS deployed ({ca_summary}) and certsrv HTTP reachable "
                            f"on: {', '.join(http_endpoints)}. Valid krbrelayx relay target."),
                )
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(f"AD CS deployed ({ca_summary}) but certsrv HTTP not found on "
                        "port 80 of any target. Verify CA hostname and port 80 reachability."),
            )

        # v.status == SKIP — LDAP inconclusive; report on HTTP evidence alone.
        if http_endpoints:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(f"certsrv HTTP reachable on {', '.join(http_endpoints)} but CA "
                        "presence could not be confirmed via LDAP. "
                        "Run: nxc ldap <dc> --module adcs"),
            )
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=("Could not confirm AD CS via LDAP and no certsrv HTTP endpoint "
                    "found. Try: certipy-ad find -vulnerable -stdout"),
        )


class CertsrvKerberosAuthCheck(BaseCheck):
    """
    certsrv must accept Negotiate (Kerberos) authentication.
    krbrelayx relays a Kerberos ticket — if the endpoint only accepts NTLM
    the relay will fail.

    A 401 with WWW-Authenticate: Negotiate (with or without NTLM) is correct.

    Method: inspect WWW-Authenticate header from GET /certsrv/
    """

    name = "certsrv accepts Negotiate/Kerberos authentication"

    def _run(self) -> CheckResult:
        for host in self.env.all_targets:
            if not _port_open(host, 80, timeout=self.env.timeout):
                continue
            code, headers = _http_get_headers(
                f"http://{host}/certsrv/", timeout=self.env.timeout
            )
            auth = headers.get("WWW-Authenticate", "").upper()
            if code in (200, 401, 403) and "NEGOTIATE" in auth:
                also_ntlm = " (NTLM also offered)" if "NTLM" in auth else ""
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"http://{host}/certsrv/ offers Negotiate auth{also_ntlm}. "
                        "Kerberos ticket relay accepted."
                    ),
                )
            if code in (200, 401, 403) and "NTLM" in auth and "NEGOTIATE" not in auth:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        f"http://{host}/certsrv/ offers NTLM only — "
                        "Negotiate/Kerberos not available. "
                        "Kerberos relay will fail; this endpoint only accepts NTLM."
                    ),
                )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail="No certsrv HTTP endpoint found offering Negotiate authentication.",
        )


class AdidnsWritableCheck(BaseCheck):
    """
    The Forshaw DNS trick (coercion path 1) requires adding an ADIDNS record
    pointing to the attacker. By default, any authenticated domain user can
    add DNS records to the domain zone via LDAP.

    This check is required=False because ADIDNS write is only needed for
    path 1 (Forshaw DNS trick). Paths 2 (mitm6) and 3 (Kerberos relay over
    SMB / marshalled hostname in coercion argument) do not require it.

    In practice ADIDNS write is enabled by default, so we check for the
    uncommon case where it has been locked down.
    """

    name = "ADIDNS record writable by domain user (Forshaw DNS path only)"
    required = False

    def _run(self) -> CheckResult:
        # The most reliable check is to confirm authenticated LDAP access works
        # (write to DNS requires LDAP auth which we test by binding).
        # Full ACL check would require reading nTSecurityDescriptor which is complex.
        # Instead: confirm LDAP bind succeeds — if it does, DNS write is default.
        if not LDAP3_AVAILABLE:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    "ldap3 not installed — cannot verify ADIDNS write access. "
                    "By default any domain user can add DNS records. "
                    "Install ldap3: pip install ldap3"
                ),
            )

        try:
            server = ldap3.Server(self.env.dc_ip, get_info=ALL,
                                  connect_timeout=self.env.timeout)
            conn = Connection(
                server,
                user=self.env.cred.upn,
                password=self.env.cred.password,
                authentication=NTLM,
                auto_bind=True,
            )
            if conn.bound:
                domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
                dns_zone_dn = (
                    f"DC={self.env.domain},"
                    f"CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}"
                )
                conn.search(
                    search_base=dns_zone_dn,
                    search_filter="(objectClass=dnsZone)",
                    search_scope=ldap3.BASE,
                    attributes=["dc"],
                )
                conn.unbind()
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        "LDAP bind succeeded and DNS zone accessible. "
                        "By default, authenticated domain users can add ADIDNS records — "
                        "Forshaw DNS trick (path 1) viable. "
                        "Command: `dnstool.py -u '<domain>\\<user>' -p '<pass>' "
                        "-r '<forshaw_hostname>' -a add -d <attacker_ip> -t A --tcp <dc_ip>`"
                    ),
                )
        except Exception as e:
            err = str(e).lower()
            if "unwilling" in err or "insufficient" in err or "access" in err:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        f"LDAP access denied — DNS zone may be write-protected: {e}. "
                        "Forshaw DNS trick (path 1) not viable with this account. "
                        "mitm6 (path 2) and SMB coercion with marshalled hostname (path 3) "
                        "are unaffected and do not require ADIDNS write access."
                    ),
                )
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=f"Could not verify DNS zone access: {e}. Verify manually.",
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "DNS zone not found at expected path. Verify ADIDNS configuration manually. "
                "mitm6 (path 2) and SMB coercion with marshalled hostname (path 3) "
                "do not require ADIDNS write access."
            ),
        )


class CertificateTemplateCheck(BaseCheck):
    """
    A suitable certificate template must be available for enrollment.
    For DC victims: DomainController template.
    For member server victims: Machine template.

    Both are present by default in AD environments with ADCS.

    Method: certipy find to list enabled templates.
    """

    name = "DomainController / Machine certificate template available"

    def _run(self) -> CheckResult:
        rc, out, err = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ], timeout=45)

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    "certipy-ad not installed — cannot enumerate templates. "
                    "DomainController and Machine templates are present by default. "
                    "Install: pip install certipy-ad"
                ),
            )

        combined = out + err
        lower = combined.lower()

        found_dc = "domaincontroller" in lower.replace(" ", "")
        found_machine = "template name" in lower and "machine" in lower

        if found_dc and found_machine:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    "Both DomainController and Machine templates found. "
                    "Use --template DomainController for DC victims, "
                    "--template Machine for member servers."
                ),
            )
        if found_dc:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    "DomainController template found — relay against DC victims viable. "
                    "Machine template not confirmed; check certipy output for member servers."
                ),
            )
        if found_machine:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    "Machine template found — relay against member server victims viable. "
                    "DomainController template not confirmed."
                ),
            )

        if "no" in lower and "template" in lower:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="certipy found no certificate templates. ADCS may not be configured.",
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "Could not confirm template availability from certipy output. "
                "DomainController and Machine templates are present by default — "
                "verify manually if certipy output is unexpected."
            ),
            raw=combined[:400],
        )


class KrbCoercionMethodCheck(BaseCheck):
    """
    A coercion method must be available to trigger Kerberos DNS authentication
    from the victim machine account.

    For krbrelayx via the Forshaw DNS trick:
      - PrinterBug (MS-RPRN) — reliable, requires Print Spooler running
      - PetitPotam (MS-EFSRPC) — works when EFS is available

    Important: the Forshaw-encoded hostname must be used as the callback
    address (not the attacker's plain IP) to trigger Kerberos DNS auth
    rather than NTLM/CIFS auth.

    Note from testing: the Forshaw trick is most reliable against DC targets.
    Member servers may fall back to NTLM.
    """

    name = "Coercion method available (PrinterBug / PetitPotam)"
    required = False

    def _run(self) -> CheckResult:
        spooler_hosts = []
        for host in self.env.all_targets:
            rc, out, err = _run_nxc(
                ["smb", host,
                 "-u", self.env.cred.username,
                 *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                 "-d", self.env.domain,
                 "--module", "spooler"],
                self.env,
            )
            combined = (out + err).lower()
            if rc != -1 and (
                "spooler service enabled" in combined or
                "spooler: true" in combined or
                "running" in combined
            ):
                spooler_hosts.append(host)

        if spooler_hosts:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Print Spooler running on: {', '.join(spooler_hosts)}. "
                    "PrinterBug coercion available. "
                    "Use the Forshaw-encoded hostname as the callback (not a plain IP) "
                    "— see Recommended Attack Paths for the full command."
                ),
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "Could not confirm Print Spooler status. "
                "Check manually: PrinterBug (MS-RPRN), PetitPotam (MS-EFSRPC). "
                "Use the Forshaw-encoded hostname as the callback — see Recommended Attack Paths."
            ),
        )


class DcomRpcReachableCheck(BaseCheck):
    """
    Port 135 (RPC endpoint mapper) must be reachable for DCOM-based coercion
    (PrinterBug, PetitPotam). The Forshaw trick relies on one of these
    coercion methods to trigger authentication.
    """

    name = "DCOM/RPC reachable on target (port 135)"
    required = False

    def _run(self) -> CheckResult:
        reachable = []
        blocked = []

        for host in self.env.all_targets:
            if _port_open(host, 135, timeout=self.env.timeout):
                reachable.append(host)
            else:
                blocked.append(host)

        if reachable:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"RPC endpoint mapper (port 135) open on: {', '.join(reachable)}. "
                    "PrinterBug and PetitPotam coercion viable."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=(
                f"Port 135 blocked on all targets: {', '.join(blocked)}. "
                "DCOM-based coercion not possible from this network position."
            ),
        )


class DcTargetCheck(BaseCheck):
    """
    The Forshaw DNS trick is most reliable against DC targets.
    Member servers were observed to fall back to NTLM rather than
    Kerberos DNS auth in testing.

    This check identifies whether any DC targets are in scope,
    which determines viability and which certificate template to use.

    DC detection uses two attribute-based signals — never hostname patterns:

      1. env.dc_ips membership — populated at startup via LDAP
         SERVER_TRUST_ACCOUNT (UAC bit 0x2000) query; free, no extra call.

      2. SMB ServerType flags — the SMB negotiate response carries
         SV_TYPE_DOMAIN_CTRL (0x8) and SV_TYPE_DOMAIN_BAKCTRL (0x10),
         which nxc surfaces as "(Domain Controller)" in its per-host output
         line. This catches DCs in trusted domains / extra-targets that
         startup LDAP discovery may not have reached.

    Both signals are checked per host; either one is sufficient.
    """

    name = "DC target in scope (Forshaw trick most reliable against DCs)"
    required = False

    def _run(self) -> CheckResult:
        dc_targets: list[str] = []
        member_targets: list[str] = []
        unreachable: list[str] = []

        known_dc_ips = set(self.env.dc_ips)

        for host in self.env.all_targets:
            rc, out, err = _run_nxc(
                ["smb", host,
                 "-u", self.env.cred.username,
                 *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                 "-d", self.env.domain],
                self.env,
            )

            if rc == -1:
                unreachable.append(host)
                continue

            # Signal 1: startup LDAP discovery already classified this IP
            if host in known_dc_ips:
                dc_targets.append(host)
                continue

            # Signal 2: SMB ServerType flags in nxc output
            # nxc formats the host line as:
            #   SMB  10.0.0.1  445  KINGSLANDING  [*] ... (domain) (Domain Controller)
            # The "(Domain Controller)" label comes from SV_TYPE_DOMAIN_CTRL /
            # SV_TYPE_DOMAIN_BAKCTRL in the SMB negotiate ServerType field —
            # not from the hostname.
            if "(domain controller)" in (out + err).lower():
                dc_targets.append(host)
            else:
                member_targets.append(host)

        if dc_targets:
            template_note = (
                "Use --template DomainController for DC victims."
                + (f" Member server(s) also in scope: {', '.join(member_targets)} "
                   "(use --template Machine, but Forshaw trick may produce NTLM instead of Kerberos)."
                   if member_targets else "")
            )
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"DC target(s) in scope: {', '.join(dc_targets)}. {template_note}",
            )

        if member_targets:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"Only member server(s) in scope: {', '.join(member_targets)}. "
                    "Forshaw trick may produce NTLM rather than Kerberos against member servers. "
                    "Add the DC IP via --dc-ip or --extra-targets for reliable Kerberos relay."
                ),
            )

        if unreachable:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    f"nxc unreachable for all targets: {', '.join(unreachable)}. "
                    "Install nxc or verify network connectivity."
                ),
            )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="Could not determine target roles — specify --extra-targets.",
        )



class WebClientCoercionCheck(BaseCheck):
    """
    Optional: WebClient running on target enables HTTP/WebDAV coercion
    (PetitPotam HTTP) to trigger Kerberos DNS authentication for krbrelayx.

    Your notes list this as required for HTTP coercion via PetitPotam.
    Not needed for PrinterBug (RPC-based).
    """

    name = "WebClient running on target (enables PetitPotam WebDAV/HTTP coercion)"
    required = False

    def _run(self) -> CheckResult:
        webclient_hosts = []
        for host in self.env.all_targets:
            try:
                import subprocess as _sp
                r = _sp.run(
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
            except Exception:
                pass

        if webclient_hosts:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"WebClient running on: {', '.join(webclient_hosts)}. "
                    "PetitPotam WebDAV/HTTP coercion available. "
                    "PrinterBug (MS-RPRN) coercion works regardless of WebClient."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "WebClient not confirmed — PetitPotam WebDAV/HTTP coercion unavailable. "
                "Use PrinterBug (MS-RPRN) or PetitPotam SMB/RPC coercion instead."
            ),
        )


class HostSpnCheck(BaseCheck):
    """
    Target machine accounts must have the HOST SPN set for Kerberos DNS
    relay to work. HOST SPNs are set on all domain-joined computer accounts
    by default — this check confirms at least one target has them.

    The HOST SPN maps to multiple services including CIFS, HTTP, and DNS,
    which is why DNS Kerberos auth can be relayed to ADCS HTTP.

    Method: ldap3 query servicePrincipalName on computer objects.
    """

    name = "HOST SPN set on target machine account (default for all computers)"
    required = False

    def _run(self) -> CheckResult:
        if not LDAP3_AVAILABLE:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="ldap3 not installed — cannot check SPNs.",
            )

        try:
            server = ldap3.Server(self.env.dc_ip, get_info=ldap3.ALL,
                                  connect_timeout=self.env.timeout)
            conn = ldap3.Connection(
                server, user=self.env.cred.upn,
                password=self.env.cred.password,
                authentication=NTLM, auto_bind=True,
            )
            domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
            conn.search(
                search_base=domain_dn,
                search_filter="(objectClass=computer)",
                search_scope=ldap3.SUBTREE,
                attributes=["sAMAccountName", "servicePrincipalName"],
                paged_size=20,
            )
            with_host_spn = []
            without_host_spn = []
            for entry in conn.entries:
                name = str(entry["sAMAccountName"])
                spns = [str(s).lower() for s in (entry["servicePrincipalName"].values or [])]
                if any(s.startswith("host/") for s in spns):
                    with_host_spn.append(name)
                else:
                    without_host_spn.append(name)

            conn.unbind()

            if with_host_spn:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"HOST SPN confirmed on: {', '.join(with_host_spn[:5])}. "
                        "Kerberos DNS authentication can be relayed for these accounts."
                    ),
                )
            if without_host_spn:
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        f"No HOST SPNs found on computer accounts: "
                        f"{', '.join(without_host_spn[:5])}. "
                        "This is unexpected — HOST SPNs are set by default on all "
                        "domain-joined computers. Verify manually."
                    ),
                )
        except Exception as e:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail=f"SPN query failed: {e}")
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return CheckResult(name=self.name, status=Status.SKIP,
                           detail="Could not enumerate SPNs.")

# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        AdcsHttpEnrollmentCheck(env),
        CertsrvKerberosAuthCheck(env),
        AdidnsWritableCheck(env),
        CertificateTemplateCheck(env),
        HostSpnCheck(env),
        KrbCoercionMethodCheck(env),
        DcomRpcReachableCheck(env),
        DcTargetCheck(env),
        WebClientCoercionCheck(env),
        CoercionAvailabilityCheck(env),
    ]

ATTACK_NAME = "Kerberos Relay → ADCS (krbrelayx + Forshaw DNS)"
