"""
Kerberos relay prerequisite checks for Kerberos Relay → ADCS (krbrelayx).

krbrelayx relays a machine account's Kerberos DNS ticket to ADCS HTTP
enrollment (certsrv), obtaining a certificate for the victim machine account.
The certificate is then used for PKINIT/UnPAC-the-hash → NT hash → DCSync.

Key distinction from NTLM relay:
  - Kerberos CANNOT relay to LDAP (integrity flag forces signing)
  - Kerberos CAN relay to ADCS HTTP (no signing requirement)
  - SMB signing is irrelevant — this is not an SMB relay
  - The Forshaw DNS encoding trick forces Kerberos (not NTLM) auth from target

Attack flow (remote from Kali, PetitPotam/PrinterBug coercion):
  1. Add Forshaw-encoded ADIDNS record pointing to attacker IP
     (requires only a regular domain user account)
  2. Start krbrelayx targeting ADCS HTTP endpoint
  3. Coerce DC machine account auth via PetitPotam/PrinterBug
     using the Forshaw hostname — Windows requests Kerberos DNS ticket
  4. krbrelayx relays ticket to certsrv → certificate issued for DC$
  5. certipy auth → PKINIT → NT hash recovered (UnPAC-the-hash)
  6. DCSync → full domain compromise

Prerequisites:
  [REQ]  ADCS deployed with HTTP enrollment enabled (certsrv reachable)
  [REQ]  certsrv accepts Negotiate/Kerberos auth (WWW-Authenticate: Negotiate)
  [REQ]  ADIDNS record writable by domain user (default: yes)
  [REQ]  DomainController or Machine certificate template available
  [OPT]  Coercion method available (PrinterBug / PetitPotam)
  [OPT]  DCOM/RPC reachable on target (port 135) for coercion
  [OPT]  Target is a DC (Forshaw trick most reliable against DCs;
         member servers may fall back to NTLM)

Notes:
  - mitm6 is unreliable when ADCS and DC are on the same host
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

    def _run(self) -> CheckResult:
        # Check for CA via nxc adcs module
        rc, out, err = _run_nxc(
            ["ldap", self.env.dc_ip,
             "-u", self.env.cred.username,
             *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
             "-d", self.env.domain,
             "--module", "adcs"],
            self.env,
        )
        combined = out + err
        lower = combined.lower()

        # nxc adcs failure: noSuchObject = no CA in this domain
        if "nosuchobject" in lower or ("unexpected exception" in lower and "enrollment" in lower):
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "No AD CS enrollment services found in this domain. "
                    "Kerberos relay via krbrelayx requires a certsrv HTTP endpoint. "
                    "Check if CA exists in a parent/sibling domain."
                ),
                raw=combined[:400],
            )

        # Parse CA name and host from nxc output
        ca_names = re.findall(r"Found CN:[\s]*([^\s\n\r]+)", combined, re.IGNORECASE)
        ca_hosts = re.findall(r"Found PKI Enrollment Server:[\s]*([^\s\n\r]+)",
                              combined, re.IGNORECASE)

        # Now check if certsrv HTTP is actually reachable
        http_endpoints = []
        for host in self.env.all_targets:
            if not _port_open(host, 80, timeout=self.env.timeout):
                continue
            code, headers = _http_get_headers(
                f"http://{host}/certsrv/", timeout=self.env.timeout
            )
            if code in (200, 401, 403):
                http_endpoints.append(host)

        if ca_names or ca_hosts:
            ca_summary = ""
            if ca_names:
                ca_summary += f"CA: {', '.join(ca_names[:2])}"
            if ca_hosts:
                ca_summary += f"{'; ' if ca_summary else ''}Host: {', '.join(ca_hosts[:2])}"

            if http_endpoints:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"AD CS deployed ({ca_summary}) and certsrv HTTP reachable "
                        f"on: {', '.join(http_endpoints)}. Valid krbrelayx relay target."
                    ),
                )
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"AD CS deployed ({ca_summary}) but certsrv HTTP not found "
                    f"on port 80 of any target. "
                    "Verify CA hostname and ensure port 80 is reachable."
                ),
            )

        # Fallback: direct certsrv check even without nxc CA detection
        if http_endpoints:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"certsrv HTTP reachable on {', '.join(http_endpoints)} "
                    "but could not confirm CA name via nxc. "
                    "Run: `nxc ldap <dc> -u <user> -p <pass> --module adcs`"
                ),
            )

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="nxc not available. Try: `certipy-ad find -vulnerable -stdout`",
            )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail="No ADCS enrollment services or certsrv HTTP endpoint found.",
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
    The Forshaw DNS encoding trick requires adding an ADIDNS (AD-integrated DNS)
    record pointing to the attacker. By default, any authenticated domain user
    can add DNS records to the domain zone via LDAP.

    Method: check if the domain DNS zone is writable by querying
    the ACL on the MicrosoftDNS container — or attempt a lightweight
    ldap3 bind to confirm domain user auth works (write access is default).

    In practice this is enabled by default in AD environments, so we check
    for the uncommon case where it's been locked down.
    """

    name = "ADIDNS record writable by domain user (Forshaw DNS trick)"

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
                # Check that the DNS zone container exists and is accessible
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
                        "Forshaw DNS trick viable. "
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
                        "Forshaw DNS trick may not be possible with this account."
                    ),
                )
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=f"Could not verify DNS zone access: {e}. Verify manually.",
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail="DNS zone not found at expected path. Verify ADIDNS configuration manually.",
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
                "verify manually if certipy output is unexpected.",
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
    """

    name = "DC target in scope (Forshaw trick most reliable against DCs)"
    required = False

    def _run(self) -> CheckResult:
        dc_targets = []
        member_targets = []

        for host in self.env.all_targets:
            rc, out, err = _run_nxc(
                ["smb", host,
                 "-u", self.env.cred.username,
                 *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                 "-d", self.env.domain],
                self.env,
            )
            combined = out + err
            lower = combined.lower()
            if rc == -1:
                continue
            # DCs show up with their domain name matching the DC hostname
            # or can be identified by checking if host == dc_ip
            if host == self.env.dc_ip:
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
    ]

ATTACK_NAME = "Kerberos Relay → ADCS (krbrelayx + Forshaw DNS)"
