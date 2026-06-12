"""
ADCS prerequisite checks for NTLM Relay → ADCS (ESC8).

ESC8 = AD CS web enrollment endpoint accepts NTLM auth over HTTP (not HTTPS),
allowing relay of a DC's machine account to enroll a certificate.

Prerequisites:
  [REQ]  AD CS is deployed in the domain
  [REQ]  Web Enrollment (certsrv) HTTP endpoint reachable
  [REQ]  Web enrollment endpoint uses NTLM (not Kerberos-only)
  [REQ]  Enrollable certificate template with Client Authentication EKU exists
         and grants enrollment rights to machine accounts or Domain Controllers
  [REQ]  CA Request Disposition = Issue (auto-approve; manual approval → pending
         request only, no usable certificate)
  [OPT]  HTTPS endpoint also present (NTLM over HTTPS requires EPA disabled)
  [OPT]  certipy-ad confirms ESC8 vulnerability
"""
from __future__ import annotations
import socket
import subprocess
import urllib.request
import urllib.error

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv
from .esc11 import RequestDispositionCheck
from ..utils import CoercionAvailabilityCheck


# ── helpers ────────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 10) -> tuple[int, dict, str]:
    """
    Simple HTTP GET. Returns (status_code, headers, body_snippet).
    Merges duplicate WWW-Authenticate headers (e.g. Negotiate + NTLM on
    separate lines) into one comma-joined string so NTLM detection is reliable.
    """
    def _merge_auth(headers) -> dict:
        try:
            merged = dict(headers)
        except (ValueError, TypeError):
            merged = {}
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
            body = resp.read(1024).decode("utf-8", errors="replace")
            return resp.status, _merge_auth(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, _merge_auth(e.headers), e.read(512).decode("utf-8", errors="replace")
    except Exception:
        return -1, {}, ""


def _port_open(host: str, port: int, timeout: int = 5) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _run_certipy(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            ["certipy-ad"] + args, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["certipy"] + args, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError:
            return -1, "", "certipy-ad/certipy not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


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


# ── individual checks ──────────────────────────────────────────────────────

class AdcsDeployedCheck(BaseCheck):
    """
    AD CS must be deployed. Check via LDAP for PKI containers and
    optionally nxc --module adcs.

    Method: nxc ldap <dc> --module adcs
            OR ldap query CN=Enrollment Services,CN=Public Key Services,...
    """

    name = "AD CS deployed in domain"

    def _run(self) -> CheckResult:
        # Try nxc adcs module
        rc, out, err = _run_nxc_ldap(["--module", "adcs"], self.env)
        combined = out + err
        if rc != -1 and combined.strip():
            lower = combined.lower()
            import re

            # nxc adcs failure: "noSuchObject" or "[-] Obtained unexpected exception"
            # means the PKI container doesn't exist in this domain — no CA here
            if "nosuchobject" in lower or ("unexpected exception" in lower and "enrollment" in lower):
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "No AD CS enrollment services found in this domain "
                        "(nxc adcs: noSuchObject). The CA likely lives in a parent/sibling domain. "
                        "ESC8 relay requires a certsrv endpoint in the target domain."
                    ),
                    raw=combined[:400],
                )

            # nxc adcs success lines:
            #   "Found PKI Enrollment Server: kingslanding.sevenkingdoms.local"
            #   "Found CN: SEVENKINGDOMS-CA"
            ca_hosts = re.findall(r"Found PKI Enrollment Server:[\s]*([^\s\n\r]+)", combined, re.IGNORECASE)

            ca_names = re.findall(r"Found CN:[\s]*([^\s\n\r]+)", combined, re.IGNORECASE)


            if ca_names or ca_hosts:
                parts = []
                if ca_names:
                    parts.append(f"CA: {', '.join(ca_names[:2])}")
                if ca_hosts:
                    parts.append(f"Host: {', '.join(ca_hosts[:2])}")
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=f"AD CS deployed — {'; '.join(parts)}",
                    raw=combined[:400],
                )

            if "no" in lower and "ca" in lower:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail="nxc adcs module found no Certificate Authority.",
                    raw=combined[:400],
                )

        # Fallback: certipy find
        rc2, out2, err2 = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ], timeout=30)
        combined2 = (out2 + err2).lower()
        if rc2 != -1:
            if "certificate authorit" in combined2 or "ca name" in combined2:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="AD CS CA found via certipy.",
                    raw=(out2 + err2)[:400],
                )
            if "no certificate" in combined2 or "no ca" in combined2:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail="certipy found no CA in the domain.",
                )

        # Fallback: try ldap3
        try:
            import ldap3
            from ldap3 import Server, Connection, NTLM, SUBTREE
            server = ldap3.Server(self.env.dc_ip, connect_timeout=self.env.timeout)
            conn = Connection(
                server, user=self.env.cred.upn, password=self.env.cred.password,
                authentication=NTLM, auto_bind=True,
            )
            config_dn = "CN=Configuration," + ",".join(
                f"DC={p}" for p in self.env.domain.split(".")
            )
            conn.search(
                search_base=f"CN=Enrollment Services,CN=Public Key Services,"
                            f"CN=Services,{config_dn}",
                search_filter="(objectClass=pKIEnrollmentService)",
                search_scope=SUBTREE,
                attributes=["cn", "dNSHostName"],
            )
            if conn.entries:
                ca_names = [str(e["cn"]) for e in conn.entries]
                hosts = [str(e["dNSHostName"]) for e in conn.entries]
                conn.unbind()
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=f"CA(s) found: {', '.join(ca_names)} on {', '.join(hosts)}",
                )
            conn.unbind()
        except Exception:
            pass

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="Could not query for AD CS. Try: certipy-ad find or nxc ldap --module adcs",
        )


class CertsrvHttpCheck(BaseCheck):
    """
    The /certsrv endpoint must be reachable over HTTP (port 80) on the CA server.
    NTLM relay requires HTTP (not HTTPS without EPA bypass).

    Method: curl/requests GET http://<ca>/certsrv/  → 401 with WWW-Authenticate: NTLM
    """

    name = "Web enrollment HTTP endpoint reachable (port 80)"

    def _run(self) -> CheckResult:
        http_targets = []
        # Check DC + extra targets
        for host in self.env.all_targets:
            if _port_open(host, 80, timeout=self.env.timeout):
                http_targets.append(host)

        if not http_targets:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "Port 80 not reachable on any target. "
                    "ESC8 requires the certsrv web enrollment to be HTTP-accessible."
                ),
            )

        ntlm_endpoints = []
        other_endpoints = []
        for host in http_targets:
            url = f"http://{host}/certsrv/"
            code, headers, body = _http_get(url, timeout=self.env.timeout)
            auth = headers.get("WWW-Authenticate", "").upper()
            if code == 401 and "NTLM" in auth:
                ntlm_endpoints.append(host)
            elif code in (200, 401, 403):
                other_endpoints.append(f"{host}({code})")

        if ntlm_endpoints:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"/certsrv/ returns 401+NTLM on: {', '.join(ntlm_endpoints)}. "
                    "Perfect relay target for ESC8."
                ),
            )
        if other_endpoints:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"/certsrv/ found but without NTLM challenge: {', '.join(other_endpoints)}. "
                    "May use Kerberos-only auth or redirects to HTTPS."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=(
                f"Port 80 open on {', '.join(http_targets)} but /certsrv/ not found. "
                "Web enrollment may not be installed."
            ),
        )


class CertsrvNtlmAuthCheck(BaseCheck):
    """
    Web enrollment must accept NTLM (not enforce Kerberos or require EPA).
    Reachable via HTTPS is OK but requires EPA check.

    Method: Inspect WWW-Authenticate header from /certsrv/
    """

    name = "certsrv uses NTLM auth (not Kerberos-only)"

    def _run(self) -> CheckResult:
        for host in self.env.all_targets:
            for scheme in ("http", "https"):
                port = 80 if scheme == "http" else 443
                if not _port_open(host, port, timeout=self.env.timeout):
                    continue
                url = f"{scheme}://{host}/certsrv/"
                code, headers, body = _http_get(url, timeout=self.env.timeout)
                auth_header = headers.get("WWW-Authenticate", "")
                if "NTLM" in auth_header.upper():
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail=(
                            f"{scheme.upper()}://{host}/certsrv/ offers NTLM auth "
                            f"({'HTTP — ideal for relay' if scheme == 'http' else 'HTTPS — EPA check needed'})."
                        ),
                    )
                if "Negotiate" in auth_header and "NTLM" not in auth_header.upper():
                    return CheckResult(
                        name=self.name, status=Status.WARN,
                        detail=(
                            f"{scheme.upper()}://{host}/certsrv/ uses Negotiate (Kerberos preferred). "
                            "Relay may still work — depends on client/server Kerberos support."
                        ),
                    )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail="No /certsrv/ endpoint found offering NTLM authentication.",
        )


class EnrollableTemplateCheck(BaseCheck):
    """
    An enrollable certificate template with a suitable EKU must exist for
    ESC8 to yield a usable certificate. The relay coerces a machine account
    (typically a DC) to enroll — the template must:
      - Be published on the CA (enabled)
      - Allow machine account or Domain Controller enrollment
      - Have Client Authentication EKU (1.3.6.1.5.5.7.3.2), Smart Card Logon,
        Any Purpose (2.5.29.37.0), or no EKU (any purpose implied)

    The DomainController and Machine templates satisfy all of these by default
    and are present in every default ADCS deployment. This check matters because
    templates can be disabled or deleted.

    Method: certipy find — look for templates with Client Authentication EKU
            and enrollment rights for Domain Controllers or Domain Computers.
            LDAP fallback: query pKIEnrollmentServices and pKICertificateTemplate
            objects in the Configuration partition.
    """

    name = "Enrollable template with Client Authentication EKU exists"

    # OIDs that satisfy the EKU requirement for PKINIT/auth use
    AUTH_EKUS = {
        "1.3.6.1.5.5.7.3.2",   # Client Authentication
        "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
        "2.5.29.37.0",          # Any Purpose
        "1.3.6.1.5.2.3.4",     # PKINIT Client Auth
    }

    def _run(self) -> CheckResult:
        rc, out, err = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ], timeout=45)

        if rc != -1:
            combined = out + err
            lower = combined.lower()
            import re

            # Parse template blocks from certipy output.
            # Each template block starts with "Template Name" and contains
            # "Client Authentication : True/False" and enrollment rights.
            # We look for templates where:
            #   - Client Authentication is True (or EKU includes a suitable OID)
            #   - Enrollment Rights include Domain Controllers or Domain Computers
            suitable: list[str] = []

            # Split on template name lines to get per-template blocks
            blocks = re.split(r"(?=Template Name\s*:)", combined, flags=re.IGNORECASE)
            for block in blocks:
                name_m = re.search(r"Template Name\s*:\s*([^\r\n]+)", block, re.IGNORECASE)
                if not name_m:
                    continue
                tname = name_m.group(1).strip()

                # Skip disabled templates — cannot be used for enrollment
                enabled_m = re.search(r"Enabled\s*:\s*(True|False)", block, re.IGNORECASE)
                if enabled_m and enabled_m.group(1).strip().lower() == "false":
                    continue

                # Client Authentication field is the authoritative signal.
                # Do NOT check for the string "client authentication" in the
                # full block — it appears in the field label even when False.
                ca_m = re.search(r"Client Authentication\s*:\s*(True|False)", block, re.IGNORECASE)
                has_client_auth = ca_m and ca_m.group(1).strip().lower() == "true"

                # Check Extended Key Usage section for relevant OIDs/names.
                # Scoped to the EKU section only to avoid false matches on field labels.
                eku_m = re.search(r"Extended Key Usage\s*:(.*?)(?=\n\s{4}\w|\Z)", block, re.IGNORECASE | re.DOTALL)
                eku_section = eku_m.group(1).lower() if eku_m else ""
                has_auth_eku = has_client_auth or any(eku in eku_section for eku in [
                    "smart card logon",
                    "any purpose",
                    "kdc authentication",
                    "1.3.6.1.5.5.7.3.2",
                    "2.5.29.37.0",
                ])

                # Check enrollment rights include machine accounts or DCs
                block_lower = block.lower()
                has_machine_enroll = any(term in block_lower for term in [
                    "domain controllers",
                    "domain computers",
                    "enterprise domain controllers",
                    "authenticated users",
                    "domain users",
                    "everyone",
                ])

                if has_auth_eku and has_machine_enroll:
                    suitable.append(tname)

            if suitable:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"Suitable template(s) found: {', '.join(suitable[:3])}. "
                        "Machine/DC enrollment with Client Authentication EKU available."
                    ),
                )

            # certipy ran and found templates but none suitable
            if "template name" in lower:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "No certificate template found that allows machine/DC enrollment "
                        "with Client Authentication EKU. "
                        "ESC8 relay will not yield a usable certificate without a suitable template."
                    ),
                    raw=combined[:400],
                )

        # Fallback: LDAP query for published templates
        try:
            import ldap3
            from ldap3 import Server, Connection, NTLM, SUBTREE
            server = ldap3.Server(self.env.dc_ip, connect_timeout=self.env.timeout)
            if self.env.cred.nt_hash:
                nh = self.env.cred.nt_hash.split(":")[-1]
                auth_pw = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
            else:
                auth_pw = self.env.cred.password
            conn = Connection(
                server, user=self.env.cred.upn, password=auth_pw,
                authentication=NTLM, auto_bind=True,
            )
            config_dn = "CN=Configuration," + ",".join(
                f"DC={p}" for p in self.env.domain.split(".")
            )
            # Query published templates from the CA enrollment services object
            conn.search(
                search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}",
                search_filter="(objectClass=pKIEnrollmentService)",
                search_scope=SUBTREE,
                attributes=["certificateTemplates"],
            )
            published = set()
            for entry in conn.entries:
                for t in (entry["certificateTemplates"].values or []):
                    published.add(str(t).lower())

            # Check each published template for auth EKU
            if published:
                conn.search(
                    search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}",
                    search_filter="(objectClass=pKICertificateTemplate)",
                    search_scope=SUBTREE,
                    attributes=["cn", "pKIExtendedKeyUsage"],
                )
                suitable_ldap = []
                for entry in conn.entries:
                    cn = str(entry["cn"]).lower()
                    if cn not in published:
                        continue
                    ekus = [str(e) for e in (entry["pKIExtendedKeyUsage"].values or [])]
                    if not ekus or any(e in self.AUTH_EKUS for e in ekus):
                        suitable_ldap.append(str(entry["cn"]))
                conn.unbind()
                if suitable_ldap:
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail=(
                            f"Published template(s) with suitable EKU (via LDAP): "
                            f"{', '.join(suitable_ldap[:3])}."
                        ),
                    )
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "No published template with Client Authentication EKU found via LDAP. "
                        "ESC8 relay will not yield a usable certificate."
                    ),
                )
        except Exception:
            pass

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Could not enumerate certificate templates. "
                "Install certipy-ad (pip install certipy-ad) for reliable template enumeration."
            ),
        )


class ESC8CertipyCheck(BaseCheck):
    """
    Run certipy-ad find -vulnerable to confirm ESC8 and list affected templates.

    Method: certipy-ad find -u user@domain -p pass -dc-ip <ip> -vulnerable -stdout
    """

    name = "certipy confirms ESC8 vulnerability"
    required = False   # if certipy not available, other checks are sufficient

    def _run(self) -> CheckResult:
        rc, out, err = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-vulnerable",
            "-stdout",
        ], timeout=45)

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="certipy-ad not installed. Run: pip install certipy-ad",
            )

        combined = out + err
        lower = combined.lower()

        if "esc8" in lower:
            import re
            # Extract CA name and web enrollment URL — skip error/info lines
            ca_match = re.search(r"CA Name[\s]*:[\s]*([^\r\n]+)", combined, re.IGNORECASE)

            url_match = re.search(r"Web Enrollment[\s]*:[\s]*(https?://[^\s\r\n]+)", combined, re.IGNORECASE)

            ca_name = ca_match.group(1).strip() if ca_match else None
            enroll_url = url_match.group(1).strip() if url_match else None

            parts = []
            if ca_name:
                parts.append(f"CA: {ca_name}")
            if enroll_url:
                parts.append(f"Enrollment URL: {enroll_url}")
            if not parts:
                parts.append("ESC8 confirmed")

            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"certipy confirmed ESC8 — {'; '.join(parts)}. "
                    "Note: certipy queries the forest-wide CA — verify the CA host is "
                    "reachable from this domain if targeting a child/sibling domain."
                ),
                raw=combined[:600],
            )
        if "vulnerable" in lower and "web enrollment" in lower:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    "certipy found vulnerable web enrollment (ESC8 likely). "
                    "Note: verify CA host is reachable in the target domain."
                ),
                raw=combined[:400],
            )
        if "no vulnerable" in lower:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="certipy found no vulnerable configurations (ESC8 not present).",
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail="certipy ran but ESC8 status unclear. Review output manually.",
            raw=combined[:400],
        )


class HttpsEpaCheck(BaseCheck):
    """
    Optional: if only HTTPS certsrv is available, EPA (Extended Protection for Auth)
    must be disabled for relay to succeed.

    This is an informational check.
    """

    name = "HTTPS certsrv: EPA disabled (optional HTTPS relay path)"
    required = False

    def _run(self) -> CheckResult:
        for host in self.env.all_targets:
            if not _port_open(host, 443, timeout=self.env.timeout):
                continue
            url = f"https://{host}/certsrv/"
            code, headers, body = _http_get(url, timeout=self.env.timeout)
            if code in (401, 200, 403):
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        f"HTTPS certsrv reachable on {host}. "
                        "EPA status must be checked manually: "
                        "`reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters /v ExtendedProtection`"
                    ),
                )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="No HTTPS certsrv endpoint found — check not applicable.",
        )


# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        AdcsDeployedCheck(env),
        CertsrvHttpCheck(env),
        CertsrvNtlmAuthCheck(env),
        EnrollableTemplateCheck(env),
        RequestDispositionCheck(env),
        ESC8CertipyCheck(env),
        HttpsEpaCheck(env),
        CoercionAvailabilityCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → ADCS (ESC8)"
