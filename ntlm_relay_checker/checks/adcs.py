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
from ..utils import CoercionAvailabilityCheck, adcs_enrollment_verdict


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
    AD CS must be deployed in the *target* domain for ESC8 relay to have a
    certsrv endpoint to relay to.

    Detection strategy — authoritative signal first:

      1. LDAP (primary): search for pKIEnrollmentService objects under
         CN=Enrollment Services,CN=Public Key Services,CN=Services,<configNC>.
         That object is the canonical Enterprise-CA registration — the same
         signal certipy/Certify key on. The Configuration NC is read from
         RootDSE (configurationNamingContext), NOT built from the domain name:
         in a child domain the Configuration partition lives at the forest
         root, so constructing it from the local domain yields a spurious
         noSuchObject and a false "no ADCS" verdict.
           >= 1 entry              -> PASS  (CA registered; still true when the
                                     CA host VM is offline — the object persists)
           0 entries / noSuchObject -> FAIL  (no Enterprise CA in this domain)
           bind/query inconclusive  -> fall through to (2)

      2. nxc / certipy (fallback enrichment): consulted only when the LDAP
         probe could not give a definitive answer (e.g. NTLM-over-LDAP refused).
         Trusted for a best-effort PASS only — their output strings are
         version-dependent, so a non-match yields SKIP, never a fragile FAIL.
    """

    name = "AD CS deployed in domain"
    breaks_on_fail = True  # all downstream checks are pointless without ADCS

    _LDAP_NO_SUCH_OBJECT = 32  # RFC 4511 resultCode for noSuchObject

    def _ldap_verdict(self) -> "CheckResult | None":
        """
        Authoritative pKIEnrollmentService probe. Delegates to the shared
        utils.adcs_enrollment_verdict() (which also reads/writes the
        cross-module cache), and adapts its tri-state result:
          PASS/FAIL -> definitive CheckResult
          SKIP      -> None, so _run() falls back to nxc/certipy enrichment
        """
        v = adcs_enrollment_verdict(self.env)
        if v.status in (Status.PASS, Status.FAIL):
            return CheckResult(name=self.name, status=v.status, detail=v.detail)
        return None

    def _run(self) -> CheckResult:
        # 1. Authoritative LDAP probe.
        verdict = self._ldap_verdict()
        if verdict is not None:
            return verdict

        # 2. Fallback enrichment — only reached when LDAP was inconclusive.
        #    Trusted for PASS, never for FAIL.
        import re
        rc, out, err = _run_nxc_ldap(["--module", "adcs"], self.env)
        combined = out + err
        if rc != -1 and combined.strip():
            ca_hosts = re.findall(
                r"Found PKI Enrollment Server:[\s]*([^\s\n\r]+)",
                combined, re.IGNORECASE)
            ca_names = re.findall(
                r"Found CN:[\s]*([^\s\n\r]+)", combined, re.IGNORECASE)
            if ca_names or ca_hosts:
                parts = []
                if ca_names:
                    parts.append(f"CA: {', '.join(ca_names[:2])}")
                if ca_hosts:
                    parts.append(f"Host: {', '.join(ca_hosts[:2])}")
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=f"AD CS deployed — {'; '.join(parts)} (nxc adcs).",
                    raw=combined[:400],
                )

        rc2, out2, err2 = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash
               else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ], timeout=30)
        combined2 = (out2 + err2).lower()
        if rc2 != -1 and ("certificate authorit" in combined2 or "ca name" in combined2):
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="AD CS CA found via certipy.",
                raw=(out2 + err2)[:400],
            )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=("Could not determine AD CS presence. The LDAP bind to the "
                    "DC may have been refused (NTLM-over-LDAP disabled?), and "
                    "no tool confirmed a CA. Try: nxc ldap <dc> --module adcs "
                    "or certipy-ad find -stdout."),
        )

    def run(self) -> CheckResult:
        result = super().run()
        # Write to shared cache so esc11 and kerberos modules can skip the
        # repeat query if ADCS is confirmed absent (or present).
        if result.status == Status.FAIL:
            self.env.shared_cache["adcs_deployed"] = False
        elif result.status == Status.PASS:
            self.env.shared_cache["adcs_deployed"] = True
        return result


class CertsrvHttpCheck(BaseCheck):
    """
    The /certsrv endpoint must be reachable for ESC8. NTLM relay over plain HTTP
    (port 80) is the cleanest path; relay over HTTPS (443) is also viable when
    EPA is not enforced on the binding (see HttpsEpaCheck). So HTTPS-only is NOT
    a hard failure — it's a WARN deferring to the EPA check. We FAIL only when no
    certsrv endpoint is reachable on either port.

    Method: GET http(s)://<ca>/certsrv/ → 401 with WWW-Authenticate: NTLM
    """

    name = "Web enrollment endpoint reachable (HTTP or HTTPS)"

    def _run(self) -> CheckResult:
        http_targets  = [h for h in self.env.all_targets
                         if _port_open(h, 80, timeout=self.env.timeout)]
        https_targets = [h for h in self.env.all_targets
                         if _port_open(h, 443, timeout=self.env.timeout)]

        if not http_targets and not https_targets:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "Neither port 80 nor 443 reachable on any target. "
                    "ESC8 requires a reachable certsrv web-enrollment endpoint."
                ),
            )

        # HTTP path: look for 401 + NTLM challenge (ideal relay target).
        ntlm_endpoints  = []
        other_http      = []
        for host in http_targets:
            code, headers, body = _http_get(f"http://{host}/certsrv/", timeout=self.env.timeout)
            auth = headers.get("WWW-Authenticate", "").upper()
            if code == 401 and "NTLM" in auth:
                ntlm_endpoints.append(host)
            elif code in (200, 401, 403):
                other_http.append(f"{host}({code})")

        if ntlm_endpoints:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"/certsrv/ returns 401+NTLM over HTTP on: {', '.join(ntlm_endpoints)}. "
                    "Ideal relay target for ESC8."
                ),
            )

        # HTTPS path: confirm certsrv answers over TLS. Relay viability then
        # depends on EPA (HttpsEpaCheck), so this is a WARN, not a hard pass/fail.
        https_certsrv = []
        for host in https_targets:
            code, headers, body = _http_get(f"https://{host}/certsrv/", timeout=self.env.timeout)
            if code in (200, 401, 403):
                https_certsrv.append(f"{host}({code})")

        if https_certsrv:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"/certsrv/ reachable over HTTPS on: {', '.join(https_certsrv)} "
                    "(no plain-HTTP NTLM endpoint found). ESC8 over HTTPS is viable only "
                    "if EPA is not enforced — see the HTTPS EPA check."
                ),
            )

        if other_http:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"/certsrv/ found over HTTP without an NTLM challenge: {', '.join(other_http)}. "
                    "May use Kerberos-only auth or redirect to HTTPS."
                ),
            )

        reached = http_targets + https_targets
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=(
                f"Port 80/443 open on {', '.join(reached)} but /certsrv/ not found. "
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
