"""
ESC11 prerequisite checks for NTLM Relay → ADCS (RPC/ICertPassage).

ESC11 abuses the ICertPassage RPC interface exposed by ADCS CAs.
Unlike ESC8 (HTTP), this relay uses the RPC transport — meaning EPA on
the certsrv HTTP endpoint is irrelevant. If the CA's RPC interface does
not enforce encryption/signing, NTLM credentials relayed over it can be
used to request certificates.

Prerequisites:
  [REQ]  ADCS deployed in the domain
  [REQ]  CA RPC interface reachable (port 135 + dynamic RPC ports)
  [REQ]  IF_ENFORCEENCRYPTICERTREQUEST flag NOT set on the CA
         (i.e. the CA does not require encrypted RPC connections)
  [REQ]  Request Disposition set to Issue (automatic certificate approval)
  [REQ]  Enrollable certificate template with Client Authentication EKU exists
         and grants enrollment rights to machine accounts or Domain Controllers
  [OPT]  certipy confirms ESC11 vulnerability
  [OPT]  SMB signing disabled on ≥1 target (to coerce relay via SMB)
  [OPT]  Coercible machine account exists in same domain as CA
         (any domain-joined machine with PrinterBug/PetitPotam available)

References:
  https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/
"""
from __future__ import annotations
import re
import socket
import subprocess

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv


# ── helpers ────────────────────────────────────────────────────────────────

def _port_open(host: str, port: int, timeout: int = 5) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


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


def _run_certipy(args: list[str], timeout: int = 45) -> tuple[int, str, str]:
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
    AD CS must be deployed. Same check as ESC8 module.
    Method: nxc ldap --module adcs
    """

    name = "AD CS deployed in domain"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "adcs"], self.env)
        combined = out + err
        lower = combined.lower()

        if rc != -1 and combined.strip():
            if "nosuchobject" in lower or ("unexpected exception" in lower and "enrollment" in lower):
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail="No AD CS enrollment services found in this domain.",
                    raw=combined[:400],
                )
            ca_names = re.findall(r"Found CN:[\s]*([^\s\n\r]+)", combined, re.IGNORECASE)
            ca_hosts = re.findall(r"Found PKI Enrollment Server:[\s]*([^\s\n\r]+)",
                                  combined, re.IGNORECASE)
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

        # Fallback: certipy
        rc2, out2, err2 = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ])
        combined2 = (out2 + err2).lower()
        if rc2 != -1:
            if "certificate authorit" in combined2 or "ca name" in combined2:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="AD CS CA found via certipy.",
                )
            if "no certificate" in combined2:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail="certipy found no CA in the domain.",
                )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="Could not query for AD CS. Try: nxc ldap <dc> --module adcs",
        )


class CaRpcReachableCheck(BaseCheck):
    """
    The CA's RPC interface must be reachable. ICertPassage is exposed via
    MS-ICPR over RPC — port 135 (endpoint mapper) must be open, and the
    CA service must be listening.

    Method: port 135 check on all targets + CA host specifically.
    """

    name = "CA RPC interface reachable (port 135)"

    def _run(self) -> CheckResult:
        reachable = []
        for host in self.env.all_targets:
            if _port_open(host, 135, timeout=self.env.timeout):
                reachable.append(host)

        if reachable:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Port 135 (RPC endpoint mapper) open on: {', '.join(reachable)}. "
                    "ICertPassage RPC interface reachable for ESC11 relay."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=(
                "Port 135 not reachable on any target. "
                "ESC11 relay requires RPC access to the CA."
            ),
        )


class CaEncryptionFlagCheck(BaseCheck):
    """
    The IF_ENFORCEENCRYPTICERTREQUEST flag must NOT be set on the CA.
    When set, the CA requires encrypted/signed RPC connections, blocking
    NTLM relay to the RPC interface.

    Default: flag is NOT set (relay viable).

    Method: certipy find -vulnerable checks for ESC11.
    Manual: reg query on CA host:
      HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>
      InterfaceFlags — bit 0x200 = IF_ENFORCEENCRYPTICERTREQUEST
    """

    name = "CA RPC encryption flag not enforced (IF_ENFORCEENCRYPTICERTREQUEST not set)"

    def _run(self) -> CheckResult:
        rc, out, err = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-vulnerable",
            "-stdout",
        ])

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    "certipy-ad not installed — cannot check encryption flag. "
                    "Manual check: read InterfaceFlags registry key on CA. "
                    "Default is NOT enforced. Install: pip install certipy-ad"
                ),
            )

        combined = out + err
        lower = combined.lower()

        if "esc11" in lower:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="certipy confirmed ESC11 — CA RPC encryption not enforced.",
                raw=combined[:400],
            )
        if "enforceencrypt" in lower or "interface flags" in lower:
            if "not set" in lower or "false" in lower:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="CA InterfaceFlags: encryption not enforced — RPC relay viable.",
                    raw=combined[:400],
                )
            if "set" in lower or "true" in lower or "enforc" in lower:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "CA requires encrypted RPC (IF_ENFORCEENCRYPTICERTREQUEST set). "
                        "NTLM relay to RPC interface blocked."
                    ),
                    raw=combined[:400],
                )

        # certipy ran but no ESC11 mention — likely not vulnerable
        if "no vulnerable" in lower or "esc11" not in lower:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    "certipy did not flag ESC11. CA may enforce RPC encryption. "
                    "Verify manually: check InterfaceFlags on CA registry or run "
                    "`certipy-ad find -vulnerable -stdout` and look for ESC11."
                ),
                raw=combined[:300],
            )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="Could not determine CA RPC encryption status from certipy output.",
        )


class Esc11CertipyCheck(BaseCheck):
    """
    Run certipy find -vulnerable to confirm ESC11 directly.
    Optional — the encryption flag check above covers the same ground,
    but certipy provides a definitive confirmation.
    """

    name = "certipy confirms ESC11 vulnerability"
    required = False

    def _run(self) -> CheckResult:
        rc, out, err = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-vulnerable",
            "-stdout",
        ])

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="certipy-ad not installed. Run: pip install certipy-ad",
            )

        combined = out + err
        if "esc11" in combined.lower():
            ca_match = re.search(r"CA Name[\s]*:[\s]*([^\r\n]+)", combined, re.IGNORECASE)
            ca_name = ca_match.group(1).strip() if ca_match else "unknown"
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"certipy confirmed ESC11 on CA: {ca_name}.",
                raw=combined[:400],
            )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail="certipy did not find ESC11 — CA likely enforces RPC encryption.",
            raw=combined[:300],
        )


class SmbSigningForCoercionCheck(BaseCheck):
    """
    ESC11 relay is triggered the same way as other NTLM relay attacks —
    a victim must be coerced into authenticating. SMB signing being disabled
    on at least one host expands the coercion surface.

    Optional — coercion can also come from WebDAV, LLMNR poisoning, etc.
    """

    name = "SMB signing disabled on ≥1 target (coercion surface)"
    required = False

    def _run(self) -> CheckResult:
        unsigned = []
        for host in self.env.smb_targets():
            rc, out, err = _run_nxc(
                ["smb", host,
                 "-u", self.env.cred.username,
                 *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                 "-d", self.env.domain],
                self.env,
            )
            combined = (out + err).lower()
            if rc == -1:
                continue
            if "signing:false" in combined or "signing: false" in combined:
                unsigned.append(host)

        if unsigned:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"SMB signing disabled on: {', '.join(unsigned)}. "
                    "Relay coercion surface available."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "SMB signing enforced on all targets. "
                "Coercion still possible via WebDAV, LLMNR/NBT-NS poisoning, or PrinterBug."
            ),
        )



class EnrollableTemplateCheck(BaseCheck):
    """
    An enrollable certificate template with a suitable EKU must exist for
    ESC11 to yield a usable certificate. The relay coerces a machine account
    (typically a DC) to enroll via RPC — the template must:
      - Be published on the CA (enabled)
      - Allow machine account or Domain Controller enrollment
      - Have Client Authentication EKU (1.3.6.1.5.5.7.3.2), Smart Card Logon,
        Any Purpose (2.5.29.37.0), or no EKU (any purpose implied)

    The DomainController and Machine templates satisfy all of these by default
    and are present in every default ADCS deployment. This check matters because
    templates can be disabled or deleted.

    NOTE: duplicated from adcs.py — candidate for consolidation into utils.py.

    Method: certipy find — look for templates with Client Authentication EKU
            and enrollment rights for Domain Controllers or Domain Computers.
            LDAP fallback: query pKIEnrollmentServices and pKICertificateTemplate
            objects in the Configuration partition.
    """

    name = "Enrollable template with Client Authentication EKU exists"

    AUTH_EKUS = {
        "1.3.6.1.5.5.7.3.2",        # Client Authentication
        "1.3.6.1.4.1.311.20.2.2",   # Smart Card Logon
        "2.5.29.37.0",               # Any Purpose
        "1.3.6.1.5.2.3.4",          # PKINIT Client Auth
    }

    def _run(self) -> CheckResult:
        rc, out, err = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *(((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password]))),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ], timeout=45)

        if rc != -1:
            combined = out + err
            lower = combined.lower()
            suitable: list[str] = []
            blocks = re.split(r"(?=Template Name\s*:)", combined, flags=re.IGNORECASE)
            for block in blocks:
                name_m = re.search(r"Template Name\s*:\s*([^\r\n]+)", block, re.IGNORECASE)
                if not name_m:
                    continue
                tname = name_m.group(1).strip()

                # Skip disabled templates
                enabled_m = re.search(r"Enabled\s*:\s*(True|False)", block, re.IGNORECASE)
                if enabled_m and enabled_m.group(1).strip().lower() == "false":
                    continue

                # Client Authentication field is authoritative — do NOT search
                # the full block for "client authentication" as it appears in
                # the field label even when the value is False
                ca_m = re.search(r"Client Authentication\s*:\s*(True|False)", block, re.IGNORECASE)
                has_client_auth = ca_m and ca_m.group(1).strip().lower() == "true"

                # Scope EKU check to the Extended Key Usage section only
                eku_m = re.search(r"Extended Key Usage\s*:(.*?)(?=\n\s{4}\w|\Z)", block, re.IGNORECASE | re.DOTALL)
                eku_section = eku_m.group(1).lower() if eku_m else ""
                has_auth_eku = has_client_auth or any(eku in eku_section for eku in [
                    "smart card logon", "any purpose", "kdc authentication",
                    "1.3.6.1.5.5.7.3.2", "2.5.29.37.0",
                ])

                block_lower = block.lower()
                has_machine_enroll = any(term in block_lower for term in [
                    "domain controllers", "domain computers",
                    "enterprise domain controllers",
                    "authenticated users", "domain users", "everyone",
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
            if "template name" in lower:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "No certificate template found that allows machine/DC enrollment "
                        "with Client Authentication EKU. "
                        "ESC11 relay will not yield a usable certificate without a suitable template."
                    ),
                    raw=combined[:400],
                )

        # Fallback: LDAP query for published templates
        try:
            import ldap3
            from ldap3 import Server, Connection, NTLM, SUBTREE
            server = ldap3.Server(self.env.dc_ip, connect_timeout=self.env.timeout)
            auth_pw = (
                f"aad3b435b51404eeaad3b435b51404ee:{self.env.cred.nt_hash.split(':')[-1]}"
                if self.env.cred.nt_hash else self.env.cred.password
            )
            conn = Connection(
                server, user=self.env.cred.upn, password=auth_pw,
                authentication=NTLM, auto_bind=True,
            )
            config_dn = "CN=Configuration," + ",".join(
                f"DC={p}" for p in self.env.domain.split(".")
            )
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
                        "ESC11 relay will not yield a usable certificate."
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


class RequestDispositionCheck(BaseCheck):
    """
    The CA must be configured to automatically issue certificates
    (Request Disposition = Issue). If manual approval is required,
    the relay will produce a pending request instead of a certificate.

    This is the same requirement as ESC8 — both attacks need automatic issuance.

    Method: certipy find output — look for "Request Disposition : Issue"
            in the CA properties section.
    """

    name = "CA Request Disposition set to Issue (auto-approve)"

    def _run(self) -> CheckResult:
        rc, out, err = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ])

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    "certipy-ad not installed — cannot check Request Disposition. "
                    "Verify manually: certipy output should show "
                    "'Request Disposition : Issue' under the CA properties."
                ),
            )

        combined = out + err
        lower = combined.lower()

        # certipy output: "Request Disposition        : Issue" or "Pending"
        import re
        m = re.search(r"request\s+disposition\s*:\s*(\w+)", combined, re.IGNORECASE)
        if m:
            disposition = m.group(1).strip().lower()
            if disposition == "issue":
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        "Request Disposition = Issue — CA automatically approves requests. "
                        "Relayed certificate request will be issued immediately."
                    ),
                )
            else:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        f"Request Disposition = {disposition.title()} — "
                        "CA requires manual approval. "
                        "Relay will produce a pending request, not a usable certificate."
                    ),
                )

        # certipy ran but no disposition found — check for any CA output
        if "certificate authorit" in lower or "ca name" in lower:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    "CA found but Request Disposition not parsed from certipy output. "
                    "Verify manually: look for 'Request Disposition' in certipy output. "
                    "Default in AD is Issue (automatic approval)."
                ),
                raw=combined[:400],
            )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="Could not check Request Disposition — no CA found in certipy output.",
        )

# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        AdcsDeployedCheck(env),
        CaRpcReachableCheck(env),
        CaEncryptionFlagCheck(env),
        EnrollableTemplateCheck(env),
        RequestDispositionCheck(env),
        Esc11CertipyCheck(env),
        SmbSigningForCoercionCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → ADCS (ESC11 / RPC)"
