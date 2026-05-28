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
        cmd = ["nxc", "ldap", env.dc_ip,
               "-u", env.cred.username,
               "-p", env.cred.password,
               "-d", env.domain] + args
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
            "-p", self.env.cred.password,
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
            "-p", self.env.cred.password,
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
            "-p", self.env.cred.password,
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
                 "-p", self.env.cred.password,
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
            "-p", self.env.cred.password,
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
        RequestDispositionCheck(env),
        Esc11CertipyCheck(env),
        SmbSigningForCoercionCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → ADCS (ESC11 / RPC)"
