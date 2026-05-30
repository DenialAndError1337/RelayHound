"""
SMB prerequisite checks for NTLM Relay → SMB (secretsdump).

Prerequisites:
  [REQ]  SMB signing disabled on ≥1 non-DC target
  [REQ]  NTLMv2 accepted (NTLMv1 not forced — relay still works with NTLMv2)
  [OPT]  Guest / null session allowed (broadens attack surface)
  [OPT]  At least one target is NOT a DC (DCs enforce signing by default)
"""
from __future__ import annotations
import socket
import subprocess
from typing import Optional

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv


# ── helpers ────────────────────────────────────────────────────────────────

def _run_nxc(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run netexec (nxc) and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            ["nxc"] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        # Try crackmapexec as fallback
        try:
            result = subprocess.run(
                ["crackmapexec"] + args,
                capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError:
            return -1, "", "nxc/crackmapexec not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def _impacket_smbclient(target: str, timeout: int = 10) -> tuple[int, str, str]:
    """Quick SMB null-session test via smbclient."""
    try:
        result = subprocess.run(
            ["smbclient", "-N", "-L", f"//{target}", "--timeout", str(timeout)],
            capture_output=True, text=True, timeout=timeout + 5
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "smbclient not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


# ── individual checks ──────────────────────────────────────────────────────

class SmbSigningCheck(BaseCheck):
    """
    SMB signing must be disabled (or not required) on at least one target
    for relay to work. DCs always have signing required; member servers often don't.

    Method: nxc smb <targets> --gen-relay-list /dev/stdout
            OR parse nxc smb output for 'signing:False'
    """

    name = "SMB signing disabled on ≥1 target"

    def __init__(self, env: TargetEnv):
        super().__init__(env)

    def _run(self) -> CheckResult:
        targets = self.env.smb_targets()
        unsigned_hosts: list[str] = []
        signed_hosts: list[str] = []
        errors: list[str] = []

        for target in targets:
            rc, out, err = _run_nxc(
                ["smb", target, "-u", self.env.cred.username,
                 *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                 "-d", self.env.cred.domain],
                timeout=self.env.timeout + 10,
            )
            combined = (out + err).lower()

            if rc == -1:
                errors.append(f"{target}: tool unavailable or timeout")
                continue

            # nxc output: "signing:True" or "signing:False"
            if "signing:false" in combined or "signing: false" in combined:
                unsigned_hosts.append(target)
            elif "signing:true" in combined or "signing: true" in combined:
                signed_hosts.append(target)
            else:
                errors.append(f"{target}: could not parse signing status")

        if unsigned_hosts:
            return CheckResult(
                name=self.name,
                status=Status.PASS,
                detail=(
                    f"Signing DISABLED on: {', '.join(unsigned_hosts)}. "
                    f"Relay targets available. "
                    "Tip: confirm LLMNR/NBT-NS traffic is present to enable coercion via "
                    "poisoning — run `responder -I <iface> -A` (analyze mode, passive)."
                ),
                raw=f"Signed: {signed_hosts} | Unsigned: {unsigned_hosts}",
            )
        elif not targets:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="No targets specified.")
        elif errors and not signed_hosts:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail=f"Could not determine signing status. Errors: {'; '.join(errors)}")
        else:
            return CheckResult(
                name=self.name,
                status=Status.FAIL,
                detail=(
                    f"SMB signing REQUIRED on all targets: {', '.join(signed_hosts)}. "
                    "Relay will fail — authentication will be rejected."
                ),
            )


class NtlmAuthEnabledCheck(BaseCheck):
    """
    NTLM authentication must not be disabled via GPO.
    If NTLM is blocked, relay is impossible regardless of signing.

    Method: nxc smb <dc> -u user -p pass  → look for NTLM error vs successful auth
    """

    name = "NTLM authentication enabled"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc(
            ["smb", self.env.dc_ip,
             "-u", self.env.cred.username,
             *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
             "-d", self.env.cred.domain],
            timeout=self.env.timeout + 5,
        )
        combined = out + err

        if rc == -1:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="nxc not available.")

        lower = combined.lower()
        if "ntlm" in lower and ("disabled" in lower or "blocked" in lower):
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="NTLM authentication appears to be disabled by policy.",
                raw=combined[:400],
            )
        if "status_logon_failure" in lower:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail="Authentication failed (bad creds?), but NTLM itself appears enabled.",
                raw=combined[:400],
            )
        if "pwned" in lower or "[+]" in lower or "guest" in lower.split("(")[0]:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="NTLM authentication successful — NTLM is enabled.",
            )
        # If we got any SMB response, NTLM is likely available
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail="Got SMB response; NTLM likely enabled but could not confirm auth success.",
            raw=combined[:400],
        )


class NonDcTargetCheck(BaseCheck):
    """
    At least one non-DC target should be reachable.
    DCs enforce SMB signing by default; workstations/member servers typically don't.
    """

    name = "Non-DC SMB target reachable"
    required = False   # lack of non-DC targets is a warning, not a hard block

    def _run(self) -> CheckResult:
        non_dc_targets = self.env.extra_targets
        if not non_dc_targets:
            return CheckResult(
                name=self.name,
                status=Status.WARN,
                detail=(
                    "No extra targets supplied via --extra-targets. "
                    "DC typically enforces SMB signing. "
                    "Add member servers / workstations for better relay surface."
                ),
            )

        reachable = []
        for t in non_dc_targets:
            try:
                sock = socket.create_connection((t, 445), timeout=self.env.timeout)
                sock.close()
                reachable.append(t)
            except OSError:
                pass

        if reachable:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"Non-DC targets reachable on port 445: {', '.join(reachable)}",
            )
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=f"None of the extra targets reachable on SMB: {non_dc_targets}",
        )


class NullSessionCheck(BaseCheck):
    """
    Optional: null/guest session broadens attack surface but not required for relay.
    """

    name = "Null/guest session allowed (optional)"
    required = False

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc(
            ["smb", self.env.dc_ip, "-u", "", "-p", ""],
            timeout=self.env.timeout + 5,
        )
        combined = (out + err).lower()
        if rc == -1:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="nxc not available.")
        if "guest" in combined or "anonymous" in combined or "[+]" in combined:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="Null/guest session accepted — expands enumeration surface.",
            )
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail="Null/guest session rejected (normal — not required for relay).",
        )


# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        SmbSigningCheck(env),
        NtlmAuthEnabledCheck(env),
        NonDcTargetCheck(env),
        NullSessionCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → SMB (secretsdump)"
