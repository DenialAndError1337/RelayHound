"""
Shared helpers and reusable check classes for RelayHound modules.

Candidates for future consolidation here:
  - _run_nxc_ldap   (duplicated in ldap_rbcd, ldap_shadowcreds, adcs, laps, ...)
  - _ldap_connect   (duplicated in ldap_rbcd, ldap_shadowcreds, laps, ...)
  - _port_open      (duplicated in kerberos, adcs, esc11, ...)
  - _http_get       (duplicated in kerberos, adcs, webdav, ...)
  - _run_bloodyad   (duplicated in ldap_rbcd, ldap_shadowcreds, laps, ...)
  - _dns_srv_ips    (duplicated in smb, startup)
  - EnrollableTemplateCheck (duplicated in adcs, esc11)
"""
from __future__ import annotations
import subprocess
from dataclasses import dataclass

from .checks.base import BaseCheck, CheckResult, Status
from .config import TargetEnv


# ── internal helpers ────────────────────────────────────────────────────────

def _run_nxc_smb(args: list[str], env: TargetEnv, timeout: int = 30) -> tuple[int, str, str]:
    """Run `nxc smb <args>`, falling back to crackmapexec. Returns (rc, stdout, stderr)."""
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


# ── coerce_plus result dataclass ─────────────────────────────────────────────

@dataclass
class CoercePlusResult:
    """Per-host result from coerce_plus."""
    host: str
    printerbug:   bool = False
    petitpotam:   bool = False
    dfscoerce:    bool = False
    shadowcoerce: bool = False
    mseven:       bool = False
    tool_unavailable: bool = False
    raw_output:   str  = ""

    @property
    def any_method(self) -> bool:
        return any([self.printerbug, self.petitpotam,
                    self.dfscoerce, self.shadowcoerce, self.mseven])

    def method_summary(self) -> str:
        """Return a compact per-method status string, e.g. 'PrinterBug ✓  PetitPotam ✗ ...'"""
        methods = [
            ("PrinterBug",   self.printerbug),
            ("PetitPotam",   self.petitpotam),
            ("DFSCoerce",    self.dfscoerce),
            ("ShadowCoerce", self.shadowcoerce),
            ("MSEven",       self.mseven),
        ]
        return "  ".join(f"{name} {'✓' if ok else '✗'}" for name, ok in methods)


def _run_coerce_plus(host: str, env: TargetEnv) -> CoercePlusResult:
    """
    Run `nxc smb <host> --module coerce_plus` (detection mode — no LISTENER).
    Never passes LISTENER= — that would trigger actual coercion.

    Real nxc output format (confirmed against GOAD):
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, DFSCoerce
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, PetitPotam
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, PrinterBug
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, PrinterBug
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, MSEven

    Non-vulnerable methods produce NO output — absence means not vulnerable.
    PrinterBug may appear twice (two RPC endpoints); handled by set membership.
    """
    result = CoercePlusResult(host=host)

    cred_args = (
        ["-H", env.cred.nt_hash] if env.cred.nt_hash
        else ["-p", env.cred.password]
    )
    base_args = [
        host,
        "-u", env.cred.username,
        *cred_args,
        "-d", env.domain,
        "--module", "coerce_plus",
    ]

    rc, out, err = _run_nxc_smb(base_args, env, timeout=env.timeout + 20)

    if rc == -1 and "nxc not found" in err:
        result.tool_unavailable = True
        return result

    result.raw_output = out + err

    # Only parse lines that start with the COERCE_PLUS tag — ignore SMB auth lines.
    # Format: "COERCE_PLUS <ip>  <port>  <hostname>  VULNERABLE, <MethodName>"
    # Non-vulnerable methods produce no output at all — absence = not vulnerable.
    # Method names are title-case in output; we compare lower-case.
    # PrinterBug may appear twice (two RPC endpoints) — set membership deduplicates.
    vulnerable_methods: set[str] = set()
    for line in (out + err).splitlines():
        if not line.lstrip().startswith("COERCE_PLUS"):
            continue
        if "vulnerable" not in line.lower():
            continue
        # Extract method name from the trailing field after the last comma.
        # e.g. "VULNERABLE, PrinterBug" → "printerbug"
        if "," in line:
            method_field = line.split(",")[-1].strip().lower()
            vulnerable_methods.add(method_field)

    result.printerbug   = "printerbug"   in vulnerable_methods
    result.petitpotam   = "petitpotam"   in vulnerable_methods
    result.dfscoerce    = "dfscoerce"    in vulnerable_methods
    result.shadowcoerce = "shadowcoerce" in vulnerable_methods
    result.mseven       = "mseven"       in vulnerable_methods

    return result


# ── CoercionAvailabilityCheck ────────────────────────────────────────────────

class CoercionAvailabilityCheck(BaseCheck):
    """
    Checks which SMB-based coercion methods are available across all in-scope
    targets using `nxc smb --module coerce_plus` (detection mode only —
    LISTENER is never set, so no authentication is actually triggered).

    Methods covered: PrinterBug (MS-RPRN), PetitPotam (MS-EFSRPC),
    DFSCoerce (MS-DFSNM), ShadowCoerce (MS-FSRVP), MSEven.

    Note: WebDAV/HTTP coercion paths (PetitPotam over WebDAV, mitm6) are NOT
    covered by coerce_plus — those are handled by the separate WebClient check.

    required=False: if no method is detected the attack may still be possible
    via out-of-band coercion; result is PARTIAL, not NOT VIABLE.
    """

    name = "SMB coercion methods available (coerce_plus)"
    required = False

    def _run(self) -> CheckResult:
        results: list[CoercePlusResult] = []
        for host in self.env.all_targets:
            results.append(_run_coerce_plus(host, self.env))

        if results and results[0].tool_unavailable:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="nxc not found — install NetExec to enable coerce_plus checks.",
            )

        vulnerable    = [r for r in results if r.any_method]
        none_detected = [r for r in results if not r.any_method and not r.tool_unavailable]

        if not vulnerable:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    "coerce_plus found no vulnerable SMB coercion methods on any target "
                    f"({', '.join(r.host for r in results)}). "
                    "Out-of-band coercion (LLMNR/NBT-NS poisoning, mitm6, social engineering) "
                    "may still be possible. WebDAV/HTTP paths checked separately."
                ),
            )

        lines = []
        for r in vulnerable:
            hostname = self.env.hostname_map.get(r.host, r.host)
            lines.append(f"{hostname} ({r.host}): {r.method_summary()}")

        no_methods = [
            f"{self.env.hostname_map.get(r.host, r.host)} ({r.host})"
            for r in none_detected
        ]
        summary = "; ".join(lines)
        if no_methods:
            summary += f". No methods found on: {', '.join(no_methods)}"

        return CheckResult(
            name=self.name, status=Status.PASS,
            detail=summary,
        )
