"""
SMB prerequisite checks for NTLM Relay → SMB (secretsdump).

Prerequisites:
  [REQ]  SMB signing disabled on ≥1 non-DC target
  [REQ]  NTLMv2 accepted (NTLMv1 not forced — relay still works with NTLMv2)
  [OPT]  Guest / null session allowed (broadens attack surface)
  [OPT]  At least one target is NOT a DC (DCs require signing by default, but it can be disabled)
"""
from __future__ import annotations
import re
import socket
import subprocess
from typing import Optional

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv
from ..utils import _dns_srv_ips


# ── helpers ────────────────────────────────────────────────────────────────

def _run_nxc(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run netexec (nxc) and return (returncode, stdout, stderr)."""
    from ..utils import _subprocess_run_with_retry
    try:
        return _subprocess_run_with_retry(["nxc"] + args, timeout)
    except FileNotFoundError:
        try:
            return _subprocess_run_with_retry(["crackmapexec"] + args, timeout)
        except FileNotFoundError:
            return -1, "", "nxc/crackmapexec not found"


def _nxc_smb_reached(output: str) -> bool:
    """True if nxc's SMB output shows it actually negotiated with the host.

    nxc/crackmapexec only print their banner fields (name/domain/signing/SMBv1)
    and a [+]/[-] or logon-failure auth result *after* a successful TCP+SMB
    negotiation. On an unreachable host (no machine on that IP, or 445 filtered)
    the tool still exits cleanly but prints only a connection error — so the
    absence of these markers means "host not reached", which must read as SKIP
    (un-testable), not as a WARN/inconclusive "we got a response".
    """
    low = output.lower()
    return ("signing:" in low or "(name:" in low or "(domain:" in low
            or "[+]" in low or "pwned" in low or "status_logon_failure" in low)


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


def _parse_nxc_domain(nxc_output: str) -> Optional[str]:
    """
    Extract the domain from nxc's SMB banner line.
    nxc format: ... (domain:north.sevenkingdoms.local) ...
    """
    m = re.search(r'\(domain:([^)]+)\)', nxc_output, re.IGNORECASE)
    return m.group(1).strip().lower() if m else None


def _is_dc(host: str, nxc_output: str, known_dc_ips: set[str],
           dc_ip: str, timeout: int) -> bool:
    """
    Determine whether host is a DC using two attribute-based signals:

      1. env.dc_ips membership — populated at startup via LDAP
         SERVER_TRUST_ACCOUNT (UAC bit 0x2000) query.

      2. DNS SRV — query _ldap._tcp.dc._msdcs.<domain> against the AD
         DNS server (dc_ip). Only DCs register this SRV record via Netlogon.
         The domain is parsed from the nxc SMB banner (domain:X), so
         cross-domain DCs are handled correctly without any prior knowledge
         of the forest topology.

    Never uses hostname patterns.
    """
    if host in known_dc_ips:
        return True
    domain = _parse_nxc_domain(nxc_output)
    if not domain:
        return False
    dc_ips_from_srv = _dns_srv_ips(domain, dns_server=dc_ip, timeout=timeout)
    return host in dc_ips_from_srv


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

        banners: dict[str, str] = self.env.shared_cache.setdefault("smb_banners", {})

        for target in targets:
            rc, out, err = _run_nxc(
                ["smb", target, "-u", self.env.cred.username,
                 *(((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password]))),
                 "-d", self.env.cred.domain],
                timeout=self.env.timeout + 10,
            )
            raw = out + err
            combined = raw.lower()

            if rc == -1:
                errors.append(f"{target}: tool unavailable or timeout")
                continue

            if not _nxc_smb_reached(raw):
                errors.append(f"{target}: no SMB response (host unreachable or 445 filtered)")
                continue

            # Stash raw (case-preserved) banner for downstream checks (e.g. SMBv1 detection)
            banners[target] = raw

            # nxc output: "signing:True" or "signing:False"
            if "signing:false" in combined or "signing: false" in combined:
                unsigned_hosts.append(target)
            elif "signing:true" in combined or "signing: true" in combined:
                signed_hosts.append(target)
            else:
                errors.append(f"{target}: banner present but signing field unparseable")

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
             *(((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password]))),
             "-d", self.env.cred.domain],
            timeout=self.env.timeout + 5,
        )
        combined = out + err

        if rc == -1:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="nxc not available.")

        lower = combined.lower()
        if not _nxc_smb_reached(combined):
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=f"No SMB response from {self.env.dc_ip} (host unreachable or "
                       "445 filtered) — could not test NTLM.",
                raw=combined[:400],
            )
        # NTLM disabled / blocked on the DC → relay is impossible, so this
        # REQUIRED gate must FAIL (not WARN — a WARN here leaves the relay
        # module free to render VIABLE against a DC where relay cannot work,
        # a cardinal-rule false positive). Two real-world surfaces, both
        # confirmed against a "Restrict NTLM" DC in GOAD:
        #   • netexec resolves the SMB negotiation to "(NTLM:False)" in its host
        #     banner when the DC does not offer NTLM (e.g. "Restrict NTLM:
        #     Incoming NTLM traffic = Deny all"); the auth line then fails with
        #     the generic STATUS_NOT_SUPPORTED rather than a named NTLM status,
        #     so we key off the explicit "(NTLM:False)" flag, not that status.
        #   • impacket/other tooling surface the wire status verbatim as
        #     STATUS_NTLM_BLOCKED (0xC0000418) — e.g. the domain-wide "NTLM
        #     authentication in this domain" pass-through block.
        # Anchor on those specific forms, never a loose "ntlm"+"disabled"/
        # "blocked" co-occurrence (nxc output carries "ntlm" in its banner and
        # unrelated "disabled"/"blocked" lines, which false-FAILed this gate).
        if (re.search(r"ntlm:\s*false", lower)
                or "status_ntlm_blocked" in lower
                or "0xc0000418" in lower):
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="NTLM authentication is disabled/blocked on the DC "
                       "(Restrict NTLM policy) — NTLM relay is not possible against it.",
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
    This check reports role classification and reachability only.
    Actual signing status for all hosts, including DCs, is determined by SmbSigningCheck.

    DC classification uses two attribute-based signals — never hostname patterns:

      1. env.dc_ips membership — populated at startup via LDAP
         SERVER_TRUST_ACCOUNT (UAC bit 0x2000) query.

      2. DNS SRV records — _ldap._tcp.dc._msdcs.<domain> is registered
         exclusively by the Netlogon service on DCs. The domain is parsed
         from the nxc SMB banner (domain:X), so cross-domain and cross-forest
         DCs passed via --extra-targets are correctly identified without
         needing --dc-ips or any prior topology knowledge.
         Queries are sent to dc_ip (the AD-integrated DNS server) so that
         internal zones are resolvable.

    extra_targets is NOT used as a proxy for "non-DC" — a user may pass a
    DC via --extra-targets (e.g. a DC in a trusted domain), which would be
    misclassified under the old logic.
    """

    name = "Non-DC SMB target reachable"
    required = False   # lack of non-DC targets is a warning, not a hard block

    def _run(self) -> CheckResult:
        all_targets = self.env.all_targets
        if not all_targets:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No targets to evaluate.",
            )

        known_dc_ips = set(self.env.dc_ips)
        member_reachable: list[str] = []
        member_unreachable: list[str] = []
        dc_reachable: list[str] = []
        nxc_unavailable = False

        for host in all_targets:
            # Null-auth call: gets the SMB banner (signing status, domain name)
            # without requiring valid credentials — works for cross-domain hosts too.
            rc, out, err = _run_nxc(
                ["smb", host, "-u", "", "-p", ""],
                timeout=self.env.timeout + 10,
            )

            if rc == -1:
                nxc_unavailable = True
                # Fall back to a plain port check so we still report reachability
                try:
                    sock = socket.create_connection((host, 445), timeout=self.env.timeout)
                    sock.close()
                    # Can't classify role without nxc — use dc_ips membership only
                    if host in known_dc_ips:
                        dc_reachable.append(host)
                    else:
                        member_reachable.append(host)
                except OSError:
                    if host not in known_dc_ips:
                        member_unreachable.append(host)
                continue

            combined = out + err
            combined_lower = combined.lower()
            is_reachable = "signing" in combined_lower or "[*]" in combined or "[+]" in combined

            if _is_dc(host, combined, known_dc_ips, self.env.dc_ip, self.env.timeout):
                if is_reachable:
                    dc_reachable.append(host)
            elif is_reachable:
                member_reachable.append(host)
            else:
                member_unreachable.append(host)

        if member_reachable:
            dc_note = (
                f" DC(s) also in scope: {', '.join(dc_reachable)}."
                if dc_reachable else ""
            )
            nxc_note = " (nxc unavailable — role detection via dc_ips only)" if nxc_unavailable else ""
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Non-DC target(s) reachable on SMB: {', '.join(member_reachable)}."
                    f"{dc_note}{nxc_note}"
                ),
            )

        if not self.env.extra_targets:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    "No extra targets supplied via --extra-targets — only DC(s) in scope. "
                    "Add member servers / workstations for better relay surface."
                ),
            )

        if dc_reachable and not member_reachable and not member_unreachable:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"All extra targets identified as DCs: {', '.join(dc_reachable)}. "
                    "No member servers in scope — add workstations or member servers via --extra-targets."
                ),
            )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=(
                "No non-DC targets reachable on SMB port 445. "
                + (f"Unreachable: {', '.join(member_unreachable)}. " if member_unreachable else "")
                + "Verify network connectivity or add reachable member servers via --extra-targets."
            ),
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
        if not _nxc_smb_reached(out + err):
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No SMB response (host unreachable or 445 filtered) — "
                       "could not test null/guest session.",
            )
        # A genuine empty-credential (null / anonymous) session is confirmed
        # ONLY by netexec's "[+]" success marker — it prints "[+] …:" and
        # appends "(Guest)" when the server accepted the bind as guest. The
        # previous gate also ORed bare "guest"/"anonymous" substrings, which
        # match a *negative* mention (a "(Guest:False)" banner flag, or an error
        # like "anonymous logon not allowed") and would false-PASS. required is
        # False so this never gated a relay verdict, but the finding must still
        # be accurate. Guest vs anonymous is a detail-text distinction only.
        if "[+]" in combined:
            as_guest = "(guest)" in combined
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=("Null session accepted (guest-level) — expands enumeration surface."
                        if as_guest else
                        "Null/anonymous session accepted — expands enumeration surface."),
            )
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail="Null/guest session rejected (normal — not required for relay).",
        )


class SmbV1DetectedCheck(BaseCheck):
    """
    Hygiene/context check: flag any hosts still advertising SMBv1.

    SMBv1 is the protocol EternalBlue (MS17-010) operates over and has been
    disabled by default since Windows Server 2016 / Windows 10 1709.
    Its presence is worth flagging in the report regardless of relay viability,
    but it has no bearing on whether the secretsdump relay succeeds — that works
    on SMBv2/v3 just as well.

    This check is purely informational and must never affect the module verdict:
      WARN = SMBv1 found on ≥1 host (hygiene finding — visible in reports)
      PASS = all scanned hosts have SMBv1 disabled (clean)
      SKIP = no banner data available

    WARN and PASS are both verdict-neutral for optional checks. Do not return
    FAIL here — an optional FAIL downgrades the verdict to PARTIAL.

    Data source: shared_cache["smb_banners"] populated by SmbSigningCheck from
    the nxc SMB banner line, which includes (SMBv1:True|False). No additional
    network calls are made.
    """

    name = "SMBv1 detection (hygiene)"
    required = False

    def _run(self) -> CheckResult:
        # Every return uses the stable class name (self.name) so the result's
        # name matches the fingerprinted check identity. The varying specifics
        # (which hosts, how many) live in `detail`, not in the name — a name that
        # changes with the outcome would make the JSON/report `name` field
        # nondeterministic and is a footgun for any name-keyed consumer.
        banners: dict[str, str] = self.env.shared_cache.get("smb_banners", {})

        if not banners:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No SMB banner data available (nxc unavailable or no targets scanned).",
            )

        smbv1_hosts: list[str] = []
        smbv1_off_hosts: list[str] = []

        for host, raw in banners.items():
            m = re.search(r"\(SMBv1:(True|False)\)", raw, re.IGNORECASE)
            if m:
                if m.group(1).lower() == "true":
                    smbv1_hosts.append(host)
                else:
                    smbv1_off_hosts.append(host)

        if not smbv1_hosts and not smbv1_off_hosts:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="SMBv1 field not present in any banner (older nxc version?).",
            )

        if smbv1_hosts:
            off_note = (f" Clean: {', '.join(smbv1_off_hosts)}."
                        if smbv1_off_hosts else "")
            return CheckResult(
                name=self.name,
                status=Status.WARN,
                detail=(
                    f"SMBv1 ENABLED on {len(smbv1_hosts)} host(s): {', '.join(smbv1_hosts)}. "
                    "Legacy protocol — EternalBlue (MS17-010) attack surface present. "
                    f"Disable via: Set-SmbServerConfiguration -EnableSMB1Protocol $false.{off_note}"
                ),
            )

        return CheckResult(
            name=self.name, status=Status.PASS,
            detail=f"SMBv1 disabled on all scanned hosts: {', '.join(smbv1_off_hosts)}.",
        )


# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        SmbSigningCheck(env),
        NtlmAuthEnabledCheck(env),
        NonDcTargetCheck(env),
        NullSessionCheck(env),
        SmbV1DetectedCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → SMB (secretsdump)"
