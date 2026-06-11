"""
SMB prerequisite checks for NTLM Relay → SMB (secretsdump).

Prerequisites:
  [REQ]  SMB signing disabled on ≥1 non-DC target
  [REQ]  NTLMv2 accepted (NTLMv1 not forced — relay still works with NTLMv2)
  [OPT]  Guest / null session allowed (broadens attack surface)
  [OPT]  At least one target is NOT a DC (DCs require signing by default, but it can be disabled)
"""
from __future__ import annotations
import os
import re
import socket
import struct
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


def _dns_srv_ips(domain: str, dns_server: str, timeout: int = 3) -> set[str]:
    """
    Query _ldap._tcp.dc._msdcs.<domain> SRV records against dns_server.
    Returns the set of IPs that the SRV target hostnames resolve to.

    Uses a raw DNS UDP socket — no external dependencies required.
    The AD-integrated DNS server (dc_ip) is used so that internal zones
    like north.sevenkingdoms.local are resolvable.
    """
    srv_name = f"_ldap._tcp.dc._msdcs.{domain}"
    try:
        tid = os.urandom(2)
        # Standard query, recursion desired
        header = tid + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        parts = srv_name.encode('ascii').split(b'.')
        qname = b''.join(bytes([len(p)]) + p for p in parts) + b'\x00'
        question = qname + b'\x00\x21\x00\x01'  # QTYPE=SRV(33), QCLASS=IN(1)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(header + question, (dns_server, 53))
        resp, _ = s.recvfrom(4096)
        s.close()
    except OSError:
        return set()

    # Parse answer section
    ancount = struct.unpack('!H', resp[6:8])[0]
    if ancount == 0:
        return set()

    # Skip past the question section
    pos = 12
    # Skip qname
    while pos < len(resp):
        if resp[pos] & 0xc0 == 0xc0:
            pos += 2
            break
        if resp[pos] == 0:
            pos += 1
            break
        pos += resp[pos] + 1
    pos += 4  # skip QTYPE + QCLASS

    def _decode_name(buf: bytes, offset: int) -> tuple[str, int]:
        """Decode a DNS name at offset, following pointers. Returns (name, new_offset)."""
        labels = []
        visited = set()
        orig_offset = offset
        jumped = False
        end_offset = offset
        while offset < len(buf):
            if offset in visited:
                break
            visited.add(offset)
            length = buf[offset]
            if length & 0xc0 == 0xc0:
                if offset + 1 >= len(buf):
                    break
                ptr = struct.unpack('!H', buf[offset:offset+2])[0] & 0x3fff
                if not jumped:
                    end_offset = offset + 2
                jumped = True
                offset = ptr
            elif length == 0:
                if not jumped:
                    end_offset = offset + 1
                break
            else:
                labels.append(buf[offset+1:offset+1+length].decode('ascii', 'replace'))
                offset += length + 1
                if not jumped:
                    end_offset = offset
        return '.'.join(labels).lower(), end_offset

    hostnames: list[str] = []
    for _ in range(ancount):
        if pos >= len(resp):
            break
        _, pos = _decode_name(resp, pos)
        if pos + 10 > len(resp):
            break
        rtype = struct.unpack('!H', resp[pos:pos+2])[0]
        rdlen = struct.unpack('!H', resp[pos+8:pos+10])[0]
        pos += 10
        if rtype == 33 and rdlen > 6:  # SRV record
            # priority(2) weight(2) port(2) then target name
            target_name, _ = _decode_name(resp, pos + 6)
            if target_name:
                hostnames.append(target_name)
        pos += rdlen

    # Resolve hostnames to IPs using the same DNS server
    ips: set[str] = set()
    for hostname in hostnames:
        try:
            # Point resolution at the AD DNS server
            tid2 = os.urandom(2)
            header2 = tid2 + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            parts2 = hostname.rstrip('.').encode('ascii').split(b'.')
            qname2 = b''.join(bytes([len(p)]) + p for p in parts2) + b'\x00'
            question2 = qname2 + b'\x00\x01\x00\x01'  # QTYPE=A(1), QCLASS=IN(1)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2.settimeout(timeout)
            s2.sendto(header2 + question2, (dns_server, 53))
            resp2, _ = s2.recvfrom(4096)
            s2.close()
            ancount2 = struct.unpack('!H', resp2[6:8])[0]
            # Skip question
            pos2 = 12
            while pos2 < len(resp2):
                if resp2[pos2] & 0xc0 == 0xc0:
                    pos2 += 2; break
                if resp2[pos2] == 0:
                    pos2 += 1; break
                pos2 += resp2[pos2] + 1
            pos2 += 4
            for _ in range(ancount2):
                if pos2 >= len(resp2): break
                _, pos2 = _decode_name(resp2, pos2)
                if pos2 + 10 > len(resp2): break
                rtype2 = struct.unpack('!H', resp2[pos2:pos2+2])[0]
                rdlen2 = struct.unpack('!H', resp2[pos2+8:pos2+10])[0]
                pos2 += 10
                if rtype2 == 1 and rdlen2 == 4:  # A record
                    ip = '.'.join(str(b) for b in resp2[pos2:pos2+4])
                    ips.add(ip)
                pos2 += rdlen2
        except OSError:
            # Fall back to system resolver as a last resort
            try:
                ip = socket.gethostbyname(hostname.rstrip('.'))
                ips.add(ip)
            except OSError:
                pass

    return ips


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

        for target in targets:
            rc, out, err = _run_nxc(
                ["smb", target, "-u", self.env.cred.username,
                 *(((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password]))),
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
             *(((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password]))),
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
