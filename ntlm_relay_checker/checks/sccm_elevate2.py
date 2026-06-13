"""
SCCM ELEVATE-2 prerequisite checks: NTLM relay via automatic client push installation.

When SCCM automatic site assignment and automatic client push installation are
enabled (with NTLM fallback allowed), an attacker can register a fake device
with the management point. SCCM then automatically pushes the client push
installation account credentials toward the registered address, which the
attacker controls.  Those credentials can be relayed to:

  ELEVATE-2.1 (SMB):  relay to any unsigned SMB target where the push account
    has local admin → secretsdump / interactive shell.  If the push account
    happens to be the site server machine account or a Domain Admin, impact
    escalates to TAKEOVER-1/2 territory.

  ELEVATE-2.2 (HTTP): if ADIDNS is writable, register a DNS A-record pointing
    to the relay server.  Site server connects via HTTP (WebClient/WebDAV),
    bypassing SMB signing.  Relay to LDAP(S) → Shadow Credentials / RBCD /
    Domain Admin group add.

Coercion mechanism: SharpSCCM (Windows-only) via `invoke client-push`.
There is no Linux equivalent for triggering client push — this is noted in
the attack path commands.

Prerequisites:
  [REQ]  SCCM detected in AD (inherited from SCCM module discovery)
  [REQ]  Management point reachable on HTTP/HTTPS (TCP 80 or 443)
  [WARN] Automatic client push installation enabled (not remotely detectable)
  [WARN] Allow connection fallback to NTLM enabled / KB15599094 not patched
  [OPT]  Unsigned SMB relay targets available (ELEVATE-2.1 path)
  [OPT]  ADIDNS writable by domain user (ELEVATE-2.2 HTTP path)
  [OPT]  WebClient running on site server (enables HTTP coercion without DNS)
"""
from __future__ import annotations

import socket
import subprocess
from typing import Optional

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv
from .sccm_takeover import _get_discovery, _port_open, _run_nxc_smb

try:
    from ldap3 import Server, Connection, NTLM, SUBTREE, ALL
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


# ── helpers ────────────────────────────────────────────────────────────────

def _ldap_connect(env: TargetEnv) -> Optional[object]:
    if not LDAP3_AVAILABLE:
        return None
    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        if env.cred.nt_hash:
            nh = env.cred.nt_hash.split(":")[-1]
            auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
        else:
            auth_password = env.cred.password
        conn = Connection(
            server,
            user=env.cred.upn,
            password=auth_password,
            authentication=NTLM,
            auto_bind=True,
        )
        return conn
    except Exception:
        return None


def _http_reachable(host: str, port: int, timeout: int = 5) -> bool:
    """Check HTTP/HTTPS reachability by attempting a TCP connection."""
    return _port_open(host, port, timeout)


# ── Check classes ──────────────────────────────────────────────────────────

class ManagementPointReachableCheck(BaseCheck):
    """Check that the SCCM management point is reachable on HTTP or HTTPS."""

    name = "Management point reachable (HTTP/HTTPS)"
    breaks_on_fail = True  # no MP reachable = client push coercion impossible

    def _run(self) -> CheckResult:
        # Cross-module short-circuit: sccm_takeover.py may have confirmed no SCCM
        if self.env.shared_cache.get("sccm_present") is False:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="SCCM not deployed in this domain (confirmed by TAKEOVER module).",
            )

        disc = _get_discovery(self.env)
        candidates = disc.management_points or disc.site_servers
        if not candidates:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="No management point hostname found in AD. "
                       "Cannot verify reachability for client push coercion.",
            )

        reachable_http  = []
        reachable_https = []

        for host in candidates:
            try:
                ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
            except (socket.gaierror, IndexError):
                ip = None

            target = ip or host
            if _http_reachable(target, 80, self.env.timeout):
                reachable_http.append(host)
            if _http_reachable(target, 443, self.env.timeout):
                reachable_https.append(host)

        if reachable_http or reachable_https:
            parts = []
            if reachable_http:
                parts.append(f"HTTP (port 80): {', '.join(reachable_http)}")
            if reachable_https:
                parts.append(f"HTTPS (port 443): {', '.join(reachable_https)}")
            sc = f" Site code: {disc.site_code}." if disc.site_code else ""
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Management point reachable — {'; '.join(parts)}.{sc} "
                    "SharpSCCM can register a fake device and trigger client push "
                    "installation toward an attacker-controlled address."
                ),
            )

        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=f"Management point candidate(s) {', '.join(candidates[:3])} "
                   "not reachable on port 80 or 443. "
                   "Cannot trigger client push installation remotely.",
        )


class ClientPushNTLMFallbackCheck(BaseCheck):
    """
    Warn that automatic client push and NTLM fallback cannot be verified remotely.

    The Misconfiguration Manager documentation explicitly states:
    'It is not possible to identify whether automatic site-wide client push
    installation, automatic site assignment, and Allow connection fallback to
    NTLM are enabled without attempting this attack.'
    """

    name = "Automatic client push + NTLM fallback (not remotely detectable)"

    @property
    def required(self) -> bool:
        return False

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "Automatic site-wide client push installation, automatic site assignment, "
                "and 'Allow connection fallback to NTLM' cannot be confirmed remotely — "
                "these settings are only visible in the SCCM console or by attempting the "
                "attack. Both are enabled by default in most deployments. "
                "KB15599094 (patches NTLM fallback in versions 2103–2206) "
                "cannot be verified remotely either. "
                "Important: if no specific push installation accounts are configured, "
                "or all configured accounts fail, the site server falls back to "
                "authenticating with its own domain machine account. If relayed over SMB "
                "to a remote site database, this escalates directly to TAKEOVER-1/2 territory "
                "(Full Administrator via db_owner on the site DB)."
            ),
        )


class UnsignedSMBRelayTargetsCheck(BaseCheck):
    """
    Check for unsigned SMB targets to relay to (ELEVATE-2.1 path).

    The client push installation account needs local admin on the relay target.
    Any unsigned host in scope is a candidate — impact depends on the push
    account's privilege level in the environment.
    """

    name = "Unsigned SMB relay targets available (ELEVATE-2.1)"

    @property
    def required(self) -> bool:
        return False

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        targets = list(self.env.extra_targets)
        if not targets:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No extra targets specified — cannot check for unsigned SMB hosts. "
                       "Use --extra-targets to include hosts in the SCCM site.",
            )

        unsigned = []
        for host in targets:
            if not _port_open(host, 445, self.env.timeout):
                continue
            auth = (["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash
                    else ["-p", self.env.cred.password])
            rc, out, err = _run_nxc_smb(
                [host, "-u", self.env.cred.username,
                 "-d", self.env.domain] + auth,
                self.env,
            )
            combined = (out + err).lower()
            if rc != -1 and ("signing:false" in combined or "signing not required" in combined):
                unsigned.append(host)

        if unsigned:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"Unsigned SMB host(s) in scope: {', '.join(unsigned)}. "
                    "If the client push account has local admin on these hosts, "
                    "ELEVATE-2.1 relay is viable. "
                    "Impact escalates to domain-level if the push account is a Domain Admin "
                    "or the site server machine account."
                ),
            )

        if targets:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"All checked targets ({', '.join(targets[:3])}) have SMB signing enabled. "
                       "ELEVATE-2.1 (relay to SMB) blocked.",
            )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="No SMB targets reachable to check signing status.",
        )


class ADIDNSWritableCheck(BaseCheck):
    """
    Check whether ADIDNS is writable by the current user (ELEVATE-2.2 HTTP path).

    If ADIDNS is writable, the attacker registers a DNS A-record pointing to
    the relay server. The site server resolves the hostname and connects via
    HTTP (WebDAV), bypassing SMB signing, allowing relay to LDAP(S).
    """

    name = "ADIDNS writable by domain user (ELEVATE-2.2 HTTP path)"

    @property
    def required(self) -> bool:
        return False

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        if not LDAP3_AVAILABLE:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="ldap3 not available — cannot check ADIDNS writability.",
            )

        conn = _ldap_connect(self.env)
        if not conn:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="LDAP connection failed — cannot check ADIDNS writability.",
            )

        try:
            domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
            dns_zone_dn = (
                f"DC={self.env.domain},CN=MicrosoftDNS,"
                f"DC=DomainDnsZones,{domain_dn}"
            )
            conn.search(
                search_base=dns_zone_dn,
                search_filter="(objectClass=dnsZone)",
                search_scope="BASE",
                attributes=["distinguishedName"],
            )
            zone_found = len(conn.entries) > 0
        except Exception:
            zone_found = False

        conn.unbind()

        if zone_found:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"LDAP bind succeeded and DNS zone accessible for {self.env.domain}. "
                    "By default, authenticated domain users can add ADIDNS A-records. "
                    "Use dnstool.py to register a record pointing to the relay server, "
                    "then trigger client push via SharpSCCM — site server connects via "
                    "HTTP allowing relay to LDAP(S) (ELEVATE-2.2)."
                ),
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail="DNS zone not found or not accessible via LDAP. "
                   "ADIDNS writability for ELEVATE-2.2 HTTP path could not be confirmed.",
        )


class SiteServerWebClientCheck(BaseCheck):
    """
    Check whether WebClient is running on the site server.

    If WebClient is running on the site server itself, HTTP coercion is
    possible without needing ADIDNS — the attacker can use a UNC path with
    a hostname@port format directly.
    """

    name = "WebClient running on site server (HTTP coercion without DNS)"

    @property
    def required(self) -> bool:
        return False

    def _run(self) -> CheckResult:
        disc = _get_discovery(self.env)
        candidates = disc.site_servers or disc.management_points
        if not candidates:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No site server hostname found — cannot check WebClient.",
            )

        webclient_hosts = []
        for host in candidates:
            try:
                ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
            except (socket.gaierror, IndexError):
                ip = host

            if not _port_open(ip, 445, self.env.timeout):
                continue

            auth = (["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash
                    else ["-p", self.env.cred.password])
            rc, out, err = _run_nxc_smb(
                [ip, "-u", self.env.cred.username,
                 "-d", self.env.domain] + auth + ["-M", "webdav"],
                self.env,
                timeout=15,
            )
            combined = out + err
            if rc != -1 and ("webdav" in combined.lower() or "webclient" in combined.lower()):
                if "running" in combined.lower() or "[+]" in combined:
                    webclient_hosts.append(host)

        if webclient_hosts:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"WebClient running on site server(s): {', '.join(webclient_hosts)}. "
                    "HTTP coercion is possible without ADIDNS — use "
                    f"{self.env.attacker_hostname or '<attacker-hostname>'}@80/share "
                    "as the SharpSCCM target to force HTTP auth from the site server."
                ),
            )

        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=f"WebClient not confirmed on site server(s) {', '.join(candidates[:3])}. "
                   "HTTP coercion (ELEVATE-2.2) requires either WebClient running or "
                   "ADIDNS registration. SMB coercion (ELEVATE-2.1) works regardless.",
        )


# ── Module entry point ─────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        ManagementPointReachableCheck(env),
        ClientPushNTLMFallbackCheck(env),
        UnsignedSMBRelayTargetsCheck(env),
        ADIDNSWritableCheck(env),
        SiteServerWebClientCheck(env),
    ]
