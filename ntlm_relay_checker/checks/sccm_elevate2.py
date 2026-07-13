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

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv
from .sccm_takeover import _get_discovery

try:
    import ldap3  # noqa: F401  - availability probe; ldap3 imported lazily in functions
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
from ..utils import _port_open, _run_nxc_smb
from .ldap_dns import (
    IMPACKET_AVAILABLE,
    _discover_dns_zones,
    _zone_createchild_trustees,
)


# ── helpers ────────────────────────────────────────────────────────────────


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
        _get_discovery(self.env)
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
        _get_discovery(self.env)
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
        # Reuse the ADIDNS module's DACL-aware, cached zone discovery so the
        # ELEVATE-2.2 path is judged by the *same* signal as `--modules adidns`:
        # PASS only when an open trustee (Authenticated Users / Everyone) actually
        # holds CreateChild on a zone DACL — never on mere zone existence. Zone
        # existence alone does NOT prove a relayed client-push account can write a
        # record; a hardened zone (CreateChild removed) exists and is readable but
        # is not writable by an arbitrary account. (_discover_dns_zones caches into
        # env.shared_cache["adidns_zones"], shared with the adidns module.)
        _get_discovery(self.env)
        if not LDAP3_AVAILABLE:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="ldap3 not available — cannot evaluate ADIDNS zone writability.",
            )
        if not IMPACKET_AVAILABLE:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="impacket not installed — cannot parse the DNS zone DACL to confirm "
                       "CreateChild. Zone existence alone does not prove writability, so the "
                       "ELEVATE-2.2 ADIDNS path is left unconfirmed. Install: pip install impacket",
            )

        zones = _discover_dns_zones(self.env)
        if not zones:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="No AD-integrated DNS zone DACL available to evaluate (zone enumeration "
                       "inconclusive, or no primary zone) — ELEVATE-2.2 ADIDNS path unconfirmed.",
            )

        with_sd = [z for z in zones if z.get("raw_sd")]
        if not with_sd:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="DNS zone(s) found but their nTSecurityDescriptor could not be read "
                       "(insufficient rights or SD control rejected) — cannot confirm CreateChild; "
                       "ELEVATE-2.2 ADIDNS path unconfirmed.",
            )

        open_grants: list[str] = []
        for z in with_sd:
            for _sid, label, scoped in _zone_createchild_trustees(z["raw_sd"]):
                open_grants.append(
                    f"{z['name']} ({label}{', object-scoped' if scoped else ''})"
                )

        if open_grants:
            uniq = list(dict.fromkeys(open_grants))
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    "Open CreateChild on the DNS zone DACL — any authenticated domain user "
                    f"(and thus a relayed client-push account) can add records: {', '.join(uniq[:6])}. "
                    "Register an A-record for the relay host with dnstool.py, then trigger client "
                    "push via SharpSCCM — the site server resolves it and connects over HTTP, "
                    "relayable to LDAP(S) (ELEVATE-2.2)."
                ),
            )

        scanned = ", ".join(z["name"] for z in with_sd[:5])
        return CheckResult(
            name=self.name, status=Status.FAIL,
            detail=(
                f"No CreateChild ACE for Authenticated Users/Everyone on the scanned zone(s): "
                f"{scanned}. The zone DACL is hardened — an arbitrary relayed client-push account "
                "cannot create the spoof record, so the ELEVATE-2.2 open-trustee path is not "
                "confirmed (still possible only if you relay a principal that holds CreateChild)."
            ),
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

def module_viability(ar) -> str:
    """
    SCCM ELEVATE-2 verdict (attached by the engine via AttackResult.viability_fn).

    ELEVATE-2 relays a coerced client-push authentication to a destination. The
    trigger (automatic client push + 'Allow connection fallback to NTLM') is NOT
    remotely detectable — ClientPushNTLMFallbackCheck is always WARN — and a
    reachable management point is only the coercion *source*, not a relay
    *destination*. So a reachable MP alone must NOT render VIABLE: that would claim
    a viable relay with (a) nowhere confirmed to relay to and (b) an unconfirmable
    trigger — the "false viable" the tool exists to prevent, and inconsistent with
    the couldn't-determine → not-VIABLE rule applied to EPA / LDAP signing /
    channel binding elsewhere.

    VIABLE therefore requires >=1 CONFIRMED relay path:
      - UnsignedSMBRelayTargetsCheck PASS  (ELEVATE-2.1: relay to an unsigned SMB host), or
      - ADIDNSWritableCheck PASS           (ELEVATE-2.2: ADIDNS record → HTTP → relay to LDAP(S)).
    With a reachable MP but neither path confirmed, the verdict is PARTIAL
    (conditional): the attack may still work if the undetectable trigger is enabled
    and a relay destination exists out of scope (e.g. --extra-targets not supplied),
    but we cannot confirm it — so not VIABLE. (WebClient-running is a coercion
    enabler for the 2.2 path, not itself a confirmed relay destination, so it does
    not gate VIABLE on its own.)
    """
    base = ar._generic_viability()
    if base in ("NOT VIABLE", "UNKNOWN"):
        # MP unreachable (gatekeeper FAIL) → NOT VIABLE; nothing testable → UNKNOWN.
        return base

    by_name = {c.name: c.status for c in ar.checks}
    smb_path    = by_name.get(UnsignedSMBRelayTargetsCheck.name)
    adidns_path = by_name.get(ADIDNSWritableCheck.name)

    if smb_path == Status.PASS or adidns_path == Status.PASS:
        return "VIABLE"     # >=1 confirmed relay destination
    return "PARTIAL"        # MP reachable but no confirmed relay path → conditional


def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        ManagementPointReachableCheck(env),
        ClientPushNTLMFallbackCheck(env),
        UnsignedSMBRelayTargetsCheck(env),
        ADIDNSWritableCheck(env),
        SiteServerWebClientCheck(env),
    ]
