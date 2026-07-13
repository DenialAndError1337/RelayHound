"""
TargetEnv holds all user-supplied targets and credentials.
"""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Credential:
    domain: str
    username: str
    password: str
    nt_hash: Optional[str] = None   # pass-the-hash alternative

    @property
    def upn(self) -> str:
        return f"{self.domain}\\{self.username}"

    @property
    def ldap_user(self) -> str:
        return f"{self.username}@{self.domain}"


@dataclass
class TargetEnv:
    # Primary domain + DC
    domain: str
    dc_ip: str

    # Credentials
    cred: Credential

    # Optional extra DCs / servers (parsed from --extra-targets)
    extra_targets: list[str] = field(default_factory=list)

    # Scope exclusions (parsed from --exclude): hosts / hostnames / CIDR
    # subnets to drop from per-host checks. Match RULES, not targets — a "/24"
    # is one rule, never expanded. The primary --dc-ip is never dropped (it's
    # the assessment anchor / LDAP target); a rule matching it only warns.
    exclude: list[str] = field(default_factory=list)

    # Attacker-controlled host (for relay description text)
    attacker_ip:       Optional[str] = None
    attacker_hostname: Optional[str] = None

    # Timeouts
    timeout: int = 10

    # Verbosity
    verbose: bool = False

    # Whether to run the inbound ACL coercion target finder (--find-coercion-targets)
    find_relay_targets: bool = False

    # All DC IPs discovered via LDAP at startup (populated by relayhound.py
    # after env construction; falls back to [dc_ip] if discovery fails). This is
    # forest-wide — it may include child-domain / cross-forest DCs (used for the
    # DC display and relay-target enumeration).
    dc_ips:       list[str]       = field(default_factory=list)
    # DC IPs of the TARGET domain (env.domain) ONLY — a subset of dc_ips. Used to
    # scope dc_targets() so the verdict-feeding fan-out (signing / channel binding /
    # NTLMv1) does not evaluate cross-domain / forest DCs. Populated by relayhound.py
    # from discovery; empty → dc_targets() falls back to dc_ips (synthetic envs,
    # explicit --dc-ips without discovery, or discovery failure).
    domain_dc_ips: list[str]      = field(default_factory=list)
    # Scope-safety guard (--dc-ip-only). When True, dc_targets() is confined to
    # the single --dc-ip primary, so the only checks that authenticate to
    # DISCOVERED DCs (the NTLMv1 / LDAP signing / channel-binding fan-out) never
    # reach a DC beyond --dc-ip. Discovery still runs for display/context — it
    # only reads from the --dc-ip anchor + DNS, so it sends no auth to the other
    # DCs. Narrowing-only: fewer probed DCs can only make a verdict MORE
    # conservative, never a false VIABLE (cardinal rule holds).
    dc_ip_only:   bool            = False
    # IP → short hostname map built at startup (covers DCs + extra targets)
    hostname_map: dict[str, str]  = field(default_factory=dict)

    # Shared cache for cross-module short-circuiting.
    # Modules write sentinel values here after running their first gatekeeper
    # check so subsequent modules can skip without repeating the same query.
    # Keys defined so far:
    #   "adcs_deployed"  : bool — False if AdcsDeployedCheck confirmed no ADCS
    #   "sccm_present"   : bool — False if SCCMDetectedCheck confirmed no SCCM
    shared_cache: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Ensure dc_ips always contains at least the primary DC so modules
        # can rely on it being non-empty before startup discovery runs.
        if not self.dc_ips:
            self.dc_ips = [self.dc_ip]

    # ── convenience helpers ─────────────────────────────────────────

    def _is_excluded(self, host: str) -> bool:
        """True if `host` matches any --exclude exclusion rule.

        Matches on: exact host/hostname string (case-insensitive); CIDR/subnet
        membership when `host` is an IP; and the mapped short hostname from
        hostname_map (so `--exclude` entries by name exclude IP targets too).
        Unparsable rules are ignored rather than raising.
        """
        if not self.exclude:
            return False
        h = host.strip().lower()
        mapped = self.hostname_map.get(host, "").strip().lower()
        host_ip = None
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            pass
        for token in self.exclude:
            tok = token.strip().lower()
            if not tok:
                continue
            if h == tok or (mapped and mapped == tok):
                return True
            if "/" in tok and host_ip is not None:
                try:
                    if host_ip in ipaddress.ip_network(tok, strict=False):
                        return True
                except ValueError:
                    pass
        return False

    @property
    def all_targets(self) -> list[str]:
        """DC IP + any (non-excluded) extra targets.

        The primary dc_ip is always retained — it is the assessment anchor /
        LDAP target; exclusions apply to extra targets and discovered hosts.
        """
        targets = [self.dc_ip] + [
            t for t in self.extra_targets if not self._is_excluded(t)
        ]
        return list(dict.fromkeys(targets))   # deduplicate, preserve order

    def dc_targets(self) -> list[str]:
        """DC IPs for DC-specific / fan-out checks — scoped to the TARGET domain
        (env.domain), minus exclusions. Cross-domain / forest DCs discovered for
        context are deliberately excluded here: relaying to a child/forest DC
        compromises THAT domain, not env.domain, so a signing-off (or
        NTLMv1-accepting) forest DC must not make an env.domain module read VIABLE
        (cardinal rule). Falls back to all dc_ips when domain scoping wasn't
        populated (synthetic envs, explicit --dc-ips without discovery, discovery
        failure). The primary dc_ip is always retained.

        --dc-ip-only (dc_ip_only) confines this to the single primary: the
        NTLMv1 / signing / channel-binding fan-out then authenticates to no DC
        beyond --dc-ip. Narrowing-only, so it can never produce a false VIABLE."""
        if self.dc_ip_only:
            return [self.dc_ip]
        pool = self.domain_dc_ips or self.dc_ips
        targets = [
            ip for ip in pool
            if ip == self.dc_ip or not self._is_excluded(ip)
        ]
        if self.dc_ip not in targets:
            targets.insert(0, self.dc_ip)
        return targets

    def smb_targets(self) -> list[str]:
        return self.all_targets

    def ldap_target(self) -> str:
        return self.dc_ip

    def adcs_targets(self) -> list[str]:
        return self.all_targets

    def mssql_targets(self) -> list[str]:
        return self.all_targets

    def webdav_targets(self) -> list[str]:
        return self.all_targets
