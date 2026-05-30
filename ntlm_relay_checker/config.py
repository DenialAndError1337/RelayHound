"""
TargetEnv holds all user-supplied targets and credentials.
"""
from __future__ import annotations
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

    # Attacker-controlled host (for relay description text)
    attacker_ip:       Optional[str] = None
    attacker_hostname: Optional[str] = None

    # Timeouts
    timeout: int = 10

    # Verbosity
    verbose: bool = False

    # Whether to run the inbound ACL relay target finder (--find-relay-targets)
    find_relay_targets: bool = False

    # All DC IPs discovered via LDAP at startup (populated by relayhound.py
    # after env construction; falls back to [dc_ip] if discovery fails).
    dc_ips:       list[str]       = field(default_factory=list)
    # IP → short hostname map built at startup (covers DCs + extra targets)
    hostname_map: dict[str, str]  = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Ensure dc_ips always contains at least the primary DC so modules
        # can rely on it being non-empty before startup discovery runs.
        if not self.dc_ips:
            self.dc_ips = [self.dc_ip]

    # ── convenience helpers ─────────────────────────────────────────

    @property
    def all_targets(self) -> list[str]:
        """DC IP + any extra targets."""
        targets = [self.dc_ip] + self.extra_targets
        return list(dict.fromkeys(targets))   # deduplicate, preserve order

    def dc_targets(self) -> list[str]:
        """All discovered DC IPs (use for DC-specific checks)."""
        return list(self.dc_ips)

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
