"""
Startup helpers — run once before attack checks begin.

query_domain_controllers(env)
    Queries the domain via LDAP for all DC computer objects
    (userAccountControl bit 0x2000 = SERVER_TRUST_ACCOUNT), resolves
    their dnsHostName to IPs, and returns a deduplicated list.

    Falls back to [env.dc_ip] on any failure so callers never need to
    handle an empty list.
"""
from __future__ import annotations

import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import TargetEnv

try:
    from ldap3 import Server, Connection, NTLM, SUBTREE, ALL
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


# ── DC discovery ───────────────────────────────────────────────────────────

def query_domain_controllers(env: "TargetEnv") -> tuple[list[str], dict[str, str]]:
    """
    Return (dc_ips, hostname_map) discovered from the domain via LDAP.

    dc_ips:
      Deduplicated list of DC IPs, env.dc_ip first.

    hostname_map:
      IP → short hostname (e.g. "192.168.1.10" → "kingslanding") for all
      discovered DCs.  Used to build Forshaw DNS names in attack paths.

    Strategy:
      1. Connect to env.dc_ip with the supplied credentials.
      2. Search for computer objects with the SERVER_TRUST_ACCOUNT bit
         set in userAccountControl (bit 0x2000 = 8192).
      3. Resolve each dnsHostName to an IP.  Objects whose hostname
         cannot be resolved are skipped (not reachable from attacker).
      4. Always include env.dc_ip so dc_ips is never empty even if LDAP
         is unavailable or resolution fails for every DC.
    """
    fallback_ips: list[str] = [env.dc_ip]
    fallback_map: dict[str, str] = {}

    if not LDAP3_AVAILABLE:
        return fallback_ips, fallback_map

    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        conn = Connection(
            server,
            user=env.cred.upn,
            password=env.cred.password,
            authentication=NTLM,
            auto_bind=True,
        )
    except Exception:
        return fallback_ips, fallback_map

    try:
        domain_dn = ",".join(f"DC={part}" for part in env.domain.split("."))

        # SERVER_TRUST_ACCOUNT (0x2000) bit set → domain controller
        conn.search(
            search_base=domain_dn,
            search_filter="(userAccountControl:1.2.840.113556.1.4.803:=8192)",
            search_scope=SUBTREE,
            attributes=["dnsHostName", "cn"],
        )

        entries = list(conn.entries)
    except Exception:
        return fallback_ips, fallback_map
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    if not entries:
        return fallback_ips, fallback_map

    ips: list[str] = [env.dc_ip]
    hmap: dict[str, str] = {}

    for entry in entries:
        fqdn = None
        short = None

        try:
            fqdn = str(entry["dnsHostName"]).strip()
            if fqdn.lower() in ("none", ""):
                fqdn = None
        except Exception:
            pass

        try:
            cn = str(entry["cn"]).strip()
            if cn and cn.lower() not in ("none", ""):
                short = cn
                if not fqdn:
                    fqdn = f"{cn}.{env.domain}"
        except Exception:
            pass

        if not fqdn:
            continue

        try:
            ip = socket.getaddrinfo(fqdn, None, socket.AF_INET)[0][4][0]
            if ip not in ips:
                ips.append(ip)
            if short and ip not in hmap:
                hmap[ip] = short
        except (socket.gaierror, IndexError):
            # Host not resolvable from attacker — skip
            pass

    return ips, hmap


def resolve_hostname_map(targets: list[str]) -> dict[str, str]:
    """
    Reverse-resolve a list of IPs to short hostnames via DNS.

    Used to populate hostname_map for --extra-targets at startup so the
    Forshaw DNS name can be built for member server coercion targets too.
    Returns a partial dict — targets that don't resolve are omitted.
    """
    hmap: dict[str, str] = {}
    for ip in targets:
        try:
            fqdn = socket.gethostbyaddr(ip)[0]
            short = fqdn.split(".")[0]
            if short:
                hmap[ip] = short
        except (socket.herror, socket.gaierror):
            pass
    return hmap


def format_dc_discovery_line(dc_ips: list[str], known_dc: str) -> str:
    """
    Return a human-readable summary for the run-config panel.

    Examples:
      "10.10.10.1 (only DC / not queried)"   ← ldap3 unavailable
      "10.10.10.1"                            ← 1 DC found, same as --dc-ip
      "10.10.10.1, 10.10.10.2, 10.10.10.3"  ← multiple DCs discovered
    """
    if not LDAP3_AVAILABLE:
        return f"{known_dc} (ldap3 unavailable — install to enable DC discovery)"
    if dc_ips == [known_dc]:
        return known_dc
    return ", ".join(dc_ips)
