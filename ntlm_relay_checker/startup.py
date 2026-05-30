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

def query_domain_controllers(env: "TargetEnv") -> list[str]:
    """
    Return a list of DC IPs discovered from the domain via LDAP.

    Strategy:
      1. Connect to env.dc_ip with the supplied credentials.
      2. Search for computer objects with the SERVER_TRUST_ACCOUNT bit
         set in userAccountControl (bit 0x2000 = 8192).
      3. Resolve each dnsHostName to an IP.  Objects whose hostname
         cannot be resolved are skipped (not reachable from attacker).
      4. Always include env.dc_ip so the list is never empty even if
         LDAP is unavailable or resolution fails for every DC.

    Returns a deduplicated list, env.dc_ip first.
    """
    fallback = [env.dc_ip]

    if not LDAP3_AVAILABLE:
        return fallback

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
        return fallback

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
        return fallback
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    if not entries:
        return fallback

    ips: list[str] = [env.dc_ip]   # seed with the known-good DC

    for entry in entries:
        hostname = None
        try:
            hostname = str(entry["dnsHostName"]).strip()
        except Exception:
            pass

        if not hostname or hostname.lower() in ("none", ""):
            # Fall back to cn + domain suffix
            try:
                cn = str(entry["cn"]).strip()
                if cn and cn.lower() not in ("none", ""):
                    hostname = f"{cn}.{env.domain}"
            except Exception:
                pass

        if not hostname:
            continue

        try:
            ip = socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]
            if ip not in ips:
                ips.append(ip)
        except (socket.gaierror, IndexError):
            # Host not resolvable from attacker — skip
            pass

    return ips


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
