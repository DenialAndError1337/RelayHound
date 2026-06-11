"""
Startup helpers — run once before attack checks begin.

query_domain_controllers(env)
    Discovers all reachable DCs across the forest and any extra targets,
    returning a deduplicated IP list and IP→hostname map.

    Strategy (layered — each step extends what the previous found):

      1. Own-domain LDAP query — authenticated bind to env.dc_ip, search
         SERVER_TRUST_ACCOUNT (UAC bit 0x2000) in env.domain's base DN.
         Finds all DCs in the directly-targeted domain.

      2. Cross-partition LDAP query — reads CN=Partitions,CN=Configuration
         from the same authenticated connection to enumerate all domain
         partitions in the forest (child domains, tree roots). Repeats the
         SERVER_TRUST_ACCOUNT query in each partition's base DN.
         Finds DCs in child domains like north.sevenkingdoms.local without
         needing --dc-ips.

      3. Extra-targets SRV sweep — for any IP in env.extra_targets not yet
         classified as a DC by steps 1-2: anonymous LDAP bind to port 389
         reads defaultNamingContext (no credentials required), then a DNS
         SRV query for _ldap._tcp.dc._msdcs.<domain> against env.dc_ip
         confirms DC role. Handles cross-forest targets and any domain the
         authenticated LDAP connection cannot reach.

    Falls back gracefully at each step — failure in step 2 or 3 does not
    prevent the results of earlier steps from being returned.
    Always includes env.dc_ip so dc_ips is never empty.
"""
from __future__ import annotations

import os
import re
import socket
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import TargetEnv

try:
    from ldap3 import Server, Connection, NTLM, ANONYMOUS, SUBTREE, BASE, ALL
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


# ── DNS SRV helper (no external deps) ─────────────────────────────────────

def _dns_srv_ips(domain: str, dns_server: str, timeout: int = 3) -> set[str]:
    """
    Query _ldap._tcp.dc._msdcs.<domain> SRV records against dns_server.
    Returns the set of IPs the SRV target hostnames resolve to.

    Uses raw DNS UDP sockets — no dnspython or other external library needed.
    Queries the AD-integrated DNS server (dc_ip) so internal zones resolve.
    """
    srv_name = f"_ldap._tcp.dc._msdcs.{domain}"
    try:
        tid = os.urandom(2)
        header = tid + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        parts = srv_name.encode('ascii').split(b'.')
        qname = b''.join(bytes([len(p)]) + p for p in parts) + b'\x00'
        question = qname + b'\x00\x21\x00\x01'   # QTYPE=SRV(33), QCLASS=IN(1)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(header + question, (dns_server, 53))
        resp, _ = s.recvfrom(4096)
        s.close()
    except OSError:
        return set()

    ancount = struct.unpack('!H', resp[6:8])[0]
    if ancount == 0:
        return set()

    def _decode_name(buf: bytes, offset: int) -> tuple[str, int]:
        labels: list[str] = []
        visited: set[int] = set()
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

    # Skip question section
    pos = 12
    while pos < len(resp):
        if resp[pos] & 0xc0 == 0xc0:
            pos += 2
            break
        if resp[pos] == 0:
            pos += 1
            break
        pos += resp[pos] + 1
    pos += 4  # QTYPE + QCLASS

    hostnames: list[str] = []
    for _ in range(ancount):
        if pos >= len(resp):
            break
        _, pos = _decode_name(resp, pos)
        if pos + 10 > len(resp):
            break
        rtype  = struct.unpack('!H', resp[pos:pos+2])[0]
        rdlen  = struct.unpack('!H', resp[pos+8:pos+10])[0]
        pos += 10
        if rtype == 33 and rdlen > 6:   # SRV
            target_name, _ = _decode_name(resp, pos + 6)
            if target_name:
                hostnames.append(target_name)
        pos += rdlen

    # Resolve each SRV target hostname → IP via A query to same DNS server
    ips: set[str] = set()
    for hostname in hostnames:
        try:
            tid2 = os.urandom(2)
            header2 = tid2 + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            parts2 = hostname.rstrip('.').encode('ascii').split(b'.')
            qname2 = b''.join(bytes([len(p)]) + p for p in parts2) + b'\x00'
            question2 = qname2 + b'\x00\x01\x00\x01'   # QTYPE=A(1), QCLASS=IN(1)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2.settimeout(timeout)
            s2.sendto(header2 + question2, (dns_server, 53))
            resp2, _ = s2.recvfrom(4096)
            s2.close()
            ancount2 = struct.unpack('!H', resp2[6:8])[0]
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
                rtype2  = struct.unpack('!H', resp2[pos2:pos2+2])[0]
                rdlen2  = struct.unpack('!H', resp2[pos2+8:pos2+10])[0]
                pos2 += 10
                if rtype2 == 1 and rdlen2 == 4:   # A record
                    ips.add('.'.join(str(b) for b in resp2[pos2:pos2+4]))
                pos2 += rdlen2
        except OSError:
            try:
                ip = socket.gethostbyname(hostname.rstrip('.'))
                ips.add(ip)
            except OSError:
                pass

    return ips


def _dn_to_fqdn(dn: str) -> str:
    """Convert 'DC=north,DC=sevenkingdoms,DC=local' → 'north.sevenkingdoms.local'."""
    parts = re.findall(r'DC=([^,]+)', dn, re.IGNORECASE)
    return '.'.join(parts).lower() if parts else ''


def _short_name(fqdn: str) -> str:
    """Return first label of an FQDN as the short hostname."""
    return fqdn.split('.')[0] if fqdn else ''


# ── DC discovery ───────────────────────────────────────────────────────────

def query_domain_controllers(env: "TargetEnv") -> tuple[list[str], dict[str, str]]:
    """
    Return (dc_ips, hostname_map) — see module docstring for full strategy.
    """
    fallback_ips: list[str] = [env.dc_ip]
    fallback_map: dict[str, str] = {}

    if not LDAP3_AVAILABLE:
        return fallback_ips, fallback_map

    ips: list[str] = [env.dc_ip]
    hmap: dict[str, str] = {}

    def _add(fqdn: str, short: str) -> None:
        """Resolve fqdn → IP and add to ips/hmap if reachable."""
        if not fqdn:
            return
        try:
            ip = socket.getaddrinfo(fqdn, None, socket.AF_INET)[0][4][0]
        except (socket.gaierror, IndexError):
            return
        if ip not in ips:
            ips.append(ip)
        if short and ip not in hmap:
            hmap[ip] = short

    def _search_partition(conn: object, base_dn: str) -> None:
        """Run SERVER_TRUST_ACCOUNT search in base_dn, add results to ips/hmap."""
        try:
            conn.search(  # type: ignore[attr-defined]
                search_base=base_dn,
                search_filter="(userAccountControl:1.2.840.113556.1.4.803:=8192)",
                search_scope=SUBTREE,
                attributes=["dnsHostName", "cn"],
            )
            for entry in conn.entries:  # type: ignore[attr-defined]
                fqdn = short = None
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
                            fqdn = f"{cn}.{_dn_to_fqdn(base_dn)}"
                except Exception:
                    pass
                _add(fqdn or "", short or "")
        except Exception:
            pass

    # ── Step 1: authenticated bind + own-domain query ──────────────────────
    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        auth_password = (
            f"aad3b435b51404eeaad3b435b51404ee:{env.cred.nt_hash.split(':')[-1]}"
            if env.cred.nt_hash else env.cred.password
        )
        conn = Connection(
            server,
            user=env.cred.upn,
            password=auth_password,
            authentication=NTLM,
            auto_bind=True,
        )
    except Exception:
        # Can't authenticate at all — fall through to step 3
        conn = None

    if conn:
        own_dn = ",".join(f"DC={part}" for part in env.domain.split("."))
        _search_partition(conn, own_dn)

        # ── Step 2: cross-partition — enumerate forest domains ─────────────
        try:
            # Configuration partition is at CN=Configuration,<forest root DN>
            # We get the forest root from the server's info after binding
            config_dn = None
            try:
                # ldap3 exposes this after get_info=ALL bind
                config_dn = str(server.info.other.get(
                    "configurationNamingContext", [""])[0])
            except Exception:
                pass

            if not config_dn:
                # Fallback: derive config DN from own domain DN
                # e.g. DC=sevenkingdoms,DC=local → CN=Configuration,DC=sevenkingdoms,DC=local
                config_dn = f"CN=Configuration,{own_dn}"

            partitions_dn = f"CN=Partitions,{config_dn}"
            conn.search(
                search_base=partitions_dn,
                search_filter="(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
                search_scope=SUBTREE,
                attributes=["nCName", "dnsRoot"],
            )
            for entry in conn.entries:
                try:
                    nc_name = str(entry["nCName"]).strip()
                    if not nc_name or nc_name.lower() == "none":
                        continue
                    # Skip the own domain and non-domain partitions
                    # (Schema, Configuration partitions have no DC= prefix pattern
                    #  matching a real domain)
                    fqdn_part = _dn_to_fqdn(nc_name)
                    if not fqdn_part or fqdn_part == env.domain.lower():
                        continue
                    _search_partition(conn, nc_name)
                except Exception:
                    continue
        except Exception:
            pass

        try:
            conn.unbind()
        except Exception:
            pass

    # ── Step 3: extra-targets SRV sweep ────────────────────────────────────
    # For any extra_target IP not yet in ips: anonymous LDAP rootDSE read
    # gives us the domain, then DNS SRV confirms DC role.
    known_ips = set(ips)
    for host in env.extra_targets:
        if host in known_ips:
            continue
        # Try anonymous LDAP bind to read defaultNamingContext
        domain_from_ldap: str | None = None
        try:
            anon_server = Server(host, connect_timeout=min(env.timeout, 5))
            anon_conn = Connection(
                anon_server,
                authentication=ANONYMOUS,
                auto_bind=True,
            )
            anon_conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["defaultNamingContext"],
            )
            if anon_conn.entries:
                nc = str(anon_conn.entries[0]["defaultNamingContext"]).strip()
                if nc and nc.lower() != "none":
                    domain_from_ldap = _dn_to_fqdn(nc)
            anon_conn.unbind()
        except Exception:
            pass

        if not domain_from_ldap:
            continue

        # DNS SRV confirms whether this host is actually a DC in that domain
        dc_ips_for_domain = _dns_srv_ips(
            domain_from_ldap, dns_server=env.dc_ip, timeout=min(env.timeout, 3)
        )
        if host not in dc_ips_for_domain:
            continue

        # It's a DC — resolve its hostname for the hostname map
        try:
            fqdn = socket.gethostbyaddr(host)[0]
            short = _short_name(fqdn)
        except OSError:
            fqdn = ""
            short = ""

        if host not in ips:
            ips.append(host)
        if short and host not in hmap:
            hmap[host] = short
        known_ips.add(host)

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
      \"10.10.10.1 (ldap3 unavailable)\"        ← ldap3 not installed
      \"10.10.10.1\"                             ← 1 DC found, same as --dc-ip
      \"10.10.10.1, 10.10.10.2, 10.10.10.3\"   ← multiple DCs discovered
    """
    if not LDAP3_AVAILABLE:
        return f"{known_dc} (ldap3 unavailable — install to enable DC discovery)"
    if dc_ips == [known_dc]:
        return known_dc
    return ", ".join(dc_ips)
