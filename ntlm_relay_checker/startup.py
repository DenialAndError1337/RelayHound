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

import re
import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import TargetEnv

try:
    from ldap3 import Server, Connection, NTLM, ANONYMOUS, SUBTREE, BASE, ALL
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
from .utils import _dns_srv_ips


# ── DNS SRV helper (no external deps) ─────────────────────────────────────


def _dn_to_fqdn(dn: str) -> str:
    """Convert 'DC=north,DC=sevenkingdoms,DC=local' → 'north.sevenkingdoms.local'."""
    parts = re.findall(r'DC=([^,]+)', dn, re.IGNORECASE)
    return '.'.join(parts).lower() if parts else ''


def _short_name(fqdn: str) -> str:
    """Return first label of an FQDN as the short hostname."""
    return fqdn.split('.')[0] if fqdn else ''


# ── DC discovery ───────────────────────────────────────────────────────────

def query_domain_controllers(
    env: "TargetEnv",
) -> tuple[list[str], dict[str, str], bool, "str | None", list[str]]:
    """
    Return (dc_ips, hostname_map, dc_ip_reachable, primary_dc, own_domain_dc_ips).

    dc_ips is forest-wide (all discovered DCs, for display / relay-target
    enumeration); own_domain_dc_ips is the subset belonging to env.domain, used to
    scope env.dc_targets() so fan-out checks don't evaluate cross-domain DCs.

    Discovery is anchored to the first *reachable* host in
    [dc_ip] + extra_targets, not blindly to the supplied --dc-ip, so a dead
    or wrong --dc-ip no longer collapses discovery to just the seed. DC IPs
    are resolved via SRV records queried against a live DC's own DNS (raw
    UDP — independent of the attacker box's system resolver, which in many
    labs points at a public resolver that can't see internal AD zones).

    dc_ip_reachable is False when the supplied --dc-ip could not be bound;
    the caller uses it to drop the bogus IP from the reported DC list.

    primary_dc is a reachable DC *of env.domain* to use as the LDAP/LDAPS/
    -dc-ip target (== env.dc_ip when it was reachable, else a discovered and
    bindable own-domain DC, else None). The caller retargets env.dc_ip to it
    so per-check domain operations don't hit a dead supplied IP.
    """
    fallback_ips: list[str] = [env.dc_ip]
    fallback_map: dict[str, str] = {}

    if not LDAP3_AVAILABLE:
        return fallback_ips, fallback_map, False, env.dc_ip, []

    ips: list[str] = []
    hmap: dict[str, str] = {}
    dc_ip_reachable = False
    anchor_ip: str | None = None
    forest_domains: set[str] = {env.domain.lower()}

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

    # ── Step 1: authenticated bind against the first reachable anchor ──────
    # Try the supplied --dc-ip first, then fall back to extra_targets. The
    # first host that accepts a domain NTLM bind is a live DC and becomes the
    # enumeration anchor + DNS server for SRV lookups.
    auth_password = (
        f"aad3b435b51404eeaad3b435b51404ee:{env.cred.nt_hash.split(':')[-1]}"
        if env.cred.nt_hash else env.cred.password
    )

    def _try_bind(host: str):
        """Return (server, conn) on a successful domain NTLM bind, else (None, None)."""
        try:
            srv = Server(host, get_info=ALL, connect_timeout=min(env.timeout, 5))
            cn = Connection(
                srv, user=env.cred.upn, password=auth_password,
                authentication=NTLM, auto_bind=True,
            )
            return srv, cn
        except Exception:
            return None, None

    candidates = [env.dc_ip] + [t for t in env.extra_targets if t != env.dc_ip]
    server = None
    conn = None
    for cand in candidates:
        cand_server, cand_conn = _try_bind(cand)
        if not cand_conn:
            continue
        # Bound successfully — this host is a live DC.
        server, conn, anchor_ip = cand_server, cand_conn, cand
        if cand == env.dc_ip:
            dc_ip_reachable = True
        break

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
                    # Skip non-domain partitions (Schema/Configuration have no
                    # DC= prefix matching a real domain).
                    fqdn_part = _dn_to_fqdn(nc_name)
                    if not fqdn_part:
                        continue
                    forest_domains.add(fqdn_part)
                    if fqdn_part == env.domain.lower():
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

    # ── Step 2b: SRV-based DC discovery against the live anchor's DNS ───────
    # Resolves DC IPs for every forest domain directly via the anchor DC's
    # DNS (raw UDP), so it works even when the attacker box's system resolver
    # can't see internal AD zones and even when --dc-ip itself was dead.
    # Process env.domain first so own-domain DCs lead the list deterministically
    # (set iteration order is otherwise nondeterministic).
    own_domain_dc_ips: list[str] = []
    if anchor_ip:
        own = env.domain.lower()
        ordered_domains = [own] + sorted(forest_domains - {own})
        for dom in ordered_domains:
            try:
                srv_ips = _dns_srv_ips(
                    dom, dns_server=anchor_ip, timeout=min(env.timeout, 3)
                )
            except Exception:
                srv_ips = set()
            for ip in sorted(srv_ips):
                if ip not in ips:
                    ips.append(ip)
                if dom == own and ip not in own_domain_dc_ips:
                    own_domain_dc_ips.append(ip)
        # Make sure the anchor itself is listed (it's a confirmed live DC).
        if anchor_ip not in ips:
            ips.append(anchor_ip)

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

        # DNS SRV confirms whether this host is actually a DC in that domain.
        # Query the candidate host itself (a live DC runs DNS and authoritatively
        # answers its own domain's SRV); fall back to the anchor DC. Never the
        # supplied --dc-ip, which may be dead — that was the original bug where
        # supplied extra-target DCs were silently dropped.
        dc_ips_for_domain: set[str] = set()
        for resolver in (host, anchor_ip):
            if not resolver:
                continue
            try:
                dc_ips_for_domain = _dns_srv_ips(
                    domain_from_ldap, dns_server=resolver,
                    timeout=min(env.timeout, 3),
                )
            except Exception:
                dc_ips_for_domain = set()
            if dc_ips_for_domain:
                break
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

    # ── Pick the primary DC: a *reachable* DC of the TARGET domain ─────────
    # Per-check LDAP/LDAPS/-dc-ip operations all read env.dc_ip, so when the
    # supplied --dc-ip is dead the caller retargets to this. It must be a DC of
    # env.domain — never a child-domain or cross-forest DC, or domain-specific
    # checks (DNS zones, MAQ, DFL, SCCM container, …) would query the wrong
    # domain. None means no reachable own-domain DC was found.
    primary_dc: str | None = env.dc_ip if dc_ip_reachable else None
    if primary_dc is None:
        primary_candidates = list(own_domain_dc_ips)
        # Multi-forest fallback: the anchor used for Step 2b may belong to a
        # *different* forest (e.g. the first bindable extra-target was a
        # cross-forest DC), so its DNS can't resolve env.domain's SRV and
        # own_domain_dc_ips came back empty — even though a same-forest DC is
        # reachable. Re-query env.domain's SRV against every DC we discovered;
        # a same-forest DC will answer it.
        if not primary_candidates:
            own = env.domain.lower()
            for resolver in list(ips):
                try:
                    extra_own = _dns_srv_ips(
                        own, dns_server=resolver, timeout=min(env.timeout, 3)
                    )
                except Exception:
                    extra_own = set()
                for ip in sorted(extra_own):
                    if ip not in primary_candidates:
                        primary_candidates.append(ip)
                    if ip not in ips:
                        ips.append(ip)
                if primary_candidates:
                    break
        for cand in primary_candidates:
            if cand == anchor_ip:          # anchor already proven bindable
                # ...but only if the anchor actually belongs to env.domain
                # (it leads own_domain_dc_ips only when it does).
                primary_dc = cand
                break
            _s, _c = _try_bind(cand)
            if _c:
                try:
                    _c.unbind()
                except Exception:
                    pass
                primary_dc = cand
                break

    # Nothing reachable anywhere → fall back to the supplied IP so downstream
    # checks still have a target (the count will read as "no DCs discovered").
    if not ips:
        return [env.dc_ip], hmap, dc_ip_reachable, primary_dc, own_domain_dc_ips
    return ips, hmap, dc_ip_reachable, primary_dc, own_domain_dc_ips


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


def out_of_domain_dc_note(env: "TargetEnv") -> "str | None":
    """Informational signpost (NON-verdict) for forest/child DCs discovered outside the
    assessed domain.

    Relay verdicts are scoped to env.domain via dc_targets(); a DC that is in env.dc_ips
    but NOT in env.domain_dc_ips belongs to another forest domain. A coerced env.domain
    host cannot be usefully relayed there — the LDAP-write attacks (RBCD / Shadow Creds /
    ACL / ADIDNS) write to an object that must exist in the directory being authenticated
    to, and machine accounts are not replicated across domain boundaries, so the write
    fails (lab-confirmed). That's why such DCs are excluded from the verdict — but the
    operator should still know they exist and are worth a separate, per-domain assessment
    (and that child-domain compromise could pivot to forest root).

    Returns the note text, or None when scoping is inactive (no domain_dc_ips — e.g.
    ldap3 unavailable / discovery failure) or there are no out-of-domain DCs.
    """
    domain_dc = getattr(env, "domain_dc_ips", None)
    if not domain_dc:
        return None
    own = set(domain_dc)
    others = [ip for ip in env.dc_ips if ip not in own]
    if not others:
        return None

    def _lbl(ip: str) -> str:
        host = env.hostname_map.get(ip)
        return f"{host} ({ip})" if host else ip

    listed = ", ".join(_lbl(ip) for ip in others)
    plural = "s" if len(others) != 1 else ""
    return (
        f"{len(others)} forest DC{plural} outside {env.domain} discovered, excluded from "
        f"relay verdicts here: {listed}. Relay viability against a DC applies only to its "
        f"own domain — a coerced host must be relayed to a DC of its OWN domain "
        f"(cross-domain LDAP writes fail: the target object isn't in the foreign "
        f"directory). Assess each in its own domain: re-run with -d '<that DC's domain>'. "
        f"Child-domain compromise could pivot to forest root (child krbtgt + Enterprise "
        f"Admins SID; or impacket-raisechild.py)."
    )


def discovered_dc_probe_note(env: "TargetEnv") -> "str | None":
    """Pre-probe ROE notice (NON-verdict): which discovered DCs will be authenticated to.

    All discovered-DC auth traffic funnels through dc_targets(): the NTLMv1 SMB
    probe and the LDAP/LDAPS signing + channel-binding fan-out. Discovery itself
    only reads from the --dc-ip anchor (+ DNS SRV), so any DC the operator did not
    supply stays silent until those probes fire — an ROE-relevant fact the run-config
    banner (which merely lists discovered DCs) does not convey. Surface it up front so
    an ROE-conscious operator can abort and re-run with --dc-ip-only.

    Computes the extra in-domain DCs INDEPENDENTLY of the guard (mirroring the
    un-confined dc_targets() logic) so the note can still report what --dc-ip-only
    is suppressing. Only in-domain DCs are considered — out-of-domain/forest DCs are
    already excluded from probing and covered by out_of_domain_dc_note().

    Returns:
      - a confinement confirmation when --dc-ip-only is set AND discovery found
        in-domain DCs beyond the primary (so the operator sees the guard took effect);
      - a warning naming the extra in-domain DCs that WILL be probed (guard off);
      - None when there is only the primary to probe (nothing to say).
    """
    primary = env.dc_ip
    pool = env.domain_dc_ips or env.dc_ips
    extras = [ip for ip in pool if ip != primary and not env._is_excluded(ip)]
    if not extras:
        return None

    def _lbl(ip: str) -> str:
        host = env.hostname_map.get(ip)
        return f"{host} ({ip})" if host else ip

    listed = ", ".join(_lbl(ip) for ip in extras)
    plural = "s" if len(extras) != 1 else ""
    primary_lbl = _lbl(primary)

    if getattr(env, "dc_ip_only", False):
        return (
            f"--dc-ip-only: DC probing confined to {primary_lbl}. "
            f"{len(extras)} other discovered in-domain DC{plural} shown for context "
            f"only — NOT authenticated to: {listed}. If any is more permissive than "
            f"{primary_lbl}, that relay path won't be detected — a not-viable verdict "
            f"here means 'not viable via {primary_lbl}', not 'not viable anywhere'."
        )
    return (
        f"{len(extras)} discovered in-domain DC{plural} beyond --dc-ip will be "
        f"authenticated to (SMB NTLMv1 probe + LDAP/LDAPS signing & channel-binding "
        f"binds): {listed}. To confine all DC probing to {primary_lbl}, re-run with "
        f"--dc-ip-only."
    )


def format_dc_discovery_status(
    seed_ips: list[str],
    final_ips: list[str],
    dc_ip_reachable: bool = True,
    known_dc: str | None = None,
) -> str:
    """
    Plain-text status for the startup "Querying domain for DC IPs..." line.

    Honest about discovered-vs-supplied and about an unreachable --dc-ip: the
    supplied --dc-ip (and any --dc-ips) are *seeded* before discovery runs, and
    a bare "found N" misleads — it reads as if an active query located a live DC
    when it may have just echoed the supplied IP. When the supplied --dc-ip
    could not be bound, that is called out explicitly.

    seed_ips        : DC IPs supplied on the CLI (--dc-ip + --dc-ips)
    final_ips       : DC IPs after discovery (dead --dc-ip already dropped)
    dc_ip_reachable : False if the supplied --dc-ip could not be bound
    known_dc        : the supplied --dc-ip (to detect the no-discovery fallback)

    Examples:
      "skipped (ldap3 unavailable)"
      "discovered 2 additional DCs (3 total)"
      "no additional DCs discovered — using supplied --dc-ip"
      "supplied --dc-ip unreachable — discovered 3 DCs via fallback"
      "supplied --dc-ip unreachable — no DCs discovered"
    """
    if not LDAP3_AVAILABLE:
        return "skipped (ldap3 unavailable)"

    if not dc_ip_reachable:
        # Supplied --dc-ip was dead; did the anchor fallback find anything?
        if known_dc is not None and final_ips == [known_dc]:
            return "supplied --dc-ip unreachable — no DCs discovered"
        n = len(final_ips)
        return (f"supplied --dc-ip unreachable — discovered {n} "
                f"DC{'s' if n != 1 else ''} via fallback")

    discovered_new = [ip for ip in final_ips if ip not in seed_ips]
    if discovered_new:
        n = len(discovered_new)
        return (f"discovered {n} additional DC{'s' if n != 1 else ''} "
                f"({len(final_ips)} total)")
    supplied = len(seed_ips)
    if supplied == 1:
        return "no additional DCs discovered — using supplied --dc-ip"
    return f"no additional DCs discovered — using {supplied} supplied DC IPs"
