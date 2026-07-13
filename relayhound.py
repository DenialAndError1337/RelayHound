#!/usr/bin/env python3
"""
RelayRecon — NTLM Relay Prerequisite Checker
=====================================================
Checks whether an Active Directory environment meets the prerequisites
for common NTLM relay attacks. Outputs a summary table to the terminal
and saves a Markdown report.

Usage:
    python relayrecon.py -d corp.local --dc-ip 10.10.10.1 \\
        -u lowpriv -p password123 --extra-targets 10.10.10.20 \\
        --attacker-ip 10.10.10.99 -v -o report.md

"""
from __future__ import annotations
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ntlm_relay_checker.config import Credential, TargetEnv
from ntlm_relay_checker.engine import (
    DEFAULT_MAX_PARALLEL,
    run_all_checks,
    run_checks_parallel,
    relay_target_results,
)
from ntlm_relay_checker.startup import (
    query_domain_controllers,
    resolve_hostname_map,
    format_dc_discovery_line,
    format_dc_discovery_status,
    out_of_domain_dc_note,
    discovered_dc_probe_note,
)
from ntlm_relay_checker.output import (
    CheckProgress,
    print_summary_table,
    print_verbose_details,
    print_attack_paths,
    print_relay_target_summary,
    write_markdown_report,
    write_html_report,
    write_json_report,
    write_relay_list,
    write_laps_scope,
)


# ── Banner ─────────────────────────────────────────────────────────────────

BANNER = """
██████╗ ███████╗██╗      █████╗ ██╗   ██╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
██╔══██╗██╔════╝██║     ██╔══██╗╚██╗ ██╔╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
██████╔╝█████╗  ██║     ███████║ ╚████╔╝ ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██╔══██╗██╔══╝  ██║     ██╔══██║  ╚██╔╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██║  ██║███████╗███████╗██║  ██║   ██║   ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝

  Relay Attack Prerequisite Checker
"""


# ── Argument parser ────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="relayhound.py",
        description="RelayHound — Relay Attack Prerequisite Checker. Check NTLM relay attack prerequisites against an AD environment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic check against primary DC
  python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123

  # With member servers and attacker IP
  python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --extra-targets 10.10.10.20,10.10.10.21 --attacker-ip 10.10.10.99 -v -o report.md

  # Pass-the-hash
  python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -H aad3b435b51404eeaad3b435b51404ee:NTHASH

  # Find which accounts are worth coercing and for which attack
  python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --find-coercion-targets
        """,
    )

    # Target
    tgt = p.add_argument_group("Target")
    tgt.add_argument("-d", "--domain",   required=True,
                     help="Target domain (e.g. corp.local)")
    tgt.add_argument("--dc-ip",          required=True,
                     help="Primary Domain Controller IP")
    tgt.add_argument("--dc-ips",         default=None,
                     help="Comma-separated IPs of additional known DCs (e.g. DCs in other "
                          "domains/forests) so they rank as DC-level targets in attack paths")
    tgt.add_argument("--dc-ip-only",     action="store_true",
                     help="Confine all DC probing (NTLMv1 / LDAP signing / channel-binding "
                          "fan-out) to the --dc-ip primary; do not authenticate to any other "
                          "discovered DC. Discovery still runs for display/context. Scope-"
                          "safety guard; mutually exclusive with --dc-ips. Note: confining to "
                          "one DC can under-report — a relay path viable only via a more-"
                          "permissive sibling DC (signing off / CB not required / NTLMv1 "
                          "accepted there) will read as not-viable.")
    tgt.add_argument("--extra-targets",  default="",
                     help="Comma-separated IPs, hostnames, CIDR ranges, or dash ranges. "
                          "A token starting with '@' reads targets from a file "
                          "(@targets.txt: one per line, # comments allowed).")
    tgt.add_argument("--exclude",        default="",
                     help="Comma-separated hosts/hostnames/CIDR subnets to EXCLUDE from "
                          "checks (e.g. 10.0.0.9,dc03.corp.local,192.168.99.0/24). A token "
                          "starting with '@' reads rules from a file (@scope.txt: one per "
                          "line, # comments allowed). Match rules, not targets — a /24 is one "
                          "rule. The primary --dc-ip is never excluded.")
    tgt.add_argument("--attacker-ip",       default=None,
                     help="Attacker/relay listener IP (your Kali box)")
    tgt.add_argument("--attacker-hostname", default=None,
                     help="Your Kali/attacker hostname — used for WebDAV coercion and ADIDNS commands in attack paths")

    # Credentials
    cred = p.add_argument_group("Credentials")
    cred.add_argument("-u", "--username", required=True,
                      help="Domain username (low-privilege)")
    cred_exc = cred.add_mutually_exclusive_group(required=True)
    cred_exc.add_argument("-p", "--password", default=None,
                          help="Plaintext password")
    cred_exc.add_argument("-H", "--hashes", dest="nt_hash", default=None,
                          help="NT hash for pass-the-hash (format: AABBCC...)")

    # Options
    opts = p.add_argument_group("Options")
    opts.add_argument("-v", "--verbose",  action="store_true",
                      help="Show per-check details in terminal output")
    opts.add_argument("-q", "--quiet",    action="store_true",
                      help="Suppress NOT VIABLE modules from terminal output "
                           "(summary table and -v details). File reports are unaffected.")
    opts.add_argument("--parallel",       action="store_true",
                      help="Run attack checks in parallel (faster, noisier; "
                           "mutually exclusive with --delay/--jitter). Best-effort: "
                           "high concurrency can time out per-check probes and "
                           "under-report — sequential (default) is authoritative.")
    opts.add_argument("--max-parallel", type=int, default=DEFAULT_MAX_PARALLEL,
                      metavar="N",
                      help=f"Max attack modules run at once in --parallel mode "
                           f"(default: {DEFAULT_MAX_PARALLEL}). Lower it if per-check "
                           f"probes time out under load; raise it to go faster on a "
                           f"resilient DC. Ignored without --parallel.")
    opts.add_argument("--modules",        default=None,
                      help="Comma-separated list of module short names to run "
                           "(e.g. smb,rbcd,adcs). Invalid names print valid aliases and exit.")
    opts.add_argument("--delay",          type=int, default=0,
                      help="Sleep N seconds between each attack module (default: 0). Also randomises module execution order")
    opts.add_argument("--jitter",         type=int, default=0,
                      help="Add up to N seconds of random variation to the delay (default: 0)")
    opts.add_argument("--timeout",        type=int, default=10,
                      help="Network timeout in seconds (default: 10)")
    opts.add_argument("-o", "--output",   default=None,
                      help="Save Markdown report to this file")
    opts.add_argument("--no-report",      action="store_true",
                      help="Skip writing the Markdown and HTML reports")
    opts.add_argument("--no-html",        action="store_true",
                      help="Skip writing the HTML report (keep Markdown only)")
    opts.add_argument("--output-json",    default=None,
                      help="JSON report path (default: <domain>_ntlm_relay_report.json)")
    opts.add_argument("--no-json",        action="store_true",
                      help="Skip writing the JSON report")
    opts.add_argument("--relay-list",    default=None,
                      help="Save SMB unsigned hosts to this file for ntlmrelayx -tf")
    opts.add_argument("--no-relay-list", action="store_true",
                      help="Skip writing the relay targets file")
    opts.add_argument("--laps-scope",    default=None,
                      help="Save LAPS-managed computer names to this file")
    opts.add_argument("--no-laps-scope", action="store_true",
                      help="Skip writing the LAPS scope file")
    opts.add_argument("--find-coercion-targets", dest="find_relay_targets",
                      action="store_true",
                      help=(
                          "Find accounts whose authentication, once relayed, abuses "
                          "their AD rights (RBCD / Shadow Credentials / LAPS / ACL). "
                          "Machine accounts are coerced (PetitPotam/PrinterBug); user "
                          "accounts are captured via poisoning (mitm6/Responder). "
                          "Scans nTSecurityDescriptor ACLs on computer objects, the "
                          "domain root, and high-value groups, as the enumeration "
                          "credential — no extra passwords needed."
                      ))

    return p


def _detect_single_dash_longopt(
    parser: argparse.ArgumentParser, argv: list[str]
) -> "tuple[str, str] | None":
    """Catch a long option written with a single dash (e.g. ``-parallel``).

    POSIX short-option parsing makes argparse read ``-parallel`` as
    ``-p arallel`` — silently setting ``--password`` to ``arallel`` and leaving
    ``--parallel`` off, with no error. For a tool whose verdicts drive security
    decisions, that silent misconfiguration can turn a real finding into a false
    NOT VIABLE, so we reject it before parsing.

    Returns ``(offending_token, suggested_flag)`` or ``None``. Only inspects
    single-dash tokens, so argparse's own ``--`` prefix matching (e.g.
    ``--find-coercion-target`` → ``--find-coercion-targets``) is left untouched.
    """
    long_opts = {
        opt
        for action in parser._actions
        for opt in action.option_strings
        if opt.startswith("--")
    }
    for token in argv:
        if token == "--":           # explicit end-of-options marker
            break
        if (token.startswith("-") and not token.startswith("--")
                and "=" not in token and len(token) > 2):
            candidate = "--" + token[1:]
            if candidate in long_opts:
                return token, candidate
    return None


# ── Helpers ────────────────────────────────────────────────────────────────

def _expand_targets(raw: str) -> list[str]:
    import ipaddress
    import re as _re
    results = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        dash = _re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", token)
        if dash:
            prefix, start, end = dash.group(1), int(dash.group(2)), int(dash.group(3))
            results.extend(f"{prefix}{i}" for i in range(start, end + 1))
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            if net.num_addresses == 1:
                results.append(str(net.network_address))
            else:
                results.extend(str(ip) for ip in net.hosts())
        except ValueError:
            results.append(token)
    return list(dict.fromkeys(results))


def _load_targets(extra_arg: str) -> list[str]:
    """Parse --extra-targets (inline targets and/or '@file' tokens) into an
    expanded target list. A comma-separated token starting with '@' is read as a
    targets file (one per line, '#' comments, commas allowed). CIDRs and
    dash-ranges are expanded by _expand_targets."""
    raw_tokens: list[str] = []
    for token in (extra_arg or "").split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("@"):
            raw_tokens.extend(_read_rules_file(token[1:], "Targets"))
        else:
            raw_tokens.append(token)
    return _expand_targets(",".join(raw_tokens))


def _read_rules_file(path: str, kind: str = "Exclusion") -> list[str]:
    """Read rules/targets from a file: one per line, '#' comments and blank
    lines skipped, comma-separated tokens on a line allowed."""
    rules: list[str] = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    rules.extend(t.strip() for t in line.split(",") if t.strip())
    except FileNotFoundError:
        print(f"[!] {kind} file not found: {path}")
        sys.exit(1)
    return rules


def _load_exclusions(exclude_arg: str) -> list[str]:
    """Parse --exclude (inline rules and/or '@file' tokens) into a list of
    exclusion RULES (kept raw, never expanded). Tokens may be IPs, hostnames, or
    CIDR subnets; a comma-separated token starting with '@' is read as a rules
    file. Matching is done later by TargetEnv._is_excluded."""
    rules: list[str] = []
    for token in (exclude_arg or "").split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("@"):
            rules.extend(_read_rules_file(token[1:]))
        else:
            rules.append(token)
    return list(dict.fromkeys(rules))     # dedupe, preserve order


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()

    # Reject a long option written with a single dash before argparse can
    # silently reinterpret it (e.g. -parallel → -p arallel, clobbering the
    # password and leaving --parallel off). See _detect_single_dash_longopt.
    typo = _detect_single_dash_longopt(parser, sys.argv[1:])
    if typo:
        bad, suggestion = typo
        short = bad[:2]
        rest = bad[2:]
        print(f"[!] '{bad}' is not a valid flag — did you mean '{suggestion}' (two dashes)?")
        short_action = next(
            (a for a in parser._actions if short in a.option_strings), None
        )
        if short_action is not None and short_action.nargs != 0:
            print(f"    A single dash makes argparse read '{bad}' as "
                  f"'{short} {rest}', silently setting '{short}' to '{rest}' "
                  f"and ignoring '{suggestion}'.")
        print("    Aborting to avoid running with a misconfigured argument.")
        return 2

    args   = parser.parse_args()

    # --parallel runs every module simultaneously, so the sequential throttle
    # (--delay/--jitter, applied only in run_all_checks) is never honored in that
    # path. Silently ignoring it is a real OpSec surprise — the operator believes
    # they are pacing authentications but the run bursts all at once. Refuse the
    # combination and make the choice explicit (delay/jitter of 0 = no throttle,
    # so the default --parallel run is unaffected).
    if args.parallel and (args.delay > 0 or args.jitter > 0):
        parser.error(
            "--parallel cannot be combined with --delay/--jitter — parallel mode "
            "runs all modules at once, so the throttle would be silently ignored. "
            "Drop --parallel to pace authentications with --delay/--jitter, or drop "
            "--delay/--jitter to run in parallel."
        )

    # --dc-ip-only confines DC probing to the single --dc-ip primary, while
    # --dc-ips supplies ADDITIONAL DCs to probe — a direct contradiction. Refuse
    # rather than silently pick a winner (don't drop what the operator asked for).
    if args.dc_ip_only and args.dc_ips:
        parser.error(
            "--dc-ip-only cannot be combined with --dc-ips — one confines DC probing "
            "to the --dc-ip primary, the other adds more DCs to probe. Drop --dc-ips to "
            "confine to the primary, or drop --dc-ip-only to include the extra DCs."
        )

    try:
        from rich.console import Console
        Console().print(f"[bold cyan]{BANNER}[/]")
    except ImportError:
        print(BANNER)

    # ── Resolve --modules filter ───────────────────────────────────
    from ntlm_relay_checker.engine import ATTACK_MODULES

    # Short name aliases: maps lower-case alias → index in ATTACK_MODULES
    MODULE_ALIASES: dict[str, int] = {
        "smb":           0,
        "rbcd":          1,
        "shadowcreds":   2,
        "adcs":          3,
        "esc11":         4,
        "mssql":         5,
        "kerberos":      6,
        "laps":          7,
        "addcomputer":   8,
        "acl":           9,
        "sccm_takeover": 10,
        "sccm_elevate2": 11,
        "adidns":        12,
        "dns":           12,
    }

    # Group aliases: expand to multiple module names before MODULE_ALIASES lookup
    GROUP_ALIASES: dict[str, list[str]] = {
        "sccm":  ["sccm_takeover", "sccm_elevate2"],
        "adcs":  ["adcs", "esc11", "kerberos"],
    }

    if args.modules:
        requested_raw = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
        # Expand group aliases first
        requested: list[str] = []
        for m in requested_raw:
            if m in GROUP_ALIASES:
                requested.extend(GROUP_ALIASES[m])
            else:
                requested.append(m)
        invalid = [m for m in requested if m not in MODULE_ALIASES]
        if invalid:
            print(f"[!] Unknown module(s): {', '.join(invalid)}")
            print(f"    Valid names:  {', '.join(MODULE_ALIASES)}")
            print(f"    Group aliases: {', '.join(GROUP_ALIASES)}")
            return 1
        # Keep canonical order regardless of input order
        selected_indices = sorted(set(MODULE_ALIASES[m] for m in requested))
        active_modules = [ATTACK_MODULES[i] for i in selected_indices]
    else:
        active_modules = ATTACK_MODULES

    cred = Credential(
        domain=args.domain,
        username=args.username,
        password=args.password or "",
        nt_hash=args.nt_hash,
    )

    extra = _load_targets(args.extra_targets)
    exclude = _load_exclusions(args.exclude)

    env = TargetEnv(
        domain=args.domain,
        dc_ip=args.dc_ip,
        cred=cred,
        extra_targets=extra,
        exclude=exclude,
        attacker_ip=args.attacker_ip,
        attacker_hostname=args.attacker_hostname,
        timeout=args.timeout,
        verbose=args.verbose,
        find_relay_targets=args.find_relay_targets,
        dc_ip_only=args.dc_ip_only,
    )

    # ── Seed dc_ips with any explicitly supplied DC IPs ───────────
    if args.dc_ips:
        extra_dcs = [ip.strip() for ip in args.dc_ips.split(",") if ip.strip()]
        env.dc_ips = list(dict.fromkeys([env.dc_ip] + extra_dcs))

    # ── Discover all DCs via LDAP ──────────────────────────────────
    try:
        from rich.console import Console as _C
        _C().print("[dim]Querying domain for DC IPs...[/]", end="")
    except ImportError:
        print("[*] Querying domain for DC IPs...", end="")
    supplied_dc_ip = env.dc_ip
    discovered, dc_hmap, dc_ip_reachable, primary_dc, own_domain = query_domain_controllers(env)
    seed_dc_ips = list(env.dc_ips)          # supplied --dc-ip (+ --dc-ips) before discovery
    # Retarget the primary LDAP/LDAPS/-dc-ip target if the supplied --dc-ip was
    # dead but a reachable DC *of the target domain* was discovered. Every
    # per-check domain operation reads env.dc_ip, so this one reassignment makes
    # them run against a live own-domain DC instead of the dead supplied IP.
    retargeted = False
    if not dc_ip_reachable and primary_dc and primary_dc != supplied_dc_ip:
        env.dc_ip = primary_dc
        retargeted = True
    # Honest DC list: discovered live DCs ∪ explicitly supplied --dc-ips, but a
    # bare --dc-ip that proved unreachable is dropped so it can't masquerade as
    # a Domain Controller (e.g. a placeholder/typo IP with no VM behind it).
    merged = list(discovered)
    for ip in seed_dc_ips:
        if ip == supplied_dc_ip and not dc_ip_reachable:
            continue
        if ip not in merged:
            merged.append(ip)
    env.dc_ips = merged or [env.dc_ip]
    # Float the primary (own-domain) DC to the front so the displayed list leads
    # with the DC domain checks actually run against — purely cosmetic ordering.
    if primary_dc and primary_dc in env.dc_ips:
        env.dc_ips = [primary_dc] + [ip for ip in env.dc_ips if ip != primary_dc]
    # Scope the verdict-feeding fan-out (dc_targets) to the TARGET domain: own-domain
    # DCs plus the primary (always a DC of env.domain). Forest/child DCs remain in
    # env.dc_ips for the display and relay-target enumeration, but relaying to them
    # compromises THAT domain, not env.domain, so they must not feed env.domain's
    # signing/CB/NTLMv1 viability. Always non-empty here (≥ the primary), so
    # dc_targets uses it; its fallback to dc_ips is only for synthetic/test envs.
    env.domain_dc_ips = list(dict.fromkeys([env.dc_ip, *own_domain]))
    # Reverse-resolve extra targets for hostname map, then merge DC hostnames
    env.hostname_map = resolve_hostname_map(extra)
    env.hostname_map.update(dc_hmap)

    # ── Scope exclusions (--exclude): report what got dropped ───
    # Silently removing targets is dangerous, so surface it. The primary dc_ip
    # is the assessment anchor and is never dropped — warn if a rule matches it.
    if env.exclude:
        candidates = list(dict.fromkeys([supplied_dc_ip] + extra + list(env.dc_ips)))
        dropped = [h for h in candidates
                   if h != env.dc_ip and env._is_excluded(h)]
        _label = lambda h: (f"{h} ({env.hostname_map[h]})"
                            if env.hostname_map.get(h) else h)
        try:
            from rich.console import Console as _C
            _sc = _C()
            _sc.print(f"[cyan][*] Scope: {len(env.exclude)} exclusion rule(s)[/]")
            if dropped:
                _sc.print("[cyan][*] Excluded from checks: "
                          f"{', '.join(_label(h) for h in dropped)}[/]")
            else:
                _sc.print("[dim][*] No current targets matched the exclusion rules[/]")
            if env._is_excluded(env.dc_ip):
                _sc.print(f"[yellow][!] --dc-ip {env.dc_ip} matches a scope "
                          "exclusion but is the assessment anchor (LDAP target) — "
                          "kept in scope. Point --dc-ip at an in-scope DC to avoid "
                          "querying it.[/]")
        except ImportError:
            print(f"[*] Scope: {len(env.exclude)} exclusion rule(s)")
            if dropped:
                print(f"[*] Excluded from checks: {', '.join(_label(h) for h in dropped)}")
            else:
                print("[*] No current targets matched the exclusion rules")
            if env._is_excluded(env.dc_ip):
                print(f"[!] --dc-ip {env.dc_ip} matches a scope exclusion but is the "
                      "assessment anchor — kept in scope.")

    _dc_status = format_dc_discovery_status(
        seed_dc_ips, env.dc_ips, dc_ip_reachable, supplied_dc_ip
    )
    try:
        from rich.console import Console as _C
        _c = _C()
        _c.print(f" [dim]{_dc_status}[/]")
        if retargeted:
            _c.print(
                f" [yellow]→ supplied --dc-ip {supplied_dc_ip} unreachable; "
                f"running domain checks against discovered DC {env.dc_ip}[/]"
            )
        elif not dc_ip_reachable and not primary_dc:
            _c.print(
                f" [red]→ supplied --dc-ip {supplied_dc_ip} unreachable and no "
                f"reachable {env.domain} DC was found — domain (LDAP/LDAPS) "
                f"checks will fail; pass a live --dc-ip for those.[/]"
            )
    except ImportError:
        print(f" {_dc_status}")
        if retargeted:
            print(f" -> supplied --dc-ip {supplied_dc_ip} unreachable; "
                  f"running domain checks against discovered DC {env.dc_ip}")
        elif not dc_ip_reachable and not primary_dc:
            print(f" -> supplied --dc-ip {supplied_dc_ip} unreachable and no "
                  f"reachable {env.domain} DC found — domain checks will fail.")

    # ── Print run config ───────────────────────────────────────────
    _dc_ip_display = (
        f"{env.dc_ip}  (supplied {supplied_dc_ip} unreachable)"
        if retargeted else env.dc_ip
    )
    # Annotate any extra target that scope rules will drop, so the panel doesn't
    # imply an excluded host is still in scope (the exclusion itself already applies).
    def _fmt_extra_target(t: str) -> str:
        return f"{t} [yellow](excluded)[/]" if (env.exclude and env._is_excluded(t)) else t
    _extra_display = ", ".join(_fmt_extra_target(t) for t in extra) or "none"
    try:
        from rich.console import Console
        from rich.panel import Panel
        c = Console()
        c.print(Panel(
            f"[bold]Domain:[/]           [cyan]{env.domain}[/]\n"
            f"[bold]DC IP:[/]            [cyan]{_dc_ip_display}[/]\n"
            f"[bold]Domain Controllers:[/] [cyan]{format_dc_discovery_line(env.dc_ips, env.dc_ip)}[/]\n"
            f"[bold]User:[/]             [cyan]{cred.upn}[/]\n"
            f"[bold]Auth:[/]             {'NT hash' if cred.nt_hash else 'Password'}\n"
            f"[bold]Extra targets:[/]    {_extra_display}\n"
            f"[bold]Attacker IP:[/]      {env.attacker_ip or 'not specified'}\n"
            f"[bold]Attacker Host:[/]    {env.attacker_hostname or 'not specified'}\n"
            f"[bold]Timeout:[/]          {env.timeout}s\n"
            f"[bold]Mode:[/]             {'parallel' if args.parallel else 'sequential'}\n"
            f"[bold]Modules:[/]          {args.modules or 'all'}\n"
            + (f"[bold]Delay / jitter:[/]   {args.delay}s / {args.jitter}s\n" if args.delay else "")
            + f"[bold]Find coercion targets:[/] {'yes' if args.find_relay_targets else 'no'}",
            title="Run Configuration",
            border_style="blue",
        ))
    except ImportError:
        print(f"[*] Domain:  {env.domain}")
        print(f"[*] DC IP:   {env.dc_ip}")
        print(f"[*] User:    {cred.upn}")
        print(f"[*] Targets: {env.all_targets}")

    # Informational signpost: forest/child DCs outside the assessed domain are
    # excluded from relay verdicts (cross-domain relay writes fail) — but flag them so
    # the operator knows to assess those domains separately.
    _ood_note = out_of_domain_dc_note(env)
    if _ood_note:
        try:
            from rich.console import Console
            # highlight=False: render as uniform dim prose. Rich's default
            # ReprHighlighter otherwise incidentally tints <...>/'...'/IP tokens
            # mid-sentence (e.g. the "-d '<that DC's domain>'" placeholder flipped
            # colour across rich versions) — never intended styling for an advisory note.
            Console().print(f"[dim][*] {_ood_note}[/]", highlight=False)
        except ImportError:
            print(f"[*] {_ood_note}")

    # Pre-probe scope notice: name the discovered in-domain DCs that will receive
    # authentication (all discovered-DC auth funnels through dc_targets()), so an
    # ROE-conscious operator sees it before any probe fires and can abort / re-run
    # with --dc-ip-only. Also confirms the guard took effect when it is set.
    _probe_note = discovered_dc_probe_note(env)
    if _probe_note:
        try:
            from rich.console import Console
            Console().print(f"[dim][*] {_probe_note}[/]", highlight=False)
        except ImportError:
            print(f"[*] {_probe_note}")

    # ── Run checks ─────────────────────────────────────────────────
    progress = CheckProgress(verbose=args.verbose,
                             module_total=len(active_modules),
                             parallel=args.parallel,
                             quiet=args.quiet)

    print()
    start = time.time()

    if args.parallel:
        progress.parallel_start(len(active_modules))
        results = run_checks_parallel(env, progress_callback=progress.update,
                                      modules=active_modules,
                                      module_finished_callback=progress.parallel_module_finished,
                                      max_workers=args.max_parallel)
    else:
        results = run_all_checks(env, progress_callback=progress.update,
                                 modules=active_modules,
                                 delay=args.delay, jitter=args.jitter,
                                 module_started_callback=progress.module_started,
                                 module_finished_callback=progress.module_finished)
        progress.flush()

    # ── Run coercion target finder (if requested) ─────────────────
    relay_target_summary = None
    if args.find_relay_targets:
        try:
            from rich.console import Console
            Console().print("\n[dim]Scanning ACLs for coercion target candidates...[/]")
        except ImportError:
            print("\n[*] Scanning ACLs for coercion target candidates...")
        # Cached: a per-module check may already have triggered this scan during
        # the run (when --find-coercion-targets is on), in which case this reuses it.
        relay_target_summary = relay_target_results(env)

    elapsed = time.time() - start
    print()

    # env_summary used by attack paths, reports, and JSON
    env_summary = {
        "domain":        env.domain,
        "dc_ip":         env.dc_ip,
        "dc_ips":        env.dc_ips,
        "user":          cred.upn,
        "attacker_ip":       env.attacker_ip,
        "attacker_hostname": env.attacker_hostname,
        "hostname_map":      env.hostname_map,
        "extra_targets": extra,
        "dc_ip_only":    args.dc_ip_only,
        # Scope / ROE notes: out-of-domain DCs excluded from probing, and the
        # discovered in-domain DCs that will be (or, under --dc-ip-only, were)
        # confined. Computed once above for the terminal so the report and the
        # terminal output can't drift.
        "scope_notes":   [n for n in (_ood_note, _probe_note) if n],
        # NOTE: password/nt_hash included for terminal attack-chain display ONLY.
        # Report writers (MD/HTML/JSON) must never read or emit these fields.
        "password": cred.password,
        "nt_hash":  cred.nt_hash,
    }

    # ── Print terminal summary ─────────────────────────────────────
    # Order: summary table → attack paths → relay targets → verbose details
    print_summary_table(results, quiet=args.quiet)
    print_attack_paths(results, env_summary, relay_target_summary)

    if relay_target_summary is not None:
        print_relay_target_summary(relay_target_summary)

    print_verbose_details(results, verbose=args.verbose, quiet=args.quiet)

    try:
        from rich.console import Console
        Console().print(f"[dim]Completed in {elapsed:.1f}s[/]")
    except ImportError:
        print(f"Completed in {elapsed:.1f}s")

    # ── Write reports ──────────────────────────────────────────────
    if not args.no_report:
        out_path = args.output or f"{args.domain.split('.')[0]}_ntlm_relay_report.md"
        write_markdown_report(
            results, env_summary, out_path,
            relay_target_summary=relay_target_summary,
        )
        try:
            from rich.console import Console
            Console().print(f"\n[green]✓ Markdown report saved:[/] [bold]{out_path}[/]")
        except ImportError:
            print(f"\n[+] Markdown report saved: {out_path}")

        if not args.no_html:
            # Only swap a trailing ".md" extension for ".html"; otherwise append.
            # A blanket str.replace(".md", ".html") would corrupt an embedded ".md"
            # (e.g. "q1.mddata.md" -> "q1.htmldata.md.html").
            html_path = (out_path[:-3] + ".html") if out_path.endswith(".md") \
                else out_path + ".html"
            write_html_report(
                results, env_summary, html_path,
                relay_target_summary=relay_target_summary,
            )
            try:
                from rich.console import Console
                Console().print(f"[green]✓ HTML report saved:[/]     [bold]{html_path}[/]")
            except ImportError:
                print(f"[+] HTML report saved: {html_path}")

    if not args.no_json:
        json_path = args.output_json or f"{args.domain.split('.')[0]}_ntlm_relay_report.json"
        write_json_report(
            results, env_summary, json_path,
            relay_target_summary=relay_target_summary,
        )
        try:
            from rich.console import Console
            Console().print(f"[green]✓ JSON report saved:[/]      [bold]{json_path}[/]")
        except ImportError:
            print(f"[+] JSON report saved: {json_path}")

    # ── Write relay target list ────────────────────────────────────
    if not args.no_relay_list:
        relay_path = args.relay_list or f"{args.domain.split('.')[0]}_relay_targets.txt"
        n = write_relay_list(results, relay_path)
        if n > 0:
            try:
                from rich.console import Console
                Console().print(
                    f"[green]✓ Relay targets saved:[/]    [bold]{relay_path}[/] "
                    f"[dim]({n} unsigned host{'s' if n != 1 else ''})[/]"
                )
            except ImportError:
                print(f"[+] Relay targets saved: {relay_path} ({n} hosts)")

    # ── Write LAPS scope file ──────────────────────────────────────
    if not args.no_laps_scope:
        laps_path = args.laps_scope or f"{args.domain.split('.')[0]}_laps_computers.txt"
        n = write_laps_scope(results, laps_path)
        if n > 0:
            try:
                from rich.console import Console
                Console().print(
                    f"[green]✓ LAPS scope saved:[/]       [bold]{laps_path}[/] "
                    f"[dim]({n} managed computer{'s' if n != 1 else ''})[/]"
                )
            except ImportError:
                print(f"[+] LAPS scope saved: {laps_path} ({n} computers)")

    viable = any(r.viability in ("VIABLE", "PARTIAL") for r in results)
    return 0 if viable else 1


if __name__ == "__main__":
    sys.exit(main())
