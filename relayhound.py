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
    run_all_checks,
    run_checks_parallel,
    run_relay_target_finder,
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
  python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv --nt-hash aad3b435b51404eeaad3b435b51404ee:HASH

  # Find which accounts are worth coercing and for which attack
  python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --find-relay-targets
        """,
    )

    # Target
    tgt = p.add_argument_group("Target")
    tgt.add_argument("-d", "--domain",   required=True,
                     help="Target domain (e.g. corp.local)")
    tgt.add_argument("--dc-ip",          required=True,
                     help="Primary Domain Controller IP")
    tgt.add_argument("--extra-targets",  default="",
                     help="Comma-separated IPs, hostnames, CIDR ranges, or dash ranges")
    tgt.add_argument("--attacker-ip",    default=None,
                     help="Attacker/relay listener IP (your Kali box)")

    # Credentials
    cred = p.add_argument_group("Credentials")
    cred.add_argument("-u", "--username", required=True,
                      help="Domain username (low-privilege)")
    cred_exc = cred.add_mutually_exclusive_group(required=True)
    cred_exc.add_argument("-p", "--password", default=None,
                          help="Plaintext password")
    cred_exc.add_argument("--nt-hash",   default=None,
                          help="NT hash for pass-the-hash (format: AABBCC...)")

    # Options
    opts = p.add_argument_group("Options")
    opts.add_argument("-v", "--verbose",  action="store_true",
                      help="Show per-check details in terminal output")
    opts.add_argument("--parallel",       action="store_true",
                      help="Run attack checks in parallel (faster, noisier)")
    opts.add_argument("--modules",        default=None,
                      help="Comma-separated list of module short names to run "
                           "(e.g. smb,rbcd,adcs). Invalid names print valid aliases and exit.")
    opts.add_argument("--delay",          type=int, default=0,
                      help="Sleep N seconds between each attack module (default: 0)")
    opts.add_argument("--jitter",         type=int, default=0,
                      help="Add up to N seconds of random variation to the delay (default: 0)")
    opts.add_argument("--timeout",        type=int, default=10,
                      help="Network timeout in seconds (default: 10)")
    opts.add_argument("-o", "--output",   default=None,
                      help="Save Markdown report to this file")
    opts.add_argument("--targets-file",  default=None,
                      help="File with target IPs/ranges, one per line (# for comments)")
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
    opts.add_argument("--find-relay-targets", action="store_true",
                      help=(
                          "Scan nTSecurityDescriptor ACLs on computer objects, "
                          "the domain root, and high-value groups to identify "
                          "which accounts are worth coercing for RBCD, Shadow Creds, "
                          "LAPS, or ACL Abuse relay attacks. "
                          "Runs as the enumeration credential — no extra passwords needed."
                      ))

    return p


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


def _load_targets(args_extra: str, targets_file: str | None) -> list[str]:
    raw_tokens = []
    if args_extra:
        raw_tokens.extend(args_extra.split(","))
    if targets_file:
        try:
            with open(targets_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw_tokens.extend(line.split(","))
        except FileNotFoundError:
            print(f"[!] Targets file not found: {targets_file}")
            sys.exit(1)
    return _expand_targets(",".join(raw_tokens))


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

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
        "mssql":         4,
        "webdav":        5,
        "kerberos":      6,
        "esc11":         7,
        "laps":          8,
        "addcomputer":   9,
        "acl":          10,
    }

    if args.modules:
        requested = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
        invalid = [m for m in requested if m not in MODULE_ALIASES]
        if invalid:
            print(f"[!] Unknown module(s): {', '.join(invalid)}")
            print(f"    Valid names: {', '.join(MODULE_ALIASES)}")
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

    extra = _load_targets(args.extra_targets, args.targets_file)

    env = TargetEnv(
        domain=args.domain,
        dc_ip=args.dc_ip,
        cred=cred,
        extra_targets=extra,
        attacker_ip=args.attacker_ip,
        timeout=args.timeout,
        verbose=args.verbose,
        find_relay_targets=args.find_relay_targets,
    )

    # ── Print run config ───────────────────────────────────────────
    try:
        from rich.console import Console
        from rich.panel import Panel
        c = Console()
        c.print(Panel(
            f"[bold]Domain:[/]           [cyan]{env.domain}[/]\n"
            f"[bold]DC IP:[/]            [cyan]{env.dc_ip}[/]\n"
            f"[bold]User:[/]             [cyan]{cred.upn}[/]\n"
            f"[bold]Auth:[/]             {'NT hash' if cred.nt_hash else 'Password'}\n"
            f"[bold]Extra targets:[/]    {', '.join(extra) or 'none'}\n"
            f"[bold]Attacker IP:[/]      {env.attacker_ip or 'not specified'}\n"
            f"[bold]Timeout:[/]          {env.timeout}s\n"
            f"[bold]Mode:[/]             {'parallel' if args.parallel else 'sequential'}\n"
            f"[bold]Modules:[/]          {args.modules or 'all'}\n"
            f"[bold]Delay / jitter:[/]   {args.delay}s / {args.jitter}s\n"
            f"[bold]Find relay targets:[/] {'yes' if args.find_relay_targets else 'no'}",
            title="Run Configuration",
            border_style="blue",
        ))
    except ImportError:
        print(f"[*] Domain:  {env.domain}")
        print(f"[*] DC IP:   {env.dc_ip}")
        print(f"[*] User:    {cred.upn}")
        print(f"[*] Targets: {env.all_targets}")

    # ── Run checks ─────────────────────────────────────────────────
    import random
    progress = CheckProgress(verbose=args.verbose)

    print()
    start = time.time()

    if args.parallel:
        results = run_checks_parallel(env, progress_callback=progress.update,
                                      modules=active_modules)
    else:
        results = run_all_checks(env, progress_callback=progress.update,
                                 modules=active_modules,
                                 delay=args.delay, jitter=args.jitter)

    # ── Run relay target finder (if requested) ─────────────────────
    relay_target_summary = None
    if args.find_relay_targets:
        try:
            from rich.console import Console
            Console().print("\n[dim]Scanning ACLs for relay target candidates...[/]")
        except ImportError:
            print("\n[*] Scanning ACLs for relay target candidates...")
        relay_target_summary = run_relay_target_finder(env)

    elapsed = time.time() - start
    print()

    # env_summary used by attack paths, reports, and JSON
    env_summary = {
        "domain":        env.domain,
        "dc_ip":         env.dc_ip,
        "user":          cred.upn,
        "attacker_ip":   env.attacker_ip,
        "extra_targets": extra,
    }

    # ── Print terminal summary ─────────────────────────────────────
    # Order: summary table → attack paths → relay targets → verbose details
    print_summary_table(results)
    print_attack_paths(results, env_summary, relay_target_summary)

    if relay_target_summary is not None:
        print_relay_target_summary(relay_target_summary)

    print_verbose_details(results, verbose=args.verbose)

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
            html_path = out_path.replace(".md", ".html")
            if not html_path.endswith(".html"):
                html_path += ".html"
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

    viable = any(r.viability in ("VIABLE", "PARTIAL") for r in results)
    return 0 if viable else 1


if __name__ == "__main__":
    sys.exit(main())
