"""
Output: Rich terminal table + Markdown report writer.
"""
from __future__ import annotations
import os
import sys
from datetime import datetime
from typing import Optional

from .checks.base import AttackResult, Status
from .checks.relay_target_finder import RelayTargetSummary

# ── Rich availability ──────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
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


# ── terminal output ────────────────────────────────────────────────────────

def print_summary_table(results: list[AttackResult], verbose: bool = False) -> None:
    """Print a summary table: one row per attack."""
    if RICH_AVAILABLE:
        _print_rich_summary(results, verbose)
    else:
        _print_plain_summary(results, verbose)


def _print_rich_summary(results: list[AttackResult], verbose: bool) -> None:
    console = Console()

    console.print()
    console.print(Panel.fit(
        "[bold white]NTLM Relay Prerequisite Checker[/]\n"
        "[dim]Attack viability summary[/]",
        border_style="blue",
    ))
    console.print()

    # ── Summary table ──────────────────────────────────────────────
    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        expand=True,
    )
    tbl.add_column("Attack",            style="bold white", min_width=38)
    tbl.add_column("Viable?",           justify="center",   min_width=14)
    tbl.add_column("Failed Prerequisites",                  min_width=38)
    tbl.add_column("Warnings / Skipped",                    min_width=30)

    for ar in results:
        style, label = VIABILITY_STYLE.get(ar.viability, ("dim", ar.viability))
        failed  = ", ".join(ar.missing)   or "—"
        skipped = ", ".join(ar.skipped)   or "—"
        tbl.add_row(
            ar.attack_name,
            Text(label, style=style),
            Text(failed,  style="red"  if ar.missing else "dim"),
            Text(skipped, style="yellow" if ar.skipped else "dim"),
        )

    console.print(tbl)

    if not verbose:
        console.print(
            "\n[dim]Run with [bold]-v[/bold] for per-check details.[/]"
        )
        return

    # ── Per-attack detail tables ───────────────────────────────────
    # One shared table across all attacks so column widths are consistent
    console.print()
    dtbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    dtbl.add_column("Attack / Check", min_width=44, no_wrap=False)
    dtbl.add_column("Required", justify="center", min_width=9, max_width=9)
    dtbl.add_column("Status", justify="center", min_width=10, max_width=10)
    dtbl.add_column("Details", min_width=40, no_wrap=False)

    for ar in results:
        style, label = VIABILITY_STYLE.get(ar.viability, ("dim", ar.viability))
        # Attack header row — spans as a section divider
        dtbl.add_row(
            f"[bold white]{ar.attack_name}[/]",
            "",
            Text(label, style=style),
            "",
        )
        for c in ar.checks:
            cstyle, clabel = STATUS_STYLE.get(c.status, ("dim", str(c.status)))
            req_label = "[dim]opt[/dim]" if not c.required else ""
            # Guard: coerce detail to str in case a module accidentally returns
            # a tuple or other non-string value
            detail_str = c.detail if isinstance(c.detail, str) else str(c.detail)
            dtbl.add_row(
                f"  {c.name}",
                req_label,
                Text(clabel, style=cstyle),
                detail_str,
            )
        # Blank separator row between attacks
        dtbl.add_row("", "", "", "")

    console.print(dtbl)


def _print_plain_summary(results: list[AttackResult], verbose: bool) -> None:
    """Fallback plain-text output when Rich is not installed."""
    sep = "=" * 80
    print(f"\n{sep}")
    print("  NTLM RELAY PREREQUISITE CHECKER — SUMMARY")
    print(sep)
    print(f"{'Attack':<42} {'Viable?':<14} {'Failed Prerequisites'}")
    print("-" * 80)

    for ar in results:
        _, label = VIABILITY_STYLE.get(ar.viability, ("", ar.viability))
        # Strip emoji for plain
        label = label.replace("✅ ", "").replace("⚠️  ", "").replace("❌ ", "").replace("❓ ", "")
        failed = ", ".join(ar.missing) or "none"
        print(f"{ar.attack_name:<42} {label:<14} {failed}")

    if verbose:
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
        "[bold white]Relay Target Candidates[/]\n"
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
    print("  RELAY TARGET CANDIDATES")
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

    # ── Executive summary table ────────────────────────────────────
    a("## Executive Summary")
    a("")
    a("| Attack | Viability | Failed Prerequisites |")
    a("|--------|-----------|----------------------|")

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
        a(f"| {ar.attack_name} | {md_label} | {failed} |")

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

    # ── Relay target candidates ────────────────────────────────────
    if relay_target_summary is not None:
        a("---")
        a("")
        a("## Relay Target Candidates")
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
    a("*Report generated by RelayRecon. "
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
            # in a NOT VIABLE attack doesn't mean that specific vector is exploitable
            if ar.viability == "NOT VIABLE":
                continue
            for keyword, rec in remediations.items():
                if keyword in c.name.lower() and keyword not in seen:
                    recs.append((c.name, rec))
                    seen.add(keyword)

    if not recs:
        recs.append(("No exploitable findings", "No viable attack prerequisites confirmed. Environment appears hardened against the checked attack vectors."))

    return recs



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


# ── Progress display ───────────────────────────────────────────────────────

class CheckProgress:
    """Live progress display for checks as they run."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._console = Console(stderr=True) if RICH_AVAILABLE else None
        self._current_attack = ""

    def update(self, attack_name: str, check_name: str, result) -> None:
        if not self.verbose and not RICH_AVAILABLE:
            # Print a simple dot
            print(".", end="", flush=True)
            return

        if RICH_AVAILABLE and self.verbose:
            style, label = STATUS_STYLE.get(result.status, ("dim", str(result.status)))
            if attack_name != self._current_attack:
                self._console.print(f"\n[bold cyan]▶ {attack_name}[/]")
                self._current_attack = attack_name
            self._console.print(
                f"  [{style}]{label:<8}[/] {check_name}",
                highlight=False,
            )
        elif RICH_AVAILABLE:
            if attack_name != self._current_attack:
                self._console.print(f"[dim]Checking:[/] [cyan]{attack_name}[/]...",
                                    end="", highlight=False)
                self._current_attack = attack_name


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

    # ── relay target candidates section ───────────────────────────
    relay_targets_html = ""
    if relay_target_summary is not None:
        if relay_target_summary.skipped:
            relay_targets_html = f"""
  <h2>Relay Target Candidates</h2>
  <p style="color:#f6ad55;font-size:13px;">⚠ Skipped: {esc(relay_target_summary.skipped)}</p>"""
        elif relay_target_summary.error:
            relay_targets_html = f"""
  <h2>Relay Target Candidates</h2>
  <p style="color:#fc8181;font-size:13px;">✗ Error: {esc(relay_target_summary.error)}</p>"""
        elif not relay_target_summary.entries:
            relay_targets_html = """
  <h2>Relay Target Candidates</h2>
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
  <h2>Relay Target Candidates</h2>
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

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RelayRecon Report — {domain}</title>
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
  .detail-cell {{ color: #a0aec0; font-size: 12px; max-width: 420px; }}

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
    <h1>🔍 RelayRecon — NTLM Relay Prerequisite Report</h1>
    <div class="meta-grid">
      <div class="meta-item"><strong>Generated:</strong> {now}</div>
      <div class="meta-item"><strong>Domain:</strong> <code>{domain}</code></div>
      <div class="meta-item"><strong>DC IP:</strong> <code>{dc_ip}</code></div>
      <div class="meta-item"><strong>Credentials:</strong> <code>{user}</code></div>
      <div class="meta-item"><strong>Extra Targets:</strong> <code>{esc(extra_targets)}</code></div>
    </div>
  </div>

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

  <!-- Relay Target Candidates -->
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
    Report generated by <strong>RelayRecon</strong> — Manual verification recommended for WARN/SKIP findings.
  </div>

</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
