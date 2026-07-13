"""
Check engine: discovers all attack modules, runs checks, returns AttackResults.
"""
from __future__ import annotations
import importlib
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .checks.base import AttackResult, CheckResult, Status
from .checks.relay_target_finder import RelayTargetSummary, run_relay_target_finder, relay_target_results
from .config import TargetEnv

# Default cap on how many attack modules run at once in --parallel mode. One thread
# per module (13) can overwhelm the DC/network so per-check subprocess probes
# (nxc/certipy) hit --timeout and SKIP, making --parallel under-report vs sequential
# (2026-07-08 GOAD Part F). A bounded pool reduces that burst (and is quieter). This
# is a conservative starting point, not a tuned value — override with --max-parallel
# if probes still time out (raise --timeout) or to go faster on a resilient DC.
DEFAULT_MAX_PARALLEL = 5

ATTACK_MODULES = [
    ("ntlm_relay_checker.checks.smb",               "NTLM Relay → SMB (secretsdump)"),        # 0  smb
    ("ntlm_relay_checker.checks.ldap_rbcd",          "NTLM Relay → LDAP (RBCD)"),              # 1  rbcd
    ("ntlm_relay_checker.checks.ldap_shadowcreds",   "NTLM Relay → LDAP (Shadow Credentials)"),# 2  shadowcreds
    ("ntlm_relay_checker.checks.adcs",               "NTLM Relay → ADCS (ESC8)"),              # 3  adcs
    ("ntlm_relay_checker.checks.esc11",              "NTLM Relay → ADCS (ESC11 / RPC)"),       # 4  esc11
    ("ntlm_relay_checker.checks.mssql",              "NTLM Relay → MSSQL"),                    # 5  mssql
    ("ntlm_relay_checker.checks.kerberos",           "Kerberos Relay → ADCS (krbrelayx + Forshaw DNS)"), # 6  kerberos
    ("ntlm_relay_checker.checks.laps",               "NTLM Relay → LDAP (LAPS Password Dump)"),# 7  laps
    ("ntlm_relay_checker.checks.ldaps_addcomputer",  "NTLM Relay → LDAPS (Add Computer Account)"), # 8  addcomputer
    ("ntlm_relay_checker.checks.ldaps_aclabuse",     "NTLM Relay → LDAPS (ACL Abuse)"),        # 9  acl
    ("ntlm_relay_checker.checks.sccm_takeover",      "NTLM Relay → SCCM (TAKEOVER-1/2)"),      # 10 sccm_takeover
    ("ntlm_relay_checker.checks.sccm_elevate2",      "NTLM Relay → SCCM (ELEVATE-2)"),         # 11 sccm_elevate2
    ("ntlm_relay_checker.checks.ldap_dns",           "NTLM Relay → LDAP (ADIDNS Spoofing)"),   # 12 adidns
]


def run_all_checks(
    env: TargetEnv,
    progress_callback: Callable[[str, str, CheckResult], None] | None = None,
    modules: list | None = None,
    delay: int = 0,
    jitter: int = 0,
    module_started_callback: Callable[[str, int, int], None] | None = None,
    module_finished_callback: Callable[[str, AttackResult], None] | None = None,
) -> list[AttackResult]:
    import time, random
    active = list(modules if modules is not None else ATTACK_MODULES)
    if delay > 0:
        random.shuffle(active)
    results: list[AttackResult] = []
    total = len(active)

    for i, (mod_path, attack_name) in enumerate(active):
        if module_started_callback:
            module_started_callback(attack_name, i + 1, total)

        try:
            mod = importlib.import_module(mod_path)
        except ImportError as e:
            ar = AttackResult(attack_name=attack_name)
            ar.checks.append(CheckResult(
                name="Module load", status=Status.ERROR,
                detail=f"Failed to import check module: {e}",
            ))
            results.append(ar)
            if module_finished_callback:
                module_finished_callback(attack_name, ar)
            continue

        checks = mod.get_checks(env)
        ar = AttackResult(attack_name=attack_name)
        ar.viability_fn = getattr(mod, "module_viability", None)

        blocked_by: str | None = None
        for check in checks:
            if blocked_by is not None:
                # A prior gatekeeper failed — skip remaining checks
                ar.checks.append(CheckResult(
                    name=check.name, status=Status.SKIP,
                    detail=f"Skipped — {blocked_by} failed (prerequisite not met).",
                    required=check.required,
                ))
                continue
            check_result = check.run()
            ar.checks.append(check_result)
            if progress_callback:
                progress_callback(attack_name, check_result.name, check_result)
            if (check_result.status == Status.FAIL
                    and check.required
                    and check.breaks_on_fail):
                blocked_by = check.name

        results.append(ar)
        if module_finished_callback:
            module_finished_callback(attack_name, ar)

        # Apply delay + jitter between modules (not after the last one)
        if delay > 0 and i < len(active) - 1:
            sleep_time = delay + (random.randint(0, jitter) if jitter > 0 else 0)
            time.sleep(sleep_time)

    return results


def run_checks_parallel(
    env: TargetEnv,
    progress_callback: Callable[[str, str, CheckResult], None] | None = None,
    modules: list | None = None,
    module_finished_callback: Callable[[str, AttackResult], None] | None = None,
    max_workers: int | None = None,
) -> list[AttackResult]:
    """Run modules concurrently on a BOUNDED thread pool.

    At most ``max_workers`` modules run at once (default DEFAULT_MAX_PARALLEL),
    instead of one thread per module firing all at once — the latter overwhelmed the
    DC and made per-check nxc/certipy probes time out → SKIP, under-reporting vs
    sequential. Results keep input order; callbacks are unchanged. max_workers <= 0
    or None → default; it is also capped at the module count.
    """
    active = modules if modules is not None else ATTACK_MODULES
    results: list[AttackResult | None] = [None] * len(active)
    lock = threading.Lock()

    def run_attack(idx: int, mod_path: str, attack_name: str) -> None:
        try:
            mod = importlib.import_module(mod_path)
        except ImportError as e:
            ar = AttackResult(attack_name=attack_name)
            ar.checks.append(CheckResult(
                name="Module load", status=Status.ERROR,
                detail=f"Import error: {e}",
            ))
            results[idx] = ar
            if module_finished_callback:
                with lock:
                    module_finished_callback(attack_name, ar)
            return

        checks = mod.get_checks(env)
        ar = AttackResult(attack_name=attack_name)
        ar.viability_fn = getattr(mod, "module_viability", None)

        blocked_by: str | None = None
        for check in checks:
            if blocked_by is not None:
                ar.checks.append(CheckResult(
                    name=check.name, status=Status.SKIP,
                    detail=f"Skipped — {blocked_by} failed (prerequisite not met).",
                    required=check.required,
                ))
                continue
            check_result = check.run()
            ar.checks.append(check_result)
            if progress_callback:
                with lock:
                    progress_callback(attack_name, check_result.name, check_result)
            if (check_result.status == Status.FAIL
                    and check.required
                    and check.breaks_on_fail):
                blocked_by = check.name

        results[idx] = ar
        if module_finished_callback:
            with lock:
                module_finished_callback(attack_name, ar)

    # Bounded pool: at most `workers` modules run concurrently. The pool's context
    # exit waits for every submitted task (equivalent to joining all threads).
    if not max_workers or max_workers <= 0:
        max_workers = DEFAULT_MAX_PARALLEL
    workers = max(1, min(max_workers, len(active)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, (mod_path, attack_name) in enumerate(active):
            pool.submit(run_attack, i, mod_path, attack_name)

    return [r for r in results if r is not None]


__all__ = [
    "run_all_checks",
    "run_checks_parallel",
    "run_relay_target_finder",
    "relay_target_results",
    "RelayTargetSummary",
]
