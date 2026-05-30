"""
Check engine: discovers all attack modules, runs checks, returns AttackResults.
"""
from __future__ import annotations
import importlib
import threading
from typing import Callable

from .checks.base import AttackResult, CheckResult, Status
from .checks.relay_target_finder import RelayTargetSummary, run_relay_target_finder
from .config import TargetEnv

ATTACK_MODULES = [
    ("ntlm_relay_checker.checks.smb",               "NTLM Relay → SMB (secretsdump)"),
    ("ntlm_relay_checker.checks.ldap_rbcd",          "NTLM Relay → LDAP (RBCD)"),
    ("ntlm_relay_checker.checks.ldap_shadowcreds",   "NTLM Relay → LDAP (Shadow Credentials)"),
    ("ntlm_relay_checker.checks.adcs",               "NTLM Relay → ADCS (ESC8)"),
    ("ntlm_relay_checker.checks.mssql",              "NTLM Relay → MSSQL"),
    ("ntlm_relay_checker.checks.webdav",             "NTLM Relay → HTTP/WebDAV"),
    ("ntlm_relay_checker.checks.kerberos",           "Kerberos Relay → ADCS (krbrelayx + Forshaw DNS)"),
    ("ntlm_relay_checker.checks.esc11",              "NTLM Relay → ADCS (ESC11 / RPC)"),
    ("ntlm_relay_checker.checks.laps",               "NTLM Relay → LDAP (LAPS Password Dump)"),
    ("ntlm_relay_checker.checks.ldaps_addcomputer",  "NTLM Relay → LDAPS (Add Computer Account)"),
    ("ntlm_relay_checker.checks.ldaps_aclabuse",     "NTLM Relay → LDAPS (ACL Abuse)"),
]


def run_all_checks(
    env: TargetEnv,
    progress_callback: Callable[[str, str, CheckResult], None] | None = None,
    modules: list | None = None,
    delay: int = 0,
    jitter: int = 0,
) -> list[AttackResult]:
    import time, random
    active = list(modules if modules is not None else ATTACK_MODULES)
    if delay > 0:
        random.shuffle(active)
    results: list[AttackResult] = []

    for i, (mod_path, attack_name) in enumerate(active):
        try:
            mod = importlib.import_module(mod_path)
        except ImportError as e:
            ar = AttackResult(attack_name=attack_name)
            ar.checks.append(CheckResult(
                name="Module load", status=Status.ERROR,
                detail=f"Failed to import check module: {e}",
            ))
            results.append(ar)
            continue

        checks = mod.get_checks(env)
        ar = AttackResult(attack_name=attack_name)

        for check in checks:
            check_result = check.run()
            ar.checks.append(check_result)
            if progress_callback:
                progress_callback(attack_name, check_result.name, check_result)

        results.append(ar)

        # Apply delay + jitter between modules (not after the last one)
        if delay > 0 and i < len(active) - 1:
            sleep_time = delay + (random.randint(0, jitter) if jitter > 0 else 0)
            time.sleep(sleep_time)

    return results


def run_checks_parallel(
    env: TargetEnv,
    progress_callback: Callable[[str, str, CheckResult], None] | None = None,
    modules: list | None = None,
) -> list[AttackResult]:
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
            return

        checks = mod.get_checks(env)
        ar = AttackResult(attack_name=attack_name)

        for check in checks:
            check_result = check.run()
            ar.checks.append(check_result)
            if progress_callback:
                with lock:
                    progress_callback(attack_name, check_result.name, check_result)

        results[idx] = ar

    threads = []
    for i, (mod_path, attack_name) in enumerate(active):
        t = threading.Thread(target=run_attack, args=(i, mod_path, attack_name), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return [r for r in results if r is not None]


__all__ = [
    "run_all_checks",
    "run_checks_parallel",
    "run_relay_target_finder",
    "RelayTargetSummary",
]
