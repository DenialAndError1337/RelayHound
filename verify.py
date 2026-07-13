#!/usr/bin/env python3
"""
RelayHound verification harness.

Asserts the invariants documented in the session handoff:
  - 13 attack modules, 90 checks total
  - fingerprint == 62bf486a0c5709275b7127afb5dfded8
    (md5 of every check's .name joined by '\n' in module/check order;
     `required` flags are NOT part of it)
  - py_compile clean on all source
  - ruff F-set clean (run separately in the shell)

Run:  cd <repo> && PYTHONPATH=. python3 verify.py
"""
from __future__ import annotations
import hashlib
import importlib
import sys

from ntlm_relay_checker.engine import ATTACK_MODULES
from ntlm_relay_checker.config import TargetEnv, Credential

EXPECTED_MODULES = 13
# 2026-07-03: ACL Abuse gained its plain-ldap:// path — added LdapSigningCheck +
# NtlmV1AuthProbeCheck (90 → 92). Deliberate fingerprint move (OR rework item #1).
# 2026-07-04: LAPS checks renamed off legacy-only wording ("ms-Mcs-AdmPwd …")
# to legacy + Windows LAPS. Count unchanged (92); deliberate fingerprint move.
EXPECTED_CHECKS = 92
EXPECTED_FINGERPRINT = "ea76ae8cc42fe4e5012d0e9485d11f29"


def build_env() -> TargetEnv:
    """A neutral env; get_checks() must not perform I/O at construction time."""
    cred = Credential(domain="test.local", username="alice", password="Passw0rd")
    return TargetEnv(
        domain="test.local",
        dc_ip="127.0.0.1",
        cred=cred,
        extra_targets=[],
        attacker_ip="127.0.0.2",
        attacker_hostname="ATTACKER",
        timeout=1,
    )


def collect() -> list[tuple[str, list[str]]]:
    env = build_env()
    out: list[tuple[str, list[str]]] = []
    for mod_path, attack_name in ATTACK_MODULES:
        mod = importlib.import_module(mod_path)
        checks = mod.get_checks(env)
        names = [c.name for c in checks]
        out.append((attack_name, names))
    return out


def main() -> int:
    modules = collect()
    n_modules = len(modules)
    all_names: list[str] = []
    for _, names in modules:
        all_names.extend(names)
    n_checks = len(all_names)

    fingerprint = hashlib.md5("\n".join(all_names).encode()).hexdigest()

    ok = True
    print(f"modules      : {n_modules}  (expected {EXPECTED_MODULES})")
    if n_modules != EXPECTED_MODULES:
        ok = False
        print("  ^^ MODULE COUNT MISMATCH")

    print(f"checks       : {n_checks}  (expected {EXPECTED_CHECKS})")
    if n_checks != EXPECTED_CHECKS:
        ok = False
        print("  ^^ CHECK COUNT MISMATCH")

    print(f"fingerprint  : {fingerprint}")
    print(f"expected     : {EXPECTED_FINGERPRINT}")
    if fingerprint != EXPECTED_FINGERPRINT:
        ok = False
        print("  ^^ FINGERPRINT MISMATCH")

    if not ok:
        print("\nPer-module check counts:")
        for name, names in modules:
            print(f"  {len(names):>2}  {name}")

    print("\n" + ("PASS — all invariants hold" if ok else "FAIL — invariants broken"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
