#!/usr/bin/env bash
#
# RelayHound health check — run this FIRST in any session, before trusting results.
# Confirms the tree is intact and in sync: fingerprint invariant, ruff F-set, and the
# full regression suite. Exits 0 only if everything passes.
#
#   cd RelayHound && ./check.sh
#
# Deps (sandbox): pip install impacket ldap3 ruff --break-system-packages
#
set -uo pipefail
cd "$(dirname "$0")"
export PYTHONPATH=.

fail=0

echo "== 1. verify.py (13 modules / 92 checks / fingerprint) =="
if python3 verify.py; then
    echo "   -> verify OK"
else
    echo "   -> verify FAILED — tree is out of sync or a check changed. STOP and investigate."
    fail=1
fi
echo

echo "== 2. ruff F-set (pyflakes: undefined names, unused imports) =="
if python3 -m ruff check --select F ntlm_relay_checker/; then
    echo "   -> ruff F clean"
else
    echo "   -> ruff F FAILED"
    fail=1
fi
echo

echo "== 3. regression suite (tests/) =="
tpass=0; tfail=0
for t in tests/test_*.py; do
    if python3 "$t" >/dev/null 2>&1; then
        tpass=$((tpass+1)); printf "   PASS  %s\n" "$(basename "$t")"
    else
        tfail=$((tfail+1)); printf "   FAIL  %s   <-- re-run for detail: PYTHONPATH=. python3 %s\n" "$(basename "$t")" "$t"
        fail=1
    fi
done
echo "   -> $tpass passed, $tfail failed"
echo

if [ "$fail" -eq 0 ]; then
    echo "ALL GREEN — tree is healthy and in sync. Safe to proceed."
else
    echo "NOT GREEN — do not trust lab verdicts or make changes until this is resolved."
fi
exit "$fail"
