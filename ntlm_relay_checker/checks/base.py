"""
Base classes for all prerequisite checks.
"""
from __future__ import annotations
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Status(Enum):
    PASS   = "PASS"    # prerequisite met
    FAIL   = "FAIL"    # prerequisite not met (blocks attack)
    WARN   = "WARN"    # partially met / uncertain
    SKIP   = "SKIP"    # could not be tested (no tool, timeout, etc.)
    ERROR  = "ERROR"   # unexpected exception during check


# Sentinel for CheckResult.required meaning "not set by _run() — inherit the
# check's class-level default in BaseCheck.run()". It is deliberately TRUTHY, so
# that on the (unusual) path where a CheckResult is aggregated without going
# through run(), the historical "required by default" behavior is preserved
# (viability_over reads `required` as a truthy flag). run() resolves it to a real
# bool for every check that flows through the engine.
_REQUIRED_UNSET = object()


@dataclass
class CheckResult:
    name: str                        # e.g. "SMB signing disabled"
    status: Status
    detail: str = ""                 # human-readable explanation
    # True/False → this result's own required flag (honored by run()).
    # Left unset → _REQUIRED_UNSET → run() fills it from the check's class default.
    required: bool = _REQUIRED_UNSET
    raw: Optional[str] = None        # raw output snippet for debug


@dataclass
class AttackResult:
    attack_name: str
    checks: list[CheckResult] = field(default_factory=list)
    # Optional per-module override. When set, the engine attaches the module's
    # `module_viability(ar)` function here so a module can express verdict logic
    # the generic status-aggregation can't (e.g. alternative OR-related paths).
    # When None, the generic aggregation below is used.
    viability_fn: Optional[Callable[["AttackResult"], str]] = None

    @property
    def viability(self) -> str:
        if self.viability_fn is not None:
            return self.viability_fn(self)
        return self._generic_viability()

    def _generic_viability(self) -> str:
        return viability_over(self.checks)

    @property
    def missing(self) -> list[str]:
        """Required checks that FAIL — these block the attack."""
        return [c.name for c in self.checks if c.status == Status.FAIL and c.required]

    @property
    def optional_failed(self) -> list[str]:
        """Optional checks that FAIL — reduce impact but don't block."""
        return [c.name for c in self.checks if c.status == Status.FAIL and not c.required]

    @property
    def skipped(self) -> list[str]:
        return [c.name for c in self.checks if c.status in (Status.SKIP, Status.ERROR)]


# ── Verdict aggregation ─────────────────────────────────────────────────────

def viability_over(checks: "list[CheckResult]") -> str:
    """Generic status-aggregation over an arbitrary subset of checks.

    `AttackResult._generic_viability()` is exactly `viability_over(self.checks)`.
    Factored out so a module's custom `module_viability` can aggregate over a
    *subset* — e.g. the OR relay modules evaluate their non-channel prerequisites
    with this after deciding relay-path survivability separately.
    """
    if not checks:
        return "UNKNOWN"
    # Any required check failed → NOT VIABLE
    for c in checks:
        if c.required and c.status == Status.FAIL:
            return "NOT VIABLE"
    # No required FAIL; any optional FAIL → PARTIAL
    for c in checks:
        if not c.required and c.status == Status.FAIL:
            return "PARTIAL"
    # No FAILs remain; each required check is PASS/WARN/SKIP/ERROR.
    required   = [c for c in checks if c.required]
    untestable = [c for c in required if c.status in (Status.SKIP, Status.ERROR)]
    warned     = [c for c in required if c.status == Status.WARN]
    # Every required prerequisite un-testable → UNKNOWN (must not read as viable
    # nor render chains; _viable() excludes UNKNOWN).
    if required and len(untestable) == len(required):
        return "UNKNOWN"
    # A required prerequisite that is un-testable (SKIP/ERROR) OR only partially
    # confirmed (WARN) means the posture is NOT confirmed. WARN is defined as
    # "partially met / uncertain" (see Status), and the cardinal rule forbids a
    # confident VIABLE on an unconfirmed prerequisite — so floor at PARTIAL,
    # never VIABLE. Optional-check WARNs never reach here (they are not in
    # `required`); this only affects required checks whose posture is uncertain.
    if untestable or warned:
        return "PARTIAL"
    return "VIABLE"


# ── OR relay-path model (RBCD / Shadow Credentials / LAPS / ADIDNS) ──────────
#
# NTLM relay to LDAP survives if ANY ONE channel is open — they are *alternative*
# paths, not an AND:
#   • plain ldap://  — LDAP signing not enforced
#   • ldaps:// (TLS) — LDAP channel binding = Never
#   • NTLMv1         — NTLMv1 accepted (MIC-strippable → signing flags cleared)
# so blocking the relay needs BOTH signing AND channel binding. The three checks
# below are marked optional in each module (so the generic AND-aggregation doesn't
# gate on them); these helpers supply the OR and are attached as `module_viability`.
#
# NAME STABILITY: these strings must match the checks' .name exactly. Renaming any
# of them moves the verify.py fingerprint — change deliberately.
CHECK_LDAP_SIGNING = "LDAP signing not enforced"
CHECK_LDAP_CB      = "LDAP channel binding not required"
CHECK_NTLMV1       = "NTLMv1 authentication accepted (SMB→LDAP relay enabler)"
# LDAPS-native channel signals carried by the ACL Abuse module. Its TLS path is
# detected with an LDAPS/EPA probe under these names rather than the plain-LDAP
# CHECK_LDAP_CB, so recognizing them here lets ACL Abuse reuse this shared OR
# helper. The other OR modules (RBCD / Shadow / LAPS / ADIDNS) never carry these
# names, so their behaviour is unchanged.
CHECK_LDAPS_CB     = "LDAPS channel binding (EPA) not enforced"
CHECK_LDAPS_PORT   = "LDAPS reachable (port 636)"
# TLS-path openers: an explicit CB=Never PASS on either the plain-LDAP or the
# LDAPS-native channel-binding check.
_TLS_CB_CHECKS = (CHECK_LDAP_CB, CHECK_LDAPS_CB)
# All channel-related names — excluded from the non-channel prerequisite
# aggregation in _or_base_verdict. CHECK_LDAPS_PORT is a TLS-reachability signal
# (not itself a relay path); it is excluded from prereqs but does NOT count toward
# determinability (636 being down closes only the TLS sub-path).
_LDAP_CHANNEL_CHECKS = (CHECK_LDAP_SIGNING, CHECK_LDAP_CB, CHECK_LDAPS_CB,
                        CHECK_LDAPS_PORT, CHECK_NTLMV1)
# Signals whose explicit PASS/FAIL make the relay posture "determinable".
_DETERMINABLE_SIGNALS = (CHECK_LDAP_SIGNING, CHECK_LDAP_CB, CHECK_LDAPS_CB, CHECK_NTLMV1)


def _ldap_relay_paths(ar: "AttackResult") -> "tuple[bool, bool, bool, bool]":
    """(plain_ldap_open, tls_open, ntlmv1_open, any_channel_determinable).

    Only an explicit PASS counts as *open*. A signing SKIP is "couldn't determine",
    not open. For channel binding, PASS == "Never" (the only relayable state); CB
    "When Supported" (WARN) and "Always" (FAIL) both BLOCK the TLS path — lab-
    confirmed 2026-07-02 that a relayed no-CBT bind fails under "When Supported"
    despite the direct probe succeeding.

    ── FLIP POINT ── if a future lab run shows "When Supported" allows the relay,
    widen the `tls` line to also accept Status.WARN on the CB checks; nothing else
    changes.
    """
    by = {c.name: c.status for c in ar.checks}
    plain_ldap = by.get(CHECK_LDAP_SIGNING) == Status.PASS
    tls        = any(by.get(n) == Status.PASS for n in _TLS_CB_CHECKS)
    ntlmv1     = by.get(CHECK_NTLMV1)       == Status.PASS
    determinable = any(by.get(n) in (Status.PASS, Status.FAIL) for n in _DETERMINABLE_SIGNALS)
    return plain_ldap, tls, ntlmv1, determinable


def _or_base_verdict(ar: "AttackResult") -> str:
    """Shared OR verdict: relay survives if any channel is open, then the non-channel
    prerequisites decide. A confirmed-open channel is itself a positive signal, so the
    verdict is floored at PARTIAL — it never collapses to UNKNOWN just because the
    target-object prereqs were un-enumerable (e.g. signing blocks the tool's own LDAP
    read at the signing-enforced/CB-off posture, where the relay nonetheless works over
    TLS). No channel open → NOT VIABLE (all paths closed) or UNKNOWN (no channel even
    readable — dead DC / rejected creds)."""
    plain_ldap, tls, ntlmv1, determinable = _ldap_relay_paths(ar)
    if not (plain_ldap or tls or ntlmv1):
        return "NOT VIABLE" if determinable else "UNKNOWN"
    prereqs = [c for c in ar.checks if c.name not in _LDAP_CHANNEL_CHECKS]
    v = viability_over(prereqs)
    return "PARTIAL" if v == "UNKNOWN" else v


def ldap_or_relay_viability(ar: "AttackResult") -> str:
    """OR relay-path verdict for the attribute-write LDAP modules (Shadow
    Credentials / LAPS / ADIDNS)."""
    return _or_base_verdict(ar)


# RBCD-specific check names (for the delegate-creation constraint below).
CHECK_RBCD_WRITABLE_COMPUTER = "Writable computer object exists (msDS-AllowedToActOnBehalfOfOtherIdentity)"


def rbcd_or_relay_viability(ar: "AttackResult") -> str:
    """OR verdict for RBCD. Same channel-OR as the attribute-write modules for the
    RBCD attribute write, but RBCD also needs a DELEGATE computer account.

    Creating the delegate via the relay needs a confidential channel — ldaps://636
    or StartTLS-on-389 (lab-confirmed: `-t ldap://` auto-upgrades to StartTLS to
    create), both subject to channel binding. So with only the plain-`ldap://` /
    NTLMv1 path open (CB enforced), the RBCD attribute write works but the delegate
    cannot be created over the relay: unless a writable computer already exists to
    reuse as the delegate, that's PARTIAL (viable only if the operator supplies /
    pre-creates a delegate out-of-band), not VIABLE.
    """
    verdict = _or_base_verdict(ar)
    if verdict != "VIABLE":
        return verdict
    _, tls, _, _ = _ldap_relay_paths(ar)
    by = {c.name: c.status for c in ar.checks}
    # Delegate obtainable: create over a TLS channel (CB=Never) OR reuse a
    # pre-existing writable computer.
    if tls or by.get(CHECK_RBCD_WRITABLE_COMPUTER) == Status.PASS:
        return "VIABLE"
    return "PARTIAL"


class BaseCheck(ABC):
    """Abstract base for all checks."""

    def __init__(self, env: "TargetEnv"):  # noqa: F821
        self.env = env

    @property
    @abstractmethod
    def name(self) -> str:
        """Short human-readable name for this check."""

    @property
    def required(self) -> bool:
        """Whether failure of this check makes the attack not viable."""
        return True

    @property
    def breaks_on_fail(self) -> bool:
        """
        If True and this check FAILs, the engine stops running remaining
        checks in this module. Subsequent checks are recorded as SKIP with
        a note explaining why. Only meaningful when required=True.
        Use for hard gatekeepers where all downstream checks are pointless
        if this one fails (e.g. ADCS not deployed, SCCM not present).
        """
        return False

    @abstractmethod
    def _run(self) -> CheckResult:
        """Implement the actual check logic here."""

    def run(self) -> CheckResult:
        try:
            result = self._run()
            # Honor a required flag the _run() explicitly set on its result; only
            # fall back to the class-level default when _run() left it unset. The
            # previous code unconditionally overwrote result.required, silently
            # discarding any per-result required= — a latent debugging trap. No
            # current check varies required per-branch, so this changes nothing
            # today; it makes per-result required work for checks that need it
            # (e.g. "required only when the failure is confirmed vs uncertain").
            if result.required is _REQUIRED_UNSET:
                result.required = self.required
            return result
        except Exception as exc:
            return CheckResult(
                name=self.name,
                status=Status.ERROR,
                detail=f"Exception: {exc}",
                required=self.required,
                raw=traceback.format_exc(),
            )
