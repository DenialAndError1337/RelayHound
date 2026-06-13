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


@dataclass
class CheckResult:
    name: str                        # e.g. "SMB signing disabled"
    status: Status
    detail: str = ""                 # human-readable explanation
    required: bool = True            # False → failure → PARTIAL not NOT_VIABLE
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
        if not self.checks:
            return "UNKNOWN"
        # Any required check failed → NOT VIABLE
        for c in self.checks:
            if c.required and c.status == Status.FAIL:
                return "NOT VIABLE"
        # All required checks pass or warn
        # If any optional check failed → PARTIAL
        for c in self.checks:
            if not c.required and c.status == Status.FAIL:
                return "PARTIAL"
        # If any required check is SKIP/ERROR → PARTIAL
        for c in self.checks:
            if c.required and c.status in (Status.SKIP, Status.ERROR):
                return "PARTIAL"
        return "VIABLE"

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
