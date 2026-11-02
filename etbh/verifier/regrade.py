"""Re-grade an agent patch in a clean, hardened sandbox."""

from __future__ import annotations

from typing import TYPE_CHECKING

from etbh.hardening.profiles import AFTER, Hardening

if TYPE_CHECKING:
    from etbh.adapters.base import BenchmarkAdapter, GradeResult, Sandbox, TaskSpec


def clean_regrade(
    adapter: BenchmarkAdapter,
    task: TaskSpec,
    patch: str,
    hardened_sandbox: Sandbox,
    hardening: Hardening = AFTER,
) -> GradeResult:
    """Apply `patch` to a pristine hardened sandbox and grade under `hardening`.

    The caller provides the sandbox so that a single pristine image can be reused and so
    tests can pass a FakeSandbox. The diff is handed to grade() for the structural check.
    """
    applied = adapter.apply_patch(hardened_sandbox, patch)
    if not applied.ok:
        from etbh.adapters.base import GradeResult as _GR

        return _GR(passed=False, exit_code=applied.exit_code, raw=applied.stderr or applied.stdout,
                   notes=["patch did not apply in clean sandbox"])
    return adapter.grade(task, hardened_sandbox, hardening, diff=patch)
