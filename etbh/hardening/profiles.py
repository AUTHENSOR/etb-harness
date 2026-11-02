"""Hardening profiles.

`before` is the benchmark as shipped at its pinned version: every switch off.
`after` turns every switch on. Intermediate profiles can be built with `replace()` to
attribute the gameable-rate drop to individual fixes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace


@dataclass(frozen=True)
class GradingPolicy:
    require_exit_code: bool = False
    require_junit: bool = False
    min_p2p_fraction: float = 0.0
    reject_flagged_diffs: bool = False


@dataclass(frozen=True)
class Hardening:
    name: str = "before"
    strip_git_history: bool = False
    tests_read_only: bool = False
    grader_paths_read_only: bool = False
    agent_unprivileged: bool = False
    copy_tests_at_grade_time: bool = False
    network_none: bool = False
    separate_grader_container: bool = False
    hash_check_tests: bool = False
    require_exit_code_and_junit: bool = False
    anti_degeneration_min_p2p: float = 0.0
    randomize_eval_context: bool = False

    def grading_policy(self) -> GradingPolicy:
        return GradingPolicy(
            require_exit_code=self.require_exit_code_and_junit,
            require_junit=self.require_exit_code_and_junit,
            min_p2p_fraction=self.anti_degeneration_min_p2p,
            reject_flagged_diffs=self.anti_degeneration_min_p2p > 0,
        )

    def as_dict(self) -> dict:
        return asdict(self)

    def with_(self, **changes) -> Hardening:
        return replace(self, **changes)


BEFORE = Hardening(name="before")
AFTER = Hardening(
    name="after",
    strip_git_history=True,
    tests_read_only=True,
    grader_paths_read_only=True,
    agent_unprivileged=True,
    copy_tests_at_grade_time=True,
    network_none=True,
    separate_grader_container=True,
    hash_check_tests=True,
    require_exit_code_and_junit=True,
    anti_degeneration_min_p2p=1.0,
    randomize_eval_context=True,
)

PROFILES: dict[str, Hardening] = {"before": BEFORE, "after": AFTER}


def profile(name: str) -> Hardening:
    try:
        return PROFILES[name]
    except KeyError as err:
        raise ValueError(f"unknown hardening profile {name!r}; known: {sorted(PROFILES)}") from err
