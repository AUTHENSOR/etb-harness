"""Protocols shared by every benchmark adapter, sandbox and probe."""

from __future__ import annotations

import random
import shlex
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from etbh.grading import grade_log
from etbh.hardening.profiles import BEFORE, Hardening


class AdapterUnavailable(RuntimeError):
    """Raised when an adapter needs an optional dependency, dataset or daemon that is absent."""


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass
class TaskSpec:
    benchmark: str
    task_id: str
    repo: str = ""
    base_commit: str = ""
    workdir: str = "/testbed"
    test_files: list[str] = field(default_factory=list)
    grader_paths: list[str] = field(default_factory=list)
    grader_command: str = ""
    image: str = ""
    has_reference_solution: bool = False
    fail_to_pass: list[str] = field(default_factory=list)
    pass_to_pass: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def abs_path(self, path: str) -> str:
        return path if path.startswith("/") else f"{self.workdir.rstrip('/')}/{path}"

    def as_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["metadata"] = {k: v for k, v in self.metadata.items() if not k.startswith("_")}
        return d


@runtime_checkable
class Sandbox(Protocol):
    network_allowed: bool

    def exec(self, cmd: str, timeout: float = 600) -> ExecResult: ...
    def read_file(self, path: str) -> str: ...
    def write_file(self, path: str, content: str) -> None: ...
    def path_exists(self, path: str) -> bool: ...
    def list_dir(self, path: str) -> list[str]: ...
    def snapshot(self) -> str: ...
    def restore(self, token: str) -> None: ...


@dataclass
class GradeResult:
    passed: bool
    exit_code: int | None
    raw: str = ""
    parsed: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "exit_code": self.exit_code, "parsed": self.parsed,
                "notes": list(self.notes)}


class BenchmarkAdapter(Protocol):
    name: str

    def version_pins(self) -> dict[str, str]: ...
    def task_ids(self) -> list[str]: ...
    def sample_tasks(self, n: int, seed: int) -> list[str]: ...
    def task_spec(self, task_id: str) -> TaskSpec: ...
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Any: ...
    def grade(self, task: TaskSpec, sandbox: Sandbox, hardening: Hardening | None = None,
              diff: str | None = None) -> GradeResult: ...
    def grade_output(self, task: TaskSpec, result: ExecResult, hardening: Hardening | None = None,
                     diff: str | None = None, junit_xml: str | None = None) -> GradeResult: ...
    def apply_patch(self, sandbox: Sandbox, diff: str) -> ExecResult: ...
    def monitor_format(self, task: TaskSpec, model_text: str) -> str | None: ...
    def evaluator_privileges(self, task: TaskSpec, hardening: Hardening) -> dict[str, Any] | None: ...


def deterministic_sample(ids: list[str], n: int, seed: int) -> list[str]:
    """Sort, then shuffle with a seeded RNG, then take n. Same ids + seed => same sample."""
    ordered = sorted(set(ids))
    rng = random.Random(seed)
    rng.shuffle(ordered)
    return ordered[:n]


class AdapterBase:
    """Default behaviour shared by adapters. Subclasses set `name` and the data methods."""

    name: str = "base"

    def version_pins(self) -> dict[str, str]:
        return {}

    def task_ids(self) -> list[str]:
        raise NotImplementedError

    def sample_tasks(self, n: int, seed: int) -> list[str]:
        return deterministic_sample(self.task_ids(), n, seed)

    def task_spec(self, task_id: str) -> TaskSpec:
        raise NotImplementedError

    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        raise NotImplementedError
        yield  # pragma: no cover

    def grade_output(
        self,
        task: TaskSpec,
        result: ExecResult,
        hardening: Hardening | None = None,
        diff: str | None = None,
        junit_xml: str | None = None,
    ) -> GradeResult:
        """Decide pass/fail from a captured test run. Pure; probes call this directly."""
        hardening = hardening or BEFORE
        policy = hardening.grading_policy()
        outcome = grade_log(result.stdout, result.exit_code, task.fail_to_pass,
                            task.pass_to_pass, policy, junit_xml)
        notes = list(outcome.notes)
        passed = outcome.passed
        if diff is not None and policy.reject_flagged_diffs:
            from etbh.verifier.diff_policy import diff_policy

            flags = diff_policy(diff, task)
            if flags.hard or flags.soft:
                passed = False
                notes.append("diff rejected by structural policy: " + "; ".join(flags.reasons))
        return GradeResult(passed=passed, exit_code=result.exit_code, raw=result.stdout,
                           parsed=outcome.resolution.as_dict(), notes=notes)

    def grade(
        self,
        task: TaskSpec,
        sandbox: Sandbox,
        hardening: Hardening | None = None,
        diff: str | None = None,
    ) -> GradeResult:
        hardening = hardening or BEFORE
        from etbh.hardening.transforms import pre_grade_commands, test_hashes, verify_test_hashes

        notes: list[str] = []
        if hardening.hash_check_tests:
            expected = task.metadata.get("_test_hashes")
            if expected is not None:
                changed = verify_test_hashes(expected, test_hashes(sandbox, task))
                if changed:
                    return GradeResult(passed=False, exit_code=None, raw="",
                                       notes=[f"test files changed before grading: {changed}"])
        for cmd in pre_grade_commands(hardening, task):
            sandbox.exec(cmd)
        if not task.grader_command:
            return GradeResult(passed=False, exit_code=None, raw="", notes=["no grader command"])
        res = sandbox.exec(task.grader_command, timeout=task.metadata.get("grader_timeout", 600))
        junit = None
        if hardening.require_exit_code_and_junit:
            junit_path = task.metadata.get("junit_path", f"{task.workdir.rstrip('/')}/.etbh-junit.xml")
            if sandbox.path_exists(junit_path):
                try:
                    junit = sandbox.read_file(junit_path)
                except OSError:
                    junit = None
        out = self.grade_output(task, res, hardening, diff=diff, junit_xml=junit)
        out.notes = notes + out.notes
        return out

    def grade_synthetic(self, task: TaskSpec, statuses: dict[str, str], exit_code: int,
                        hardening: Hardening | None = None, diff: str | None = None) -> GradeResult:
        """Grade a constructed run from pre-parsed statuses (grader-logic probes).

        Default: render the statuses as pytest-style lines and go through `grade_output`,
        so adapters with their own log parser override this to skip the render step.
        """
        stdout = "\n".join(f"{status} {name}" for name, status in statuses.items()) + "\n"
        return self.grade_output(task, ExecResult(exit_code, stdout), hardening, diff=diff)

    def apply_patch(self, sandbox: Sandbox, diff: str) -> ExecResult:
        sandbox.write_file("/tmp/etbh.patch", diff)
        return sandbox.exec("git apply --whitespace=nowarn /tmp/etbh.patch")

    def monitor_format(self, task: TaskSpec, model_text: str) -> str | None:
        return None

    def evaluator_privileges(self, task: TaskSpec, hardening: Hardening) -> dict[str, Any] | None:
        return None

    @staticmethod
    def q(path: str) -> str:
        return shlex.quote(path)
