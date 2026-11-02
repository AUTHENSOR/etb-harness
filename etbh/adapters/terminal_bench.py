"""Terminal-Bench adapter via the Harbor framework (thin).

Harbor (`pip install harbor`, 0.25.x) runs Terminal-Bench 2 tasks: each task is an
instruction, a Docker environment and a test script. The grader is the task's own test
script, so ETB-09/11/15/16 surfaces apply directly. The Harbor Python API used here is
UNVERIFIED offline; the adapter raises AdapterUnavailable with the exact gap until a task
list and image names have been resolved against a pinned Harbor dataset revision.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib import metadata

from etbh.adapters.base import AdapterBase, AdapterUnavailable, Sandbox, TaskSpec
from etbh.hardening.profiles import Hardening


class TerminalBenchAdapter(AdapterBase):
    name = "terminal_bench"

    def __init__(self, dataset: str = "terminal-bench", version: str = "2.0",
                 task_ids: list[str] | None = None):
        self.dataset = dataset
        self.version = version
        self._task_ids = task_ids

    def version_pins(self) -> dict[str, str]:
        try:
            harbor = metadata.version("harbor")
        except metadata.PackageNotFoundError:
            harbor = "not installed"
        return {"harbor": harbor, "dataset": self.dataset, "dataset_version": self.version,
                "task_source": "harbor registry (UNVERIFIED offline)"}

    def task_ids(self) -> list[str]:
        if self._task_ids is not None:
            return list(self._task_ids)
        raise AdapterUnavailable("Terminal-Bench task enumeration needs harbor and a dataset pin")

    def task_spec(self, task_id: str) -> TaskSpec:
        return TaskSpec(benchmark=self.name, task_id=task_id, workdir="/app",
                        test_files=["tests/test_outputs.py"], grader_paths=["tests/", "run-tests.sh"],
                        grader_command="bash /tests/run-tests.sh",
                        metadata={"UNVERIFIED": "paths follow the Terminal-Bench task layout; "
                                                "confirm per task"})

    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        raise AdapterUnavailable("Terminal-Bench sandbox wiring through Harbor not implemented")
        yield  # pragma: no cover
