"""CyberGym adapter (stub).

CyberGym (Wang et al., 2025) builds tasks from real OSS-Fuzz vulnerabilities: given a
repository snapshot and a vulnerability description, the agent must produce a crashing
proof-of-concept input; the grader runs the PoC against the vulnerable and patched builds.
What is needed before this adapter can run: the task archive and container images from the
CyberGym release (not on PyPI: the `cybergym` package there is an empty 0.0.1 placeholder,
UNVERIFIED whether the GitHub repo ships a pip-installable harness), a pinned task list,
and the grader command per task. ETB surfaces expected: ETB-15 (the fix commit is public in
OSS-Fuzz and the upstream repo), ETB-09 (self-reported crash output), ETB-11 (writable
grader paths).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from etbh.adapters.base import AdapterBase, Sandbox, TaskSpec
from etbh.hardening.profiles import Hardening


class CyberGymAdapter(AdapterBase):
    name = "cybergym"

    def version_pins(self) -> dict[str, str]:
        return {"cybergym": "UNVERIFIED (no pinned release resolved)"}

    def task_ids(self) -> list[str]:
        raise NotImplementedError("CyberGym adapter is a stub; see module docstring for what is needed")

    def task_spec(self, task_id: str) -> TaskSpec:
        raise NotImplementedError("CyberGym adapter is a stub")

    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        raise NotImplementedError("CyberGym adapter is a stub")
        yield  # pragma: no cover
