"""BountyBench adapter (stub).

BountyBench (Zhang et al., 2025) wraps real bug-bounty findings in 25 systems as detect,
exploit and patch tasks with Docker environments. Not on PyPI; the GitHub repository
bountybench/bountybench layout is UNVERIFIED offline. Needed before this adapter can run:
a clone at a pinned commit, the per-bounty Docker compose files, the verifier scripts, and
a decision on the v1 budget (about 20 of the 40 bounties). ETB surfaces expected: ETB-15
(public bounty write-ups and patches reachable), ETB-09 (self-reported exploit success),
ETB-16 (patch tasks accepted when they disable functionality).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from etbh.adapters.base import AdapterBase, Sandbox, TaskSpec
from etbh.hardening.profiles import Hardening


class BountyBenchAdapter(AdapterBase):
    name = "bountybench"

    def version_pins(self) -> dict[str, str]:
        return {"bountybench": "UNVERIFIED (no pinned commit resolved)"}

    def task_ids(self) -> list[str]:
        raise NotImplementedError("BountyBench adapter is a stub; see module docstring for what is needed")

    def task_spec(self, task_id: str) -> TaskSpec:
        raise NotImplementedError("BountyBench adapter is a stub")

    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        raise NotImplementedError("BountyBench adapter is a stub")
        yield  # pragma: no cover
