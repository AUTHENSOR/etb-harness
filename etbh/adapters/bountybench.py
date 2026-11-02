"""BountyBench adapter: enumerates bounties from the public task repository.

BountyBench (bountybench/bountybench, last pushed 2025-07-24; tasks in bountybench/bountytasks,
indexed at the commit recorded in `cache/bountybench/index.json`). Each bounty directory holds
`bounty_metadata.json` (CVE, CWE, severity, vulnerable commit, patch file mapping),
`exploit_files/`, `patch_files/`, `setup_files/`, `verify_files/verify.sh` and
`run_bounty_invariants.sh`; the project directory holds the Docker compose for the target
services and `run_repo_invariants.sh`.

How it grades (read 2026-11-02, UNVERIFIED at runtime): workflows (`phases/exploit_phase.py`,
`patch_phase.py`) run the agent in a Kali container networked to the target containers;
exploit success is judged by `verify_files/verify.sh`, which sources the task's `env` file and
inspects target state (for example a Postgres table) rather than trusting the agent's output;
patch tasks re-run the bounty exploit plus repository invariant scripts.

ETB surfaces to measure once an environment exists: ETB-11 (can the agent reach the same
target state the verifier reads, with the credentials in `env`, and write it directly?),
ETB-11 again for the invariant scripts if the task tree is mounted writable, ETB-16 (patch
accepted when it disables the feature the invariants do not cover), ETB-15 (bounty write-ups
and CVE patches are public; `bounty_link` points at them). This adapter enumerates and
describes; `sandbox()` states what a live run needs.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from etbh.adapters.base import AdapterBase, AdapterUnavailable, Sandbox, TaskSpec
from etbh.hardening.profiles import Hardening

DEFAULT_INDEX = Path(__file__).resolve().parents[2] / "cache" / "bountybench" / "index.json"


class BountyBenchAdapter(AdapterBase):
    name = "bountybench"

    def __init__(self, index: str | Path | None = None, rows: list[dict] | None = None,
                 commit: str | None = None):
        self.index_path = Path(index) if index else DEFAULT_INDEX
        self._rows: dict[str, dict] | None = {r["task_id"]: r for r in rows} if rows is not None else None
        self._commit = commit

    def _load(self) -> dict[str, dict]:
        if self._rows is not None:
            return self._rows
        if not self.index_path.exists():
            raise AdapterUnavailable(
                f"no BountyBench index at {self.index_path}; build it from bountybench/bountytasks "
                f"(see runs/README or cache/bountybench)")
        data = json.loads(self.index_path.read_text(encoding="utf-8"))
        self._commit = data.get("commit")
        self._rows = {b["task_id"]: b for b in data["bounties"]}
        return self._rows

    def version_pins(self) -> dict[str, str]:
        self._load() if self._rows is None and self.index_path.exists() else None
        return {
            "tasks_repo": "bountybench/bountytasks",
            "tasks_commit": self._commit or "UNVERIFIED",
            "harness_repo": "bountybench/bountybench (last push 2025-07-24)",
            "grader": "verify_files/verify.sh inspects target state; patch tasks re-run the exploit and "
                      "invariant scripts (UNVERIFIED at runtime)",
            "mode": "static: enumeration only; live loop not wired",
        }

    def task_ids(self) -> list[str]:
        return sorted(self._load())

    def task_spec(self, task_id: str) -> TaskSpec:
        row = self._load()[task_id]
        return TaskSpec(
            benchmark=self.name,
            task_id=task_id,
            repo=f"bountybench/bountytasks/{row['project']}",
            base_commit=row.get("vulnerable_commit") or "",
            workdir="/app",
            test_files=[f"{row['project']}/bounties/{row['bounty']}/verify_files/verify.sh"],
            grader_paths=[f"{row['project']}/bounties/{row['bounty']}/run_bounty_invariants.sh",
                          f"{row['project']}/run_repo_invariants.sh"],
            grader_command="",  # workflow-driven
            image="",
            has_reference_solution=bool(row.get("has_exploit") or row.get("has_patch")),
            fail_to_pass=[],
            pass_to_pass=[],
            metadata={
                "runner": "bountybench-workflow",
                "grader_logic_known": False,
                "project": row.get("project"),
                "cve": row.get("cve"),
                "cwe": row.get("cwe"),
                "severity": row.get("severity"),
                "bounty_link": row.get("bounty_link"),
                "has_verify": row.get("has_verify"),
                "has_patch": row.get("has_patch"),
            },
        )

    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        raise AdapterUnavailable(
            "BountyBench's live loop needs a clone of bountybench/bountybench with the bountytasks "
            "submodule, the per-project Docker compose targets, and the Kali agent environment; "
            "not wired here."
        )
        yield  # pragma: no cover

    def evaluator_privileges(self, task: TaskSpec, hardening: Hardening) -> dict[str, Any] | None:
        return {
            # verify.sh runs from the workflow, not inside the agent's Kali container (UNVERIFIED)
            "same_container": False,
            "write_access": True,  # the verifier reads target state the agent can also reach over the network
            "network": True,
            "tools": False,
            "runs_as": "workflow process",
            "source": "phases/exploit_phase.py mounts verify_files; verify.sh sources env and queries "
                      "the target database (lunary/bounties/bounty_0/verify_files/verify.sh); "
                      "UNVERIFIED at runtime",
        }
