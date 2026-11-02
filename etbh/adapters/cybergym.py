"""CyberGym adapter: enumerates the public task list and audits what the agent is given.

CyberGym (sunblaze-ucb/cybergym, read 2026-11-02; HF dataset sunblaze-ucb/cybergym at
revision bde190ded494e52bc684b66073b436c9d992c7c6, 1,507 tasks: 1,368 `arvo:` and 139
`oss-fuzz:`). Per task the agent gets, by difficulty level: level0 the vulnerable repository
archive; level1 adds the vulnerability description; level2 adds the sanitizer error output;
level3 adds the patch. The agent's deliverable is a proof-of-concept input.

How it grades (src/cybergym/server): the PoC is POSTed to a separate server
(`/submit-vul`, bound to task and agent ids by a salted checksum), which runs it against the
vulnerable build in the server's own compile container and records the target's exit code;
custom codes (timeouts and the like) are mapped to "not crashed". Task ids are masked
(`mask_map.json`) so the OSS-Fuzz issue cannot be looked up, and agent containers sit on an
internal Docker network behind an allow-listed proxy. So, by design:

- ETB-09/ETB-11: the grader runs out of the agent's reach (a separate server and container);
  the agent can only submit data, not steer the verifier.
- ETB-15: the public issue is masked and egress is allow-listed; what remains is whatever the
  archive itself contains (git history with the fix, the fix build), which this adapter can
  check offline from the public dataset.
- ETB-13: the agent reaches the grader only through one authenticated route.

What this adapter does today: enumerate tasks from `cache/cybergym/tasks.json`, describe the
grader, and (via `runs/run_cybergym_static.py`) inspect sampled archives for reachable oracle
material. Running the live loop needs the server data (~10 TB full, a 10-task subset is
published), the server, `gen_task.py` and the firewall network; `sandbox()` says so.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from etbh.adapters.base import AdapterBase, AdapterUnavailable, Sandbox, TaskSpec
from etbh.hardening.profiles import Hardening

HF_REVISION = "bde190ded494e52bc684b66073b436c9d992c7c6"
HF_BASE = "https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data"
DEFAULT_TASKS_JSON = Path(__file__).resolve().parents[2] / "cache" / "cybergym" / "tasks.json"
LEVELS = ("level0", "level1", "level2", "level3")


def archive_url(task_id: str, name: str) -> str:
    kind, num = task_id.split(":", 1)
    return f"{HF_BASE}/{kind}/{num}/{name}"


class CyberGymAdapter(AdapterBase):
    name = "cybergym"

    def __init__(self, tasks_json: str | Path | None = None, level: str = "level1",
                 rows: list[dict] | None = None):
        if level not in LEVELS:
            raise ValueError(f"level must be one of {LEVELS}")
        self.tasks_json = Path(tasks_json) if tasks_json else DEFAULT_TASKS_JSON
        self.level = level
        self._rows: dict[str, dict] | None = {r["task_id"]: r for r in rows} if rows is not None else None

    def _load(self) -> dict[str, dict]:
        if self._rows is not None:
            return self._rows
        if not self.tasks_json.exists():
            raise AdapterUnavailable(
                f"no CyberGym task list at {self.tasks_json}; fetch "
                f"{HF_BASE.rsplit('/data', 1)[0]}/tasks.json into cache/cybergym/")
        rows = json.loads(self.tasks_json.read_text(encoding="utf-8"))
        self._rows = {r["task_id"]: r for r in rows}
        return self._rows

    def version_pins(self) -> dict[str, str]:
        return {
            "dataset": "sunblaze-ucb/cybergym (Hugging Face)",
            "dataset_revision": HF_REVISION,
            "level": self.level,
            "grader": "remote PoC server (src/cybergym/server), target exit code in the server's "
                      "compile container; task ids masked; agent egress allow-listed",
            "mode": "static: task enumeration and public-archive inspection; live loop not wired",
        }

    def task_ids(self) -> list[str]:
        return sorted(self._load())

    def task_spec(self, task_id: str) -> TaskSpec:
        row = self._load()[task_id]
        given = row.get("task_difficulty", {}).get(self.level, [])
        return TaskSpec(
            benchmark=self.name,
            task_id=task_id,
            repo=row.get("project_main_repo", ""),
            base_commit="",
            workdir="/workspace",
            test_files=[],
            grader_paths=[],
            grader_command="",  # remote: POST /submit-vul
            image="",
            has_reference_solution=True,  # repo-fix.tar.gz and patch.diff exist in the public dataset
            fail_to_pass=[],
            pass_to_pass=[],
            metadata={
                "runner": "remote-poc-server",
                "grader_logic_known": False,
                "project": row.get("project_name"),
                "language": row.get("project_language"),
                "files_given_at_level": [Path(p).name for p in given],
                "patch_given": any(Path(p).name == "patch.diff" for p in given),
                "archive_urls": {n: archive_url(task_id, n)
                                 for n in ("repo-vul.tar.gz", "repo-fix.tar.gz", "patch.diff")},
            },
        )

    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        raise AdapterUnavailable(
            "CyberGym's live loop needs the PoC server with its compile containers (server data: "
            "10-task public subset or the full ~10 TB), gen_task.py output for the task, and the "
            "cybergym-internal network; none of that is wired here. Use runs/run_cybergym_static.py "
            "for the offline archive inspection."
        )
        yield  # pragma: no cover

    def evaluator_privileges(self, task: TaskSpec, hardening: Hardening) -> dict[str, Any] | None:
        return {
            "same_container": False,
            "write_access": False,
            "network": False,  # the server is reachable only via the submit route; agents are allow-listed
            "tools": False,
            "runs_as": "server process in its own container",
            "source": "src/cybergym/server/__main__.py: public /submit-vul bound by salted checksum; "
                      "verification in the server's compile container (server_utils.py)",
        }
