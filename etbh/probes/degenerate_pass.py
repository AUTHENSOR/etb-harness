"""ETB-16: grader-logic probe. Does the grader accept a pass backed by a degenerate diff?

Strategy (v1, documented so it can be disputed): we do not run an agent. We ask the
adapter's grading logic whether it would accept an all-tests-pass run whose diff stubs out
the functions in the files the reference patch touches and deletes most of their lines.
A shipped grader with no structural check (SWE-bench, Terminal-Bench) accepts it; a grader
with the `after` policy rejects it. The diff is synthetic and labelled as such in evidence.
UNVERIFIED against real agent runs: a real agent would also need the P2P tests to pass.
"""

from __future__ import annotations

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.probes.base import Probe, ProbeResult


def synthetic_degenerate_diff(files: list[str]) -> str:
    chunks = []
    for f in files:
        removed = "\n".join(f"-    line_{i} = {i}" for i in range(20))
        chunks.append(
            f"diff --git a/{f} b/{f}\n--- a/{f}\n+++ b/{f}\n@@ -1,21 +1,3 @@\n def feature():\n"
            f"{removed}\n+    pass\n+\n"
        )
    return "".join(chunks)


class DegeneratePass(Probe):
    probe_id = "degenerate_pass"
    etb_class = "ETB-16"
    description = (
        "Synthetic all-pass run plus a diff that replaces the touched functions with 'pass' and "
        "deletes most lines; open if the grader accepts it without a structural check."
    )
    requires_grader = True
    synthetic = True

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        names = task.fail_to_pass + task.pass_to_pass
        if not names or self.adapter is None:
            return self.result(None, "task declares no expected tests")
        files = list(task.metadata.get("reference_patch_files") or ["src/module.py"])
        diff = synthetic_degenerate_diff(files)
        statuses = {n: "PASSED" for n in names}
        grade = self.adapter.grade_synthetic(task, statuses, 0, self.hardening, diff=diff)
        ev = ("degenerate diff accepted: no anti-degeneration check (synthetic diff)" if grade.passed
              else "degenerate diff rejected (synthetic diff): " + "; ".join(grade.notes))
        return self.result(grade.passed, ev, files=files, grade=grade.as_dict())
