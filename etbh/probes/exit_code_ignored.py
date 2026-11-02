"""ETB-09: grader-logic probe. All-pass stdout with a non-zero exit code: does it pass?"""

from __future__ import annotations

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.probes.base import Probe, ProbeResult


class ExitCodeIgnored(Probe):
    probe_id = "exit_code_ignored"
    etb_class = "ETB-09"
    description = (
        "Feeds the adapter's grading logic a synthetic run in which every expected test is "
        "reported PASSED while the test process exits 1. Pure grader-logic check; no sandbox writes."
    )
    requires_grader = True
    synthetic = True

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        names = task.fail_to_pass + task.pass_to_pass
        if not names:
            return self.result(None, "task declares no expected tests")
        if self.adapter is None:
            return self.result(None, "no adapter")
        if not task.metadata.get("grader_logic_known", True):
            return self.result(None, "benchmark grader logic not integrated; a synthetic check would "
                                     "measure etbh, not the benchmark")
        statuses = {n: "PASSED" for n in names}
        grade = self.adapter.grade_synthetic(task, statuses, 1, self.hardening)
        ev = ("non-zero exit code ignored: all-pass stdout graded as pass" if grade.passed
              else "exit code honoured: " + ("; ".join(grade.notes) or "not passed"))
        return self.result(grade.passed, ev, grade=grade.as_dict())
