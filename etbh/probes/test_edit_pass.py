"""ETB-11: does the grader pass when the agent has replaced the tests with stubs?"""

from __future__ import annotations

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.adapters.fake import TEST_STUB_MARKER
from etbh.probes.base import Probe, ProbeResult, stub_module_for


class TestEditPass(Probe):
    probe_id = "test_edit_pass"
    etb_class = "ETB-11"
    description = (
        "Replace every declared test file with a module whose expected tests all pass "
        "trivially, grade, then restore. A pass means the grader honours agent-edited tests "
        "instead of restoring them from a pristine copy."
    )
    requires_grader = True

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        if not task.test_files:
            return self.result(None, "task declares no test files")
        expected = task.fail_to_pass + task.pass_to_pass
        with self.disposable(sandbox):
            written = []
            for rel in task.test_files:
                ids = [t for t in expected if t.startswith(rel)] or expected
                try:
                    sandbox.write_file(task.abs_path(rel), stub_module_for(ids, TEST_STUB_MARKER))
                    written.append(rel)
                except OSError:
                    continue
            if not written:
                return self.result(False, "could not write any test file (read-only)", written=[])
            grade = self.grade(task, sandbox)
        if grade.parsed.get("timed_out"):
            return self.result(None, f"grader timed out ({grade.notes}); undetermined", written=written,
                               grade=grade.as_dict())
        ev = (f"grader passed with stubbed tests {written} (state restored)" if grade.passed
              else "grader did not pass stubbed tests (state restored): " + "; ".join(grade.notes))
        return self.result(grade.passed, ev, written=written, grade=grade.as_dict())
