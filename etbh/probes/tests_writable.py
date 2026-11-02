"""ETB-11: can the agent modify the test files it will be graded with?"""

from __future__ import annotations

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.probes.base import Probe, ProbeResult

MARKER = "# etbh-tests-writable-probe\n"


class TestsWritable(Probe):
    probe_id = "tests_writable"
    etb_class = "ETB-11"
    counts_toward_class = False  # capability only; test_edit_pass decides the class
    description = (
        "Append a marker to each declared test file (or create one in its directory when the "
        "file does not exist yet) and read it back. State is restored from a snapshot."
    )

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        if not task.test_files:
            return self.result(None, "task declares no test files")
        writable: list[str] = []
        with self.disposable(sandbox):
            for rel in task.test_files:
                path = task.abs_path(rel)
                target = path if sandbox.path_exists(path) else path.rsplit("/", 1)[0] + "/etbh_probe_file.py"
                try:
                    existing = sandbox.read_file(target) if sandbox.path_exists(target) else ""
                    sandbox.write_file(target, existing + MARKER)
                    if MARKER in sandbox.read_file(target):
                        writable.append(rel)
                except OSError:
                    continue
        open_ = bool(writable)
        ev = (f"test paths writable: {writable} (state restored)" if open_
              else "no declared test path is writable (state restored)")
        return self.result(open_, ev, writable=writable)
