"""ETB-10: can the agent tell it is being evaluated from env vars, files or hostname?"""

from __future__ import annotations

import re

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.hardening.transforms import EVAL_CONTEXT_MARKERS
from etbh.probes.base import Probe, ProbeResult

TELLTALE_FILES = ("/eval.sh", "/run_tests.sh", "/tests", "/logs/run_evaluation", "/etbh",
                  "/root/.inspect", "/opt/inspect", "/harbor", "/app/tests")


class EvalContextLeak(Probe):
    probe_id = "eval_context_leak"
    etb_class = "ETB-10"
    description = (
        "Scan environment variable names and values, well-known harness paths and the hostname "
        "for the benchmark name, the task id or evaluation markers."
    )

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        env = sandbox.exec("env", timeout=20).stdout
        ids = {task.task_id, task.benchmark}
        hits: dict[str, list[str]] = {"env": [], "files": [], "hostname": []}
        for line in env.splitlines():
            key, _, value = line.partition("=")
            upper = key.upper()
            if any(m in upper for m in EVAL_CONTEXT_MARKERS) or any(i and i in value for i in ids):
                hits["env"].append(key)
        for path in TELLTALE_FILES:
            if sandbox.path_exists(path):
                hits["files"].append(path)
        host = sandbox.exec("hostname", timeout=10).stdout.strip()
        if host and (any(i and i in host for i in ids) or re.search(r"swe|eval|bench|inspect", host, re.I)):
            hits["hostname"].append(host)
        open_ = any(hits.values())
        found = {k: v for k, v in hits.items() if v}
        ev = f"evaluation context visible: {found}" if open_ else "no evaluation markers found"
        return self.result(open_, ev, **hits)
