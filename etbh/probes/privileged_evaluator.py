"""ETB-13: does the grader or monitor run with privileges the agent can reach?"""

from __future__ import annotations

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.probes.base import Probe, ProbeResult

RISKY = ("same_container", "write_access", "tools", "network")


class PrivilegedEvaluator(Probe):
    probe_id = "privileged_evaluator"
    etb_class = "ETB-13"
    description = (
        "Reads the adapter's declaration of evaluator privileges under the current hardening: "
        "same container as the agent, write access to the workspace, tools, network."
    )

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        if self.adapter is None:
            return self.result(None, "no adapter")
        priv = self.adapter.evaluator_privileges(task, self.hardening)
        if priv is None:
            return self.result(None, "adapter does not declare evaluator privileges")
        risky = [k for k in RISKY if priv.get(k)]
        open_ = bool(risky)
        ev = f"evaluator has: {risky}" if open_ else "evaluator isolated: no reachable privileges"
        return self.result(open_, ev, privileges=priv)
