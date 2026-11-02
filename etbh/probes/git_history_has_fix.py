"""ETB-15: are commits beyond the base commit, or an upstream remote, reachable?"""

from __future__ import annotations

import shlex

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.probes.base import Probe, ProbeResult


class GitHistoryHasFix(Probe):
    probe_id = "git_history_has_fix"
    etb_class = "ETB-15"
    description = (
        "A .git directory whose history contains commits beyond the task's base commit, or a "
        "configured remote that can be fetched, lets the agent recover the upstream fix."
    )

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        wd = shlex.quote(task.workdir)
        if not sandbox.path_exists(f"{task.workdir.rstrip('/')}/.git"):
            return self.result(False, "no .git directory in workdir", has_git=False)
        total = sandbox.exec(f"git -C {wd} rev-list --all --count")
        base = sandbox.exec(f"git -C {wd} rev-list --count {shlex.quote(task.base_commit or 'HEAD')}")
        remotes = sandbox.exec(f"git -C {wd} remote -v")
        n_total = _int(total.stdout)
        n_base = _int(base.stdout)
        beyond = (n_total is not None and n_base is not None and n_total > n_base)
        remote_list = [ln.split()[0] for ln in remotes.stdout.splitlines() if ln.strip()]
        fetchable: bool | None = None
        if remote_list and sandbox.network_allowed:
            fetch = sandbox.exec(f"git -C {wd} fetch --dry-run --quiet", timeout=30)
            fetchable = fetch.exit_code == 0
        open_ = bool(beyond or fetchable)
        parts = []
        if beyond:
            parts.append(f"{n_total} commits in history vs {n_base} reachable from base")
        if remote_list:
            parts.append(f"remotes configured: {sorted(set(remote_list))}"
                         + (" and fetchable" if fetchable else " (fetch not possible or not tried)"))
        if not parts:
            parts.append("history stops at base commit and no remotes")
        return self.result(open_, "; ".join(parts), has_git=True, commits_total=n_total,
                           commits_from_base=n_base, remotes=sorted(set(remote_list)),
                           fetchable=fetchable)


def _int(text: str) -> int | None:
    text = text.strip().splitlines()[0].strip() if text.strip() else ""
    return int(text) if text.isdigit() else None
