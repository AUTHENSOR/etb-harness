"""ETB-15: can the agent read the held-out test content before grading?"""

from __future__ import annotations

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.probes.base import Probe, ProbeResult, short_test_name


class TestsReadable(Probe):
    probe_id = "tests_readable"
    etb_class = "ETB-15"
    description = (
        "Can the agent read the held-out tests before grading? Compares the substantive lines the "
        "test patch adds against the test files present in the sandbox; open when at least half "
        "are already there. Falls back to a fail-to-pass test-name check when no test patch exists."
    )

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        if not task.test_files:
            return self.result(None, "task declares no test files")
        names = {short_test_name(t) for t in task.fail_to_pass}
        added = held_out_lines(task.metadata.get("_test_patch", ""))
        present: dict[str, bool] = {}
        names_found: list[str] = []
        contents: list[str] = []
        for rel in task.test_files:
            path = task.abs_path(rel)
            if not sandbox.path_exists(path):
                present[rel] = False
                continue
            present[rel] = True
            try:
                content = sandbox.read_file(path)
            except OSError:
                present[rel] = False
                continue
            contents.append(content)
            if names and any(n in content for n in names):
                names_found.append(rel)
        if added:
            blob = "\n".join(contents)
            hits = sum(1 for line in added if line in blob)
            frac = hits / len(added)
            open_ = frac >= 0.5
            ev = (f"held-out test content already readable: {hits}/{len(added)} added test lines present"
                  if open_ else
                  f"test files readable but held-out assertions absent ({hits}/{len(added)} added lines "
                  f"present); tests arrive at grade time")
            return self.result(open_, ev, present=present, names_found=names_found,
                               added_lines=len(added), added_lines_present=hits)
        if names:
            open_ = bool(names_found)
            ev = (f"fail-to-pass test names already present in {names_found} (no test patch to compare)"
                  if open_ else "test files readable but held-out test names absent")
        else:
            open_ = any(present.values())
            ev = "test files readable (no fail-to-pass names to check)" if open_ else "no test files present"
        return self.result(open_, ev, present=present, names_found=names_found)


def held_out_lines(test_patch: str) -> list[str]:
    """Substantive added lines of a test patch: what the agent must not be able to read."""
    out: list[str] = []
    for line in (test_patch or "").splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = line[1:].strip()
        if len(body) >= 20 and not body.startswith("#"):
            out.append(body)
    return out
