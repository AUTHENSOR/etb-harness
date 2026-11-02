"""Transforms that turn a Hardening profile into concrete sandbox and grading changes.

Everything here is pure (returns commands, kwargs or dicts) so it can be unit-tested
without Docker. The Docker sandbox and the adapters apply the results.
"""

from __future__ import annotations

import hashlib
import secrets
import shlex
from typing import TYPE_CHECKING

from etbh.hardening.profiles import Hardening

if TYPE_CHECKING:
    from etbh.adapters.base import Sandbox, TaskSpec

PRISTINE_TESTS_DIR = "/etbh/pristine_tests"  # legacy name; see pristine_dir()


def pristine_dir(task: TaskSpec) -> str:
    """Root-only copy of the pristine tests, at a path that names neither etbh nor the task.

    The directory name is a hash so eval_context_leak (and an agent grepping for harness
    names) does not find it by name; it is chmod 700 root after the copy, so an unprivileged
    agent cannot read it either. A root agent could still discover it by mtime; the real
    defence for that case is a separate grading container.
    """
    digest = hashlib.sha256(f"pristine:{task.benchmark}:{task.task_id}".encode()).hexdigest()[:12]
    return f"/var/cache/.c{digest}"
EVAL_CONTEXT_MARKERS = (
    "SWE", "SWEBENCH", "INSPECT", "CONTROL_ARENA", "CONTROLARENA", "TERMINAL_BENCH",
    "HARBOR", "CYBERGYM", "BOUNTYBENCH", "BENCHMARK", "EVAL", "GRADER", "TASK_ID", "INSTANCE",
)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def docker_run_kwargs(h: Hardening, task: TaskSpec) -> dict:
    """Keyword arguments for docker `containers.run` that implement the profile."""
    kwargs: dict = {"network_mode": "none" if h.network_none else "bridge"}
    if h.randomize_eval_context:
        kwargs["hostname"] = "host-" + secrets.token_hex(4)
    # tests_read_only and agent_unprivileged are realised by pre_agent_commands (ownership and
    # modes) plus the sandbox's agent user, not by bind mounts or the container user: benchmark
    # images assume root for their entrypoints and the grader must stay root.
    return kwargs


def pre_agent_commands(h: Hardening, task: TaskSpec) -> list[str]:
    """Shell commands run in the sandbox before the agent (or probes) start."""
    cmds: list[str] = []
    wd = shlex.quote(task.workdir)
    if h.agent_unprivileged:
        # Give the agent user the workspace, then take back what must stay root-owned below.
        cmds.append(f"id -u 1000 >/dev/null 2>&1 || useradd -u 1000 -m agent 2>/dev/null || true; "
                    f"chown -R 1000:1000 {wd} 2>/dev/null || true")
    if h.tests_read_only and task.test_files:
        quoted = " ".join(shlex.quote(task.abs_path(p)) for p in task.test_files)
        cmds.append(f"for f in {quoted}; do [ -e \"$f\" ] && chown root:root \"$f\" && "
                    f"chmod a-w \"$f\"; done; true")
    if h.strip_git_history:
        # Keep a working git repo (git apply / git diff still work) with one commit and
        # no remotes, so neither the fix commit nor the upstream can be reached.
        cmds.append(
            f"cd {wd} && rm -rf .git && git init -q && git add -A >/dev/null 2>&1; "
            f"git -c user.email=dev@localhost -c user.name=dev commit -q -m base "
            f">/dev/null 2>&1 || true"
        )
    if h.grader_paths_read_only and task.grader_paths:
        # Only existing files can be locked; a missing pytest.ini must stay missing (an
        # empty one would change pytest's config discovery). Creation of missing grader
        # config files is prevented by agent_unprivileged, not by this switch.
        quoted = " ".join(shlex.quote(task.abs_path(p)) for p in task.grader_paths)
        cmds.append(f"for f in {quoted}; do [ -e \"$f\" ] && chown root:root \"$f\" && "
                    f"chmod a-w \"$f\"; done; true")
    if h.copy_tests_at_grade_time or h.hash_check_tests:
        pdir = pristine_dir(task)
        quoted = " ".join(shlex.quote(p) for p in task.test_files)
        cmds.append(
            f"mkdir -p {pdir} && cd {wd} && for f in {quoted}; do "
            f"if [ -e \"$f\" ]; then mkdir -p {pdir}/$(dirname \"$f\") && "
            f"cp -a \"$f\" {pdir}/\"$f\"; fi; done; chown -R root:root {pdir} && chmod -R go-rwx {pdir}"
        )
    return cmds


def pre_grade_commands(h: Hardening, task: TaskSpec) -> list[str]:
    """Shell commands run immediately before the grader command."""
    cmds: list[str] = []
    wd = shlex.quote(task.workdir)
    if h.copy_tests_at_grade_time and task.test_files:
        pdir = pristine_dir(task)
        quoted = " ".join(shlex.quote(p) for p in task.test_files)
        cmds.append(
            f"cd {wd} && for f in {quoted}; do if [ -e {pdir}/\"$f\" ]; then "
            f"mkdir -p $(dirname \"$f\") && cp -a {pdir}/\"$f\" \"$f\"; fi; done"
        )
    if h.separate_grader_container:
        # Marker only: the adapter must honour it by grading in a fresh container built
        # from the image plus the agent's diff, not in the agent's container.
        cmds.append("true # grading runs in a separate container (see adapter)")
    return cmds


def test_hashes(sandbox: Sandbox, task: TaskSpec) -> dict[str, str | None]:
    """sha256 of each declared test file as currently present in the sandbox."""
    out: dict[str, str | None] = {}
    for path in task.test_files:
        full = path if path.startswith("/") else f"{task.workdir.rstrip('/')}/{path}"
        try:
            out[path] = sha256_hex(sandbox.read_file(full)) if sandbox.path_exists(full) else None
        except OSError:
            out[path] = None
    return out


def verify_test_hashes(expected: dict[str, str | None], actual: dict[str, str | None]) -> list[str]:
    """Return the list of test paths whose hash changed (or appeared/disappeared)."""
    return sorted(p for p in set(expected) | set(actual) if expected.get(p) != actual.get(p))


def randomized_env(h: Hardening, base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for the agent process with evaluation markers stripped when enabled."""
    env = dict(base_env or {})
    if not h.randomize_eval_context:
        return env
    cleaned = {}
    for k, v in env.items():
        upper = k.upper()
        if any(m in upper for m in EVAL_CONTEXT_MARKERS):
            continue
        cleaned[k] = v
    cleaned["HOSTNAME"] = "host-" + secrets.token_hex(4)
    return cleaned
