from __future__ import annotations

from etbh.hardening import (
    AFTER,
    BEFORE,
    docker_run_kwargs,
    pre_agent_commands,
    pre_grade_commands,
    profile,
    randomized_env,
    verify_test_hashes,
)
from etbh.hardening import (
    test_hashes as hashes_of,
)
from tests.conftest import make_sandbox, make_task


def test_profiles():
    assert profile("before") is BEFORE and profile("after") is AFTER
    assert not any(v for k, v in BEFORE.as_dict().items() if k != "name")
    assert AFTER.grading_policy().require_exit_code and AFTER.grading_policy().reject_flagged_diffs
    assert BEFORE.with_(network_none=True).network_none and BEFORE.name == "before"


def test_docker_kwargs():
    task = make_task()
    assert docker_run_kwargs(BEFORE, task) == {"network_mode": "bridge"}
    kw = docker_run_kwargs(AFTER, task)
    assert kw["network_mode"] == "none"
    assert "volumes" not in kw and "user" not in kw  # realised via ownership + agent user instead
    assert kw["hostname"].startswith("host-")


def test_commands():
    task = make_task()
    assert pre_agent_commands(BEFORE, task) == []
    cmds = pre_agent_commands(AFTER, task)
    assert any("rm -rf .git" in c and "git init" in c for c in cmds)
    assert any("pristine_tests" in c for c in cmds)
    assert any("chmod a-w" in c for c in cmds)
    assert any("chown -R 1000:1000" in c for c in cmds)
    assert any("/testbed/tests/test_feature.py" in c and "chown root:root" in c for c in cmds)
    assert pre_grade_commands(BEFORE, task) == []
    assert any("cp -a" in c for c in pre_grade_commands(AFTER, task))


def test_hashes_detect_edits():
    task = make_task()
    sb = make_sandbox(task)
    before = hashes_of(sb, task)
    assert verify_test_hashes(before, hashes_of(sb, task)) == []
    sb.files[task.abs_path("tests/test_feature.py")] += "# edit\n"
    assert verify_test_hashes(before, hashes_of(sb, task)) == ["tests/test_feature.py"]


def test_randomized_env_strips_markers():
    env = {"PATH": "/usr/bin", "SWE_INSTANCE_ID": "x", "INSPECT_EVAL": "1", "HOME": "/root"}
    assert randomized_env(BEFORE, env) == env
    out = randomized_env(AFTER, env)
    assert "SWE_INSTANCE_ID" not in out and "INSPECT_EVAL" not in out and out["HOSTNAME"].startswith("host-")
