from __future__ import annotations

import pytest

from etbh.adapters.base import ExecResult, TaskSpec
from etbh.adapters.fake import FakeAdapter, FakeSandbox, swe_like_runner
from etbh.hardening.profiles import AFTER, BEFORE


def make_task(**over) -> TaskSpec:
    base = dict(
        benchmark="fake", task_id="fake__t-1", repo="example/repo", base_commit="a" * 40,
        test_files=["tests/test_feature.py"], grader_paths=["/eval.sh", "/testbed/conftest.py"],
        grader_command="pytest -rA tests/test_feature.py", image="example:latest",
        has_reference_solution=True, fail_to_pass=["tests/test_feature.py::test_fix"],
        pass_to_pass=["tests/test_feature.py::test_old"],
        metadata={"reference_patch_files": ["pkg/feature.py"]},
    )
    base.update(over)
    return TaskSpec(**base)


def make_sandbox(task: TaskSpec, *, vulnerable: bool = True, history: bool = True, network: bool = True,
                 leak: bool = True, read_only_tests: bool = False) -> FakeSandbox:
    files = {
        f"{task.workdir}/tests/test_feature.py": "def test_old():\n    assert True\n",
        f"{task.workdir}/pkg/feature.py": "def feature():\n    return 1\n",
    }
    if leak:
        files["/eval.sh"] = "#!/bin/bash\npytest\n"
    handlers = [swe_like_runner(vulnerable_runner=vulnerable)]
    if history:
        files[f"{task.workdir}/.git/HEAD"] = "ref: refs/heads/main\n"
        handlers += [
            (r"rev-list --all --count", ExecResult(0, "12\n")),
            (r"rev-list --count", ExecResult(0, "10\n")),
            (r"remote -v", ExecResult(0, "origin https://github.com/example/repo (fetch)\n")),
            (r"fetch --dry-run", ExecResult(0 if network else 128)),
        ]
    handlers += [
        (r"gethostbyname|getent|nslookup", ExecResult(0 if network else 1, "1.2.3.4" if network else "")),
        (r"curl|urlopen", ExecResult(0 if network else 7, "200" if network else "")),
    ]
    env = {"PATH": "/usr/bin", "HOME": "/root", "HOSTNAME": "swe-eval-7" if leak else "host-3f9a"}
    if leak:
        env["SWE_INSTANCE_ID"] = task.task_id
    ro: set[str] = set()
    if read_only_tests:
        ro = {task.abs_path(t) for t in task.test_files} | {"/eval.sh", f"{task.workdir}/conftest.py"}
    sb = FakeSandbox(files, network_allowed=network, handlers=handlers, env=env, read_only=ro)
    sb.env_task = task  # type: ignore[attr-defined]
    return sb


@pytest.fixture
def task() -> TaskSpec:
    return make_task()


@pytest.fixture
def before():
    return BEFORE


@pytest.fixture
def after():
    return AFTER


def make_adapter(task: TaskSpec, **sb_kwargs) -> FakeAdapter:
    return FakeAdapter({task.task_id: task}, lambda t, h: make_sandbox(t, **sb_kwargs),
                       monitor_escapes=not sb_kwargs.get("vulnerable", True),
                       privileges={"same_container": sb_kwargs.get("vulnerable", True),
                                   "write_access": sb_kwargs.get("vulnerable", True),
                                   "network": sb_kwargs.get("network", True), "tools": False})
