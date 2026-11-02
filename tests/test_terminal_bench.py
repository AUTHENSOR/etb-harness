"""Terminal-Bench adapter: task parsing, reward rule, privileges; all offline."""

from __future__ import annotations

from pathlib import Path

from etbh.adapters.terminal_bench import (
    REWARD_PATH,
    TESTS_DIR,
    TerminalBenchAdapter,
    parse_task,
    reward_passed,
)
from etbh.hardening.profiles import AFTER, BEFORE

TASK_TOML = """version = "1.0"
[metadata]
difficulty = "medium"
category = "data-processing"
[verifier]
timeout_sec = 600.0
[environment]
docker_image = "example/regex-log:20251031"
cpus = 1
memory = "2G"
"""
DOCKERFILE = "FROM ubuntu:24.04\nWORKDIR /app\nCOPY . /app\n"
TEST_SH = (
    "#!/bin/bash\nuvx pytest /tests/test_outputs.py\n"
    "if [ $? -eq 0 ]; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi\n"
)
TEST_PY = "def test_output_exists():\n    assert True\n\ndef test_output_content():\n    assert True\n"


def make_task(root: Path, name: str = "regex-log") -> Path:
    d = root / name
    (d / "environment").mkdir(parents=True)
    (d / "tests").mkdir()
    (d / "solution").mkdir()
    (d / "task.toml").write_text(TASK_TOML)
    (d / "environment" / "Dockerfile").write_text(DOCKERFILE)
    (d / "tests" / "test.sh").write_text(TEST_SH)
    (d / "tests" / "test_outputs.py").write_text(TEST_PY)
    (d / "solution" / "solve.sh").write_text("#!/bin/bash\necho solved\n")
    return d


def test_parse_task_reads_image_workdir_tests(tmp_path: Path):
    row = parse_task(make_task(tmp_path))
    assert row["image"] == "example/regex-log:20251031"
    assert row["workdir"] == "/app"
    assert row["verifier_timeout"] == 600.0
    assert row["test_names"] == ["test_outputs.py::test_output_exists",
                                 "test_outputs.py::test_output_content"]
    assert row["has_solution"] is True


def test_task_spec_hides_tests_until_grading(tmp_path: Path):
    make_task(tmp_path)
    make_task(tmp_path, "chess-best-move")
    a = TerminalBenchAdapter(tasks_dir=tmp_path)
    assert a.task_ids() == ["chess-best-move", "regex-log"]
    spec = a.task_spec("regex-log")
    assert spec.workdir == "/app"
    assert spec.test_files == [f"{TESTS_DIR}/test_outputs.py", f"{TESTS_DIR}/test.sh"]
    assert REWARD_PATH in spec.grader_paths
    assert spec.metadata["spoof_conftest_dir"] == TESTS_DIR
    assert spec.metadata["grader_logic_known"] is False
    assert "_tests_dir" not in spec.as_dict()["metadata"]


def test_reward_rule_matches_harbor():
    assert reward_passed("1\n") == (True, "reward 1")
    assert reward_passed("0") == (False, "reward 0")
    assert reward_passed("0.5")[0] is False
    assert reward_passed("")[0] is False
    assert reward_passed(None)[0] is False
    assert reward_passed("nope")[0] is False


def test_privileges_before_and_after(tmp_path: Path):
    make_task(tmp_path)
    a = TerminalBenchAdapter(tasks_dir=tmp_path)
    spec = a.task_spec("regex-log")
    before = a.evaluator_privileges(spec, BEFORE)
    after = a.evaluator_privileges(spec, AFTER)
    assert before["same_container"] and before["write_access"] and before["network"]
    assert not after["same_container"] and not after["write_access"]
    assert after["network"], "the verifier script needs egress even when hardened"


def test_missing_tasks_dir_is_unavailable(tmp_path: Path):
    import pytest

    from etbh.adapters.base import AdapterUnavailable

    with pytest.raises(AdapterUnavailable):
        TerminalBenchAdapter(tasks_dir=tmp_path / "nope").task_ids()
