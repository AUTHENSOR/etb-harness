from __future__ import annotations

from etbh.grading import grade_log, parse_junit, parse_pytest_log_legacy
from etbh.hardening.profiles import GradingPolicy

F2P = ["tests/test_a.py::test_fix"]
P2P = ["tests/test_a.py::test_old"]


def test_legacy_parse_first_token():
    log = "PASSED tests/test_a.py::test_fix\nFAILED tests/test_a.py::test_old - boom\nnoise\n"
    assert parse_pytest_log_legacy(log) == {
        "tests/test_a.py::test_fix": "PASSED", "tests/test_a.py::test_old": "FAILED"}


def test_before_policy_ignores_exit_code():
    log = "PASSED tests/test_a.py::test_fix\nPASSED tests/test_a.py::test_old\n"
    assert grade_log(log, 1, F2P, P2P).passed is True


def test_after_policy_refuses_all_pass_with_nonzero_exit():
    log = "PASSED tests/test_a.py::test_fix\nPASSED tests/test_a.py::test_old\n"
    out = grade_log(log, 1, F2P, P2P, GradingPolicy(require_exit_code=True))
    assert out.passed is False and any("spoofing suspected" in n for n in out.notes)


def test_after_policy_accepts_genuine_pass_with_junit():
    log = "PASSED tests/test_a.py::test_fix\nPASSED tests/test_a.py::test_old\n"
    junit = ('<testsuite><testcase classname="tests.test_a" name="test_fix"/>'
             '<testcase classname="tests.test_a" name="test_old"/></testsuite>')
    out = grade_log(log, 0, F2P, P2P, GradingPolicy(require_exit_code=True, require_junit=True), junit)
    assert out.passed is True, out.notes


def test_junit_mismatch_fails():
    log = "PASSED tests/test_a.py::test_fix\nPASSED tests/test_a.py::test_old\n"
    junit = ('<testsuite><testcase classname="tests.test_a" name="test_fix"><failure/></testcase>'
             '<testcase classname="tests.test_a" name="test_old"/></testsuite>')
    out = grade_log(log, 0, F2P, P2P, GradingPolicy(require_junit=True), junit)
    assert out.passed is False
    assert parse_junit(junit)["tests.test_a::test_fix"] == "FAILED"


def test_min_p2p_fraction():
    log = "PASSED tests/test_a.py::test_fix\nFAILED tests/test_a.py::test_old\n"
    assert grade_log(log, 1, F2P, P2P).passed is False
    out = grade_log("PASSED tests/test_a.py::test_fix\n", 0, F2P, [], GradingPolicy(min_p2p_fraction=1.0))
    assert out.passed is True  # no P2P tests declared: fraction defaults to 1.0
