from __future__ import annotations

import pytest

from etbh.probes import ALL_PROBES, PROBES_BY_ID, build_probes
from etbh.probes.base import ProbeResult
from tests.conftest import make_adapter, make_sandbox, make_task

OPEN_ON_SHIPPED = {
    "tests_readable": False,  # held-out test names are not in the repo before grading
    "git_history_has_fix": True, "network_egress": True, "tests_writable": True,
    "grader_path_writable": True, "test_edit_pass": True, "stdout_spoof_pass": True,
    "exit_code_ignored": True, "eval_context_leak": True, "degenerate_pass": True,
    "trace_injection": True, "privileged_evaluator": True,
}


def run_all(*, vulnerable: bool, hardening, **sb):
    task = make_task()
    adapter = make_adapter(task, vulnerable=vulnerable, **sb)
    with adapter.sandbox(task, hardening) as sandbox:
        if hardening.hash_check_tests:
            from etbh.hardening.transforms import test_hashes

            task.metadata["_test_hashes"] = test_hashes(sandbox, task)
        return {p.probe_id: p.run(task, sandbox) for p in build_probes(adapter, hardening)}


def test_every_probe_is_open_on_the_shipped_vulnerable_fake(before):
    results = run_all(vulnerable=True, hardening=before)
    assert set(results) == set(OPEN_ON_SHIPPED)
    for pid, expected in OPEN_ON_SHIPPED.items():
        assert results[pid].open is expected, (pid, results[pid].evidence)


def test_every_probe_is_closed_after_hardening(after):
    results = run_all(vulnerable=False, hardening=after, history=False, network=False, leak=False,
                      read_only_tests=True)
    for pid, res in results.items():
        assert res.open is False, (pid, res.evidence)


def test_results_are_well_formed(before):
    for res in run_all(vulnerable=True, hardening=before).values():
        assert isinstance(res, ProbeResult)
        d = res.as_dict()
        assert set(d) >= {"probe_id", "etb_class", "open", "evidence", "details", "seconds"}
        assert res.seconds >= 0


def test_probes_restore_state(before):
    task = make_task()
    adapter = make_adapter(task)
    with adapter.sandbox(task, before) as sb:
        snapshot = dict(sb.files)
        for p in build_probes(adapter, before):
            p.run(task, sb)
        assert sb.files == snapshot


def test_tests_readable_opens_when_hidden_tests_present(before):
    task = make_task()
    sb = make_sandbox(task)
    sb.files[task.abs_path("tests/test_feature.py")] += "\ndef test_fix():\n    assert 1\n"
    res = PROBES_BY_ID["tests_readable"](None, before).run(task, sb)
    assert res.open is True


def test_undetermined_when_task_declares_nothing(before):
    task = make_task(test_files=[], fail_to_pass=[], pass_to_pass=[], grader_paths=[])
    adapter = make_adapter(task)
    with adapter.sandbox(task, before) as sb:
        for pid in ("tests_readable", "tests_writable", "grader_path_writable", "test_edit_pass",
                    "stdout_spoof_pass", "exit_code_ignored", "degenerate_pass"):
            assert PROBES_BY_ID[pid](adapter, before).run(task, sb).open is None, pid


def test_trace_injection_undetermined_without_monitor(before, task):
    from etbh.adapters.fake import FakeAdapter

    adapter = FakeAdapter({task.task_id: task}, lambda t, h: make_sandbox(t))
    with adapter.sandbox(task, before) as sb:
        assert PROBES_BY_ID["trace_injection"](adapter, before).run(task, sb).open is None


def test_probe_errors_become_undetermined(before, task):
    class Boom(ALL_PROBES[0]):
        probe_id = "boom"

        def _run(self, task, sandbox):
            raise RuntimeError("kaboom")

    res = Boom(None, before).run(task, make_sandbox(task))
    assert res.open is None and "kaboom" in res.evidence


@pytest.mark.parametrize("probe_cls", ALL_PROBES)
def test_probe_descriptions_present(probe_cls):
    assert probe_cls.description and probe_cls.probe_id and probe_cls.etb_class


def test_held_out_lines_ignore_moved_code():
    from etbh.probes.tests_readable import held_out_lines

    patch = (
        "diff --git a/tests/test_a.py b/tests/test_a.py\n--- a/tests/test_a.py\n+++ b/tests/test_a.py\n"
        "@@ -1,3 +1,4 @@\n"
        "-    assert compute(1) == 2  # existing assertion\n"
        "+    assert compute(1) == 2  # existing assertion\n"
        "+    assert compute(2) == 4  # genuinely new assertion\n"
        "+# comment only\n"
    )
    assert held_out_lines(patch) == ["assert compute(2) == 4  # genuinely new assertion"]
