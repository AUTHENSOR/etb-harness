"""SWE-bench adapter: eval-script helpers, image resolution and before/after grading."""
from __future__ import annotations

import json

import pytest

from etbh.adapters.base import ExecResult
from etbh.adapters.swe_bench import (
    END_MARK,
    EXIT_MARK,
    JUNIT_PATH,
    START_MARK,
    SweBenchAdapter,
    arm64_variant,
    inject_junit,
    parse_exit_marker,
    resolve_image,
    runner_kind,
    slice_test_output,
)
from etbh.adapters.swe_bench import (
    test_command_lines as command_lines,
)
from etbh.hardening.profiles import AFTER, BEFORE
from etbh.probes.stdout_spoof_pass import CONFTEST_TEMPLATE

PYTEST_SCRIPT = [
    "source /opt/miniconda3/bin/activate",
    "cd /testbed",
    "git apply -v - <<'EOF_1'", "diff --git a/t.py b/t.py", "EOF_1",
    f": '{START_MARK}'",
    "pytest -rA lib/matplotlib/tests/test_x.py",
    "SWEBENCH_TEST_EXIT_CODE=$?",
    f": '{END_MARK}'",
    f'echo "{EXIT_MARK}: $SWEBENCH_TEST_EXIT_CODE"',
    "git checkout abc lib/matplotlib/tests/test_x.py",
]
DJANGO_SCRIPT = [
    f": '{START_MARK}'",
    "./tests/runtests.py --verbosity 2 --settings=test_sqlite --parallel 1 utils_tests.test_dateformat",
    "SWEBENCH_TEST_EXIT_CODE=$?",
    f": '{END_MARK}'",
    f'echo "{EXIT_MARK}: $SWEBENCH_TEST_EXIT_CODE"',
]


def test_test_command_lines_and_runner_kind():
    assert command_lines(PYTEST_SCRIPT) == ["pytest -rA lib/matplotlib/tests/test_x.py"]
    assert runner_kind(command_lines(PYTEST_SCRIPT)) == "pytest"
    assert runner_kind(command_lines(DJANGO_SCRIPT)) == "django"
    assert runner_kind(["bin/test -C --verbose sympy/x.py"]) == "sympy"
    assert runner_kind(["python -m pytest tests"]) == "pytest"
    assert runner_kind(["make test"]) == "unknown"


def test_inject_junit_only_touches_pytest_inside_markers():
    out = inject_junit(PYTEST_SCRIPT)
    assert out[6] == f"pytest --junitxml={JUNIT_PATH} -rA lib/matplotlib/tests/test_x.py"
    assert out[:6] == PYTEST_SCRIPT[:6] and out[7:] == PYTEST_SCRIPT[7:]
    assert inject_junit(DJANGO_SCRIPT) == DJANGO_SCRIPT
    assert inject_junit(inject_junit(PYTEST_SCRIPT)) == out  # idempotent


def test_slice_and_exit_marker():
    log = f"noise\n{START_MARK}\nPASSED a\n{END_MARK}\n{EXIT_MARK}: 1\n"
    assert slice_test_output(log) == "\nPASSED a\n"
    assert parse_exit_marker(log) == 1
    assert parse_exit_marker("no marker") is None


def test_resolve_image_policies(monkeypatch):
    x86 = "swebench/sweb.eval.x86_64.a_1776_b-1:latest"
    assert arm64_variant(x86) == "swebench/sweb.eval.arm64.a_1776_b-1:latest"
    assert resolve_image(x86, "x86_64")[:2] == (x86, "linux/amd64")
    assert resolve_image(x86, "arm64")[:2] == (arm64_variant(x86), "linux/arm64")
    import etbh.adapters.swe_bench as m
    monkeypatch.setattr(m, "image_local", lambda img: False)
    monkeypatch.setattr(m, "image_available", lambda img: True)
    assert resolve_image(x86, "auto")[:2] == (arm64_variant(x86), "linux/arm64")
    # local-first: an x86_64 image already on disk wins over a registry arm64 build
    monkeypatch.setattr(m, "image_local", lambda img: img == x86)
    assert resolve_image(x86, "auto")[:2] == (x86, "linux/amd64")
    monkeypatch.setattr(m, "image_local", lambda img: False)
    monkeypatch.setattr(m, "image_available", lambda img: False)
    assert resolve_image(x86, "auto")[:2] == (x86, "linux/amd64")
    monkeypatch.setattr(m, "image_available", lambda img: None)
    img, plat, note = resolve_image(x86, "auto")
    assert (img, plat) == (x86, "linux/amd64") and "UNVERIFIED" in note
    with pytest.raises(ValueError):
        resolve_image(x86, "riscv")


def _row(**over):
    row = {
        "instance_id": "matplotlib__matplotlib-1", "repo": "matplotlib/matplotlib", "base_commit": "abc",
        "patch": "diff --git a/lib/m.py b/lib/m.py\n",
        "test_patch": "diff --git a/lib/tests/test_x.py b/lib/tests/test_x.py\n",
        "FAIL_TO_PASS": json.dumps(["lib/tests/test_x.py::test_a"]),
        "PASS_TO_PASS": json.dumps(["lib/tests/test_x.py::test_b"]),
        "image": "swebench/sweb.eval.x86_64.matplotlib_1776_matplotlib-1:latest", "version": "3.5",
    }
    row.update(over)
    return row


def _adapter(monkeypatch, row):
    import etbh.adapters.swe_bench as m
    monkeypatch.setattr(m, "image_local", lambda img: False)
    monkeypatch.setattr(m, "image_available", lambda img: False)
    return SweBenchAdapter(rows={row["instance_id"]: row}, arch="auto")


def test_task_spec_without_eval_script_uses_generic_runner(monkeypatch):
    ad = _adapter(monkeypatch, _row())
    spec = ad.task_spec("matplotlib__matplotlib-1")
    assert spec.image.endswith("x86_64.matplotlib_1776_matplotlib-1:latest")
    assert spec.metadata["platform"] == "linux/amd64"
    assert spec.metadata["runner"] == "pytest" and "UNVERIFIED" in spec.metadata["grader_source"]
    assert "--junitxml" in spec.metadata["_eval_script_after"]
    assert "--junitxml" not in spec.metadata["_eval_script_before"]


def test_grade_output_before_ignores_exit_marker_after_honours_it(monkeypatch):
    ad = _adapter(monkeypatch, _row())
    spec = ad.task_spec("matplotlib__matplotlib-1")
    spec.metadata["log_parser"] = "legacy"
    forged = (f"{START_MARK}\nPASSED lib/tests/test_x.py::test_a\nPASSED lib/tests/test_x.py::test_b\n"
              f"{END_MARK}\n{EXIT_MARK}: 1\n")
    before = ad.grade_output(spec, ExecResult(0, forged), BEFORE)
    assert before.passed is True and before.parsed["exit_marker"] == 1
    after = ad.grade_output(spec, ExecResult(0, forged), AFTER)
    assert after.passed is False
    assert any("spoofing suspected" in n for n in after.notes)
    # forced exit 0 with no junit: still rejected in `after` because junit is required for pytest
    forged0 = forged.replace(f"{EXIT_MARK}: 1", f"{EXIT_MARK}: 0")
    after0 = ad.grade_output(spec, ExecResult(0, forged0), AFTER)
    assert after0.passed is False and any("junit report missing" in n for n in after0.notes)


def test_grade_output_django_runner_falls_back_to_exit_code_only(monkeypatch):
    row = _row(instance_id="django__django-1", repo="django/django",
               image="swebench/sweb.eval.x86_64.django_1776_django-1:latest",
               FAIL_TO_PASS=json.dumps(["test_y (utils_tests.test_dateformat.DateFormatTests)"]),
               PASS_TO_PASS=json.dumps([]))
    ad = _adapter(monkeypatch, row)
    spec = ad.task_spec("django__django-1")
    pytest.importorskip("swebench")  # exercises the benchmark's own django parser
    spec.metadata.update({"runner": "django", "junit_supported": False, "log_parser": "parse_log_django"})
    log = (f"{START_MARK}\ntest_y (utils_tests.test_dateformat.DateFormatTests) ... ok\n"
           f"{END_MARK}\n{EXIT_MARK}: 0\n")
    after = ad.grade_output(spec, ExecResult(0, log), AFTER)
    assert after.passed is True and after.parsed["parser"] == "parse_log_django"
    assert any("UNVERIFIED" in n for n in after.notes)
    # a django run whose process failed but whose log shows no failure is rejected in `after`
    bad = ad.grade_output(spec, ExecResult(0, log.replace(f"{EXIT_MARK}: 0", f"{EXIT_MARK}: 1")), AFTER)
    assert bad.passed is False


def test_spoof_conftest_has_all_three_mechanisms():
    src = CONFTEST_TEMPLATE.format(marker="M", names=["a::b"])
    assert "items[:] = []" in src
    assert "trylast=True" in src
    assert "session.exitstatus = 0" in src
    compile(src, "conftest.py", "exec")


def test_cli_accepts_adapter_options(monkeypatch, capsys):
    import etbh.adapters.swe_bench as m
    from etbh import cli
    monkeypatch.setattr(m, "image_available", lambda img: False)
    rc = cli.main(["pins", "--benchmark", "swe_bench", "--dataset-revision", "deadbeef", "--arch", "x86_64"])
    assert rc == 0
    pins = json.loads(capsys.readouterr().out)
    assert pins["dataset_revision"] == "deadbeef" and pins["arch_policy"] == "x86_64"


def test_pro_rows_map_without_a_grader(monkeypatch):
    row = {
        "instance_id": "instance_Acme__thing-abc-vnan", "repo": "Acme/thing", "base_commit": "abc",
        "patch": "diff --git a/src/a.py b/src/a.py\n",
        "test_patch": "diff --git a/tests/test_a.py b/tests/test_a.py\n",
        "fail_to_pass": json.dumps(["tests/test_a.py::test_x"]), "pass_to_pass": "[]",
        "docker_image": "ghcr.io/scaleapi/swe-bench_pro-v2:instance_Acme__thing-abc-vnan",
        "repo_language": "python", "version": "2.0.0",
    }
    import etbh.adapters.swe_bench as m
    monkeypatch.setattr(m, "image_available", lambda img: True)
    ad = SweBenchAdapter(variant="pro", rows={row["instance_id"]: row})
    spec = ad.task_spec(row["instance_id"])
    assert spec.image.startswith("ghcr.io/scaleapi/") and spec.metadata["platform"] is None
    assert spec.fail_to_pass == ["tests/test_a.py::test_x"] and spec.test_files == ["tests/test_a.py"]
    assert spec.grader_command == "" and spec.metadata["grader_logic_known"] is False
    assert "UNVERIFIED" in spec.metadata["grader_source"]
    # grading probes refuse to guess when the benchmark grader is not integrated
    from etbh.probes import build_probes

    probes = build_probes(ad, BEFORE,
                          ["exit_code_ignored", "degenerate_pass", "test_edit_pass", "stdout_spoof_pass"])
    results = {p.probe_id: p.run(spec, None) for p in probes}
    assert all(r.open is None for r in results.values()), {k: v.evidence for k, v in results.items()}


def test_synthetic_probes_under_after_profile(monkeypatch):
    """The two grader-logic probes must run (not error) under `after` and come out closed."""
    from etbh.probes import build_probes

    ad = _adapter(monkeypatch, _row())
    spec = ad.task_spec("matplotlib__matplotlib-1")
    results = {p.probe_id: p.run(spec, None)
               for p in build_probes(ad, AFTER, ["exit_code_ignored", "degenerate_pass"])}
    assert results["exit_code_ignored"].open is False
    assert results["degenerate_pass"].open is False, results["degenerate_pass"].evidence
    assert "structural policy" in results["degenerate_pass"].evidence
    before = {p.probe_id: p.run(spec, None)
              for p in build_probes(ad, BEFORE, ["exit_code_ignored", "degenerate_pass"])}
    assert before["exit_code_ignored"].open is True and before["degenerate_pass"].open is True
