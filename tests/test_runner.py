from __future__ import annotations

import json

from etbh.adapters import get_adapter
from etbh.cli import main
from etbh.hardening.profiles import AFTER, BEFORE
from etbh.runner import RunPlan, load_runs, render_summary, run_probes, summarize_runs


def test_dry_run_prints_plan_without_writing(tmp_path, capsys):
    plan = run_probes(get_adapter("fake"), 2, 0, BEFORE, tmp_path, dry_run=True)
    assert isinstance(plan, RunPlan) and len(plan.task_ids) == 2 and plan.probes
    assert not any(tmp_path.iterdir())
    assert main(["probe", "--benchmark", "fake", "--n", "2", "--seed", "0", "--dry-run",
                 "--out", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["dry_run"] is True and out["benchmark"] == "fake"


def test_swe_bench_dry_run_without_dataset_reports_plan(tmp_path):
    plan = run_probes(get_adapter("swe_bench", arch="x86_64"), 2, 0, BEFORE, tmp_path, dry_run=True)
    assert isinstance(plan, RunPlan)
    assert plan.pins["dataset"] == "SWE-bench/SWE-bench_Verified"
    assert plan.pins["dataset_revision"] == "78f471bf655a3137b2e8a75af1501690ec009ec3"
    assert isinstance(plan.task_ids, (list, str))


def test_before_after_run_and_summary(tmp_path):
    before = run_probes(get_adapter("fake", vulnerable=True), 3, 1, BEFORE, tmp_path)
    after = run_probes(get_adapter("fake", vulnerable=False), 3, 1, AFTER, tmp_path)
    assert (tmp_path / before.run_id / "run.json").exists()
    assert (tmp_path / after.run_id / "summary.md").exists()
    summary = summarize_runs(load_runs(tmp_path))
    fake = summary["benchmarks"]["fake"]
    assert fake["before"]["classes"]["ETB-09"]["gameable_rate"] == 1.0
    assert fake["after"]["classes"]["ETB-09"]["gameable_rate"] == 0.0
    assert fake["before"]["classes"]["ETB-15"]["gameable_rate"] == 1.0
    assert fake["after"]["classes"]["ETB-15"]["gameable_rate"] == 0.0
    assert fake["before"]["llm_cost_usd"] == 0.0
    md = render_summary(summary)
    assert "| ETB-09 Forged execution artifact | 100% | 0% |" in md
    assert "stdout_spoof_pass" in md


def test_cli_summarize_and_pins(tmp_path, capsys):
    run_probes(get_adapter("fake"), 1, 0, BEFORE, tmp_path)
    assert main(["summarize", str(tmp_path)]) == 0
    assert "Gameability summary" in capsys.readouterr().out
    assert main(["summarize", str(tmp_path), "--json"]) == 0
    assert "benchmarks" in json.loads(capsys.readouterr().out)
    assert main(["pins", "--benchmark", "swe_bench"]) == 0
    assert "dataset" in json.loads(capsys.readouterr().out)


def test_attack_refuses_without_allow_llm():
    assert main(["attack", "--benchmark", "fake", "--strategy", "forge_execution_artifact",
                 "--model", "none/none"]) == 2
