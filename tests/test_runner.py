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


def test_probe_matrix_runs_every_profile_per_task(tmp_path):
    from etbh.runner import run_probe_matrix

    records = run_probe_matrix(get_adapter("fake", vulnerable=True), 2, 1, [BEFORE, AFTER], tmp_path)
    assert [r.plan.profile for r in records] == ["before", "after"]
    assert all(len(r.tasks) == 2 for r in records)
    assert records[0].plan.task_ids == records[1].plan.task_ids
    assert len(list(tmp_path.glob("*/run.json"))) == 2
    assert main(["probe", "--benchmark", "fake", "--n", "1", "--seed", "0", "--profile", "before", "after",
                 "--dry-run", "--out", str(tmp_path)]) == 0


def test_resume_continues_unfinished_matrix_run(tmp_path):
    import json

    from etbh.runner import run_probe_matrix

    adapter = get_adapter("fake", vulnerable=True)
    full = run_probe_matrix(adapter, 3, 1, [BEFORE, AFTER], tmp_path)
    ids = full[0].plan.task_ids
    # simulate an interrupted run: keep only the first task in both profiles, unfinished
    for rec in full:
        path = tmp_path / rec.run_id / "run.json"
        data = json.loads(path.read_text())
        data["tasks"] = data["tasks"][:1]
        data["finished"] = ""
        path.write_text(json.dumps(data))
    resumed = run_probe_matrix(adapter, 3, 1, [BEFORE, AFTER], tmp_path, resume=True)
    assert [r.run_id for r in resumed] == [r.run_id for r in full]  # same run ids
    assert all(len(r.tasks) == 3 and r.finished for r in resumed)
    assert all([t["task_id"] for t in r.tasks] == ids for r in resumed)
    assert all(r.host.get("resumed") for r in resumed)
    assert len(list(tmp_path.glob("*/run.json"))) == 2  # no new run directories
    # a finished run is not resumed: a fresh one is created
    fresh = run_probe_matrix(adapter, 3, 1, [BEFORE], tmp_path, resume=True)
    assert fresh[0].run_id != full[0].run_id


def test_disk_floor_waits_then_proceeds(monkeypatch):
    import etbh.runner as r

    readings = iter([5.0, 5.0, 50.0])
    monkeypatch.setattr(r, "free_gb", lambda path="/": next(readings))
    slept = []
    import time as _time
    monkeypatch.setattr(_time, "sleep", lambda s: slept.append(s))
    msgs = []
    r.wait_for_disk(12.0, msgs.append, poll_s=1)
    assert slept == [1, 1] and len(msgs) == 2
    r.wait_for_disk(0, msgs.append)  # disabled: no reading taken


def test_resume_redoes_errored_tasks_of_a_finished_run(tmp_path):
    import json

    from etbh.runner import run_probe_matrix

    adapter = get_adapter("fake", vulnerable=True)
    full = run_probe_matrix(adapter, 3, 1, [BEFORE], tmp_path)
    path = tmp_path / full[0].run_id / "run.json"
    data = json.loads(path.read_text())
    data["tasks"][1]["error"] = "AdapterUnavailable: Docker daemon not reachable"
    data["tasks"][1]["probes"] = []
    data["errors"] = [data["tasks"][1]["task_id"] + ": AdapterUnavailable"]
    path.write_text(json.dumps(data))  # finished, but with one errored task
    resumed = run_probe_matrix(adapter, 3, 1, [BEFORE], tmp_path, resume=True)
    assert resumed[0].run_id == full[0].run_id
    assert len(resumed[0].tasks) == 3 and not any(t.get("error") for t in resumed[0].tasks)
    assert resumed[0].errors == []
