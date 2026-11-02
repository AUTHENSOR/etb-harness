"""Run probes over a sample of tasks and write results; build before/after summaries."""

from __future__ import annotations

import json
import platform
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from etbh import __version__
from etbh.adapters.base import AdapterUnavailable, BenchmarkAdapter
from etbh.hardening.profiles import Hardening
from etbh.hardening.transforms import pre_agent_commands, test_hashes
from etbh.probes import build_probes
from etbh.taxonomy import BY_ID, CLASSES


@dataclass
class RunPlan:
    benchmark: str
    profile: str
    n: int
    seed: int
    pins: dict[str, str]
    task_ids: list[str] | str
    probes: list[str]
    hardening: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class RunRecord:
    run_id: str
    plan: RunPlan
    started: str
    finished: str = ""
    host: dict[str, str] = field(default_factory=dict)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    llm_cost_usd: float = 0.0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "etbh_version": __version__,
            "run_id": self.run_id,
            "plan": self.plan.as_dict(),
            "started": self.started,
            "finished": self.finished,
            "host": self.host,
            "tasks": self.tasks,
            "llm_cost_usd": self.llm_cost_usd,
            "errors": self.errors,
        }


def make_plan(adapter: BenchmarkAdapter, n: int, seed: int, hardening: Hardening,
              include: list[str] | None = None, task_ids: list[str] | None = None) -> RunPlan:
    try:
        ids: list[str] | str = list(task_ids) if task_ids else adapter.sample_tasks(n, seed)
    except AdapterUnavailable as err:
        ids = f"resolved at run time ({err})"
    except NotImplementedError:
        ids = "adapter is a stub"
    probes = [p.probe_id for p in build_probes(adapter, hardening, include)]
    return RunPlan(adapter.name, hardening.name, n, seed, adapter.version_pins(), ids, probes,
                   hardening.as_dict())


def run_probes(
    adapter: BenchmarkAdapter,
    n: int,
    seed: int,
    hardening: Hardening,
    out_dir: Path,
    include: list[str] | None = None,
    dry_run: bool = False,
    prune: bool = False,
    task_ids: list[str] | None = None,
    log: Any = None,
) -> RunRecord | RunPlan:
    result = run_probe_matrix(adapter, n, seed, [hardening], out_dir, include=include, dry_run=dry_run,
                              prune=prune, task_ids=task_ids, log=log)
    return result[0]


def run_probe_matrix(
    adapter: BenchmarkAdapter,
    n: int,
    seed: int,
    hardenings: list[Hardening],
    out_dir: Path,
    include: list[str] | None = None,
    dry_run: bool = False,
    prune: bool = False,
    task_ids: list[str] | None = None,
    log: Any = None,
) -> list[RunRecord] | list[RunPlan]:
    """Probe every task under each profile in turn, pulling each task image once.

    One RunRecord (and results directory) per profile, so `summarize` is unchanged. The
    task image is pruned after the last profile when `prune` is set.
    """
    say = log or (lambda msg: None)
    plans = [make_plan(adapter, n, seed, h, include, task_ids) for h in hardenings]
    if dry_run:
        return plans
    for plan in plans:
        if isinstance(plan.task_ids, str):
            raise AdapterUnavailable(f"cannot run: {plan.task_ids}")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    host = {"platform": platform.platform(), "machine": platform.machine()}
    records = [RunRecord(run_id=f"{stamp}-{adapter.name}-{h.name}-s{seed}", plan=plan,
                         started=datetime.now(UTC).isoformat(), host=dict(host))
               for h, plan in zip(hardenings, plans, strict=True)]
    probe_sets = [build_probes(adapter, h, include) for h in hardenings]
    ids = plans[0].task_ids
    assert isinstance(ids, list)
    for i, task_id in enumerate(ids, 1):
        for j, (hardening, record, probes) in enumerate(zip(hardenings, records, probe_sets, strict=True)):
            task = adapter.task_spec(task_id)
            entry: dict[str, Any] = {"task_id": task_id, "image": task.image,
                                     "task": task.as_dict(), "probes": [], "seconds": 0.0}
            say(f"[{i}/{len(ids)}] {task_id} profile={hardening.name} image={task.image} "
                f"platform={task.metadata.get('platform')} runner={task.metadata.get('runner')}")
            t0 = time.monotonic()
            last_profile = j == len(hardenings) - 1
            try:
                with adapter.sandbox(task, hardening) as sb:
                    for cmd in pre_agent_commands(hardening, task):
                        root_exec = getattr(sb, "exec_as", None)
                        (root_exec(cmd, "root", 600) if root_exec else sb.exec(cmd))
                    if hardening.hash_check_tests:
                        task.metadata["_test_hashes"] = test_hashes(sb, task)
                    for probe in probes:
                        result = probe.run(task, sb)
                        entry["probes"].append(result.as_dict())
                        say(f"    {result.probe_id:<22} open={result.open!s:<5} {result.seconds:7.1f}s  "
                            f"{result.evidence[:110]}")
                    if prune and last_profile and hasattr(sb, "prune_image"):
                        sb.prune_image()
            except Exception as err:  # noqa: BLE001 - record and continue with the next task
                entry["error"] = f"{type(err).__name__}: {err}"
                record.errors.append(f"{task_id}: {entry['error']}")
                say(f"    ERROR {entry['error']}")
            entry["seconds"] = round(time.monotonic() - t0, 3)
            say(f"    task done in {entry['seconds']:.0f}s")
            record.tasks.append(entry)
            write_run(record, out_dir)  # checkpoint after every task
    for record in records:
        record.finished = datetime.now(UTC).isoformat()
        write_run(record, out_dir)
    return records


def write_run(record: RunRecord, out_dir: Path) -> Path:
    run_dir = out_dir / record.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(json.dumps(record.as_dict(), indent=2, sort_keys=True))
    (run_dir / "summary.md").write_text(render_summary(summarize_runs([record.as_dict()])))
    return run_dir


# -- summaries --------------------------------------------------------------------------

def class_rates(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per ETB class: tasks with >= 1 open probe / tasks probed, plus per-probe open rates."""
    tasks = run["tasks"]
    probed = [t for t in tasks if t.get("probes")]
    per_class: dict[str, dict[str, Any]] = {}
    probe_open: dict[str, list[bool | None]] = defaultdict(list)
    for cls in CLASSES:
        open_tasks = 0
        determinable = 0
        for t in probed:
            results = [p for p in t["probes"] if p["etb_class"] == cls.id
                       and p.get("counts_toward_class", True)]
            if not results:
                continue
            if any(p["open"] is not None for p in results):
                determinable += 1
            if any(p["open"] is True for p in results):
                open_tasks += 1
        if determinable or any(p["etb_class"] == cls.id and p.get("counts_toward_class", True)
                               for t in probed for p in t["probes"]):
            per_class[cls.id] = {
                "name": cls.name,
                "status": cls.status,
                "open_tasks": open_tasks,
                "tasks_probed": len(probed),
                "determinable": determinable,
                "gameable_rate": (open_tasks / len(probed)) if probed else None,
            }
    for t in probed:
        for p in t["probes"]:
            probe_open[p["probe_id"]].append(p["open"])
    per_probe = {
        pid: {
            "open": sum(1 for v in vals if v is True),
            "closed": sum(1 for v in vals if v is False),
            "undetermined": sum(1 for v in vals if v is None),
            "open_rate": (sum(1 for v in vals if v is True) / len(vals)) if vals else None,
        }
        for pid, vals in sorted(probe_open.items())
    }
    return {"classes": per_class, "probes": per_probe, "tasks_probed": len(probed),
            "errors": len(run.get("errors", []))}


def summarize_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Group runs by benchmark and profile; keep the latest run per (benchmark, profile)."""
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for run in sorted(runs, key=lambda r: r["started"]):
        latest[(run["plan"]["benchmark"], run["plan"]["profile"])] = run
    table: dict[str, dict[str, Any]] = {}
    for (bench, prof), run in latest.items():
        table.setdefault(bench, {})[prof] = {
            "run_id": run["run_id"],
            "pins": run["plan"]["pins"],
            "seed": run["plan"]["seed"],
            "llm_cost_usd": run.get("llm_cost_usd", 0.0),
            **class_rates(run),
        }
    return {"benchmarks": table, "generated": datetime.now(UTC).isoformat()}


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.0f}%"


def render_summary(summary: dict[str, Any]) -> str:
    lines = ["# Gameability summary", "", f"Generated {summary['generated']}. Static gameable rate "
             "per ETB class = tasks with at least one open class-counting probe in that class / tasks "
             "probed (capability-only probes such as tests_writable are reported per probe but do not "
             "set the class rate; see each probe's counts_toward_class). Probes marked synthetic feed "
             "the grader logic a constructed run instead of executing one. Dynamic bypass rates appear "
             "only when LLM attacker runs exist.", ""]
    for bench, profiles in summary["benchmarks"].items():
        lines.append(f"## {bench}")
        lines.append("")
        classes = sorted({c for p in profiles.values() for c in p["classes"]})
        cols = " | ".join(f"{p} (n={profiles[p]['tasks_probed']})" for p in profiles)
        header = f"| ETB class | {cols} |"
        lines.append(header)
        lines.append("|---|" + "---|" * len(profiles))
        for cid in classes:
            name = BY_ID[cid].name if cid in BY_ID else cid
            cells = [_pct(profiles[p]["classes"].get(cid, {}).get("gameable_rate")) for p in profiles]
            lines.append(f"| {cid} {name} | " + " | ".join(cells) + " |")
        lines.append("")
        lines.append("Per probe (open / closed / undetermined):")
        lines.append("")
        probe_ids = sorted({pid for p in profiles.values() for pid in p["probes"]})
        lines.append("| probe | " + " | ".join(profiles) + " |")
        lines.append("|---|" + "---|" * len(profiles))
        for pid in probe_ids:
            cells = []
            for p in profiles.values():
                r = p["probes"].get(pid)
                cells.append(f"{r['open']}/{r['closed']}/{r['undetermined']}" if r else "-")
            lines.append(f"| {pid} | " + " | ".join(cells) + " |")
        lines.append("")
        for prof, p in profiles.items():
            pins = ", ".join(f"{k}={v}" for k, v in p["pins"].items()) or "none"
            lines.append(f"- {prof}: run `{p['run_id']}`, seed {p['seed']}, pins: {pins}, "
                         f"LLM cost ${p['llm_cost_usd']:.2f}, task errors {p['errors']}")
        lines.append("")
    return "\n".join(lines)


def load_runs(results_dir: Path) -> list[dict[str, Any]]:
    runs = []
    for path in sorted(results_dir.glob("*/run.json")):
        runs.append(json.loads(path.read_text()))
    return runs
