"""`etbh` command line."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from etbh import __version__
from etbh.adapters import ADAPTER_NAMES, get_adapter
from etbh.adapters.base import AdapterUnavailable
from etbh.hardening.profiles import PROFILES, profile
from etbh.probes import PROBES_BY_ID
from etbh.runner import RunPlan, load_runs, render_summary, run_probe_matrix, summarize_runs


def _add_probe(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("probe", help="run deterministic capability probes")
    p.add_argument("--benchmark", required=True, choices=ADAPTER_NAMES)
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--profile", nargs="+", default=["before"], choices=sorted(PROFILES),
                   help="one or more profiles; with several, each task image is pulled once")
    p.add_argument("--out", type=Path, default=Path("results"))
    p.add_argument("--probes", nargs="*", choices=sorted(PROBES_BY_ID), default=None)
    p.add_argument("--dry-run", action="store_true", help="print the plan; touch nothing")
    p.add_argument("--prune", action="store_true", help="remove each task image after use")
    p.add_argument("--task-ids", nargs="*", default=None,
                   help="probe exactly these task ids instead of the seeded sample")
    _add_adapter_options(p)


def _add_summarize(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("summarize", help="build the before/after table from results/")
    p.add_argument("results", type=Path, nargs="?", default=Path("results"))
    p.add_argument("--json", action="store_true")


def _add_adapter_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dataset-revision", default=None,
                   help="HF dataset commit to pin (SWE-bench adapters; default is the adapter's pin)")
    p.add_argument("--arch", default=None, choices=["auto", "arm64", "x86_64"],
                   help="image architecture policy (SWE-bench adapters; default auto)")


def _adapter_kwargs(args: argparse.Namespace) -> dict:
    kwargs = {}
    if getattr(args, "dataset_revision", None):
        kwargs["dataset_revision"] = args.dataset_revision
    if getattr(args, "arch", None):
        kwargs["arch"] = args.arch
    if kwargs and not args.benchmark.startswith("swe_bench"):
        print("note: --dataset-revision/--arch only apply to swe_bench adapters", file=sys.stderr)
        return {}
    return kwargs


def _add_pins(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("pins", help="print an adapter's version pins")
    p.add_argument("--benchmark", required=True, choices=ADAPTER_NAMES)
    _add_adapter_options(p)


def _add_doctor(sub: argparse._SubParsersAction) -> None:
    sub.add_parser("doctor", help="check Docker, optional deps and disk headroom")


def _add_attack(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("attack", help="run an LLM attacker strategy (opt-in, costs money)")
    p.add_argument("--benchmark", required=True, choices=ADAPTER_NAMES)
    p.add_argument("--strategy", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--n", type=int, default=5)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--profile", default="before", choices=sorted(PROFILES))
    p.add_argument("--allow-llm", action="store_true")
    p.add_argument("--token-budget", type=int, default=None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="etbh", description="ETB gameability harness")
    parser.add_argument("--version", action="version", version=f"etbh {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    _add_probe(sub)
    _add_summarize(sub)
    _add_pins(sub)
    _add_doctor(sub)
    _add_attack(sub)
    args = parser.parse_args(argv)
    try:
        return {
            "probe": cmd_probe, "summarize": cmd_summarize, "pins": cmd_pins,
            "doctor": cmd_doctor, "attack": cmd_attack,
        }[args.cmd](args)
    except AdapterUnavailable as err:
        print(f"unavailable: {err}", file=sys.stderr)
        return 3


def cmd_probe(args: argparse.Namespace) -> int:
    adapter = get_adapter(args.benchmark, **_adapter_kwargs(args))
    results = run_probe_matrix(adapter, args.n, args.seed, [profile(p) for p in args.profile], args.out,
                               include=args.probes, dry_run=args.dry_run, prune=args.prune,
                               task_ids=args.task_ids,
                               log=lambda msg: print(msg, file=sys.stderr, flush=True))
    if results and isinstance(results[0], RunPlan):
        plans = [{"dry_run": True, **r.as_dict()} for r in results]
        print(json.dumps(plans[0] if len(plans) == 1 else plans, indent=2))
        return 0
    for rec in results:
        print(f"wrote {args.out / rec.run_id}/run.json ({len(rec.tasks)} tasks, {len(rec.errors)} errors)")
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    runs = load_runs(args.results)
    if not runs:
        print(f"no runs under {args.results}", file=sys.stderr)
        return 1
    summary = summarize_runs(runs)
    print(json.dumps(summary, indent=2) if args.json else render_summary(summary))
    return 0


def cmd_pins(args: argparse.Namespace) -> int:
    print(json.dumps(get_adapter(args.benchmark, **_adapter_kwargs(args)).version_pins(), indent=2))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from etbh.sandbox.docker_sandbox import docker_available

    checks: dict[str, str] = {}
    checks["docker_daemon"] = ("reachable" if docker_available()
                               else "not running (start Docker Desktop manually)")
    for mod in ("datasets", "swebench", "inspect_ai", "inspect_evals", "control_arena", "harbor"):
        try:
            __import__(mod)
            checks[mod] = "installed"
        except ImportError:
            checks[mod] = "missing"
    usage = shutil.disk_usage(Path.home())
    free_gb = usage.free / 1e9
    checks["internal_disk_free_gb"] = f"{free_gb:.1f} (prune per task; offload idle data to the USB drives)"
    print(json.dumps(checks, indent=2))
    return 0


def cmd_attack(args: argparse.Namespace) -> int:
    from etbh.attackers import AttackConfig, load_strategies, run_attack

    strategies = load_strategies()
    if args.strategy not in strategies:
        print(f"unknown strategy; known: {sorted(strategies)}", file=sys.stderr)
        return 2
    if not args.allow_llm:
        print("refusing to spend model budget without --allow-llm", file=sys.stderr)
        return 2
    adapter = get_adapter(args.benchmark)
    hardening = profile(args.profile)
    config = AttackConfig(model=args.model, strategy_id=args.strategy, allow_llm=True,
                          token_budget=args.token_budget)
    for task_id in adapter.sample_tasks(args.n, args.seed):
        out = run_attack(adapter, adapter.task_spec(task_id), config, hardening)
        print(json.dumps(out))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
