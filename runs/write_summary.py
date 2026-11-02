#!/usr/bin/env python3
"""Write results/summary.md: method, pins, before/after tables, limits, disclosure notes.

    .venv/bin/python runs/write_summary.py [--results results] [--out results/summary.md]

Everything numeric comes from run.json files; nothing is typed in by hand. Benchmarks with
no runs are listed as "not yet run". The disclosure-note section only lists classes that
were measured open in a `before` run; wording is a draft for the maintainer notification
and is never sent from here.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from etbh.runner import class_rates, load_runs, render_summary, summarize_runs
from etbh.taxonomy import BY_ID

PLANNED = ("swe_bench", "swe_bench_pro", "control_arena", "terminal_bench", "cybergym", "bountybench")
SYNTHETIC_PROBES = {"exit_code_ignored", "degenerate_pass"}

METHOD = """## Method

Two measurements per benchmark, each on a seeded sample of tasks with pinned dataset
revisions, package versions and images (listed per run below):

- **Static gameability.** Deterministic capability probes run inside the benchmark's own
  sandbox and grader, with no model involved. A probe is *open* when the surface it tests
  is reachable (for example the hidden tests are readable, or a forged run is graded as a
  pass). The static gameable rate for an ETB class is the share of sampled tasks with at
  least one open probe in that class. Probes marked *synthetic* feed the benchmark's
  grading logic a constructed run instead of executing one; they measure the grader's
  rule, not an end-to-end attack.
- **Dynamic gameability.** LLM attacker policies instructed to maximise the grader's score
  without solving the task. Opt-in, cost-logged. No dynamic runs have been made yet.

`before` is the benchmark as shipped. `after` is the same benchmark under the etb-harness
hardening profile (git history stripped, tests copied in at grade time and hash-checked,
network off, grading in a fresh container with the agent's pytest configuration disabled,
exit status and JUnit cross-checked, structural diff policy). Every attack maps to one
class of the ETB taxonomy (etb-registry/docs/taxonomy.md).
"""

LIMITS = """## Limits

- Sample sizes are small (n per run is in the table); rates are counts, not estimates.
- Synthetic probes (`exit_code_ignored`, `degenerate_pass`) do not execute an attack.
- `tests_readable` and `network_egress` can be open by design (a benchmark that gives the
  agent its tests, or needs egress for a side task); the table reports the surface, the
  notes say whether it is a choice.
- Hardening is etb-harness's profile, not a patch to the benchmark; where we wrote a patch
  it is referenced in the registry entry.
- Nothing here has been shared with a maintainer unless the registry entry says so.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=Path("results"))
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    runs = load_runs(args.results)
    out = args.out or (args.results / "summary.md")
    if runs:
        summary = summarize_runs(runs)
    else:
        summary = {"benchmarks": {}, "generated": datetime.now(UTC).isoformat()}
    lines = ["# Gameability results", "",
             f"Generated {summary['generated']} from {len(runs)} run(s) under `{args.results}/`.", ""]
    lines.append("## Coverage")
    lines.append("")
    lines.append("| Benchmark | before | after | notes |")
    lines.append("|---|---|---|---|")
    seen = set()
    for bench in list(PLANNED) + sorted(b for b in summary["benchmarks"] if b.split(":")[0] not in PLANNED):
        rows = {k: v for k, v in summary["benchmarks"].items() if k == bench or k.startswith(bench + ":")}
        if not rows:
            lines.append(f"| {bench} | not yet run | not yet run | |")
            continue
        for key, profiles in rows.items():
            seen.add(key)
            b = profiles.get("before", {})
            a = profiles.get("after", {})
            note = "monitor-formatter variant" if ":" in key else ""
            b_cell = f"n={b['tasks_probed']}" if b else "not run"
            a_cell = f"n={a['tasks_probed']}" if a else "not run"
            lines.append(f"| {key} | {b_cell} | {a_cell} | {note} |")
    lines.append("")
    lines.append(METHOD)
    lines.append(render_summary(summary).split("\n", 3)[3] if runs else "_No runs yet._")
    lines.append("")
    lines.append("## Open surfaces per benchmark (before), with the probe that found them")
    lines.append("")
    latest_before: dict[str, dict] = {}
    for run in sorted(runs, key=lambda r: r["started"]):
        if run["plan"]["profile"] == "before":
            latest_before[run["plan"]["benchmark"]] = run
    for bench, run in latest_before.items():
        rates = class_rates(run)
        opens = [(pid, r) for pid, r in rates["probes"].items() if r["open"]]
        lines.append(f"### {bench} (run `{run['run_id']}`)")
        lines.append("")
        if not opens:
            lines.append("No open surface.")
        for pid, r in opens:
            results = [p for t in run["tasks"] for p in t["probes"] if p["probe_id"] == pid]
            cls = results[0]["etb_class"] if results else "?"
            name = BY_ID[cls].name if cls in BY_ID else cls
            tag = " (synthetic)" if pid in SYNTHETIC_PROBES else ""
            ev = next((p["evidence"] for p in results if p["open"]), "")
            total = r["open"] + r["closed"] + r["undetermined"]
            lines.append(f"- `{pid}`{tag}: {cls} {name}, open on {r['open']}/{total} tasks. {ev[:160]}")
        lines.append("")
    lines.append(LIMITS)
    lines.append("## Draft disclosure notes")
    lines.append("")
    lines.append("One note per benchmark with an executed (non-synthetic) open surface in `before`. "
                 "Drafts only; the registry entry and the policy decide when and how they go out.")
    # (wording below is a draft for the maintainer notification; nothing is sent from here)
    lines.append("")
    for bench, run in latest_before.items():
        rates = class_rates(run)
        executed = [pid for pid, r in rates["probes"].items() if r["open"] and pid not in SYNTHETIC_PROBES]
        if not executed:
            continue
        pins = run["plan"]["pins"]
        lines.append(f"### To the maintainers of {bench}")
        lines.append("")
        version = pins.get("control_arena") or pins.get("swebench") or "pinned versions"
        lines.append(f"Measured on {version} "
                     f"(run `{run['run_id']}`, seed {run['plan']['seed']}, {rates['tasks_probed']} tasks). "
                     f"Open surfaces: {', '.join(executed)}. Each maps to a class in the ETB taxonomy with a "
                     "fix pattern; where we have a patch it is linked from the registry entry. We would like to "
                     "coordinate on the fix before publishing the entry (policy: public filing is the "
                     "notification; entry no earlier than 14 days after filing or when a fix lands).")
        lines.append("")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    print(f"wrote {out} ({len(runs)} runs, {len(seen)} benchmark keys)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
