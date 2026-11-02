#!/usr/bin/env python3
"""Run the ControlArena (bash setting) probes without touching the shared CLI.

    .venv/bin/python runs/run_control_arena.py --n 5 --seed 20261101 --profile before \
        --formatter last_tool_calls --out results

The image must exist first (built from the installed package's setting directory):

    docker build -t etbh/control-arena-bash:20.1.1 \
        .venv/lib/python3.12/site-packages/control_arena/settings/bash
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from etbh.adapters.base import AdapterUnavailable
from etbh.adapters.control_arena import FORMATTERS, ControlArenaAdapter
from etbh.hardening.profiles import PROFILES, profile
from etbh.runner import RunPlan, run_probes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--profile", default="before", choices=sorted(PROFILES))
    ap.add_argument("--formatter", default="last_tool_calls", choices=FORMATTERS)
    ap.add_argument("--image", default=None)
    ap.add_argument("--out", type=Path, default=Path("results"))
    ap.add_argument("--probes", nargs="*", default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    adapter = ControlArenaAdapter(monitor_formatter=args.formatter, image=args.image)
    try:
        result = run_probes(adapter, args.n, args.seed, profile(args.profile), args.out,
                            include=args.probes, dry_run=args.dry_run)
    except AdapterUnavailable as err:
        print(f"unavailable: {err}", file=sys.stderr)
        return 3
    if isinstance(result, RunPlan):
        print(json.dumps({"dry_run": True, **result.as_dict()}, indent=2))
        return 0
    print(f"wrote {args.out / result.run_id}/run.json "
          f"({len(result.tasks)} tasks, {len(result.errors)} errors)")
    for e in result.errors:
        print("  error:", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
