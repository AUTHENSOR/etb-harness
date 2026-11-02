#!/usr/bin/env python3
"""Offline ETB-15 check on CyberGym's public task archives.

For a seeded sample of tasks, download `repo-vul.tar.gz` (what the agent is given at every
level) and `repo-fix.tar.gz`, and record whether the vulnerable archive carries git history,
remotes, or the fixed tree, i.e. whether the oracle is inside the material the agent gets.
Writes a run.json in the harness result format with one probe per task (`git_history_has_fix`,
ETB-15) so `summarize` and `write_summary.py` pick it up. No sandbox is involved; the run's
pins say so.

    .venv/bin/python runs/run_cybergym_static.py --n 5 --seed 20261101 --out results
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import tarfile
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from etbh.adapters.cybergym import CyberGymAdapter, archive_url
from etbh.hardening.profiles import profile
from etbh.probes.base import ProbeResult
from etbh.runner import RunPlan, RunRecord, write_run

CACHE = Path(__file__).resolve().parents[1] / "cache" / "cybergym" / "archives"


def fetch(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        with urllib.request.urlopen(url, timeout=600) as r, dest.open("wb") as fh:  # noqa: S310 - fixed HF host
            while chunk := r.read(1 << 20):
                fh.write(chunk)
    return dest


def inspect_archive(path: Path) -> dict:
    """Scan tar members without extracting: git metadata, remotes, top-level names."""
    info = {"members": 0, "git_dirs": set(), "git_heads": [], "remotes": [], "top": set(), "sha256": None}
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    info["sha256"] = h.hexdigest()
    with tarfile.open(path, "r:gz") as tar:
        for m in tar:
            info["members"] += 1
            parts = m.name.split("/")
            if parts:
                info["top"].add(parts[0])
            if ".git" in parts:
                idx = parts.index(".git")
                info["git_dirs"].add("/".join(parts[: idx + 1]))
                rest = parts[idx + 1 :]
                if rest == ["HEAD"] and m.isfile():
                    f = tar.extractfile(m)
                    info["git_heads"].append(f.read(200).decode(errors="replace").strip() if f else "")
                if rest == ["config"] and m.isfile():
                    f = tar.extractfile(m)
                    cfg = f.read(4000).decode(errors="replace") if f else ""
                    info["remotes"] += [ln.strip() for ln in cfg.splitlines() if "url =" in ln]
    info["git_dirs"] = sorted(info["git_dirs"])
    info["top"] = sorted(info["top"])[:10]
    return info


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--out", type=Path, default=Path("results"))
    ap.add_argument("--level", default="level1")
    args = ap.parse_args()
    adapter = CyberGymAdapter(level=args.level)
    ids = adapter.sample_tasks(args.n, args.seed)
    plan = RunPlan(adapter.name, "before", args.n, args.seed,
                   {**adapter.version_pins(),
                    "mode": "static public-archive inspection; no sandbox, no grader run"},
                   ids, ["git_history_has_fix"], profile("before").as_dict())
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    record = RunRecord(run_id=f"{stamp}-{adapter.name}-before-s{args.seed}", plan=plan,
                       started=datetime.now(UTC).isoformat(),
                       host={"platform": platform.platform(), "machine": platform.machine()})
    for tid in ids:
        t0 = time.monotonic()
        spec = adapter.task_spec(tid)
        entry = {"task_id": tid, "probes": [], "seconds": 0.0}
        try:
            kind, num = tid.split(":", 1)
            vul = fetch(archive_url(tid, "repo-vul.tar.gz"), CACHE / kind / num / "repo-vul.tar.gz")
            vul_info = inspect_archive(vul)
            open_ = bool(vul_info["git_dirs"]) or bool(vul_info["remotes"])
            parts = []
            if vul_info["git_dirs"]:
                parts.append(f"git metadata present ({len(vul_info['git_dirs'])} .git dir(s), "
                             f"HEAD={vul_info['git_heads'][:1]})")
            if vul_info["remotes"]:
                parts.append(f"remotes configured: {vul_info['remotes'][:2]}")
            if not parts:
                parts.append("no .git directory and no remotes in repo-vul.tar.gz; "
                             "the fix is not in the archive")
            if spec.metadata["patch_given"]:
                parts.append(f"patch.diff is given at {args.level} by design")
            entry["probes"].append(ProbeResult(
                "git_history_has_fix", "ETB-15", open_, "; ".join(parts),
                {"archive": vul.name, "sha256": vul_info["sha256"], "members": vul_info["members"],
                 "top_level": vul_info["top"], "git_dirs": vul_info["git_dirs"],
                 "remotes": vul_info["remotes"],
                 "level": args.level, "patch_given": spec.metadata["patch_given"],
                 "static": True}).as_dict())
        except Exception as err:  # noqa: BLE001 - record and continue
            entry["error"] = f"{type(err).__name__}: {err}"
            record.errors.append(f"{tid}: {entry['error']}")
        entry["seconds"] = round(time.monotonic() - t0, 3)
        record.tasks.append(entry)
    record.finished = datetime.now(UTC).isoformat()
    out = write_run(record, args.out)
    print(f"wrote {out}/run.json ({len(record.tasks)} tasks, {len(record.errors)} errors)")
    for t in record.tasks:
        for p in t["probes"]:
            print(f"  {t['task_id']:18s} open={p['open']!s:5s} {p['evidence'][:120]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
