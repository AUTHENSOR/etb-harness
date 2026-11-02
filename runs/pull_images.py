#!/usr/bin/env python3
"""Pull images with a per-attempt timeout and retries, before a harness run.

Docker Hub pulls on this connection stall silently now and then; `docker pull` then blocks
forever. This wrapper gives each attempt a deadline, kills it, and retries.

    .venv/bin/python runs/pull_images.py --timeout 600 --retries 4 image1 image2 ...
    .venv/bin/python runs/pull_images.py --benchmark terminal_bench --n 5 --seed 20261101
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time


def have(image: str) -> bool:
    proc = subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False)
    return proc.returncode == 0


def pull(image: str, timeout: int, retries: int, platform: str | None) -> bool:
    if have(image):
        print(f"present  {image}")
        return True
    cmd = ["docker", "pull", "-q"] + (["--platform", platform] if platform else []) + [image]
    for attempt in range(1, retries + 1):
        t0 = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            if proc.returncode == 0 and have(image):
                print(f"pulled   {image} in {time.monotonic() - t0:.0f}s (attempt {attempt})")
                return True
            print(f"failed   {image} attempt {attempt}: {proc.stderr.strip()[:160]}")
        except subprocess.TimeoutExpired:
            print(f"timeout  {image} attempt {attempt} after {timeout}s")
        time.sleep(min(60, 15 * attempt))
    return False


def images_for(benchmark: str, n: int, seed: int) -> list[str]:
    from etbh.adapters import get_adapter

    adapter = get_adapter(benchmark)
    return [adapter.task_spec(t).image for t in adapter.sample_tasks(n, seed)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("images", nargs="*")
    ap.add_argument("--benchmark", default=None)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--retries", type=int, default=4)
    ap.add_argument("--platform", default=None)
    args = ap.parse_args()
    images = list(args.images)
    if args.benchmark:
        images += images_for(args.benchmark, args.n, args.seed)
    images = [i for i in images if i]
    ok = all(pull(i, args.timeout, args.retries, args.platform) for i in images)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
