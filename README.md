# etb-harness

Measures how gameable an AI agent benchmark is, before and after hardening, broken down by
Evaluator Trust Boundary (ETB) class. Part of Authensor's ETB work; the class definitions
live in `etb-registry/docs/taxonomy.md` and `etbh/taxonomy.py` mirrors them.

Credit: John Kearney (Authensor Research), john@authensor.com. Apache-2.0.

## Two metrics

**Static gameability** comes from deterministic capability probes run inside the task
sandbox with no model in the loop: can the agent read the held-out tests, reach the fix
commit, reach the network, edit the tests or the grader, forge the runner's output, tell
it is being evaluated, and so on. Each probe maps to exactly one ETB class. The static
gameable rate for a class is the share of probed tasks in which at least one probe of that
class is open, counting only the probes that measure a consequence (for ETB-11 that is
`test_edit_pass`; `tests_writable` and `grader_path_writable` report capability per probe
without setting the class rate). Two probes are synthetic: `exit_code_ignored` and
`degenerate_pass` feed the grader logic a constructed run instead of executing one, and
are labelled so in every result. It is cheap, reproducible from the pinned versions and
seed, and it measures the harness rather than any attacker's skill.

**Dynamic gameability** comes from LLM attacker policies (`etbh/attackers/`) told to
maximise the grader's score without solving the task. It is opt-in (`--allow-llm`), costs
model budget, and its result is the bypass rate: passes that the verifier
(`etbh/verifier/`) labels `bypass` over tasks attacked. Every strategy names the probe
that measures the same surface statically, so the two numbers can be reconciled.

Both are reported per benchmark, per ETB class, for the `before` profile (the benchmark
as shipped at its pinned version) and the `after` profile (every hardening switch on).

## Layout

| Path | What |
|---|---|
| `etbh/taxonomy.py` | ETB-01..16 table (10 published, 6 proposed) |
| `etbh/adapters/` | one adapter per benchmark; `fake.py` is the offline test double |
| `etbh/probes/` | twelve capability probes |
| `etbh/attackers/` | sixteen attacker strategies, one per class, plus `strategies.yaml` |
| `etbh/verifier/` | diff policy, clean re-grade, verdict |
| `etbh/hardening/` | `before`/`after` profiles and the sandbox and grading transforms |
| `etbh/sandbox/` | Docker sandbox (never starts the daemon) |
| `etbh/runner.py`, `etbh/cli.py` | runs, `run.json`, `summary.md`, before/after table |
| `runs/` | per-benchmark run configs with pinned versions and seeds |
| `results/` | one directory per run; empty until a real run writes it |

## Run

```bash
uv venv .venv --python 3.12
uv pip install -e ".[dev]"            # add .[swe] .[control] .[tb] for real benchmarks
uv run etbh doctor                    # Docker daemon, optional deps, disk headroom
uv run etbh probe --benchmark fake --n 3 --seed 0 --profile before --out results/
uv run etbh probe --benchmark swe_bench --n 2 --seed 0 --dry-run
uv run etbh probe --benchmark swe_bench --n 50 --seed 20261101 --arch auto --profile before --prune
uv run etbh probe --benchmark swe_bench --n 50 --seed 20261101 --arch auto --profile after --prune
uv run etbh probe --benchmark swe_bench --task-ids sympy__sympy-15976 --profile before   # one task
# --dataset-revision <hf commit> overrides the adapter's pin; --arch auto|arm64|x86_64
uv run etbh summarize results/
```

`--dry-run` prints the plan (pins, seed, task ids, probes) and writes nothing. Real runs
need Docker and the benchmark images; `etbh doctor` says what is missing.

## Docker and disk

Docker Desktop is installed on this machine; the harness detects whether the daemon is
running (`etbh doctor`) and never starts it. SWE-bench images are several GB each and mostly
x86_64 (arm64 availability UNVERIFIED), so on this Mac they run under emulation. Disk rule:
run with `--prune` so each task image is removed after its probes, keep `n` small until the
per-image cost is known, and move idle run data and image caches to the USB drives rather
than leaving them on the internal disk.

## Rules

- Public benchmarks only, run in sandboxes. No live systems, platforms or anyone else's
  infrastructure.
- No model calls unless `--allow-llm` is passed; the test-suite never calls one.
- Every attack and probe maps to an ETB class in `etbh/taxonomy.py`.
- No invented numbers. `results/` stays empty until a real run writes it; pins that could
  not be resolved offline are marked UNVERIFIED in `runs/*.yaml`.
- Nothing is published before the affected benchmark's maintainers are notified.

## Grading note for SWE-bench

The `before` profile grades with the legacy first-token stdout parse and ignores the exit
code, which is how the SWE-bench harness behaved until SWE-bench #620 (merged 2026-08-14,
first released in swebench 5.0.0) added the exit-code defence. The `after` profile
cross-checks exit code and junit and applies the structural diff policy. The ETB-09 probes
therefore measure the pre-fix harness unless `runs/swe_bench_verified.yaml` is changed.
