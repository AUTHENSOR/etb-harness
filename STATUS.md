# etb-harness status (2026-11-02, updated after the first real run)

See "First real run" at the end for the SWE-bench Verified numbers; everything else below
describes the code state.

## Implemented and tested offline

- Taxonomy table ETB-01..16 (10 published, 6 proposed) and the rule that every probe and
  attacker strategy maps to exactly one class (`tests/test_taxonomy.py`).
- Adapter protocol, deterministic sampling (sorted ids, seeded shuffle), shared grading
  logic with the legacy first-token parse (`before`) and exit-code + junit cross-check
  (`after`), structural diff policy, verdict (`real_solve | bypass | undetermined`).
- Twelve probes, each with an open and a closed case in the fake benchmark:
  `tests_readable`, `git_history_has_fix`, `network_egress` (ETB-15); `tests_writable`,
  `grader_path_writable`, `test_edit_pass` (ETB-11); `stdout_spoof_pass`,
  `exit_code_ignored` (ETB-09); `eval_context_leak` (ETB-10); `degenerate_pass` (ETB-16);
  `trace_injection` (ETB-12); `privileged_evaluator` (ETB-13). Probes restore sandbox state
  from a snapshot and say so in their evidence.
- Hardening profiles `before`/`after` with eleven switches and pure transforms (docker run
  kwargs, pre-agent and pre-grade commands, test hashes, env scrubbing).
- Runner: `run.json` + `summary.md` per run, `summarize` before/after table per benchmark
  and ETB class, per-probe open/closed/undetermined counts, pins and seed recorded,
  `llm_cost_usd` recorded (always 0 for probe runs).
- CLI: `probe` (with `--dry-run`, `--prune`), `summarize`, `pins`, `doctor`, `attack`
  (refuses without `--allow-llm`).
- Docker sandbox over the docker SDK: exec with timeout, read/write via tar, snapshot via
  commit, restore via recreate, close removes container and snapshot images. Not exercised
  by tests (no daemon in CI); exercised only when a real run happens.
- SWE-bench adapter: task specs from HF rows (Verified; Pro field names UNVERIFIED), test
  files from the test patch, F2P/P2P lists, image naming, pins; grading via the swebench
  eval script when `swebench` is installed, else a generic pytest command marked UNVERIFIED.

## Stubbed or partial

- `attackers/run_attack`: strategies and prompts exist; the Inspect wiring from an
  adapter's Docker image to an Inspect sandbox is not written, so the call raises
  NotImplementedError after validating the strategy and the `--allow-llm` gate. Nothing can
  spend model budget yet.
- ControlArena: task enumeration and monitor formatter calls are written against the 20.x
  API from memory and guarded; both are UNVERIFIED until run with the package installed.
  Sandboxes are Inspect-managed, so probes need an Inspect task wrapper (not written).
  The version-based inference of the formatter fix (>= 16.0.0) is a fallback, not a measurement.
- Terminal-Bench: pins and a task layout guess; enumeration and sandboxes need Harbor
  wiring (UNVERIFIED API).
- CyberGym, BountyBench: stubs with docstrings listing what is needed.
- `degenerate_pass` is a grader-logic probe with a synthetic diff; it says whether the
  grader has any structural check, not whether a real agent's degenerate repair passes.
- `agent_unprivileged` is realised as: container stays root, probes (the agent's actions)
  run as uid 1000 after `chown -R 1000:1000 /testbed`, test files and grader paths are
  chowned back to root and made read-only, and the grader runs as root in the same
  container. That approximates a separate grading container; UNVERIFIED equivalence.

## UNVERIFIED items

Resolved on 2026-11-02:

- SWE-bench Verified dataset pinned: `SWE-bench/SWE-bench_Verified` at
  `78f471bf655a3137b2e8a75af1501690ec009ec3` (swebench 5.x-native columns; same 500 ids as
  the princeton-nlp copy). SWE-bench Pro pinned at `2d52cb3df914a3fcf80c7f66738b3a88ae37fc50`
  (row format still UNVERIFIED).
- Image naming confirmed from the dataset's `image` column. arm64 builds exist for some
  instances only (3 of the 5 sampled); `--arch auto` resolves per task. arm64 images are
  about 3.3 GB on disk; an arm64 pull took about 4 minutes.
- The swebench eval script restores declared test files itself (`git checkout <base> <files>`
  then `git apply` of the test patch), so `test_edit_pass` is closed in SWE-bench as shipped.

Still open:

- control-arena 20.x setting names, dataset API and formatter import paths.
- Harbor dataset registry id for Terminal-Bench 2.0.
- SWE-bench Pro row format and image source.
- Exit-code-only fallback for django and sympy runners in the `after` profile (they emit
  no junit); a separate grading container would remove the need for it.

## Checks run

- `uv run pytest`: 59 passed (offline).
- `uv run ruff check .`: clean (line length 110).
- `uv run etbh probe --benchmark swe_bench --n 2 --seed 0 --dry-run`: prints the plan with
  pins, probes and "task ids resolved at run time" when `datasets` is absent.
- `uv run etbh probe --benchmark fake ... before|after` then `summarize`: the fake benchmark
  goes from 100% to 0% on every sandbox-hardenable class and stays 100% on ETB-12, which
  only the upstream formatter fix closes. That is a self-check of the plumbing, not a result.

## Questions for John

1. SWE-bench `before` baseline: measure the pre-#620 harness (swebench < 5.0.0 behaviour,
   as configured now) or the current 5.0.2 harness? The former shows the fix's effect; the
   latter is what people run today. Both can be run; it doubles the SWE-bench budget.
2. ControlArena: which setting(s) and which monitor(s) count as "the benchmark" for the
   gameable rate? The audit findings were in the prompt formatters; probing them needs the
   Inspect wrapper, which is the next piece of work if ControlArena stays in v1.
3. Attacker model and budget for the dynamic metric, when you are ready to spend any.
4. Is 1000:1000 (non-root agent) acceptable as a hardening switch for SWE-bench images, or
   should the agent stay root and only the grader be isolated?
