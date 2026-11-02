"""SWE-bench Verified (and the public SWE-bench Pro split) adapter.

Dataset: the swebench 5.x-native HF dataset `SWE-bench/SWE-bench_Verified` (test split,
500 instances) carries `image`, `eval_script`, `log_parser` and `eval_type` columns, which
is what `swebench.harness.utils.make_test_spec` needs. Pinned by commit below.
`ScaleAI/SWE-bench_Pro` (public split, 731 instances) is pinned too; its field names are
UNVERIFIED and the generic fallback grader is used until checked.

Images: the dataset names the x86_64 image (`swebench/sweb.eval.x86_64.<id>:latest`).
Some instances also have an arm64 build under `sweb.eval.arm64.`; with `arch=auto` the
adapter asks the registry (`docker manifest inspect`) and prefers arm64 on this Mac,
falling back to the x86_64 image run under emulation (`platform=linux/amd64`).

Grading: the task's eval script (from `make_test_spec`) checks out the pristine test files,
applies the test patch, runs the repository's own test command between
`>>>>> Start Test Output` / `>>>>> End Test Output` markers and, since swebench 5.0.0
(SWE-bench #620), echoes `>>>>> Test Exit Code: N` after the end marker. etbh grades the
same log two ways:

- `before`: the pre-#620 behaviour. The log slice is parsed with the benchmark's own
  parser (`log_parser` column) and the exit-code marker is ignored.
- `after`: the exit-code marker is honoured, a junit report from the grader's own pytest
  invocation is required where the runner is pytest, test files are restored from a
  pristine copy, hashes are checked, and the structural diff policy applies. Runners that
  cannot emit junit (django's runtests.py, sympy's bin/test) fall back to exit code only,
  marked UNVERIFIED in the grade notes.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from functools import cache
from importlib import metadata
from typing import Any

from etbh.adapters.base import AdapterBase, AdapterUnavailable, ExecResult, GradeResult, Sandbox, TaskSpec
from etbh.grading import grade_log, parse_pytest_log_legacy
from etbh.hardening.profiles import BEFORE, Hardening
from etbh.hardening.transforms import docker_run_kwargs, randomized_env

DATASETS: dict[str, tuple[str, str, str]] = {
    # variant: (dataset, split, pinned revision)
    "verified": ("SWE-bench/SWE-bench_Verified", "test", "78f471bf655a3137b2e8a75af1501690ec009ec3"),
    "pro": ("ScaleAI/SWE-bench_Pro", "test", "2d52cb3df914a3fcf80c7f66738b3a88ae37fc50"),
}
ARCHES = ("auto", "arm64", "x86_64")
START_MARK = ">>>>> Start Test Output"
END_MARK = ">>>>> End Test Output"
EXIT_MARK = ">>>>> Test Exit Code"
EXIT_RE = re.compile(re.escape(EXIT_MARK) + r":\s*(-?\d+)")
JUNIT_PATH = "/testbed/.etbh-junit.xml"
GRADER_PATHS = ["/eval.sh", "conftest.py", "pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml"]
GRADER_TIMEOUT = 1800
_DIFF_FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.M)
_PYTEST_RE = re.compile(r"(?<![\w/.-])(py\.test|pytest)(?![\w.-])")


def _installed(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return "not installed"


def files_in_patch(patch: str) -> list[str]:
    return sorted({m.group(2) for m in _DIFF_FILE_RE.finditer(patch or "")})


def image_name(instance_id: str, arch: str = "x86_64", namespace: str = "swebench",
               tag: str = "latest") -> str:
    """Docker Hub naming used by swebench (double underscore -> _1776_). Confirmed 2026-11-02."""
    return f"{namespace}/sweb.eval.{arch}.{instance_id.lower().replace('__', '_1776_')}:{tag}"


def arm64_variant(image: str) -> str:
    return image.replace(".x86_64.", ".arm64.")


@cache
def image_available(image: str) -> bool | None:
    """Ask the registry whether an image exists. None when the docker CLI is unavailable."""
    if shutil.which("docker") is None:
        return None
    try:
        proc = subprocess.run(["docker", "manifest", "inspect", image], capture_output=True,
                              text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.returncode == 0


def resolve_image(x86_image: str, arch: str) -> tuple[str, str, str]:
    """(image, docker platform, note) for the requested arch policy."""
    if arch not in ARCHES:
        raise ValueError(f"arch must be one of {ARCHES}")
    if arch == "x86_64":
        return x86_image, "linux/amd64", "x86_64 requested"
    arm = arm64_variant(x86_image)
    if arch == "arm64":
        return arm, "linux/arm64", "arm64 requested"
    avail = image_available(arm)
    if avail:
        return arm, "linux/arm64", "arm64 image available in registry"
    if avail is None:
        return x86_image, "linux/amd64", "docker CLI unavailable; assumed x86_64 only (UNVERIFIED)"
    return x86_image, "linux/amd64", "no arm64 image in registry; x86_64 under emulation"


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return [str(v) for v in parsed] if isinstance(parsed, list) else [value]
        except json.JSONDecodeError:
            return [value]
    return []


# -- eval script helpers (pure, unit-tested) ---------------------------------------------

def test_command_lines(script_lines: list[str]) -> list[str]:
    """The command lines between the start and end markers, minus the exit-code capture."""
    out: list[str] = []
    inside = False
    for line in script_lines:
        if START_MARK in line:
            inside = True
            continue
        if END_MARK in line:
            break
        if inside and not line.startswith("SWEBENCH_TEST_EXIT_CODE="):
            out.append(line)
    return out


def runner_kind(command_lines: list[str]) -> str:
    cmd = "\n".join(command_lines)
    if "runtests.py" in cmd:
        return "django"
    if "bin/test" in cmd:
        return "sympy"
    if _PYTEST_RE.search(cmd):
        return "pytest"
    return "unknown"


def inject_junit(script_lines: list[str], junit_path: str = JUNIT_PATH) -> list[str]:
    """Add `--junitxml=<path>` to pytest invocations inside the test-output markers."""
    out: list[str] = []
    inside = False
    for line in script_lines:
        if START_MARK in line:
            inside = True
        elif END_MARK in line:
            inside = False
        elif inside and _PYTEST_RE.search(line) and "--junitxml" not in line:
            line = _PYTEST_RE.sub(lambda m: f"{m.group(1)} --junitxml={junit_path}", line, count=1)
        out.append(line)
    return out


def slice_test_output(log: str) -> str:
    """The region swebench parses: between the markers, else the whole log."""
    if START_MARK in log and END_MARK in log:
        return log.split(START_MARK, 1)[1].split(END_MARK, 1)[0]
    return log


def parse_exit_marker(log: str) -> int | None:
    m = EXIT_RE.search(log)
    return int(m.group(1)) if m else None


def parse_with_swebench(log_slice: str, parser_name: str, spec: Any) -> dict[str, str] | None:
    """Run the benchmark's own parser by name; None when swebench is not importable."""
    try:
        from swebench.harness.log_parsers import PARSER_REGISTRY  # type: ignore
    except ImportError:
        return None
    parser = PARSER_REGISTRY.get(parser_name)
    if parser is None:
        return None
    return parser(log_slice, spec)


class SweBenchAdapter(AdapterBase):
    def __init__(self, variant: str = "verified", dataset_revision: str | None = None,
                 arch: str = "auto", namespace: str = "swebench", rows: dict[str, dict] | None = None):
        if variant not in DATASETS:
            raise ValueError(f"variant must be one of {sorted(DATASETS)}")
        if arch not in ARCHES:
            raise ValueError(f"arch must be one of {ARCHES}")
        self.variant = variant
        self.name = "swe_bench" if variant == "verified" else "swe_bench_pro"
        self.dataset_name, self.split, pinned = DATASETS[variant]
        self.dataset_revision = dataset_revision or pinned
        self.arch = arch
        self.namespace = namespace
        self._rows: dict[str, dict] | None = rows  # injectable for tests

    # -- data ---------------------------------------------------------------------------
    def _load(self) -> dict[str, dict]:
        if self._rows is not None:
            return self._rows
        try:
            from datasets import load_dataset  # type: ignore
        except ImportError as err:
            raise AdapterUnavailable("`datasets` not installed; pip install -e '.[swe]'") from err
        try:
            ds = load_dataset(self.dataset_name, split=self.split, revision=self.dataset_revision)
        except Exception as err:  # network / auth / missing revision
            raise AdapterUnavailable(f"could not load {self.dataset_name}: {err}") from err
        self._rows = {row["instance_id"]: dict(row) for row in ds}
        return self._rows

    def version_pins(self) -> dict[str, str]:
        return {
            "dataset": self.dataset_name,
            "dataset_split": self.split,
            "dataset_revision": self.dataset_revision,
            "swebench": _installed("swebench"),
            "datasets": _installed("datasets"),
            "image_namespace": self.namespace,
            "arch_policy": self.arch,
            "grader_before": ("benchmark's own log parser on the marker slice; exit-code marker ignored "
                              "(pre SWE-bench #620)"),
            "grader_after": ("exit-code marker honoured + junit cross-check where the runner is pytest + "
                             "pristine tests + hash check + structural diff policy"),
            "grader_timeout_s": str(GRADER_TIMEOUT),
        }

    def task_ids(self) -> list[str]:
        return sorted(self._load())

    def task_spec(self, task_id: str) -> TaskSpec:
        row = self._load()[task_id]
        test_patch = row.get("test_patch", "")
        test_files = files_in_patch(test_patch)
        f2p = _as_list(row.get("FAIL_TO_PASS"))
        p2p = _as_list(row.get("PASS_TO_PASS"))
        x86_image = row.get("image") or image_name(task_id, "x86_64", self.namespace)
        image, platform, image_note = resolve_image(x86_image, self.arch)
        before, after, spec, grader_source, runner = self._eval_scripts(row, test_files)
        return TaskSpec(
            benchmark=self.name,
            task_id=task_id,
            repo=row.get("repo", ""),
            base_commit=row.get("base_commit", ""),
            workdir="/testbed",
            test_files=test_files,
            grader_paths=GRADER_PATHS,
            grader_command=before,
            image=image,
            has_reference_solution=bool(row.get("patch")),
            fail_to_pass=f2p,
            pass_to_pass=p2p,
            metadata={
                "version": row.get("version"),
                "reference_patch_files": files_in_patch(row.get("patch", "")),
                "grader_source": grader_source,
                "runner": runner,
                "junit_supported": runner == "pytest",
                "log_parser": row.get("log_parser") or "legacy",
                "platform": platform,
                "image_note": image_note,
                "grader_timeout": GRADER_TIMEOUT,
                "junit_path": JUNIT_PATH,
                "_eval_script_before": before,
                "_eval_script_after": after,
                "_spec": spec,
                "_reference_patch": row.get("patch", ""),
                "_test_patch": test_patch,
            },
        )

    def _eval_scripts(self, row: dict, test_files: list[str]) -> tuple[str, str, Any, str, str]:
        """(before script, after script, swebench TestSpec or None, source, runner kind)."""
        if row.get("eval_script"):
            try:
                from swebench.harness.utils import make_test_spec  # swebench >= 5

                spec = make_test_spec(row)
                lines = list(spec.eval_script_list)
                runner = runner_kind(test_command_lines(lines))
                before = "\n".join(lines)
                after = "\n".join(inject_junit(lines) if runner == "pytest" else lines)
                return before, after, spec, "swebench.harness.utils.make_test_spec", runner
            except Exception as err:  # noqa: BLE001 - fall through to the generic runner
                note = f"make_test_spec failed: {type(err).__name__}: {err}"
            else:  # pragma: no cover
                note = ""
        else:
            note = "row has no eval_script column"
        files = " ".join(test_files) or "tests"
        before = f"cd /testbed && pytest -rA {files}"
        after = f"cd /testbed && pytest -rA --junitxml={JUNIT_PATH} {files}"
        return before, after, None, f"UNVERIFIED generic pytest ({note})", "pytest"

    # -- sandbox -------------------------------------------------------------------------
    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        from etbh.sandbox.docker_sandbox import DockerSandbox

        sb = DockerSandbox(
            task.image,
            workdir=task.workdir,
            network_allowed=not hardening.network_none,
            run_kwargs=docker_run_kwargs(hardening, task),
            env=randomized_env(hardening, {}),
            platform=task.metadata.get("platform"),
            agent_user="1000:1000" if hardening.agent_unprivileged else None,
        )
        try:
            yield sb
        finally:
            sb.close()

    # -- grading -------------------------------------------------------------------------
    def grade(self, task: TaskSpec, sandbox: Sandbox, hardening: Hardening | None = None,
              diff: str | None = None) -> GradeResult:
        hardening = hardening or BEFORE
        from etbh.hardening.transforms import pre_grade_commands, test_hashes, verify_test_hashes

        notes: list[str] = []
        if hardening.hash_check_tests:
            expected = task.metadata.get("_test_hashes")
            if expected is not None:
                changed = verify_test_hashes(expected, test_hashes(sandbox, task))
                if changed:
                    return GradeResult(passed=False, exit_code=None, raw="",
                                       notes=[f"test files changed before grading: {changed}"])
        strict = hardening.require_exit_code_and_junit
        script = task.metadata.get("_eval_script_after" if strict else "_eval_script_before") \
            or task.grader_command
        if not script:
            return GradeResult(passed=False, exit_code=None, raw="", notes=["no grader command"])
        run_as_root = getattr(sandbox, "exec_as", None)
        exec_ = (lambda c, t: run_as_root(c, "root", t)) if run_as_root else sandbox.exec  # noqa: E731
        write = getattr(sandbox, "write_file_as_root", None) or sandbox.write_file
        for cmd in pre_grade_commands(hardening, task):
            exec_(cmd, 600)
        write("/eval.sh", script + "\n")
        exec_(f"rm -f {JUNIT_PATH}", 60)
        t0 = time.monotonic()
        res = exec_("bash /eval.sh 2>&1", task.metadata.get("grader_timeout", GRADER_TIMEOUT))
        elapsed = round(time.monotonic() - t0, 1)
        if res.timed_out:
            return GradeResult(passed=False, exit_code=res.exit_code, raw=res.stdout[-4000:],
                               parsed={"timed_out": True, "seconds": elapsed},
                               notes=[f"grader timed out after {elapsed}s"])
        junit = None
        if strict and task.metadata.get("junit_supported") and sandbox.path_exists(JUNIT_PATH):
            try:
                junit = sandbox.read_file(JUNIT_PATH)
            except OSError:
                junit = None
        out = self.grade_output(task, res, hardening, diff=diff, junit_xml=junit)
        out.parsed["seconds"] = elapsed
        out.notes = notes + out.notes
        return out

    def grade_output(self, task: TaskSpec, result: ExecResult, hardening: Hardening | None = None,
                     diff: str | None = None, junit_xml: str | None = None) -> GradeResult:
        """Grade a captured eval-script run with the benchmark's own parser, then the policy."""
        log = result.stdout if not result.stderr else result.stdout + "\n" + result.stderr
        log_slice = slice_test_output(log)
        statuses = parse_with_swebench(log_slice, task.metadata.get("log_parser", ""),
                                       task.metadata.get("_spec"))
        parser_used = task.metadata.get("log_parser", "legacy")
        if statuses is None:
            statuses = parse_pytest_log_legacy(log_slice)
            parser_used = "legacy"
        marker = parse_exit_marker(log)
        return self._policy_grade(task, statuses, marker, result.exit_code, hardening, diff, junit_xml,
                                  raw=log[-6000:], parser=parser_used)

    def grade_synthetic(self, task: TaskSpec, statuses: dict[str, str], exit_code: int,
                        hardening: Hardening | None = None, diff: str | None = None) -> GradeResult:
        """Grader-logic probes hand over statuses directly; the parser is not under test."""
        return self._policy_grade(task, statuses, exit_code, exit_code, hardening, diff, None,
                                  raw="", parser="synthetic")

    def _policy_grade(self, task: TaskSpec, statuses: dict[str, str], marker: int | None,
                      process_exit: int | None, hardening: Hardening | None, diff: str | None,
                      junit_xml: str | None, *, raw: str, parser: str) -> GradeResult:
        hardening = hardening or BEFORE
        policy = hardening.grading_policy()
        notes: list[str] = []
        # before: the pre-#620 harness never looked at the exit status.
        exit_code: int | None = None
        if policy.require_exit_code:
            exit_code = marker if marker is not None else process_exit
        if policy.require_junit and not task.metadata.get("junit_supported", True):
            policy = policy.__class__(require_exit_code=policy.require_exit_code, require_junit=False,
                                      min_p2p_fraction=policy.min_p2p_fraction,
                                      reject_flagged_diffs=policy.reject_flagged_diffs)
            notes.append(f"runner {task.metadata.get('runner')} emits no junit; exit code only (UNVERIFIED)")
        outcome = grade_log("", exit_code, task.fail_to_pass, task.pass_to_pass, policy, junit_xml,
                            statuses=statuses)
        passed = outcome.passed
        if policy.reject_flagged_diffs and diff:
            from etbh.verifier.diff_policy import diff_flags

            flags = diff_flags(diff, task)
            bad = [k for k, v in flags.items() if v is True and k != "ok"]
            if bad:
                passed = False
                notes.append(f"diff rejected by structural policy: {bad}")
        parsed = {"resolution": outcome.resolution.as_dict(), "parser": parser,
                  "exit_marker": marker, "statuses_parsed": len(statuses)}
        return GradeResult(passed=passed, exit_code=marker if marker is not None else process_exit,
                           raw=raw, parsed=parsed, notes=notes + outcome.notes)

    def evaluator_privileges(self, task: TaskSpec, hardening: Hardening) -> dict[str, Any] | None:
        return {
            "same_container": not hardening.separate_grader_container,
            "write_access": not hardening.separate_grader_container,
            "network": not hardening.network_none,
            "tools": False,
            "runs_as": "root",
            "source": ("swebench run_evaluation executes the eval script inside the agent's container "
                       "as root" if not hardening.separate_grader_container else
                       "etbh after-profile approximation: grader runs as root with pristine tests while "
                       "the agent is uid 1000 in the same container (UNVERIFIED equivalent of a separate "
                       "container)"),
        }


def log_line(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)
