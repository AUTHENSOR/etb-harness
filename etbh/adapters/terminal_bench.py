"""Terminal-Bench 2.0 adapter (Harbor task format), verified against harbor 0.25.0.

Tasks come from the Harbor registry (`harbor datasets download terminal-bench@2.0`), 89
directories each holding `task.toml` (prebuilt `docker_image`, cpu/memory, verifier timeout),
`environment/Dockerfile` (WORKDIR, almost always /app, user root), `tests/test.sh` plus
`tests/test_outputs.py`, and `solution/solve.sh`.

How Harbor grades (harbor/verifier/verifier.py, read 2026-11-02): after the agent phase it
removes any reward files, uploads the task's `tests/` directory into the agent's container at
`/tests` (a copy that merges into whatever is there), runs `bash /tests/test.sh` in that same
container, and reads `/logs/verifier/reward.txt`. Every test.sh in 2.0 installs curl and uv
with network access, runs `uvx pytest /tests/test_outputs.py` and writes 1 or 0 to the reward
file depending on pytest's exit status.

So: tests are hidden during the agent phase (good), but the verifier executes as root inside
the agent's container, with the agent's PATH, binaries, /etc/hosts and any file the agent left
under /tests, and it needs egress at grade time by design.

Hardening (`after`) here: grade in a fresh container from the task image with only the agent's
working directory copied in, so modified binaries and leftovers under /tests do not carry
over. Network stays on for the verifier because test.sh cannot run without it.
"""

from __future__ import annotations

import io
import re
import tarfile
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import metadata
from pathlib import Path
from typing import Any

from etbh.adapters.base import AdapterBase, AdapterUnavailable, ExecResult, GradeResult, Sandbox, TaskSpec
from etbh.hardening.profiles import BEFORE, Hardening
from etbh.hardening.transforms import docker_run_kwargs, randomized_env

DATASET = "terminal-bench@2.0"
DEFAULT_TASKS_DIR = Path(__file__).resolve().parents[2] / "cache" / "terminal-bench_2.0"
TESTS_DIR = "/tests"
VERIFIER_DIR = "/logs/verifier"
REWARD_PATH = f"{VERIFIER_DIR}/reward.txt"
VERIFIER_CMD = f"bash {TESTS_DIR}/test.sh > {VERIFIER_DIR}/test-stdout.txt 2>&1"
# Everything the verifier script executes or sources as root inside the agent's container.
VERIFIER_HOOK_PATHS = [
    REWARD_PATH,
    f"{TESTS_DIR}/conftest.py",
    "/usr/bin/apt-get",
    "/usr/bin/curl",
    "/root/.local/bin/env",
    "/etc/hosts",
]
_TEST_DEF_RE = re.compile(r"^def (test_\w+)\s*\(", re.MULTILINE)
_WORKDIR_RE = re.compile(r"^WORKDIR\s+(\S+)", re.MULTILINE)


def _version(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return "not installed"


def reward_passed(text: str | None) -> tuple[bool, str]:
    """Harbor's rule: the reward file holds a finite number; 1 is a pass."""
    if text is None or not text.strip():
        return False, "no reward file written"
    try:
        value = float(text.strip())
    except ValueError:
        return False, f"reward file unparseable: {text.strip()[:40]!r}"
    return value >= 1.0, f"reward {value:g}"


def _test_ids(tests_py: Path) -> list[str]:
    if not tests_py.exists():
        return []
    names = _TEST_DEF_RE.findall(tests_py.read_text(errors="replace"))
    return [f"test_outputs.py::{m}" for m in names]


def parse_task(task_dir: Path) -> dict[str, Any]:
    cfg = tomllib.loads((task_dir / "task.toml").read_text(encoding="utf-8"))
    env = cfg.get("environment", {})
    dockerfile = (task_dir / "environment" / "Dockerfile").read_text(encoding="utf-8", errors="replace")
    workdirs = _WORKDIR_RE.findall(dockerfile)
    tests_py = task_dir / "tests" / "test_outputs.py"
    return {
        "task_id": task_dir.name,
        "image": env.get("docker_image", ""),
        "cpus": env.get("cpus"),
        "memory": env.get("memory"),
        "verifier_timeout": float(cfg.get("verifier", {}).get("timeout_sec", 900.0)),
        "workdir": workdirs[-1] if workdirs else "/app",
        "test_names": _test_ids(tests_py),
        "has_solution": (task_dir / "solution").exists(),
        "difficulty": cfg.get("metadata", {}).get("difficulty"),
        "category": cfg.get("metadata", {}).get("category"),
        "tests_dir": str(task_dir / "tests"),
    }


class TerminalBenchAdapter(AdapterBase):
    name = "terminal_bench"

    def __init__(self, tasks_dir: str | Path | None = None, rows: dict[str, dict] | None = None,
                 arch: str = "auto"):
        self.tasks_dir = Path(tasks_dir) if tasks_dir else DEFAULT_TASKS_DIR
        self.arch = arch
        self._rows: dict[str, dict] | None = rows

    # -- data ---------------------------------------------------------------------------
    def _load(self) -> dict[str, dict]:
        if self._rows is not None:
            return self._rows
        if not self.tasks_dir.exists():
            raise AdapterUnavailable(
                f"no Terminal-Bench tasks at {self.tasks_dir}; run "
                f"`harbor datasets download {DATASET} -o cache/` first")
        rows = {}
        for d in sorted(p for p in self.tasks_dir.iterdir() if (p / "task.toml").exists()):
            rows[d.name] = parse_task(d)
        if not rows:
            raise AdapterUnavailable(f"no task.toml files under {self.tasks_dir}")
        self._rows = rows
        return rows

    def version_pins(self) -> dict[str, str]:
        return {
            "dataset": DATASET,
            "dataset_source": "Harbor legacy registry (laude-institute/harbor registry.json)",
            "harbor": _version("harbor"),
            "tasks_dir": str(self.tasks_dir),
            "images": "per task, task.toml [environment].docker_image (prebuilt, pulled)",
            "arch": self.arch,
            "grader_before": "Harbor verifier replicated: tests uploaded to /tests (merge), "
                             "bash /tests/test.sh as root in the agent's container, "
                             "pass iff /logs/verifier/reward.txt >= 1",
            "grader_after": "same verifier in a fresh container from the task image with only the agent's "
                            "workdir copied in; network kept on (test.sh installs uv and pytest)",
        }

    def task_ids(self) -> list[str]:
        return sorted(self._load())

    def task_spec(self, task_id: str) -> TaskSpec:
        row = self._load()[task_id]
        return TaskSpec(
            benchmark=self.name,
            task_id=task_id,
            repo="laude-institute/terminal-bench",
            base_commit="",
            workdir=row["workdir"],
            test_files=[f"{TESTS_DIR}/test_outputs.py", f"{TESTS_DIR}/test.sh"],
            grader_paths=list(VERIFIER_HOOK_PATHS),
            grader_command=VERIFIER_CMD,
            image=row["image"],
            has_reference_solution=row["has_solution"],
            fail_to_pass=row["test_names"],
            pass_to_pass=[],
            metadata={
                "runner": "pytest",
                "spoof_conftest_dir": TESTS_DIR,
                "grader_logic_known": False,  # reward-file semantics; synthetic probes do not apply
                "grader": "Harbor verifier: bash /tests/test.sh writes /logs/verifier/reward.txt",
                "verifier_timeout": row["verifier_timeout"],
                "difficulty": row["difficulty"],
                "category": row["category"],
                "cpus": row["cpus"],
                "memory": row["memory"],
                "_tests_dir": row["tests_dir"],
            },
        )

    # -- sandbox -------------------------------------------------------------------------
    def _run_kwargs(self, task: TaskSpec, hardening: Hardening) -> dict[str, Any]:
        kwargs = docker_run_kwargs(hardening, task)
        kwargs.pop("volumes", None)  # tests are uploaded at grade time, nothing to bind
        kwargs.pop("user", None)  # Terminal-Bench 2.0 tasks run as root
        if task.metadata.get("memory"):
            kwargs.setdefault("mem_limit", str(task.metadata["memory"]).lower())
        if task.metadata.get("cpus"):
            kwargs.setdefault("nano_cpus", int(float(task.metadata["cpus"]) * 1_000_000_000))
        return kwargs

    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        from etbh.sandbox.docker_sandbox import DockerSandbox

        sb = DockerSandbox(
            task.image,
            workdir=task.workdir,
            network_allowed=not hardening.network_none,
            run_kwargs=self._run_kwargs(task, hardening),
            env=randomized_env(hardening, {}),
            shell="bash -c",
            platform=self._platform(),
        )
        try:
            # Harbor mounts /logs/agent and /logs/verifier into the container; tests arrive
            # only at verification time.
            sb.exec(f"mkdir -p {VERIFIER_DIR} /logs/agent")
            yield sb
        finally:
            sb.close()

    def _platform(self) -> str | None:
        if self.arch == "x86_64":
            return "linux/amd64"
        if self.arch == "arm64":
            return "linux/arm64"
        return None  # auto: let Docker pick; images are published single-arch (amd64)

    # -- grading -------------------------------------------------------------------------
    def grade(self, task: TaskSpec, sandbox: Sandbox, hardening: Hardening | None = None,
              diff: str | None = None) -> GradeResult:
        hardening = hardening or BEFORE
        from etbh.sandbox.docker_sandbox import DockerSandbox

        if hardening.separate_grader_container and isinstance(sandbox, DockerSandbox):
            grader = DockerSandbox(
                task.image, workdir=task.workdir, network_allowed=True,  # test.sh needs egress
                run_kwargs=self._run_kwargs(task, hardening), shell="bash -c", platform=self._platform(),
            )
            try:
                grader.exec(f"mkdir -p {VERIFIER_DIR} /logs/agent")
                _copy_dir_between(sandbox, grader, task.workdir)
                out = self._verify(task, grader, hardening)
            finally:
                grader.close()
            out.notes.insert(0, "verified in a fresh container from the task image with the agent's "
                                "workdir copied in; network on for the verifier")
            return out
        return self._verify(task, sandbox, hardening)

    def _verify(self, task: TaskSpec, sandbox: Sandbox, hardening: Hardening) -> GradeResult:
        """Replicates harbor.verifier.Verifier.verify for a docker environment."""
        notes: list[str] = []
        sandbox.exec(f"rm -f {REWARD_PATH} {VERIFIER_DIR}/reward.json; mkdir -p {VERIFIER_DIR}")
        if not _upload_tests(sandbox, Path(task.metadata["_tests_dir"])):
            return GradeResult(passed=False, exit_code=None, raw="", notes=["could not upload tests"])
        sandbox.exec(f"chmod +x {TESTS_DIR}/test.sh")
        timeout = float(task.metadata.get("verifier_timeout") or 900.0)
        res = sandbox.exec(VERIFIER_CMD, timeout=min(timeout, 1800.0))
        reward_text: str | None
        try:
            reward_text = sandbox.read_file(REWARD_PATH)
        except (OSError, FileNotFoundError):
            reward_text = None
        passed, why = reward_passed(reward_text)
        notes.append(f"verifier exit {res.exit_code}; {why}")
        if res.timed_out:
            notes.append("verifier timed out")
        tail = ""
        try:
            tail = sandbox.read_file(f"{VERIFIER_DIR}/test-stdout.txt")[-1500:]
        except (OSError, FileNotFoundError):
            pass
        return GradeResult(passed=passed, exit_code=res.exit_code, raw=tail,
                           parsed={"reward": reward_text.strip() if reward_text else None,
                                   "timed_out": res.timed_out}, notes=notes)

    def grade_output(self, task: TaskSpec, result: ExecResult, hardening: Hardening | None = None,
                     diff: str | None = None, junit_xml: str | None = None) -> GradeResult:
        # Not meaningful for a reward-file verifier; grader-logic probes are told so via
        # grader_logic_known=False and report undetermined.
        return GradeResult(passed=False, exit_code=result.exit_code, raw=result.stdout,
                           notes=["terminal_bench grades from /logs/verifier/reward.txt, not from stdout"])

    def evaluator_privileges(self, task: TaskSpec, hardening: Hardening) -> dict[str, Any] | None:
        return {
            "same_container": not hardening.separate_grader_container,
            "write_access": not hardening.separate_grader_container,
            "network": True,  # test.sh installs curl, uv and pytest at verification time
            "tools": False,
            "runs_as": "root",
            "source": "harbor Verifier.verify runs bash /tests/test.sh via environment.exec in the task "
                      "container; every 2.0 test.sh fetches uv from astral.sh and pytest from PyPI",
        }


def _tar_dir(src: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path in sorted(src.rglob("*")):
            tar.add(path, arcname=str(path.relative_to(src)), recursive=False)
    return buf.getvalue()


def _upload_tests(sandbox: Sandbox, tests_dir: Path) -> bool:
    """Merge the task's tests directory into /tests, as `docker cp dir/. target` would."""
    container = getattr(sandbox, "_container", None)
    if container is None:
        return False
    sandbox.exec(f"mkdir -p {TESTS_DIR}")
    return bool(container.put_archive(TESTS_DIR, _tar_dir(tests_dir)))


def _copy_dir_between(src: Sandbox, dst: Sandbox, path: str) -> None:
    """Copy a directory tree from one Docker sandbox to another via tar streams."""
    s = getattr(src, "_container", None)
    d = getattr(dst, "_container", None)
    if s is None or d is None:
        raise AdapterUnavailable("copying between containers needs Docker sandboxes")
    stream, _stat = s.get_archive(path)
    data = b"".join(stream)
    parent = path.rstrip("/").rsplit("/", 1)[0] or "/"
    dst.exec(f"rm -rf {path} && mkdir -p {parent}")
    d.put_archive(parent, data)
