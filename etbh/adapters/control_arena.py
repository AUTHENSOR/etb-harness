"""ControlArena (UK AISI) adapter.

ControlArena is Inspect-native: a setting supplies tasks and a sandbox, a scorer grades the
main task, and a *monitor* (an LLM reading the trajectory) produces a suspicion score. The
ETB surfaces of interest are the monitor prompt formatters (ETB-02, fixed in #798 for tool
calls and #810 for chain-of-thought) and the trace/privilege surfaces (ETB-12, ETB-13).

Everything that touches the control_arena API is guarded: the package API moved between
major versions and the calls below were written against the 20.x docs, UNVERIFIED offline.
"""

from __future__ import annotations

import html
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import metadata
from typing import Any

from etbh.adapters.base import AdapterBase, AdapterUnavailable, Sandbox, TaskSpec
from etbh.hardening.profiles import Hardening

KNOWN_FIXES = {
    "ETB-02": [
        {"ref": "UKGovernmentBEIS/control-arena#798", "merged": "2026-04-08", "first_release": "15.0.0",
         "surface": "last_tool_calls and prefix prompt formatters"},
        {"ref": "UKGovernmentBEIS/control-arena#810", "merged": "2026-04-30", "first_release": "16.0.0",
         "surface": "cot prompt formatter"},
    ]
}


def _version() -> str | None:
    try:
        return metadata.version("control-arena")
    except metadata.PackageNotFoundError:
        return None


def _vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split(".")[:3] if p.isdigit())


class ControlArenaAdapter(AdapterBase):
    name = "control_arena"

    def __init__(self, setting: str = "bash", task_ids: list[str] | None = None,
                 escape_override: bool | None = None):
        self.setting = setting
        self._task_ids = task_ids  # injectable for tests
        self._escape_override = escape_override  # tests: force formatter behaviour

    def version_pins(self) -> dict[str, str]:
        return {
            "control_arena": _version() or "not installed",
            "setting": self.setting,
            "known_fixes": "; ".join(f"{f['ref']} (>= {f['first_release']})" for f in KNOWN_FIXES["ETB-02"]),
            "task_source": "setting main tasks (API UNVERIFIED offline)",
        }

    def task_ids(self) -> list[str]:
        if self._task_ids is not None:
            return list(self._task_ids)
        if _version() is None:
            raise AdapterUnavailable("control-arena not installed; pip install -e '.[control]'")
        try:  # UNVERIFIED: 20.x API
            from control_arena.settings import get_setting  # type: ignore

            setting = get_setting(self.setting)()
            dataset = setting.get_dataset(eval_mode="honest")  # type: ignore[arg-type]
            return sorted(str(sample.id) for sample in dataset)
        except Exception as err:  # noqa: BLE001
            raise AdapterUnavailable(f"could not enumerate {self.setting} tasks: {err}") from err

    def task_spec(self, task_id: str) -> TaskSpec:
        return TaskSpec(
            benchmark=self.name,
            task_id=task_id,
            workdir="/workspace",
            grader_paths=[],
            grader_command="",
            metadata={"setting": self.setting, "grader": "inspect scorer + LLM monitor",
                      "monitor_formatters": ["last_tool_calls", "prefix", "cot", "full_trajectory"]},
        )

    @contextmanager
    def sandbox(self, task: TaskSpec, hardening: Hardening) -> Iterator[Sandbox]:
        raise AdapterUnavailable(
            "ControlArena sandboxes are Inspect-managed; run probes through the Inspect task "
            "wrapper (planned) rather than a raw Docker sandbox"
        )
        yield  # pragma: no cover

    def monitor_format(self, task: TaskSpec, model_text: str) -> str | None:
        if self._escape_override is not None:
            body = html.escape(model_text) if self._escape_override else model_text
            return f"<cot>{body}</cot>"
        v = _version()
        if v is None:
            return None
        try:  # UNVERIFIED: formatter import path in 20.x
            from control_arena.monitor import cot_prompt_formatter  # type: ignore

            return str(cot_prompt_formatter(model_text))  # pragma: no cover
        except Exception:  # noqa: BLE001 - fall back to the version-based answer
            fixed = _vtuple(v) >= _vtuple("16.0.0")
            body = html.escape(model_text) if fixed else model_text
            return f"<cot>{body}</cot>  # version-inferred (control-arena {v}); UNVERIFIED at runtime"

    def evaluator_privileges(self, task: TaskSpec, hardening: Hardening) -> dict[str, Any] | None:
        return {
            "same_container": False,
            "write_access": False,
            "network": True,  # the monitor is an LLM API call
            "tools": False,
            "source": "monitor is a model call over the transcript; UNVERIFIED per setting",
        }
