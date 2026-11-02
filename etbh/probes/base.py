"""Probe protocol: a deterministic capability check mapped to exactly one ETB class."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any

from etbh.adapters.base import BenchmarkAdapter, GradeResult, Sandbox, TaskSpec
from etbh.hardening.profiles import BEFORE, Hardening
from etbh.taxonomy import validate_class_id


@dataclass
class ProbeResult:
    probe_id: str
    etb_class: str
    open: bool | None  # True = surface open, False = closed, None = could not determine
    evidence: str
    details: dict[str, Any] = field(default_factory=dict)
    seconds: float = 0.0
    counts_toward_class: bool = True  # capability-only probes set False (reported per probe only)
    synthetic: bool = False  # True when the probe fed the grader logic a constructed run

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class Probe:
    probe_id: str = "base"
    etb_class: str = "ETB-00"
    description: str = ""
    requires_grader: bool = False
    counts_toward_class: bool = True
    synthetic: bool = False

    def __init__(self, adapter: BenchmarkAdapter | None = None, hardening: Hardening = BEFORE) -> None:
        validate_class_id(self.etb_class)
        self.adapter = adapter
        self.hardening = hardening

    # -- API -------------------------------------------------------------------------
    def run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        start = time.monotonic()
        try:
            result = self._run(task, sandbox)
        except Exception as err:  # noqa: BLE001 - a probe error must not abort the run
            result = self.result(None, f"probe error: {type(err).__name__}: {err}")
        result.seconds = round(time.monotonic() - start, 4)
        return result

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:  # pragma: no cover
        raise NotImplementedError

    # -- helpers ---------------------------------------------------------------------
    def result(self, open_: bool | None, evidence: str, **details: Any) -> ProbeResult:
        return ProbeResult(self.probe_id, self.etb_class, open_, evidence, details,
                           counts_toward_class=self.counts_toward_class, synthetic=self.synthetic)

    def grade(self, task: TaskSpec, sandbox: Sandbox, diff: str | None = None) -> GradeResult:
        if self.adapter is None:
            raise RuntimeError(f"{self.probe_id} needs an adapter to grade")
        return self.adapter.grade(task, sandbox, self.hardening, diff=diff)

    @contextmanager
    def disposable(self, sandbox: Sandbox) -> Iterator[None]:
        """Snapshot before, restore after. Evidence should say the state was restored."""
        token = sandbox.snapshot()
        try:
            yield
        finally:
            sandbox.restore(token)


def short_test_name(test_id: str) -> str:
    """'tests/test_x.py::Class::test_y[param]' -> 'test_y'."""
    name = test_id.split("::")[-1]
    return name.split("[")[0]


def stub_module_for(test_ids: list[str], marker: str) -> str:
    names = sorted({short_test_name(t) for t in test_ids})
    body = "\n\n".join(f"def {n}():\n    pass" for n in names) or "def test_placeholder():\n    pass"
    return f"# {marker}\n{body}\n"
