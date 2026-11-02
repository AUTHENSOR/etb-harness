"""Deterministic capability probes. Each maps to exactly one ETB class."""

from __future__ import annotations

from etbh.adapters.base import BenchmarkAdapter
from etbh.hardening.profiles import BEFORE, Hardening
from etbh.probes.base import Probe, ProbeResult
from etbh.probes.degenerate_pass import DegeneratePass
from etbh.probes.eval_context_leak import EvalContextLeak
from etbh.probes.exit_code_ignored import ExitCodeIgnored
from etbh.probes.git_history_has_fix import GitHistoryHasFix
from etbh.probes.grader_path_writable import GraderPathWritable
from etbh.probes.network_egress import NetworkEgress
from etbh.probes.privileged_evaluator import PrivilegedEvaluator
from etbh.probes.stdout_spoof_pass import StdoutSpoofPass
from etbh.probes.test_edit_pass import TestEditPass
from etbh.probes.tests_readable import TestsReadable
from etbh.probes.tests_writable import TestsWritable
from etbh.probes.trace_injection import TraceInjection

ALL_PROBES: tuple[type[Probe], ...] = (
    TestsReadable,
    GitHistoryHasFix,
    NetworkEgress,
    TestsWritable,
    GraderPathWritable,
    TestEditPass,
    StdoutSpoofPass,
    ExitCodeIgnored,
    EvalContextLeak,
    DegeneratePass,
    TraceInjection,
    PrivilegedEvaluator,
)
PROBES_BY_ID: dict[str, type[Probe]] = {p.probe_id: p for p in ALL_PROBES}


def build_probes(
    adapter: BenchmarkAdapter | None,
    hardening: Hardening = BEFORE,
    include: list[str] | None = None,
) -> list[Probe]:
    chosen = ALL_PROBES if include is None else tuple(PROBES_BY_ID[i] for i in include)
    return [cls(adapter, hardening) for cls in chosen]


__all__ = ["ALL_PROBES", "PROBES_BY_ID", "Probe", "ProbeResult", "build_probes"]
