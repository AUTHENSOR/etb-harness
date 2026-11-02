"""Benchmark adapters. One per benchmark, all speaking the protocol in `base`."""

from __future__ import annotations

from etbh.adapters.base import (
    AdapterBase,
    AdapterUnavailable,
    BenchmarkAdapter,
    ExecResult,
    GradeResult,
    Sandbox,
    TaskSpec,
    deterministic_sample,
)

ADAPTER_NAMES = ("swe_bench", "swe_bench_pro", "control_arena", "terminal_bench",
                 "cybergym", "bountybench", "fake")


def get_adapter(name: str, **kwargs) -> BenchmarkAdapter:
    """Instantiate an adapter by name. Imports lazily so optional deps stay optional."""
    if name == "swe_bench":
        from etbh.adapters.swe_bench import SweBenchAdapter

        return SweBenchAdapter(variant="verified", **kwargs)
    if name == "swe_bench_pro":
        from etbh.adapters.swe_bench import SweBenchAdapter

        return SweBenchAdapter(variant="pro", **kwargs)
    if name == "control_arena":
        from etbh.adapters.control_arena import ControlArenaAdapter

        return ControlArenaAdapter(**kwargs)
    if name == "terminal_bench":
        from etbh.adapters.terminal_bench import TerminalBenchAdapter

        return TerminalBenchAdapter(**kwargs)
    if name == "cybergym":
        from etbh.adapters.cybergym import CyberGymAdapter

        return CyberGymAdapter(**kwargs)
    if name == "bountybench":
        from etbh.adapters.bountybench import BountyBenchAdapter

        return BountyBenchAdapter(**kwargs)
    if name == "fake":
        from etbh.adapters.fake import FakeAdapter

        return FakeAdapter.example(**kwargs)
    raise ValueError(f"unknown benchmark adapter {name!r}; known: {ADAPTER_NAMES}")


__all__ = [
    "ADAPTER_NAMES",
    "AdapterBase",
    "AdapterUnavailable",
    "BenchmarkAdapter",
    "ExecResult",
    "GradeResult",
    "Sandbox",
    "TaskSpec",
    "deterministic_sample",
    "get_adapter",
]
