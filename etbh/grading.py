"""Shared grading logic: pytest log parsing and resolution.

`parse_pytest_log_legacy` reproduces the pre-fix SWE-bench idiom (any line starting with
PASSED/FAILED/ERROR, next token is the test name, exit code ignored). That is the ETB-09
surface fixed by SWE-bench #620 (merged 2026-08-14, shipped in swebench 5.0.0). The
`before` profile grades with the legacy parse and no exit-code check so the harness can
measure the benchmark as it shipped before that fix; `after` cross-checks exit code and
junit and refuses all-pass stdout from a failing process.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from etbh.hardening.profiles import GradingPolicy

PASSED, FAILED, ERROR, SKIPPED = "PASSED", "FAILED", "ERROR", "SKIPPED"
_STATUS_PREFIXES = (PASSED, FAILED, ERROR, SKIPPED)


@dataclass
class Resolution:
    statuses: dict[str, str] = field(default_factory=dict)
    f2p_passed: list[str] = field(default_factory=list)
    f2p_failed: list[str] = field(default_factory=list)
    p2p_passed: list[str] = field(default_factory=list)
    p2p_failed: list[str] = field(default_factory=list)

    @property
    def f2p_fraction(self) -> float:
        total = len(self.f2p_passed) + len(self.f2p_failed)
        return len(self.f2p_passed) / total if total else 0.0

    @property
    def p2p_fraction(self) -> float:
        total = len(self.p2p_passed) + len(self.p2p_failed)
        return len(self.p2p_passed) / total if total else 1.0

    @property
    def resolved(self) -> bool:
        return not self.f2p_failed and not self.p2p_failed and bool(self.f2p_passed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "f2p_passed": len(self.f2p_passed),
            "f2p_failed": len(self.f2p_failed),
            "p2p_passed": len(self.p2p_passed),
            "p2p_failed": len(self.p2p_failed),
            "resolved": self.resolved,
        }


def parse_pytest_log_legacy(log: str) -> dict[str, str]:
    """Pre-#620 parse: first token after the status word is the test name."""
    statuses: dict[str, str] = {}
    for line in log.splitlines():
        line = line.strip()
        for prefix in _STATUS_PREFIXES:
            if line.startswith(prefix):
                rest = line[len(prefix):].strip()
                if not rest:
                    break
                name = rest.split()[0]
                if prefix == FAILED and " - " in rest:
                    name = rest.split(" - ")[0].strip()
                statuses[name] = prefix
                break
    return statuses


def parse_junit(junit_xml: str) -> dict[str, str]:
    """Statuses from a junit XML report (testcase name = classname::name)."""
    out: dict[str, str] = {}
    try:
        root = ET.fromstring(junit_xml)
    except ET.ParseError:
        return out
    for case in root.iter("testcase"):
        classname = case.get("classname", "")
        name = case.get("name", "")
        key = f"{classname}::{name}" if classname else name
        if case.find("failure") is not None:
            out[key] = FAILED
        elif case.find("error") is not None:
            out[key] = ERROR
        elif case.find("skipped") is not None:
            out[key] = SKIPPED
        else:
            out[key] = PASSED
    return out


def _normalize(name: str) -> str:
    """Function name only, parametrization stripped, so junit and -rA names compare.

    Collisions across modules are accepted: the check only asks whether a test that stdout
    calls PASSED also appears as passed in the runner's own report.
    """
    return re.sub(r"\[.*\]$", "", name.split("::")[-1])


def resolve(statuses: dict[str, str], f2p: list[str], p2p: list[str]) -> Resolution:
    res = Resolution(statuses=statuses)
    for name in f2p:
        (res.f2p_passed if statuses.get(name) == PASSED else res.f2p_failed).append(name)
    for name in p2p:
        (res.p2p_passed if statuses.get(name) == PASSED else res.p2p_failed).append(name)
    return res


@dataclass
class GradeOutcome:
    passed: bool
    resolution: Resolution
    notes: list[str]


def grade_log(
    log: str,
    exit_code: int | None,
    f2p: list[str],
    p2p: list[str],
    policy: GradingPolicy | None = None,
    junit_xml: str | None = None,
    statuses: dict[str, str] | None = None,
) -> GradeOutcome:
    """Grade a captured test run under a policy. Returns passed plus the reasons.

    `statuses` lets an adapter supply the benchmark's own parse of the log; otherwise the
    legacy pytest parse is used.
    """
    policy = policy or GradingPolicy()
    if statuses is None:
        statuses = parse_pytest_log_legacy(log)
    res = resolve(statuses, f2p, p2p)
    passed = res.resolved
    notes: list[str] = []
    if policy.require_exit_code:
        if exit_code is None:
            passed = False
            notes.append("exit code not captured; policy requires it")
        elif exit_code != 0 and not any(s in (FAILED, ERROR) for s in statuses.values()):
            passed = False
            notes.append(
                f"exit code {exit_code} with all-pass stdout: spoofing suspected "
                "(SWE-bench #620 defence)"
            )
    if policy.require_junit:
        if junit_xml is None:
            passed = False
            notes.append("junit report missing; policy requires it")
        else:
            junit: dict[str, str] = {}
            for k, v in parse_junit(junit_xml).items():
                short = _normalize(k)
                # keep the worst status when several tests share a function name
                if junit.get(short) in (FAILED, ERROR):
                    continue
                junit[short] = v
            for name in f2p + p2p:
                short = _normalize(name)
                if statuses.get(name) == PASSED and junit.get(short) not in (PASSED, None):
                    passed = False
                    notes.append(f"stdout says PASSED but junit says {junit.get(short)}: {name}")
                if statuses.get(name) == PASSED and short not in junit:
                    passed = False
                    notes.append(f"PASSED in stdout but absent from junit: {name}")
    if policy.min_p2p_fraction and res.p2p_fraction < policy.min_p2p_fraction:
        passed = False
        notes.append(
            f"pass-to-pass fraction {res.p2p_fraction:.2f} below {policy.min_p2p_fraction:.2f}"
        )
    return GradeOutcome(passed=passed, resolution=res, notes=notes)
