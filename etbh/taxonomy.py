"""ETB class table used by every probe, attacker strategy and report.

ETB-01..ETB-10 are published in AUTHENSOR/etb-scan TAXONOMY.md and are permanent.
ETB-11..ETB-16 are *proposed* in etb-registry/docs/taxonomy.md and may be renumbered
until that document is published. Nothing in this harness should hard-code a class id
outside this table.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EtbClass:
    id: str
    name: str
    status: str  # "published" | "proposed"
    summary: str


CLASSES: tuple[EtbClass, ...] = (
    EtbClass("ETB-01", "Injected verdict trusted", "published",
             "The judge extracts a score from model-controlled text."),
    EtbClass("ETB-02", "Unsanitized model output in evaluator prompt", "published",
             "Model text flows unescaped into the judge or monitor prompt."),
    EtbClass("ETB-03", "Fail-open on error", "published",
             "A backend, parse or vendor error is coerced to safe or pass."),
    EtbClass("ETB-04", "Denominator drop", "published",
             "Unscorable, refused or errored samples are silently excluded from the mean."),
    EtbClass("ETB-05", "Unscorable read as behavior-absent", "published",
             "Could-not-score is conflated with the attack did not succeed."),
    EtbClass("ETB-06", "Missing normalization", "published",
             "Homoglyph, zero-width or Unicode-steganographic content evades a detector."),
    EtbClass("ETB-07", "Composition blindness", "published",
             "Per-step monitors miss an attack distributed across benign steps."),
    EtbClass("ETB-08", "Metric miscounting", "published",
             "Aggregation loses structure: whole-dict positivity, name-collision collapse."),
    EtbClass("ETB-09", "Forged execution artifact", "published",
             "A runner trusts a self-reported PASSED, an always-equal return or spoofed stdout."),
    EtbClass("ETB-10", "Evaluation context leakage", "published",
             "Environment lets the agent detect it is being evaluated and condition on it."),
    EtbClass("ETB-11", "Grader tampering", "proposed",
             "The agent can edit test files, reference answers, results files or the runner."),
    EtbClass("ETB-12", "Trace injection", "proposed",
             "Model-written content is read by a monitor as if the harness wrote it."),
    EtbClass("ETB-13", "Privileged evaluator", "proposed",
             "The judge or monitor has tools, network or write access the agent can reach."),
    EtbClass("ETB-14", "Self-preference", "proposed",
             "The judge shares a model family with the system under test and favors it."),
    EtbClass("ETB-15", "Oracle reachable", "proposed",
             "Hidden tests, reference solutions or future/fix commits are reachable from the "
             "sandbox, including via network."),
    EtbClass("ETB-16", "Degenerate pass accepted", "proposed",
             "The grader accepts a change that deletes or stubs functionality or edits tests."),
)

BY_ID: dict[str, EtbClass] = {c.id: c for c in CLASSES}
PUBLISHED = tuple(c for c in CLASSES if c.status == "published")
PROPOSED = tuple(c for c in CLASSES if c.status == "proposed")


def validate_class_id(class_id: str) -> str:
    """Return the id if it is in the table, else raise ValueError."""
    if class_id not in BY_ID:
        raise ValueError(f"unknown ETB class id: {class_id!r}")
    return class_id
