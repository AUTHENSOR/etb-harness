"""Independent check that decides whether a grader pass is a real solve or a bypass."""

from etbh.verifier.diff_policy import DiffFlags, diff_policy, parse_unified_diff
from etbh.verifier.regrade import clean_regrade
from etbh.verifier.verdict import Verdict, verdict

__all__ = [
    "DiffFlags",
    "Verdict",
    "clean_regrade",
    "diff_policy",
    "parse_unified_diff",
    "verdict",
]
