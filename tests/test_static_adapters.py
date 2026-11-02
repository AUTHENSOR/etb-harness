"""CyberGym and BountyBench adapters enumerate from public indexes and refuse to pretend to run."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from etbh.adapters.base import AdapterUnavailable
from etbh.adapters.bountybench import BountyBenchAdapter
from etbh.adapters.cybergym import CyberGymAdapter, archive_url
from etbh.hardening.profiles import BEFORE

CG_ROWS = [
    {"task_id": "arvo:1065", "project_name": "file",
     "project_main_repo": "https://github.com/file/file.git",
     "project_language": "c++", "vulnerability_description": "x",
     "task_difficulty": {"level0": ["data/arvo/1065/repo-vul.tar.gz"],
                         "level1": ["data/arvo/1065/repo-vul.tar.gz", "data/arvo/1065/description.txt"],
                         "level3": ["data/arvo/1065/repo-vul.tar.gz", "data/arvo/1065/patch.diff"]}},
    {"task_id": "oss-fuzz:42535201", "project_name": "libxml2", "project_main_repo": "",
     "project_language": "c", "vulnerability_description": "y",
     "task_difficulty": {"level1": ["data/oss-fuzz/42535201/repo-vul.tar.gz"]}},
]
BB_ROWS = [
    {"task_id": "lunary/bounty_0", "project": "lunary", "bounty": "bounty_0", "cve": "CVE-2024-1625",
     "cwe": "CWE-639", "severity": "7.5", "bounty_link": "https://huntr.com/bounties/x",
     "vulnerable_commit": "fc95998", "has_verify": True, "has_exploit": True, "has_patch": True,
     "has_invariants": True},
]


def test_cybergym_enumerates_and_describes_levels():
    a = CyberGymAdapter(rows=CG_ROWS, level="level1")
    assert a.task_ids() == ["arvo:1065", "oss-fuzz:42535201"]
    spec = a.task_spec("arvo:1065")
    assert spec.metadata["files_given_at_level"] == ["repo-vul.tar.gz", "description.txt"]
    assert spec.metadata["patch_given"] is False
    level3 = CyberGymAdapter(rows=CG_ROWS, level="level3").task_spec("arvo:1065")
    assert level3.metadata["patch_given"] is True
    assert archive_url("arvo:1065", "patch.diff").endswith("/data/arvo/1065/patch.diff")
    priv = a.evaluator_privileges(spec, BEFORE)
    assert not priv["same_container"] and not priv["write_access"]


def test_cybergym_sandbox_is_unavailable_not_fake():
    a = CyberGymAdapter(rows=CG_ROWS)
    with pytest.raises(AdapterUnavailable):
        with a.sandbox(a.task_spec("arvo:1065"), BEFORE):
            pass


def test_bountybench_enumerates_from_index(tmp_path: Path):
    idx = tmp_path / "index.json"
    idx.write_text(json.dumps({"commit": "1956e5f", "bounties": BB_ROWS}))
    a = BountyBenchAdapter(index=idx)
    assert a.task_ids() == ["lunary/bounty_0"]
    spec = a.task_spec("lunary/bounty_0")
    assert spec.metadata["cve"] == "CVE-2024-1625"
    assert spec.test_files == ["lunary/bounties/bounty_0/verify_files/verify.sh"]
    assert a.version_pins()["tasks_commit"] == "1956e5f"
    with pytest.raises(AdapterUnavailable):
        with a.sandbox(spec, BEFORE):
            pass


def test_missing_indexes_are_unavailable(tmp_path: Path):
    with pytest.raises(AdapterUnavailable):
        CyberGymAdapter(tasks_json=tmp_path / "none.json").task_ids()
    with pytest.raises(AdapterUnavailable):
        BountyBenchAdapter(index=tmp_path / "none.json").task_ids()
