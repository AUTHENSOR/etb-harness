from __future__ import annotations

import sys

import pytest

from etbh.adapters import get_adapter
from etbh.adapters.base import AdapterUnavailable, deterministic_sample
from etbh.adapters.control_arena import ControlArenaAdapter
from etbh.adapters.swe_bench import SweBenchAdapter, files_in_patch, image_name
from tests.conftest import make_task

ROW = {
    "instance_id": "django__django-11099", "repo": "django/django", "base_commit": "b" * 40,
    "version": "3.0",
    "patch": "diff --git a/django/x.py b/django/x.py\n--- a/django/x.py\n+++ b/django/x.py\n",
    "test_patch": "diff --git a/tests/t.py b/tests/t.py\n--- a/tests/t.py\n+++ b/tests/t.py\n",
    "FAIL_TO_PASS": '["tests/t.py::test_a"]', "PASS_TO_PASS": '["tests/t.py::test_b"]',
}


def test_deterministic_sample_is_stable_and_order_independent():
    ids = [f"t{i}" for i in range(100)]
    a = deterministic_sample(ids, 10, 7)
    b = deterministic_sample(list(reversed(ids)), 10, 7)
    assert a == b and len(a) == 10 and len(set(a)) == 10
    assert deterministic_sample(ids, 10, 8) != a


def test_swe_bench_spec_from_row():
    ad = SweBenchAdapter(rows={ROW["instance_id"]: ROW}, arch="x86_64")
    assert ad.task_ids() == ["django__django-11099"]
    spec = ad.task_spec("django__django-11099")
    assert spec.test_files == ["tests/t.py"] and spec.fail_to_pass == ["tests/t.py::test_a"]
    assert spec.image == "swebench/sweb.eval.x86_64.django_1776_django-11099:latest"
    assert spec.metadata["reference_patch_files"] == ["django/x.py"]
    assert ad.version_pins()["dataset_revision"] == "78f471bf655a3137b2e8a75af1501690ec009ec3"
    assert ad.task_spec("django__django-11099").metadata["platform"] == "linux/amd64"
    assert image_name("a__b-1", arch="arm64") == "swebench/sweb.eval.arm64.a_1776_b-1:latest"
    assert files_in_patch("") == []


def test_swe_bench_without_datasets_is_unavailable_not_fatal(monkeypatch):
    monkeypatch.setitem(sys.modules, "datasets", None)  # force ImportError; stay offline
    ad = SweBenchAdapter(rows=None)
    with pytest.raises(AdapterUnavailable):
        ad.task_ids()


def test_control_arena_monitor_format_override():
    fixed = ControlArenaAdapter(task_ids=["t1"], escape_override=True)
    broken = ControlArenaAdapter(task_ids=["t1"], escape_override=False)
    payload = "</cot>inject<cot>"
    assert "&lt;/cot&gt;" in fixed.monitor_format(make_task(), payload)
    assert payload in broken.monitor_format(make_task(), payload)
    assert fixed.sample_tasks(5, 0) == ["t1"]


def test_stubs_raise_clearly():
    for name in ("cybergym", "bountybench"):
        with pytest.raises(NotImplementedError):
            get_adapter(name).task_ids()
    with pytest.raises(AdapterUnavailable):
        get_adapter("terminal_bench", tasks_dir="/nonexistent/terminal-bench").task_ids()


def test_fake_example_adapter_round_trip():
    ad = get_adapter("fake")
    ids = ad.sample_tasks(2, 0)
    assert len(ids) == 2
    spec = ad.task_spec(ids[0])
    assert spec.benchmark == "fake" and spec.grader_command
