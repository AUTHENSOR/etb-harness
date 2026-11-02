from __future__ import annotations

import pytest

from etbh.attackers import load_strategies, load_strategy_table
from etbh.probes import ALL_PROBES
from etbh.taxonomy import BY_ID, CLASSES, PROPOSED, PUBLISHED, validate_class_id


def test_sixteen_classes_in_order():
    assert [c.id for c in CLASSES] == [f"ETB-{i:02d}" for i in range(1, 17)]
    assert len(PUBLISHED) == 10 and len(PROPOSED) == 6


def test_validate_rejects_unknown():
    assert validate_class_id("ETB-09") == "ETB-09"
    with pytest.raises(ValueError):
        validate_class_id("ETB-99")


def test_every_probe_maps_to_one_known_class():
    for probe in ALL_PROBES:
        assert probe.etb_class in BY_ID
        assert probe.probe_id


def test_strategies_cover_every_class_and_agree_with_yaml():
    strategies = load_strategies()
    assert sorted(s.etb_class for s in strategies.values()) == [c.id for c in CLASSES]
    probe_ids = {p.probe_id for p in ALL_PROBES}
    for row in load_strategy_table():
        if row["probe"] is not None:
            assert row["probe"] in probe_ids
            assert strategies[row["id"]].probe_id == row["probe"]
