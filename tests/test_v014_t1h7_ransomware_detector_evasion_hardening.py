from __future__ import annotations

from dataclasses import replace
import math

import pytest

from sentinel import ransomware_detector as rd


def _positive():
    return rd.positive_fixture()


@pytest.mark.parametrize("field", ["observed_at", "entropy_delta"])
@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), float("-inf"), 10**5000],
    ids=["nan", "pos-inf", "neg-inf", "huge-int"],
)
def test_pathological_numeric_observation_values_fail_closed(field, bad):
    item = replace(_positive()[0], **{field: bad})
    with pytest.raises(ValueError, match=f"{field.split('_')[0]}|invalid"):
        rd.detect((item,))


@pytest.mark.parametrize(
    "field",
    [
        "extension_changed",
        "canary_touched",
        "known_backup_workflow",
        "user_initiated_bulk_operation",
    ],
)
@pytest.mark.parametrize("bad", ["false", 1, None, []], ids=["string", "int", "none", "list"])
def test_boolean_signal_and_suppressor_fields_require_actual_bool(field, bad):
    item = replace(_positive()[0], **{field: bad})
    with pytest.raises(ValueError, match=f"{field}_invalid"):
        rd.detect((item,))


@pytest.mark.parametrize("bad", [None, 7, [], {}], ids=["none", "int", "list", "dict"])
def test_correlation_key_type_confusion_fails_closed(bad):
    item = replace(_positive()[0], correlation_key=bad)
    with pytest.raises(ValueError, match="correlation_key_invalid"):
        rd.detect((item,))


def test_malformed_observation_is_validated_before_sorting():
    with pytest.raises(ValueError, match="type_invalid"):
        rd.detect(({"event_id": "not-a-dataclass"},))


def test_mixed_correlation_keys_cannot_be_aggregated():
    first, second = _positive()[:2]
    second = replace(second, correlation_key="b81:unrelated-workflow")
    with pytest.raises(ValueError, match="mixed_correlation_keys"):
        rd.detect((first, second))


def test_unrelated_backup_suppressor_cannot_poison_positive_batch():
    positive = _positive()
    poison = replace(
        positive[0],
        event_id="b81-unrelated-backup",
        evidence_id="ev-b81-unrelated-backup",
        correlation_key="b81:unrelated-backup",
        write_count_window=0,
        rename_count_window=0,
        entropy_delta=0.0,
        extension_changed=False,
        canary_touched=False,
        known_backup_workflow=True,
    )
    with pytest.raises(ValueError, match="mixed_correlation_keys"):
        rd.detect((*positive, poison))


def test_irregular_same_workflow_observations_still_detect():
    items = _positive()
    shifted = tuple(
        replace(item, observed_at=100.0 + index * 1.75)
        for index, item in enumerate(items)
    )
    result = rd.detect(tuple(reversed(shifted)))
    assert result.outcome == rd.OUTCOME_DETECTED
    assert result.score >= rd.DETECT_SCORE
    assert math.isfinite(result.detection_latency)


@pytest.mark.parametrize(
    ("field", "bad", "failure"),
    [
        ("outcome", [], "result:outcome_invalid"),
        ("matched_signals", [[]], "result:signals_invalid"),
        ("first_observed_at", float("nan"), "result:first_observed_at_invalid"),
        ("detection_observed_at", float("inf"), "result:detection_observed_at_invalid"),
        ("detection_latency", 10**5000, "result:detection_latency_invalid"),
    ],
    ids=["outcome-list", "signal-list", "nan-time", "inf-time", "huge-latency"],
)
def test_result_validator_rejects_type_confusion_and_nonfinite_numbers(field, bad, failure):
    payload = rd.detect(_positive()).to_dict()
    payload[field] = bad
    validation = rd.validate_result(payload)
    assert validation.passed is False
    assert failure in validation.failures


def test_graph_builder_validates_before_sorting():
    result = rd.detect(_positive())
    with pytest.raises(ValueError, match="type_invalid"):
        rd.build_evidence_graph(({"observed_at": 1.0},), result)


@pytest.mark.parametrize(
    ("field", "bad", "failure"),
    [
        ("event_id", [], "event_id_invalid"),
        ("event_id", {}, "event_id_invalid"),
        ("evidence_id", [], "evidence_id_invalid"),
        ("evidence_id", {}, "evidence_id_invalid"),
    ],
    ids=["event-list", "event-dict", "evidence-list", "evidence-dict"],
)
def test_unhashable_identifiers_fail_closed_before_set_operations(field, bad, failure):
    item = replace(_positive()[0], **{field: bad})
    with pytest.raises(ValueError, match=failure):
        rd.detect((item,))
