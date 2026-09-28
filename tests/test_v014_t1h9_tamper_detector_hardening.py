from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel import defense_evasion_detector as de


def _positive():
    return de.positive_fixture()


@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), float("-inf"), 10**5000],
    ids=["nan", "pos-inf", "neg-inf", "huge-int"],
)
def test_nonfinite_and_pathological_timestamps_fail_closed(bad):
    item = replace(_positive()[0], observed_at=bad)
    with pytest.raises(ValueError, match="observed_at_invalid"):
        de.detect((item,))


@pytest.mark.parametrize(
    "field",
    [
        "protection_disable_attempted",
        "telemetry_suppressed",
        "exclusion_scope_expanded",
        "policy_weakened",
        "security_service_stop_attempted",
        "approved_change",
        "maintenance_window",
        "signed_admin_workflow",
    ],
)
@pytest.mark.parametrize("bad", ["false", 1, None, []], ids=["string", "int", "none", "list"])
def test_signal_and_suppressor_fields_require_actual_bool(field, bad):
    item = replace(_positive()[0], **{field: bad})
    with pytest.raises(ValueError, match=f"{field}_invalid"):
        de.detect((item,))


def test_from_dict_does_not_coerce_false_string_into_admin_suppressor():
    payload = _positive()[0].to_dict()
    payload["approved_change"] = "false"
    with pytest.raises(ValueError, match="approved_change_invalid"):
        de.ControlTamperObservation.from_dict(payload)


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
def test_unhashable_identifiers_fail_closed(field, bad, failure):
    item = replace(_positive()[0], **{field: bad})
    with pytest.raises(ValueError, match=failure):
        de.detect((item,))


@pytest.mark.parametrize("bad", [None, 7, [], {}], ids=["none", "int", "list", "dict"])
def test_correlation_key_type_confusion_fails_closed(bad):
    item = replace(_positive()[0], correlation_key=bad)
    with pytest.raises(ValueError, match="correlation_key_invalid"):
        de.detect((item,))


def test_malformed_observation_is_validated_before_sorting():
    with pytest.raises(ValueError, match="type_invalid"):
        de.detect(({"event_id": "not-a-dataclass"},))


def test_mixed_workflows_cannot_be_aggregated():
    first, second = _positive()
    second = replace(second, correlation_key="b82:unrelated-workflow")
    with pytest.raises(ValueError, match="mixed_correlation_keys"):
        de.detect((first, second))


def test_unrelated_approved_change_cannot_poison_positive_batch():
    poison = replace(
        de.admin_fixture()[0],
        event_id="b82-unrelated-approved",
        evidence_id="ev-b82-unrelated-approved",
        correlation_key="b82:unrelated-approved",
    )
    with pytest.raises(ValueError, match="mixed_correlation_keys"):
        de.detect((*_positive(), poison))


@pytest.mark.parametrize(
    ("field", "bad", "failure"),
    [
        ("outcome", [], "result:outcome_invalid"),
        ("matched_signals", [[]], "result:signals_invalid"),
        ("first_observed_at", float("nan"), "result:first_observed_at_invalid"),
        ("detection_observed_at", float("inf"), "result:detection_observed_at_invalid"),
        ("detection_latency", 10**5000, "result:detection_latency_invalid"),
        ("suppressor_reasons", ["FORGED"], "result:suppressor_reasons_invalid"),
    ],
    ids=[
        "outcome-list",
        "signal-list",
        "nan-time",
        "inf-time",
        "huge-latency",
        "forged-suppressor",
    ],
)
def test_result_validator_rejects_type_confusion_and_forged_fields(field, bad, failure):
    payload = de.detect(_positive()).to_dict()
    payload[field] = bad
    validation = de.validate_result(payload)
    assert validation.passed is False
    assert failure in validation.failures


def test_result_validator_binds_score_outcome_and_latency_to_evidence_shape():
    payload = de.detect(_positive()).to_dict()

    forged_score = dict(payload)
    forged_score["score"] = 3
    assert "result:score_signal_mismatch" in de.validate_result(forged_score).failures

    forged_outcome = dict(payload)
    forged_outcome["outcome"] = de.OUTCOME_NO_MATCH
    assert "result:outcome_signal_mismatch" in de.validate_result(forged_outcome).failures

    forged_latency = dict(payload)
    forged_latency["detection_latency"] = payload["detection_latency"] + 1.0
    assert "result:detection_latency_mismatch" in de.validate_result(forged_latency).failures


def test_detection_result_from_dict_rejects_forged_score():
    payload = de.detect(_positive()).to_dict()
    payload["score"] = 0
    with pytest.raises(ValueError, match="score_signal_mismatch"):
        de.DetectionResult.from_dict(payload)


def test_graph_builder_validates_before_sorting():
    result = de.detect(_positive())
    with pytest.raises(ValueError, match="type_invalid"):
        de.build_evidence_graph(({"observed_at": 1.0},), result)
