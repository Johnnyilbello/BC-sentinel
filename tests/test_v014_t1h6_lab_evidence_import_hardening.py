from __future__ import annotations

import pytest

from sentinel import beta14_lab_evidence_importer as b143


def _dynamic_record() -> dict:
    return b143._fixture(
        run_id="b143-hardening-dynamic",
        sample_id="malware-dynamic-hardening",
        sample_sha256="9" * 64,
        sample_kind=b143.SAMPLE_MALWARE,
        environment=b143.ENVIRONMENT_ISOLATED,
        result=b143.RESULT_DETECTED,
        layer="BEHAVIOR",
        real_sample_executed=True,
        authorization_class=b143.AUTH_APPROVED_RESEARCH,
    )


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("False", id="false-string"),
        pytest.param(1, id="integer-one"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
        pytest.param(None, id="none"),
    ],
)
def test_b143_real_sample_execution_requires_boolean(value: object) -> None:
    record = _dynamic_record()
    record["real_sample_executed"] = value
    failures = b143.validate_record(record)
    assert "b143:real_sample_executed_invalid" in failures
    assert b143.authoritative_for_internal_lab(record) is False


@pytest.mark.parametrize(
    ("field", "failure"),
    [
        ("sample_kind", "b143:sample_kind_invalid"),
        ("authorization_class", "b143:authorization_class_invalid"),
        ("environment_classification", "b143:environment_invalid"),
        ("network_mode", "b143:network_mode_invalid"),
        ("result", "b143:result_invalid"),
        ("detection_layer", "b143:detection_layer_invalid"),
        ("quarantine_state", "b143:quarantine_state_invalid"),
        ("restore_state", "b143:restore_state_invalid"),
    ],
)
@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param(["unexpected"], id="list"),
        pytest.param({"unexpected": "object"}, id="dict"),
    ],
)
def test_b143_unhashable_enum_values_fail_closed(
    field: str,
    failure: str,
    malformed: object,
) -> None:
    record = _dynamic_record()
    record[field] = malformed
    failures = b143.validate_record(record)
    assert failure in failures


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(float("inf"), id="pos-inf"),
        pytest.param(float("-inf"), id="neg-inf"),
        pytest.param(float("nan"), id="nan"),
        pytest.param(10**10000, id="huge-int"),
        pytest.param(True, id="bool"),
    ],
)
def test_b143_pathological_latency_fails_closed(value: object) -> None:
    record = _dynamic_record()
    record["detection_latency_ms"] = value
    assert "b143:detection_latency_invalid" in b143.validate_record(record)


@pytest.mark.parametrize(
    "malformed_member",
    [
        pytest.param({"unexpected": "object"}, id="dict-member"),
        pytest.param(["unexpected"], id="list-member"),
    ],
)
def test_b143_unhashable_evidence_id_member_fails_closed(
    malformed_member: object,
) -> None:
    record = _dynamic_record()
    record["evidence_ids"] = [malformed_member]
    assert "b143:evidence_ids_invalid" in b143.validate_record(record)


def test_b143_import_batch_rejects_type_confusion_without_crashing() -> None:
    record = _dynamic_record()
    record["real_sample_executed"] = "False"
    report = b143.import_batch((record,))
    assert report["passed"] is False
    assert report["accepted_count"] == 0
    assert report["authoritative_count"] == 0
    assert any("b143:real_sample_executed_invalid" in item for item in report["failures"])
