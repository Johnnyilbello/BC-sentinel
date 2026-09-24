from __future__ import annotations

import pytest

from sentinel import beta14_t3_isolated_dynamic_evidence as b148


def _record() -> dict:
    return b148._fixture(
        905,
        result=b148.RESULT_DETECTED,
        category=b148.CATEGORY_TROJAN,
    )


@pytest.mark.parametrize(
    ("field", "failure"),
    [
        ("malware_category", "b148:malware_category_invalid"),
        ("authorization_class", "b148:authorization_class_invalid"),
        ("network_mode", "b148:network_mode_invalid"),
        ("result", "b148:result_invalid"),
        ("primary_detection_layer", "b148:primary_detection_layer_invalid"),
        ("quarantine_state", "b148:quarantine_state_invalid"),
    ],
)
@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param(["unexpected"], id="list"),
        pytest.param({"unexpected": "object"}, id="dict"),
    ],
)
def test_b148_unhashable_enum_values_fail_closed(
    field: str,
    failure: str,
    malformed: object,
) -> None:
    record = _record()
    record[field] = malformed
    failures = b148.validate_record(record)
    assert failure in failures


@pytest.mark.parametrize(
    ("field", "failure"),
    [
        ("supporting_detection_layers", "b148:supporting_detection_layers_invalid"),
        ("observed_behaviors", "b148:observed_behaviors_invalid"),
        ("evidence_ids", "b148:evidence_ids_invalid"),
    ],
)
@pytest.mark.parametrize(
    "malformed_member",
    [
        pytest.param({"unexpected": "object"}, id="dict-member"),
        pytest.param(["unexpected"], id="list-member"),
    ],
)
def test_b148_unhashable_collection_members_fail_closed(
    field: str,
    failure: str,
    malformed_member: object,
) -> None:
    record = _record()
    record[field] = [malformed_member]
    failures = b148.validate_record(record)
    assert failure in failures


def test_b148_batch_rejects_malformed_nested_json_without_exception() -> None:
    record = _record()
    record["observed_behaviors"] = [{"unexpected": "object"}]
    report = b148.summarize_batch((record,))
    assert report["passed"] is False
    assert report["accepted_count"] == 0
    assert any("b148:observed_behaviors_invalid" in item for item in report["failures"])
