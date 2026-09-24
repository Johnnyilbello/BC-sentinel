from __future__ import annotations

import pytest

from sentinel import beta14_t3_isolated_dynamic_evidence as b148


def _record() -> dict:
    return b148._fixture(
        901,
        result=b148.RESULT_DETECTED,
        category=b148.CATEGORY_TROJAN,
    )


@pytest.mark.parametrize(
    "value",
    [
        float("inf"),
        float("-inf"),
        float("nan"),
        10**10000,
        True,
    ],
)
def test_b148_rejects_pathological_detection_latency(value: object) -> None:
    record = _record()
    record["detection_latency_ms"] = value
    failures = b148.validate_record(record)
    assert "b148:detection_latency_invalid" in failures


@pytest.mark.parametrize(
    "value",
    [
        float("inf"),
        float("-inf"),
        float("nan"),
        10**10000,
        True,
    ],
)
def test_b148_rejects_pathological_execution_duration(value: object) -> None:
    record = _record()
    record["execution_duration_ms"] = value
    failures = b148.validate_record(record)
    assert "b148:execution_duration_invalid" in failures


def test_b148_pathological_numeric_metadata_fails_closed_without_crashing_batch() -> None:
    record = _record()
    record["detection_latency_ms"] = 10**10000
    report = b148.summarize_batch((record,))
    assert report["passed"] is False
    assert report["accepted_count"] == 0
    assert any("b148:detection_latency_invalid" in item for item in report["failures"])


def test_b148_nonfinite_metadata_never_reaches_metrics_aggregation() -> None:
    record = _record()
    record["execution_duration_ms"] = float("inf")
    report = b148.summarize_batch((record,))
    assert report["passed"] is False
    assert report["accepted_count"] == 0
    assert report["mean_execution_duration_ms"] is None
