from __future__ import annotations

import pytest

from sentinel.offline_benchmark import SCHEMA, evaluate, validate_manifest


def manifest(*, better: bool = False) -> dict:
    rows = []
    for index in range(400):
        malicious = index < 200
        common = {"detected": malicious, "seconds": 2.0,
                  "cpu_seconds": 1.0, "peak_rss_bytes": 128_000_000}
        bc = [{**common, "detected": malicious if better else common["detected"],
               "seconds": 1.0 if better else 2.0,
               "cpu_seconds": 0.5 if better else 1.0,
               "peak_rss_bytes": 64_000_000 if better else 128_000_000}
              for _ in range(5)]
        defender = [{**common, "detected": ((index % 5 != 0) if malicious else (index % 5 == 0))
                     if better else common["detected"]} for _ in range(5)]
        rows.append({"sha256": f"{index:064x}", "label": "malicious" if malicious else "benign",
                     "category": "synthetic-metadata", "results": {
                         "bc_sentinel": bc, "microsoft_defender": defender}})
    return {"schema": SCHEMA, "bc_sentinel_commit": "a" * 40,
            "defender_version": "synthetic-control", "host_evidence_id": "synthetic-only",
            "snapshot_revert_evidence_id": "synthetic-only", "corpus_id": "synthetic-only",
            "samples": rows}


def test_ties_prohibit_superiority_claim():
    report = evaluate(manifest(), bootstrap_iterations=1000)
    assert report["statistical_gate_passed"] is False
    assert report["public_superiority_claim_authorized"] is False


def test_strict_advantage_only_passes_statistical_gate():
    report = evaluate(manifest(better=True), bootstrap_iterations=1000)
    assert report["statistical_gate_passed"] is True
    assert all(value > 0 for value in report["simultaneous_95_lower_bounds"].values())
    assert report["public_superiority_claim_authorized"] is False
    assert report["sample_executed"] is False


def test_missing_samples_and_malformed_metrics_are_rejected():
    raw = manifest()
    raw["samples"] = raw["samples"][:199]
    with pytest.raises(ValueError, match="too small"):
        validate_manifest(raw)
    raw = manifest()
    raw["samples"][0]["results"]["bc_sentinel"][0]["seconds"] = float("nan")
    with pytest.raises(ValueError, match="finite"):
        validate_manifest(raw)
    raw = manifest()
    raw["samples"][0]["results"]["bc_sentinel"][0]["detected"] = "false"
    with pytest.raises(ValueError, match="boolean"):
        validate_manifest(raw)


def test_missing_repetition_and_duplicate_identity_are_rejected():
    raw = manifest()
    raw["samples"][0]["results"]["bc_sentinel"].pop()
    with pytest.raises(ValueError, match="five runs"):
        validate_manifest(raw)
    raw = manifest()
    raw["samples"][1]["sha256"] = raw["samples"][0]["sha256"]
    with pytest.raises(ValueError, match="duplicate"):
        validate_manifest(raw)
