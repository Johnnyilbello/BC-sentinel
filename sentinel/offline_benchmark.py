"""Metadata-only, preregistered BC Sentinel/Defender comparison gate.

This module never opens, transfers, scans or executes sample bytes. A statistical
PASS is only a candidate for independent evidence review, not a product claim.
"""
from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path

SCHEMA = "bc-sentinel-offline-benchmark-v1"
PRODUCTS = ("bc_sentinel", "microsoft_defender")
METRICS = ("sensitivity", "false_positive_rate", "seconds_per_file",
           "cpu_seconds_per_file", "peak_rss_bytes_per_file")
REPEATS = 5
MIN_PER_CLASS = 200


def _number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    try:
        result = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} outside numeric range") from exc
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return result


def validate_manifest(raw: object) -> list[dict]:
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
        raise ValueError("benchmark schema mismatch")
    for key in ("bc_sentinel_commit", "defender_version", "host_evidence_id",
                "snapshot_revert_evidence_id", "corpus_id"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise ValueError(f"missing benchmark provenance: {key}")
    samples = raw.get("samples")
    if not isinstance(samples, list) or not 2 * MIN_PER_CLASS <= len(samples) <= 10000:
        raise ValueError("benchmark corpus is too small")
    counts = {"malicious": 0, "benign": 0}
    hashes: set[str] = set()
    for row in samples:
        if not isinstance(row, dict):
            raise ValueError("sample must be an object")
        digest = row.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("sample SHA-256 invalid")
        if digest in hashes:
            raise ValueError("duplicate sample SHA-256")
        hashes.add(digest)
        label = row.get("label")
        if not isinstance(label, str) or label not in counts:
            raise ValueError("sample label invalid")
        counts[label] += 1
        if not isinstance(row.get("category"), str) or not row["category"].strip():
            raise ValueError("sample category missing")
        results = row.get("results")
        if not isinstance(results, dict) or set(results) != set(PRODUCTS):
            raise ValueError("paired product results required")
        for product in PRODUCTS:
            runs = results[product]
            if not isinstance(runs, list) or len(runs) != REPEATS:
                raise ValueError("five runs per product and sample required")
            for run in runs:
                if not isinstance(run, dict) or type(run.get("detected")) is not bool:
                    raise ValueError("detection outcome must be boolean")
                for name in ("seconds", "cpu_seconds", "peak_rss_bytes"):
                    _number(run.get(name), name)
    if min(counts.values()) < MIN_PER_CLASS:
        raise ValueError("benchmark requires 200 malicious and 200 benign samples")
    return samples


def _scores(rows: list[dict]) -> dict[str, dict[str, float]]:
    scored: dict[str, dict[str, float]] = {}
    for product in PRODUCTS:
        malicious = [run["detected"] for row in rows if row["label"] == "malicious"
                     for run in row["results"][product]]
        benign = [run["detected"] for row in rows if row["label"] == "benign"
                  for run in row["results"][product]]
        runs = [run for row in rows for run in row["results"][product]]
        scored[product] = {
            "sensitivity": sum(malicious) / len(malicious),
            "false_positive_rate": sum(benign) / len(benign),
            "seconds_per_file": sum(_number(run["seconds"], "seconds") for run in runs) / len(runs),
            "cpu_seconds_per_file": sum(_number(run["cpu_seconds"], "cpu_seconds") for run in runs) / len(runs),
            "peak_rss_bytes_per_file": sum(_number(run["peak_rss_bytes"], "peak_rss_bytes") for run in runs) / len(runs),
        }
    return scored


def _advantage(scores: dict[str, dict[str, float]]) -> dict[str, float]:
    bc, defender = (scores[name] for name in PRODUCTS)
    return {
        name: bc[name] - defender[name] if name == "sensitivity" else defender[name] - bc[name]
        for name in METRICS
    }


def evaluate(raw: object, *, bootstrap_iterations: int = 2000) -> dict:
    rows = validate_manifest(raw)
    if type(bootstrap_iterations) is not int or not 1000 <= bootstrap_iterations <= 10000:
        raise ValueError("at least 1000 bootstrap iterations required")
    scores = _scores(rows)
    differences = _advantage(scores)
    by_label = {label: [row for row in rows if row["label"] == label]
                for label in ("malicious", "benign")}
    rng = random.Random(0xBC1406)
    draws = {name: [] for name in METRICS}
    for _ in range(bootstrap_iterations):
        subset = [rng.choice(group) for group in by_label.values() for _ in range(len(group))]
        for name, value in _advantage(_scores(subset)).items():
            draws[name].append(value)
    # Bonferroni: five one-sided 99% lower bounds give familywise >=95%.
    lower_bounds = {name: sorted(draws[name])[max(0, int(bootstrap_iterations * 0.01) - 1)]
                    for name in METRICS}
    passed = all(differences[name] > 0 and lower_bounds[name] > 0 for name in METRICS)
    return {
        "schema": SCHEMA,
        "sample_counts": {name: len(group) for name, group in by_label.items()},
        "repetitions_per_product": REPEATS,
        "scores": scores,
        "bc_advantage": differences,
        "simultaneous_95_lower_bounds": lower_bounds,
        "statistical_gate_passed": passed,
        "independent_evidence_review_required": True,
        "public_superiority_claim_authorized": False,
        "sample_bytes_accessed": False,
        "sample_executed": False,
        "network_used": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        report = evaluate(json.loads(args.manifest.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"statistical_gate_passed": False, "reason": str(exc)}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["statistical_gate_passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
