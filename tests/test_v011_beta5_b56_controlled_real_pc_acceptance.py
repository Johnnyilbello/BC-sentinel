from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_real_pc_acceptance as b56

HOST = "a" * 64
TARGET = "b" * 64


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_evidence(base: Path, name: str, data: bytes = b"evidence") -> dict:
    path = base / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": str(path), "sha256": sha(path), "size": path.stat().st_size, "kind": "fixture"}


def write_scenario(
    base: Path,
    scenario_id: str,
    *,
    env: str = b56.ENV_CONTROLLED_FIXTURE,
    status: str = b56.STATUS_PASS,
    host: str = HOST,
    before: str = TARGET,
    after: str = TARGET,
    refusal: list[str] | None = None,
    filename: str | None = None,
) -> Path:
    evidence = [write_evidence(base, f"evidence-{scenario_id}-{filename or scenario_id}.json", scenario_id.encode())]
    record = b56.build_scenario_record(
        scenario_id=scenario_id,
        environment_type=env,
        status=status,
        host_fingerprint=host,
        target_fingerprint_before=before,
        target_fingerprint_after=after,
        evidence=evidence,
        checks={"fixture_check": True},
        refusal_reasons=refusal,
        notes=["test fixture"],
    )
    path = base / (filename or f"{scenario_id}.json")
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def build_full_set(base: Path, *, include_problematic: bool = False) -> None:
    write_scenario(base, b56.SCENARIO_KNOWN_GOOD, env=b56.ENV_REAL_HARDWARE)
    write_scenario(base, b56.SCENARIO_DAMAGED)
    write_scenario(base, b56.SCENARIO_PERSISTENCE)
    write_scenario(base, b56.SCENARIO_RESOURCE)
    write_scenario(base, b56.SCENARIO_LOCKED, status=b56.STATUS_REFUSED, refusal=["locked_volume_refused_without_unlock"])
    write_scenario(base, b56.SCENARIO_RESUME)
    if include_problematic:
        write_scenario(base, b56.SCENARIO_PROBLEMATIC, env=b56.ENV_OPERATOR_SUPPLIED)


def test_build_scenario_record_hash_is_valid() -> None:
    record = b56.build_scenario_record(
        scenario_id=b56.SCENARIO_KNOWN_GOOD,
        environment_type=b56.ENV_REAL_HARDWARE,
        status=b56.STATUS_PASS,
        host_fingerprint=HOST,
        target_fingerprint_before=TARGET,
        target_fingerprint_after=TARGET,
        evidence=[],
        checks={"ok": True},
    )
    assert len(record["scenario_sha256"]) == 64
    assert record["target_unchanged"] is True


def test_unknown_scenario_refused() -> None:
    with pytest.raises(ValueError, match="unknown_scenario_id"):
        b56.build_scenario_record(
            scenario_id="unknown", environment_type=b56.ENV_REAL_HARDWARE, status=b56.STATUS_PASS,
            host_fingerprint=HOST, target_fingerprint_before=TARGET, target_fingerprint_after=TARGET,
            evidence=[], checks={"ok": True},
        )


def test_invalid_environment_refused() -> None:
    with pytest.raises(ValueError, match="invalid_environment_type"):
        b56.build_scenario_record(
            scenario_id=b56.SCENARIO_KNOWN_GOOD, environment_type="SIMULATED_AS_REAL", status=b56.STATUS_PASS,
            host_fingerprint=HOST, target_fingerprint_before=TARGET, target_fingerprint_after=TARGET,
            evidence=[], checks={"ok": True},
        )


def test_full_required_set_passes(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is True
    assert result["counts"]["same_host_controlled"] >= 4


def test_missing_required_scenario_fails(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    (base / f"{b56.SCENARIO_DAMAGED}.json").unlink()
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is False
    assert any("missing_required_scenario:damaged_offline_windows" in x for x in result["failures"])


def test_known_good_must_be_real_hardware(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    write_scenario(base, b56.SCENARIO_KNOWN_GOOD, env=b56.ENV_CONTROLLED_FIXTURE)
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is False
    assert "known_good_control_must_be_real_hardware" in result["failures"]


def test_tampered_scenario_hash_fails_closed(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    path = base / f"{b56.SCENARIO_RESOURCE}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["notes"] = ["tampered"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is False
    assert any("scenario_sha256_mismatch" in x for x in result["failures"])


def test_tampered_evidence_hash_fails_closed(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    payload = json.loads((base / f"{b56.SCENARIO_PERSISTENCE}.json").read_text(encoding="utf-8"))
    evidence_path = Path(payload["evidence"][0]["path"])
    evidence_path.write_bytes(b"changed")
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is False
    assert any("evidence_sha256_mismatch" in x or "evidence_size_mismatch" in x for x in result["failures"])


def test_duplicate_scenario_fails(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    write_scenario(base, b56.SCENARIO_DAMAGED, filename="damaged-duplicate.json")
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is False
    assert any("duplicate_scenario:damaged_offline_windows" in x for x in result["failures"])


def test_required_not_run_fails(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    write_scenario(base, b56.SCENARIO_RESOURCE, status=b56.STATUS_NOT_RUN)
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is False
    assert any("required_scenario_not_run" in x for x in result["failures"])


def test_locked_refusal_with_reason_is_accepted(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    locked = next(x for x in result["scenario_results"] if x["scenario_id"] == b56.SCENARIO_LOCKED)
    assert locked["status"] == b56.STATUS_REFUSED
    assert result["passed"] is True


def test_refused_without_reason_is_untrusted(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    write_scenario(base, b56.SCENARIO_LOCKED, status=b56.STATUS_REFUSED, refusal=[])
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is False
    assert any("refused_without_reason" in x for x in result["failures"])


def test_problematic_pc_can_remain_optional(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json", require_problematic_pc=False))
    assert result["passed"] is True
    assert result["problematic_pc_status"] == b56.STATUS_NOT_RUN


def test_problematic_pc_requirement_fails_when_missing(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json", require_problematic_pc=True))
    assert result["passed"] is False
    assert any("missing_required_scenario:problematic_pc_optional" in x for x in result["failures"])


def test_problematic_pc_requirement_passes_when_supplied(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base, include_problematic=True)
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json", require_problematic_pc=True))
    assert result["passed"] is True
    assert result["problematic_pc_status"] == b56.STATUS_PASS


def test_scenario_symlink_refused_when_supported(tmp_path: Path) -> None:
    base = tmp_path / "scenarios"
    base.mkdir()
    build_full_set(base)
    source = base / f"{b56.SCENARIO_DAMAGED}.json"
    real = tmp_path / "real-damaged.json"
    real.write_bytes(source.read_bytes())
    source.unlink()
    try:
        source.symlink_to(real)
    except OSError:
        pytest.skip("symlink unavailable")
    result = b56.build_acceptance_summary(b56.AcceptanceRequest(base, tmp_path / "summary.json"))
    assert result["passed"] is False
    assert any("symlink" in x or "reparse" in x for x in result["failures"])
