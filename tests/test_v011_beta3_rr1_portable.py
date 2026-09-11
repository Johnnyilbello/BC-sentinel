from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel.rescue_portable import (
    MAX_FILE_BYTES,
    MAX_ITEMS,
    PROFILE,
    PortableLimits,
    run_portable_acquisition,
)


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "target"
    output = tmp_path / "evidence"
    target.mkdir()
    (target / "a.txt").write_text("alpha", encoding="utf-8")
    nested = target / "nested"
    nested.mkdir()
    (nested / "b.bin").write_bytes(b"beta")
    return target, output


def test_profile_is_rr1() -> None:
    assert PROFILE == "v0.11.0-beta.3-rr1"


def test_limits_defaults_validate() -> None:
    PortableLimits().validate()


@pytest.mark.parametrize("value", [0, -1, MAX_ITEMS + 1])
def test_max_items_is_bounded(value: int) -> None:
    with pytest.raises(ValueError):
        PortableLimits(max_items=value).validate()


@pytest.mark.parametrize("value", [0, -1, MAX_FILE_BYTES + 1])
def test_max_file_bytes_is_bounded(value: int) -> None:
    with pytest.raises(ValueError):
        PortableLimits(max_file_bytes=value).validate()


def test_acquisition_hashes_files_and_writes_only_output(tmp_path: Path) -> None:
    target, output = _fixture(tmp_path)
    before = {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    result = run_portable_acquisition(target, output)
    after = {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    assert before == after
    assert result["summary"]["hashed"] == 2
    assert (output / "rr1-evidence.json").is_file()


def test_sha256_evidence_is_correct(tmp_path: Path) -> None:
    target, output = _fixture(tmp_path)
    result = run_portable_acquisition(target, output)
    records = {row["relative_path"]: row for row in result["records"]}
    assert records["a.txt"]["sha256"] == hashlib.sha256(b"alpha").hexdigest()
    assert records[str(Path("nested") / "b.bin")]["sha256"] == hashlib.sha256(b"beta").hexdigest()


def test_output_manifest_round_trips_json(tmp_path: Path) -> None:
    target, output = _fixture(tmp_path)
    run_portable_acquisition(target, output)
    payload = json.loads((output / "rr1-evidence.json").read_text(encoding="utf-8"))
    assert payload["profile"] == PROFILE
    assert payload["mode"] == "portable_read_only_acquisition"
    assert payload["manifest"]["write_authorized"] is False
    assert payload["manifest"]["recovery_certification_available"] is False


def test_output_inside_target_is_rejected(tmp_path: Path) -> None:
    target, _ = _fixture(tmp_path)
    with pytest.raises(ValueError, match="must not be inside the target tree"):
        run_portable_acquisition(target, target / "evidence")


def test_missing_target_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        run_portable_acquisition(tmp_path / "missing", tmp_path / "out")


def test_file_size_limit_skips_without_mutation(tmp_path: Path) -> None:
    target = tmp_path / "target"
    output = tmp_path / "out"
    target.mkdir()
    big = target / "big.bin"
    big.write_bytes(b"123456")
    before = big.read_bytes()
    result = run_portable_acquisition(target, output, limits=PortableLimits(max_items=10, max_file_bytes=4))
    assert big.read_bytes() == before
    assert result["summary"]["skipped"] == 1
    assert result["records"][0]["reason"] == "file_too_large"


def test_item_limit_is_enforced(tmp_path: Path) -> None:
    target = tmp_path / "target"
    output = tmp_path / "out"
    target.mkdir()
    for index in range(6):
        (target / f"{index}.txt").write_text(str(index), encoding="utf-8")
    result = run_portable_acquisition(target, output, limits=PortableLimits(max_items=3))
    assert result["summary"]["enumerated"] == 3
    assert result["summary"]["truncated_by_max_items"] is True


def test_safety_contract_disables_install_and_destructive_actions(tmp_path: Path) -> None:
    target, output = _fixture(tmp_path)
    safety = run_portable_acquisition(target, output)["safety"]
    required_false = {
        "installation_required",
        "service_install",
        "driver_install",
        "registry_write",
        "boot_write",
        "target_filesystem_write",
        "file_delete",
        "process_kill",
        "network_required",
        "cloud_required",
        "repair_engine_enabled",
        "quarantine_execution_enabled",
        "recovery_certification_enabled",
    }
    assert required_false.issubset(safety)
    assert all(safety[key] is False for key in required_false)


def test_manifest_uses_compromised_windows_context(tmp_path: Path) -> None:
    target, output = _fixture(tmp_path)
    result = run_portable_acquisition(target, output)
    assert result["manifest"]["execution_context"] == "compromised_windows"


def test_evidence_output_is_outside_target(tmp_path: Path) -> None:
    target, output = _fixture(tmp_path)
    result = run_portable_acquisition(target, output)
    assert Path(result["output_dir"]).resolve() == output.resolve()
    assert Path(result["target_root"]).resolve() == target.resolve()
