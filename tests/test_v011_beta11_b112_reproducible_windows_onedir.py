from __future__ import annotations

import copy
from pathlib import Path

from sentinel import beta11_artifact_manifest as artifact

BUILD_COMMIT = "a" * 40


def _fixture_tree(tmp_path: Path) -> Path:
    root = tmp_path / artifact.ARTIFACT_BASENAME
    root.mkdir()
    (root / artifact.ARTIFACT_NAME).write_bytes(b"MZ-beta11-test-exe")
    internal = root / "_internal"
    internal.mkdir()
    (internal / "module.bin").write_bytes(b"module-data")
    (internal / "config.json").write_text('{"ok":true}\n', encoding="utf-8")
    return root


def test_manifest_round_trip_validates_exact_tree(tmp_path: Path) -> None:
    root = _fixture_tree(tmp_path)
    data = artifact.create_manifest(
        root,
        build_commit=BUILD_COMMIT,
        python_version="3.12.10",
        pyinstaller_version="6.22.3",
    )
    assert artifact.validate_manifest(data, root=root, expected_build_commit=BUILD_COMMIT) == ()
    assert data["artifact"] == artifact.ARTIFACT_NAME
    assert data["build_mode"] == "onedir"
    assert data["windowed"] is True
    assert data["file_count"] == 3
    assert len(data["artifact_sha256"]) == 64
    assert len(data["tree_digest"]) == 64


def test_inventory_is_sorted_and_digest_is_deterministic(tmp_path: Path) -> None:
    root = _fixture_tree(tmp_path)
    first = artifact.build_inventory(root)
    second = artifact.build_inventory(root)
    assert first == second
    assert [item["path"] for item in first] == sorted((item["path"] for item in first), key=str.lower)
    assert artifact.inventory_digest(first) == artifact.inventory_digest(second)


def test_manifest_fails_closed_after_payload_tamper(tmp_path: Path) -> None:
    root = _fixture_tree(tmp_path)
    data = artifact.create_manifest(
        root,
        build_commit=BUILD_COMMIT,
        python_version="3.12.10",
        pyinstaller_version="6.22.3",
    )
    (root / "_internal" / "module.bin").write_bytes(b"tampered")
    failures = artifact.validate_manifest(data, root=root, expected_build_commit=BUILD_COMMIT)
    assert "b112:artifact_tree_changed" in failures


def test_manifest_rejects_wrong_build_commit(tmp_path: Path) -> None:
    root = _fixture_tree(tmp_path)
    data = artifact.create_manifest(
        root,
        build_commit=BUILD_COMMIT,
        python_version="3.12.10",
        pyinstaller_version="6.22.3",
    )
    failures = artifact.validate_manifest(data, root=root, expected_build_commit="b" * 40)
    assert "b112:build_commit_mismatch" in failures


def test_manifest_rejects_tree_digest_mutation(tmp_path: Path) -> None:
    root = _fixture_tree(tmp_path)
    data = artifact.create_manifest(
        root,
        build_commit=BUILD_COMMIT,
        python_version="3.12.10",
        pyinstaller_version="6.22.3",
    )
    broken = copy.deepcopy(data)
    broken["tree_digest"] = "0" * 64
    failures = artifact.validate_manifest(broken)
    assert "b112:tree_digest_invalid" in failures


def test_manifest_preserves_beta11_safety_and_coverage_boundaries(tmp_path: Path) -> None:
    root = _fixture_tree(tmp_path)
    data = artifact.create_manifest(
        root,
        build_commit=BUILD_COMMIT,
        python_version="3.12.10",
        pyinstaller_version="6.22.3",
    )
    assert data["source_checkpoint"] == "checkpoint/v011-beta11-b111-pass"
    assert data["source_checkpoint_commit"] == "2d49bc2037d3d1f3fb40280277cf8d53927cc68b"
    assert data["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert data["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert data["release_artifact_available"] is True
    assert data["installer_available"] is False
    assert data["artifact_signed"] is False
    assert data["startup_authority_expanded"] is False
    assert data["coverage_promoted"] is False
    assert data["network_required_for_core_startup"] is False
    assert data["cloud_required_for_core_startup"] is False


def test_manifest_rejects_early_installer_or_signing_claim(tmp_path: Path) -> None:
    root = _fixture_tree(tmp_path)
    data = artifact.create_manifest(
        root,
        build_commit=BUILD_COMMIT,
        python_version="3.12.10",
        pyinstaller_version="6.22.3",
    )
    for key in ("installer_available", "artifact_signed", "startup_authority_expanded", "coverage_promoted"):
        broken = copy.deepcopy(data)
        broken[key] = True
        failures = artifact.validate_manifest(broken)
        assert f"b112:{key}_invalid" in failures
