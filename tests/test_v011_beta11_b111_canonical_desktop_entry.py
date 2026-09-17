from __future__ import annotations

import copy
from pathlib import Path

from sentinel import beta11_productization_foundation as foundation
from sentinel import beta11_runtime_identity as runtime


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "packaging" / "beta11_desktop_entry.py"


def _mutated() -> dict:
    return copy.deepcopy(runtime.runtime_identity())


def test_b111_identity_is_deterministic_and_valid() -> None:
    first = runtime.runtime_identity()
    second = runtime.runtime_identity()
    assert first == second
    assert runtime.validate_runtime_identity(first) == ()
    assert runtime.self_check()["passed"] is True


def test_b111_is_bound_to_exact_b110_checkpoint() -> None:
    data = runtime.runtime_identity()
    assert data["source_checkpoint"] == "checkpoint/v011-beta11-b110-pass"
    assert data["source_checkpoint_commit"] == "0bee65100c6713d11dedd56c28ee3118f0082624"


def test_b111_canonical_entry_binds_accepted_trust_center_ui() -> None:
    data = runtime.runtime_identity()
    source = ENTRY.read_text(encoding="utf-8")
    assert data["canonical_entrypoint"] == "packaging/beta11_desktop_entry.py"
    assert data["canonical_ui_module"] == "sentinel.beta10_trust_center_ui"
    assert data["canonical_ui_class"] == "TrustCenterWindow"
    assert "beta10_trust_center_ui as product_ui" in source
    assert "product_ui.TrustCenterWindow" in source
    assert "from sentinel.home_security_ui import main" not in source


def test_b111_preserves_accepted_coverage_and_verified_identity() -> None:
    data = runtime.runtime_identity()
    assert data["coverage_summary"] == foundation.SOURCE_COVERAGE == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert tuple(data["verified_scenarios"]) == foundation.VERIFIED_SCENARIOS
    assert data["coverage_promoted_in_b111"] is False


def test_b111_distribution_state_claims_only_entry_and_runtime_identity() -> None:
    state = runtime.runtime_identity()["distribution_state"]
    assert state["canonical_beta11_desktop_entry_available"] is True
    assert state["runtime_identity_available"] is True
    assert state["trust_center_included"] is True
    assert state["beta11_release_artifact_available"] is False
    assert state["installer_available"] is False
    assert state["uninstaller_available"] is False
    assert state["artifact_signed"] is False
    assert state["windows_service_installed"] is False
    assert state["kernel_driver_installed"] is False
    assert state["autostart_registered"] is False
    assert state["automatic_update_enabled"] is False


def test_b111_startup_boundary_remains_passive_and_unprivileged() -> None:
    startup = runtime.runtime_identity()["startup_boundary"]
    assert startup
    assert not any(startup.values())


def test_b111_validator_rejects_source_checkpoint_change() -> None:
    data = _mutated()
    data["source_checkpoint_commit"] = "0" * 40
    assert "b111:source_checkpoint_invalid" in runtime.validate_runtime_identity(data)


def test_b111_validator_rejects_old_or_wrong_entrypoint() -> None:
    data = _mutated()
    data["canonical_entrypoint"] = "packaging/home_security_ui_entry.py"
    assert "b111:entrypoint_invalid" in runtime.validate_runtime_identity(data)


def test_b111_validator_rejects_coverage_promotion() -> None:
    data = _mutated()
    data["coverage_summary"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    assert "b111:coverage_changed" in runtime.validate_runtime_identity(data)


def test_b111_validator_rejects_premature_installer_or_signature_claim() -> None:
    data = _mutated()
    data["distribution_state"]["installer_available"] = True
    assert any(item.startswith("b111:") for item in runtime.validate_runtime_identity(data))
    data = _mutated()
    data["distribution_state"]["artifact_signed"] = True
    assert any(item.startswith("b111:") for item in runtime.validate_runtime_identity(data))


def test_b111_validator_rejects_startup_authority_expansion() -> None:
    data = _mutated()
    data["startup_boundary"]["requires_administrator"] = True
    failures = runtime.validate_runtime_identity(data)
    assert "b111:startup_boundary_invalid" in failures or "b111:startup_authority_expanded" in failures


def test_b111_validator_rejects_release_or_authority_claim_flags() -> None:
    data = _mutated()
    data["release_artifact_claimed"] = True
    assert "b111:forbidden_claim:release_artifact_claimed" in runtime.validate_runtime_identity(data)
    data = _mutated()
    data["authority_expanded_in_b111"] = True
    assert "b111:forbidden_claim:authority_expanded_in_b111" in runtime.validate_runtime_identity(data)
