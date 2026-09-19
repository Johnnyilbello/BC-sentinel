from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel import beta12_product_integration as b128
from sentinel import beta13_commercial_readiness as b136
from sentinel import beta13_commercial_ui as ui


def _sign_entitlement(*, now: float = 1000.0, expires_at: float | None = 5000.0):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = b136.entitlement_payload(
        license_id="fixture-license",
        edition="home",
        issued_at=now,
        expires_at=expires_at,
    )
    signature = private.sign(b136._canonical(payload))
    return b136.attach_entitlement_signature(payload, signature), public


def test_self_check_binds_exact_b135_checkpoint_and_reduces_blockers() -> None:
    report = b136.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v013-b135-pass"
    assert report["source_checkpoint_commit"] == "cbead4c4e01818f5764ebeb82f85eb69f64e1f67"
    projection = report["readiness_projection"]
    assert projection["pillar_counts"] == {"READY": 9, "PARTIAL": 0, "BLOCKED": 1}
    assert projection["release_blockers"] == ["CODE_SIGNING"]
    assert projection["release_blocker_count"] == 1


def test_new_trial_is_initialized_and_remains_protected(tmp_path: Path) -> None:
    store = tmp_path / "trial.json"
    state = b136.load_trial(store, now=1000.0, initialize_if_missing=True)
    assert store.is_file()
    assert state.status == b136.TRIAL_ACTIVE
    assert state.protection_enabled is True
    assert state.trial_remaining_days == b136.DEFAULT_TRIAL_DAYS


def test_expired_trial_never_disables_core_protection() -> None:
    state = b136.evaluate_trial(
        {
            "schema": b136.TRIAL_SCHEMA,
            "started_at": 0.0,
            "trial_days": 1,
        },
        now=86401.0,
    )
    assert state.status == b136.TRIAL_EXPIRED
    assert state.protection_enabled is True
    assert state.reason == "trial_expired_protection_retained"


def test_corrupt_or_future_trial_state_fails_safe_without_disabling_protection() -> None:
    corrupt = b136.evaluate_trial({"bad": "state"}, now=100.0)
    future = b136.evaluate_trial(
        {
            "schema": b136.TRIAL_SCHEMA,
            "started_at": 1000.0,
            "trial_days": 14,
        },
        now=0.0,
    )
    assert corrupt.status == b136.UNAVAILABLE
    assert corrupt.protection_enabled is True
    assert future.status == b136.UNAVAILABLE
    assert future.protection_enabled is True


def test_signed_entitlement_verifies_locally_without_network() -> None:
    token, public = _sign_entitlement()
    state = b136.verify_signed_entitlement(token, public_key=public, now=2000.0)
    assert state.status == b136.LICENSED
    assert state.entitlement_verified is True
    assert state.protection_enabled is True


def test_tampered_entitlement_is_invalid_but_protection_remains() -> None:
    token, public = _sign_entitlement()
    token["edition"] = "PRO"
    state = b136.verify_signed_entitlement(token, public_key=public, now=2000.0)
    assert state.status == b136.INVALID
    assert state.protection_enabled is True


def test_missing_activation_key_is_unavailable_not_protection_failure() -> None:
    token, _ = _sign_entitlement()
    state = b136.verify_signed_entitlement(token, public_key=None, now=2000.0)
    assert state.status == b136.UNAVAILABLE
    assert state.protection_enabled is True


def test_expired_verified_entitlement_keeps_core_protection() -> None:
    token, public = _sign_entitlement(now=1000.0, expires_at=1500.0)
    state = b136.verify_signed_entitlement(token, public_key=public, now=2000.0)
    assert state.entitlement_verified is True
    assert state.status == b136.TRIAL_EXPIRED
    assert state.protection_enabled is True


def test_verified_license_overrides_trial_only_for_commercial_state() -> None:
    trial = b136.CommercialState(
        status=b136.TRIAL_EXPIRED,
        mode="TRIAL",
        protection_enabled=True,
    )
    licensed = b136.CommercialState(
        status=b136.LICENSED,
        mode="LICENSE",
        protection_enabled=True,
        entitlement_verified=True,
    )
    resolved = b136.resolve_commercial_state(trial=trial, entitlement=licensed)
    assert resolved == licensed
    assert resolved.protection_enabled is True


def test_policy_surfaces_are_complete_and_versioned() -> None:
    surfaces = b136.policy_surfaces()
    assert [item["surface_id"] for item in surfaces] == ["PRIVACY", "EULA", "SUPPORT"]
    assert all(item["version"] for item in surfaces)
    assert all(item["summary"] for item in surfaces)


def test_diagnostic_snapshot_is_privacy_minimal() -> None:
    state = b136.CommercialState(
        status=b136.TRIAL_ACTIVE,
        mode="TRIAL",
        protection_enabled=True,
        trial_days=14,
        trial_remaining_days=10,
    )
    payload = b136.diagnostic_snapshot(commercial_state=state)
    assert b136.validate_diagnostic_snapshot(payload) == ()
    assert payload["raw_paths_included"] is False
    assert payload["command_lines_included"] is False
    assert payload["usernames_included"] is False
    assert payload["license_token_included"] is False
    assert payload["license_id_included"] is False
    assert payload["file_contents_included"] is False


def test_explicit_diagnostic_export_contains_no_token_or_identifier(tmp_path: Path) -> None:
    target = tmp_path / "diagnostics.json"
    state = b136.CommercialState(
        status=b136.LICENSED,
        mode="LICENSE",
        protection_enabled=True,
        entitlement_verified=True,
    )
    report = b136.export_diagnostics(target, commercial_state=state)
    assert report["exported"] is True
    assert len(report["sha256"]) == 64
    raw = target.read_text(encoding="utf-8")
    payload = json.loads(raw)
    assert payload["commercial_status"] == b136.LICENSED
    assert payload["license_token_included"] is False
    assert payload["license_id_included"] is False
    assert "fixture-license" not in raw


def test_commercial_ui_is_responsive_and_non_destructive() -> None:
    snapshot = b128.build_product_snapshot()
    assert snapshot["passed"] is True
    report = ui.smoke_test_window(snapshot)
    assert report["passed"] is True
    assert report["page_count"] == 9
    assert report["commercial_selected"] is True
    assert report["policy_card_count"] == 3
    assert report["diagnostic_export_button_enabled"] is True
    assert report["diagnostic_export_callback_count"] == 1
    assert report["core_protection_enabled"] is True
    assert report["automatic_quarantine"] is False
    assert report["licensing_may_disable_core_protection"] is False
    assert report["destructive_ui_action"] is False
    assert all(value == 0 for value in report["horizontal_overflow"].values())


def test_b136_does_not_expand_authority_network_or_cloud() -> None:
    report = b136.self_check()
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False
    assert report["expired_trial_keeps_protection"] is True
    assert report["activation_unavailable_keeps_protection"] is True
