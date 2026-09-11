from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from sentinel.rescue_contract import (
    MAX_INFLIGHT_HARD_LIMIT,
    MAX_WORKERS_HARD_LIMIT,
    PROFILE,
    RescueAuditRecord,
    RescueCapability,
    RescueExecutionContext,
    RescueSafetyPolicy,
    RescueSessionManifest,
    RescueStage,
    allowed_capabilities,
    can_certify_recovery,
    rr0_contract_snapshot,
)


def test_default_rr0_policy_is_read_only_and_non_destructive():
    policy = RescueSafetyPolicy()
    policy.validate()
    assert policy.read_only_default is True
    assert policy.allow_destructive_actions is False
    assert policy.allow_file_delete is False
    assert policy.allow_process_kill is False
    assert policy.allow_host_isolation is False
    assert policy.allow_registry_write is False
    assert policy.allow_boot_write is False
    assert policy.allow_filesystem_write is False
    assert policy.allow_recovery_certification is False


@pytest.mark.parametrize(
    "kwargs",
    [
        {"read_only_default": False},
        {"allow_destructive_actions": True},
        {"allow_file_delete": True},
        {"allow_process_kill": True},
        {"allow_host_isolation": True},
        {"allow_registry_write": True},
        {"allow_boot_write": True},
        {"allow_filesystem_write": True},
        {"allow_recovery_certification": True},
        {"require_operator_confirmation_for_future_mutation": False},
        {"require_rollback_plan_for_future_mutation": False},
        {"require_provenance_for_future_mutation": False},
    ],
)
def test_rr0_rejects_unsafe_policy_variants(kwargs):
    with pytest.raises(ValueError, match="RR0 unsafe policy"):
        RescueSafetyPolicy(**kwargs).validate()


def test_rr0_requires_sha256_evidence_hashing():
    with pytest.raises(ValueError, match="sha256"):
        RescueSafetyPolicy(evidence_hash_algorithm="md5").validate()


def test_rr0_concurrency_is_bounded():
    RescueSafetyPolicy(max_workers=MAX_WORKERS_HARD_LIMIT).validate()
    RescueSafetyPolicy(max_inflight_items=MAX_INFLIGHT_HARD_LIMIT).validate()
    with pytest.raises(ValueError, match="max_workers"):
        RescueSafetyPolicy(max_workers=MAX_WORKERS_HARD_LIMIT + 1).validate()
    with pytest.raises(ValueError, match="max_inflight"):
        RescueSafetyPolicy(max_inflight_items=MAX_INFLIGHT_HARD_LIMIT + 1).validate()


def test_compromised_windows_cannot_plan_mutation():
    capabilities = allowed_capabilities(RescueExecutionContext.COMPROMISED_WINDOWS)
    assert RescueCapability.PLAN_QUARANTINE not in capabilities
    assert RescueCapability.PLAN_REPAIR not in capabilities
    assert RescueCapability.ACQUIRE_EVIDENCE in capabilities
    assert RescueCapability.INSPECT_FILESYSTEM in capabilities


def test_trusted_or_offline_context_may_only_plan_future_repair():
    for context in (
        RescueExecutionContext.TRUSTED_EXTERNAL_MEDIA,
        RescueExecutionContext.OFFLINE_IMAGE,
    ):
        capabilities = allowed_capabilities(context)
        assert RescueCapability.PLAN_QUARANTINE in capabilities
        assert RescueCapability.PLAN_REPAIR in capabilities
        assert all("delete" not in capability.value for capability in capabilities)
        assert all("write" not in capability.value for capability in capabilities)
        assert all("execute_repair" not in capability.value for capability in capabilities)


def test_rr0_never_certifies_recovery():
    assert all(can_certify_recovery(context) is False for context in RescueExecutionContext)


def test_session_manifest_is_immutable_and_write_disabled():
    manifest = RescueSessionManifest(
        session_id="rr0-session-1",
        correlation_id="rr0-corr-1",
        execution_context=RescueExecutionContext.COMPROMISED_WINDOWS,
        target_fingerprint="sha256:abc",
        created_utc="2026-09-11T12:00:00+02:00",
    )
    assert manifest.write_authorized is False
    assert manifest.recovery_certification_available is False
    with pytest.raises(FrozenInstanceError):
        manifest.write_authorized = True  # type: ignore[misc]


def test_session_manifest_rejects_write_or_certification_flags():
    base = dict(
        session_id="rr0-session-1",
        correlation_id="rr0-corr-1",
        execution_context=RescueExecutionContext.OFFLINE_IMAGE,
        target_fingerprint="sha256:abc",
        created_utc="2026-09-11T12:00:00+02:00",
    )
    with pytest.raises(ValueError, match="authorize writes"):
        RescueSessionManifest(**base, write_authorized=True)
    with pytest.raises(ValueError, match="certify recovery"):
        RescueSessionManifest(**base, recovery_certification_available=True)


def test_audit_record_requires_exact_failure_reason_and_correlation():
    record = RescueAuditRecord(
        session_id="rr0-session-1",
        correlation_id="rr0-corr-1",
        stage=RescueStage.TRUST_ASSESSMENT,
        component="rr0.contract",
        status="denied",
        reason="host_context_untrusted",
        target="disk0",
        duration_ms=1.25,
    )
    payload = record.to_record()
    for field in ("session_id", "correlation_id", "stage", "component", "status", "reason"):
        assert payload[field]
    assert payload["stage"] == "trust_assessment"


def test_rr0_snapshot_is_machine_readable_and_safe():
    snapshot = rr0_contract_snapshot()
    assert snapshot["profile"] == PROFILE
    assert snapshot["read_only_default"] is True
    assert snapshot["destructive_actions_enabled"] is False
    assert snapshot["recovery_certification_enabled"] is False
    assert snapshot["evidence_hash_algorithm"] == "sha256"
    assert set(snapshot["contexts"]) == {context.value for context in RescueExecutionContext}
