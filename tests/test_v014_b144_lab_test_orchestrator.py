from __future__ import annotations

from sentinel import beta14_lab_test_orchestrator as b144


def test_b144_binds_exact_b143_checkpoint() -> None:
    report = b144.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b143-pass"
    assert report["source_checkpoint_commit"] == "b807797b35e40dc34235c569e4f56b099824bca5"


def test_b144_defines_all_six_test_tiers() -> None:
    report = b144.self_check()
    assert report["tier_count"] == 6
    assert report["plan_count"] == 6
    assert report["real_sample_tiers"] == [b144.T2, b144.T3]
    assert report["dynamic_real_sample_tiers"] == [b144.T3]


def test_b144_full_campaign_requires_b143_importer_for_every_tier() -> None:
    campaign = b144.full_validation_campaign()
    assert campaign["passed"] is True
    assert campaign["evidence_importer_required_for_all"] is True
    assert all(plan["evidence_importer_required"] is True for plan in campaign["plans"])


def test_b144_real_sample_tiers_require_authorization_and_isolation() -> None:
    for tier in (b144.T2, b144.T3):
        plan = b144.make_plan(
            campaign_id=f"auth-{tier}",
            tier=tier,
            engine_commit=b144.SOURCE_CHECKPOINT_COMMIT,
            engine_checkpoint=b144.SOURCE_CHECKPOINT,
            rule_version="rules-test",
            network_mode=b144.NETWORK_NONE,
            lab_profile="isolated-lab",
            sample_authorized=False,
            isolated_disposable_lab=False,
        )
        failures = b144.validate_plan(plan)
        assert "b144:sample_authorization_required" in failures
        assert "b144:isolated_disposable_lab_required" in failures


def test_b144_dynamic_real_sample_tier_accepts_only_isolated_network_modes() -> None:
    for network_mode in (b144.NETWORK_NONE, b144.NETWORK_FAKE, b144.NETWORK_INETSIM):
        plan = b144.make_plan(
            campaign_id=f"dynamic-{network_mode.lower()}",
            tier=b144.T3,
            engine_commit=b144.SOURCE_CHECKPOINT_COMMIT,
            engine_checkpoint=b144.SOURCE_CHECKPOINT,
            rule_version="rules-test",
            network_mode=network_mode,
            lab_profile="isolated-dynamic-lab",
            sample_authorized=True,
            isolated_disposable_lab=True,
        )
        assert b144.validate_plan(plan) == ()


def test_b144_dynamic_direct_internet_is_rejected() -> None:
    plan = b144.make_plan(
        campaign_id="dynamic-direct-internet",
        tier=b144.T3,
        engine_commit=b144.SOURCE_CHECKPOINT_COMMIT,
        engine_checkpoint=b144.SOURCE_CHECKPOINT,
        rule_version="rules-test",
        network_mode=b144.NETWORK_INETSIM,
        lab_profile="isolated-dynamic-lab",
        sample_authorized=True,
        isolated_disposable_lab=True,
    )
    plan["network_mode"] = "DIRECT_INTERNET"
    assert "b144:network_mode_invalid" in b144.validate_plan(plan)


def test_b144_static_real_sample_tier_never_executes_sample() -> None:
    plan = b144.make_plan(
        campaign_id="static-real-sample",
        tier=b144.T2,
        engine_commit=b144.SOURCE_CHECKPOINT_COMMIT,
        engine_checkpoint=b144.SOURCE_CHECKPOINT,
        rule_version="rules-test",
        network_mode=b144.NETWORK_NONE,
        lab_profile="isolated-static-lab",
        sample_authorized=True,
        isolated_disposable_lab=True,
    )
    assert b144.validate_plan(plan) == ()
    assert plan["real_sample"] is True
    assert plan["real_sample_execution"] is False
    assert plan["orchestrator_executes_workload"] is False


def test_b144_safe_and_benign_tiers_never_become_real_sample_tiers() -> None:
    for tier in (b144.T0, b144.T1, b144.T4, b144.T5):
        spec = b144.TIER_BY_ID[tier]
        assert spec["real_sample"] is False
        assert spec["real_sample_execution"] is False


def test_b144_non_dynamic_tiers_are_network_free() -> None:
    for tier in (b144.T0, b144.T1, b144.T2, b144.T4, b144.T5):
        spec = b144.TIER_BY_ID[tier]
        assert tuple(spec["allowed_network_modes"]) == (b144.NETWORK_NONE,)


def test_b144_orchestrator_has_no_sample_or_network_authority() -> None:
    report = b144.self_check()
    assert report["orchestrator_executes_samples"] is False
    assert report["orchestrator_downloads_samples"] is False
    assert report["orchestrator_stores_samples"] is False
    assert report["orchestrator_transfers_samples"] is False
    assert report["orchestrator_unpacks_samples"] is False
    assert report["orchestrator_opens_network_connections"] is False


def test_b144_campaign_does_not_promote_coverage_or_authority() -> None:
    campaign = b144.full_validation_campaign()
    assert campaign["coverage_promoted"] is False
    assert campaign["authority_expanded"] is False
    assert campaign["orchestrator_executes_workload"] is False


def test_b144_preserves_canonical_coverage() -> None:
    report = b144.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_b144_campaign_plan_digest_is_deterministic() -> None:
    first = b144.full_validation_campaign()
    second = b144.full_validation_campaign()
    assert first["campaign_digest"] == second["campaign_digest"]


def test_b144_contract_is_deterministic() -> None:
    first = b144.self_check()
    second = b144.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]
