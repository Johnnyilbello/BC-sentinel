from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tools.v011_beta2_b2_live_acceptance import (
    EXPECTED_CLIENT_SHA256,
    EXPECTED_PROTOCOL_SHA256,
    EXPECTED_SERVICE_SHA256,
    _call_generic,
    _find_incident,
    _raw_sha,
    _sha,
)


def test_b2_is_anchored_to_accepted_b1b_full_hashes():
    assert EXPECTED_PROTOCOL_SHA256 == "2e39ec0422f820e107832b3ba20c62c103ea15cc99639159ea2ec1be211505b1"
    assert EXPECTED_SERVICE_SHA256 == "d5395dc2bb086941796703910143a0598e8fd4da36e53c19e2a910030498fe46"
    assert EXPECTED_CLIENT_SHA256 == "6910eb42f6e7c5ba4d87b1f1533dfacff99483fbf4ffb06810595effa66cc9d1"


def test_b2_sha_guard_uses_same_normalized_text_semantics_as_b1b(tmp_path: Path):
    path = tmp_path / "guard.py"
    path.write_bytes(b"alpha\r\nbeta\r\n")
    expected = hashlib.sha256("alpha\nbeta\n".encode("utf-8")).hexdigest()
    assert _sha(path) == expected
    assert _raw_sha(path) != expected


def test_generic_client_binding_uses_named_parameters_without_shifting_defaults():
    calls = []

    def request(operation, token="default-token", payload=None):
        calls.append((operation, token, payload))
        return {"ok": True}

    result = _call_generic(request, "edr_status", {"limit": 10})
    assert result == {"ok": True}
    assert calls == [("edr_status", "default-token", {"limit": 10})]


def test_generic_client_binding_expands_var_keyword_payload_without_nesting():
    calls = []

    def request(operation, token="default-token", **payload):
        calls.append((operation, token, payload))
        return {"ok": True}

    assert _call_generic(request, "edr_status", {}) == {"ok": True}
    assert calls[-1] == ("edr_status", "default-token", {})

    hunt_payload = {"indicator": "example.test", "kind": "domain", "limit": 20}
    assert _call_generic(request, "edr_hunt", hunt_payload) == {"ok": True}
    assert calls[-1] == ("edr_hunt", "default-token", hunt_payload)
    assert "payload" not in calls[-1][2]


def test_generic_client_binding_rejects_unmodelled_required_parameter():
    def request(operation, required_secret, payload=None):
        return {"ok": True}

    with pytest.raises(RuntimeError, match="unsupported required client parameter"):
        _call_generic(request, "edr_status", {})


def test_generic_client_binding_requires_payload_surface_when_payload_is_nonempty():
    def request(operation):
        return {"ok": True}

    with pytest.raises(RuntimeError, match="no payload parameter"):
        _call_generic(request, "edr_hunt", {"indicator": "example.test"})


def test_recursive_security_center_lookup_is_exact():
    target = "BCEDR-0123456789ABCDEF0123"
    payload = {"ok": True, "items": [{"incident_id": "BCEDR-AAAAAAAAAAAAAAAAAAAA"}, {"nested": {"incident_id": target}}]}
    assert _find_incident(payload, target) is True
    assert _find_incident(payload, "BCEDR-BBBBBBBBBBBBBBBBBBBB") is False


def test_b2_live_acceptance_contains_no_destructive_response_primitives():
    source = Path("tools/v011_beta2_b2_live_acceptance.py").read_text(encoding="utf-8")
    forbidden = ("TerminateProcess(", "os.remove(", "shutil.rmtree(", "firewall_block_remote", "host_isolation = True")
    assert not any(token in source for token in forbidden)


def test_b2_reapplies_frozen_beta1_compatibility_migrations_before_pytest():
    source = Path("TEST-V011-BETA2-CHECKPOINT-B2.ps1").read_text(encoding="utf-8")
    migrations = (
        "tools.v011_legacy_test_compat",
        "tools.v011_threat_package_windows_compat",
        "tools.v011_threat_index_windows_compat",
        "tools.v011_threat_trust_windows_compat",
        "tools.v011_service_update_windows_compat",
        "tools.v011_low_cpu_runtime_compat",
    )
    pytest_index = source.index("& $Py -m pytest -q --basetemp $PytestTemp")
    for migration in migrations:
        assert migration in source
        assert source.index(migration) < pytest_index
    assert "Compatibility migration failed before B2 pytest" in source
    assert "Enforced 25/10/250 service-performance result missing or failed in B2" in source


def test_b2_admin_harness_preserves_beta1_detail_and_isolates_pytest_temp():
    source = Path("TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1").read_text(encoding="utf-8")
    assert "PYTEST_ADDOPTS" in source
    assert "bc-sentinel-v011-beta2-b2-admin-" in source
    assert "acceptance-v011-beta2-b2-beta1-admin.stdout.log" in source
    assert "acceptance-v011-beta2-b2-beta1-admin.stderr.log" in source
    assert "-RedirectStandardOutput $Beta1StdoutPath" in source
    assert "-RedirectStandardError $Beta1StderrPath" in source
    assert "Start-Process -FilePath 'powershell.exe'" in source
    assert "Frozen Beta1 administrator gate failed at stage" in source
    assert "Read-LogTail" in source
    assert "*>&1 |" not in source
    assert "--max-idle-cpu-percent 25" not in source


def test_b2_admin_forces_utf8_only_for_child_acceptance_tree():
    source = Path("TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1").read_text(encoding="utf-8")
    assert "$env:PYTHONUTF8 = '1'" in source
    assert "$env:PYTHONIOENCODING = 'utf-8'" in source
    assert "$PreviousPythonUtf8 = $env:PYTHONUTF8" in source
    assert "$PreviousPythonIoEncoding = $env:PYTHONIOENCODING" in source
    assert "Remove-Item Env:PYTHONUTF8" in source
    assert "Remove-Item Env:PYTHONIOENCODING" in source
    assert "Get-Content -LiteralPath $Path -Encoding UTF8" in source


def test_b2_full_admin_synchronizes_runtime_before_live_edr():
    source = Path("TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1").read_text(encoding="utf-8")
    sync_index = source.index("$script:CurrentStage = 'runtime_sync_restart'")
    pre_index = source.index("$script:CurrentStage = 'b2_live_pre_restart'")
    persistence_index = source.index("$script:CurrentStage = 'service_restart'")
    assert sync_index < pre_index < persistence_index
    assert "runtime image freshness is unproven" in source
    assert "runtime_sync_readiness" in source
    assert source.count("Restart-ProtectionService") >= 3


def test_b2_resume_requires_pre_admin_evidence_and_finishes_standard_user_gates():
    source = Path("RETEST-V011-BETA2-B2-FROM-ADMIN.ps1").read_text(encoding="utf-8")
    assert "acceptance-v011-beta2-b2-edr-local.json" in source
    assert "acceptance-v011-beta2-b2-rc1-local.json" in source
    assert "v011_beta2_b1b_patch --verify-only" in source
    assert "tools.broker_acceptance" in source
    assert "--mode standard-user" in source
    assert "benchmark-v011-beta1-service.json" in source
    assert "does not replace the preceding 656-test/build evidence" in source
    assert "v011_beta2_b2_live_acceptance.py" in source
    assert "$LiveAcceptanceUrl" in source
    assert "Invoke-WebRequest -Uri $LiveAcceptanceUrl -OutFile $LiveAcceptance" in source


def test_b2_live_only_resume_reuses_only_verified_prior_evidence():
    source = Path("RETEST-V011-BETA2-B2-LIVE-ONLY.ps1").read_text(encoding="utf-8")
    assert "acceptance-v011-beta1-admin-phase-result.json" in source
    assert "benchmark-v011-beta1-service.json" in source
    assert "acceptance-v011-beta2-b2-edr-local.json" in source
    assert "v011_beta2_b1b_patch --verify-only" in source
    assert "TEST-V011-BETA2-CHECKPOINT-B2-LIVE-ADMIN.ps1" in source
    assert "tools.v011_beta2_b2_live_acceptance --mode standard-user" in source
    assert "tools.broker_acceptance" in source
    assert "B2 LIVE-ONLY RESUME - PASS" in source
    assert "UPDATE-TEST-V011-BETA2-CHECKPOINT-B2" not in source
    assert "$ContractTest = Join-Path $PSScriptRoot 'tests\\test_v011_beta2_b2_contract.py'" in source
    assert "$FullAdminScript = Join-Path $PSScriptRoot 'TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1'" in source
    assert "$FromAdminResume = Join-Path $PSScriptRoot 'RETEST-V011-BETA2-B2-FROM-ADMIN.ps1'" in source
    assert "-OutFile $ContractTest" in source
    assert "--basetemp $ContractPytestTemp" in source
    assert "bc-sentinel-v011-beta2-b2-live-contract-" in source
    assert "Remove-Item -LiteralPath $ContractPytestTemp -Recurse -Force" in source


def test_b2_live_only_admin_synchronizes_runtime_then_tests_persistence_restart():
    source = Path("TEST-V011-BETA2-CHECKPOINT-B2-LIVE-ADMIN.ps1").read_text(encoding="utf-8")
    assert "acceptance-v011-beta1-admin-phase-result.json" in source
    assert "benchmark-v011-beta1-service.json" in source
    sync_index = source.index("$script:CurrentStage = 'runtime_sync_restart'")
    pre_index = source.index("$script:CurrentStage = 'b2_live_pre_restart'")
    persistence_index = source.index("$script:CurrentStage = 'service_restart'")
    post_index = source.index("$script:CurrentStage = 'b2_live_post_restart'")
    assert sync_index < pre_index < persistence_index < post_index
    assert source.count("Restart-ProtectionService") >= 3
    assert "runtime image freshness is unproven" in source
    assert "runtime_sync_readiness" in source
    assert "--mode pre-restart" in source
    assert "--mode post-restart" in source
    assert "B2 pre-restart live acceptance failed:" in source
    assert "B2 post-restart live acceptance failed:" in source
    assert "B2 LIVE-ONLY ADMIN GATE PASS" in source


def test_b2_live_only_probes_frozen_b1b_code_before_uac():
    launcher = Path("RETEST-V011-BETA2-B2-LIVE-ONLY.ps1").read_text(encoding="utf-8")
    probe = Path("tools/v011_beta2_b2_frozen_runtime_probe.py").read_text(encoding="utf-8")
    assert "v011_beta2_b2_frozen_runtime_probe.py" in launcher
    assert "tools.v011_beta2_b2_frozen_runtime_probe" in launcher
    assert "Frozen Protection Service B1b probe failed before UAC" in launcher
    assert launcher.index("tools.v011_beta2_b2_frozen_runtime_probe") < launcher.index("Opening B2 live-only UAC phase")
    assert "protocol_has_edr_status_literal" in probe
    assert "service_has_legacy_dispatch" in probe
    assert "service_has_b1b_dispatch" in probe
    assert "service_references_dispatch_read" in probe
    assert "frozen_b1b_protocol_and_service_present" in probe
