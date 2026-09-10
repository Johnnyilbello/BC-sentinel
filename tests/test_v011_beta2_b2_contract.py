from __future__ import annotations

from pathlib import Path

import pytest

from tools.v011_beta2_b2_live_acceptance import (
    EXPECTED_CLIENT_SHA256,
    EXPECTED_PROTOCOL_SHA256,
    EXPECTED_SERVICE_SHA256,
    _call_generic,
    _find_incident,
)


def test_b2_is_anchored_to_accepted_b1b_full_hashes():
    assert EXPECTED_PROTOCOL_SHA256 == "2e39ec0422f820e107832b3ba20c62c103ea15cc99639159ea2ec1be211505b1"
    assert EXPECTED_SERVICE_SHA256 == "d5395dc2bb086941796703910143a0598e8fd4da36e53c19e2a910030498fe46"
    assert EXPECTED_CLIENT_SHA256 == "6910eb42f6e7c5ba4d87b1f1533dfacff99483fbf4ffb06810595effa66cc9d1"


def test_generic_client_binding_uses_named_parameters_without_shifting_defaults():
    calls = []

    def request(operation, token="default-token", payload=None):
        calls.append((operation, token, payload))
        return {"ok": True}

    result = _call_generic(request, "edr_status", {"limit": 10})
    assert result == {"ok": True}
    assert calls == [("edr_status", "default-token", {"limit": 10})]


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
