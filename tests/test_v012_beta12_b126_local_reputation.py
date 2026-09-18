from __future__ import annotations

from copy import deepcopy
import json

import pytest

from sentinel import beta12_local_reputation as b126


def _entry() -> dict:
    return {
        "entry_id": "b126-known-good-1",
        "sha256": "a" * 64,
        "signer_subject_digest": "b" * 64,
        "source": "EXPLICIT_EPHEMERAL_ACCEPTANCE_ALLOWLIST",
    }


def _control(
    control_id: str,
    sha256: str,
    signer_state: str,
    signer_subject_digest: str | None,
    *,
    hit: bool,
    entry_id: str | None,
) -> dict:
    return {
        "control_id": control_id,
        "live_observation": True,
        "sha256": sha256,
        "path_digest": ("c" if control_id == "known-good-signed-allowlisted" else "d" if control_id == "signed-unknown" else "e") * 64,
        "signer_state": signer_state,
        "signer_subject_digest": signer_subject_digest,
        "local_allowlist_hit": hit,
        "allowlist_entry_id": entry_id,
        "file_executed": False,
    }


def _evidence() -> dict:
    entry = _entry()
    return {
        "schema": b126.SCHEMA,
        "source": b126.SOURCE,
        "allowlist": [entry],
        "controls": [
            _control(
                "known-good-signed-allowlisted",
                entry["sha256"],
                "SIGNED_VERIFIED",
                entry["signer_subject_digest"],
                hit=True,
                entry_id=entry["entry_id"],
            ),
            _control(
                "signed-unknown",
                "f" * 64,
                "SIGNED_VERIFIED",
                "1" * 64,
                hit=False,
                entry_id=None,
            ),
            _control(
                "unsigned-unknown",
                "2" * 64,
                "UNSIGNED",
                None,
                hit=False,
                entry_id=None,
            ),
        ],
        "boundaries": dict(b126.BOUNDARIES),
    }


def test_self_check_binds_exact_b125_checkpoint():
    report = b126.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b125-pass"
    assert report["source_checkpoint_commit"] == "04dfef15f5cb5583fd49b878efc9de663e74cdcb"
    assert report["target_scenario_id"] == "B12-LOCAL-REPUTATION-001"


def test_three_local_reputation_outcomes_are_distinct():
    report = b126.summarize(_evidence())
    outcomes = {key: value["outcome"] for key, value in report["control_results"].items()}
    assert outcomes == {
        "known-good-signed-allowlisted": "TRUSTED_LOCAL",
        "signed-unknown": "UNKNOWN_SIGNED",
        "unsigned-unknown": "UNKNOWN_UNSIGNED",
    }
    assert report["passed"] is True


def test_allowlist_requires_hash_and_signer_match():
    data = _evidence()
    row = data["controls"][0]
    result = b126.classify(row, data["allowlist"])
    assert result == {
        "outcome": "TRUSTED_LOCAL",
        "reasons": ["LOCAL_HASH_MATCH", "VERIFIED_SIGNER_MATCH"],
        "allowlist_match": "b126-known-good-1",
    }


def test_signed_unknown_is_not_implicitly_trusted():
    data = _evidence()
    result = b126.classify(data["controls"][1], data["allowlist"])
    assert result["outcome"] == "UNKNOWN_SIGNED"
    assert result["allowlist_match"] is None


def test_unsigned_unknown_is_not_called_malicious():
    data = _evidence()
    result = b126.classify(data["controls"][2], data["allowlist"])
    assert result["outcome"] == "UNKNOWN_UNSIGNED"
    report = b126.summarize(data)
    assert report["maliciousness_verdict_claimed"] is False


def test_b126_earns_seventh_verified_scenario():
    report = b126.summarize(_evidence())
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
        "B12-AUTOSTART-LINK-001",
        "B12-PROCESS-TREE-001",
        "B12-RANSOMWARE-PROCESS-001",
        "B12-LOCAL-REPUTATION-001",
    ]


def test_graph_and_incident_binding_pass():
    report = b126.summarize(_evidence())
    assert report["local_reputation_to_graph_bound"] is True
    assert report["security_graph_to_incident_bound"] is True
    assert len(report["graph_digest"]) == 64
    assert len(report["correlation_digest"]) == 64


def test_trust_mutation_network_and_authority_remain_disabled():
    report = b126.summarize(_evidence())
    assert report["trust_allowlist_mutated"] is False
    assert report["authority_expanded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False
    assert report["boundaries"]["trust_allowlist_mutation"] is False
    assert report["boundaries"]["file_execution"] is False


def test_known_good_hash_mismatch_fails_closed():
    data = _evidence()
    data["controls"][0]["sha256"] = "9" * 64
    report = b126.summarize(data)
    assert report["passed"] is False
    assert "b126:known_good_hash_binding_invalid" in report["failures"]


def test_known_good_signer_mismatch_fails_closed():
    data = _evidence()
    data["controls"][0]["signer_subject_digest"] = "8" * 64
    report = b126.summarize(data)
    assert report["passed"] is False
    assert "b126:known_good_signer_binding_invalid" in report["failures"]


def test_signed_unknown_cannot_claim_allowlist_hit():
    data = _evidence()
    data["controls"][1]["local_allowlist_hit"] = True
    report = b126.summarize(data)
    assert report["passed"] is False
    assert "b126:signed_unknown_must_not_hit" in report["failures"]


@pytest.mark.parametrize("field", ["raw_path", "file_content", "username", "command_line", "token"])
def test_sensitive_extra_fields_fail_closed_without_echo(field):
    data = _evidence()
    data["controls"][0][field] = "PRIVATE_B126_VALUE"
    report = b126.summarize(data)
    assert report["passed"] is False
    assert "PRIVATE_B126_VALUE" not in json.dumps(report)


def test_file_execution_flag_fails_closed():
    data = _evidence()
    data["controls"][0]["file_executed"] = True
    report = b126.summarize(data)
    assert report["passed"] is False
    assert any("file_execution_forbidden" in failure for failure in report["failures"])


def test_boundary_flip_fails_closed():
    data = _evidence()
    data["boundaries"]["network_io"] = True
    report = b126.summarize(data)
    assert report["passed"] is False
    assert "b126:boundary_invalid" in report["failures"]


def test_deterministic_summary():
    assert b126.summarize(_evidence()) == b126.summarize(deepcopy(_evidence()))


@pytest.mark.parametrize("bad", [None, [], "raw", 1, True, {}])
def test_malformed_top_level_fails_closed(bad):
    assert b126.summarize(bad)["passed"] is False
