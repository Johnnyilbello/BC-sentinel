from copy import deepcopy
import json

import pytest

from sentinel import beta9_event_metadata as metadata


@pytest.fixture
def document():
    return {
        "schema": metadata.SCHEMA,
        "source": metadata.SOURCE,
        "profiles": [
            {
                "profile_id": profile["profile_id"],
                "channel": profile["channel"],
                "provider": profile["provider"],
                "event_ids": list(profile["event_ids"]),
                "max_events": 4,
                "timeout_seconds": 5,
                "status": "EMPTY",
                "events": [],
            }
            for profile in metadata.PROFILES
        ],
        "boundaries": dict(metadata.BOUNDARIES),
    }


def _event(profile):
    return {
        "channel": profile["channel"],
        "provider": profile["provider"],
        "event_id": profile["event_ids"][0],
        "level": 4,
        "record_id": 42,
        "time_created_utc": "2026-09-16T11:00:00+00:00",
    }


def test_empty_query_is_real_readability_without_detector_verification(document):
    result = metadata.summarize(document)
    assert result["passed"]
    assert result["event_readability_tested"] is True
    assert result["readable_profile_count"] == len(metadata.PROFILES)
    assert result["total_event_count"] == 0
    assert result["detector_verification_performed"] is False
    assert result["threat_classification_performed"] is False
    assert result["coverage_summary"] == {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0}


def test_allowlisted_event_metadata_is_accepted(document):
    row = document["profiles"][0]
    row["status"] = "OK"
    row["events"] = [_event(metadata.PROFILES[0])]
    result = metadata.summarize(document)
    assert result["passed"]
    assert result["total_event_count"] == 1


def test_identical_input_has_deterministic_digest(document):
    assert metadata.summarize(document) == metadata.summarize(deepcopy(document))


@pytest.mark.parametrize("value", [None, [], "raw", 1, {}])
def test_malformed_root_fails_closed(value):
    result = metadata.summarize(value)
    assert result["passed"] is False


@pytest.mark.parametrize("field", list(metadata.BOUNDARIES))
def test_boundary_expansion_is_rejected(document, field):
    document["boundaries"][field] = not document["boundaries"][field]
    assert metadata.summarize(document)["passed"] is False


@pytest.mark.parametrize(
    "field",
    ["message", "properties", "username", "user_id", "machine_name", "command_line", "script", "path", "xml", "payload"],
)
def test_forbidden_or_unexpected_event_fields_are_rejected_without_echo(document, field):
    marker = "PRIVATE_SENTINEL_VALUE"
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event[field] = marker
    row["events"] = [event]
    result = metadata.summarize(document)
    assert result["passed"] is False
    assert marker not in json.dumps(result)


@pytest.mark.parametrize("status", sorted(metadata.STATUSES - {"OK"}))
def test_non_ok_states_must_not_carry_events(document, status):
    row = document["profiles"][0]
    row["status"] = status
    row["events"] = [_event(metadata.PROFILES[0])]
    assert metadata.summarize(document)["passed"] is False


def test_ok_requires_at_least_one_event(document):
    document["profiles"][0]["status"] = "OK"
    assert metadata.summarize(document)["passed"] is False


@pytest.mark.parametrize("status", ["ACCESS_DENIED", "UNSUPPORTED", "TIMEOUT", "ERROR"])
def test_unavailable_profiles_remain_explicit_and_do_not_block_other_readability(document, status):
    document["profiles"][0]["status"] = status
    result = metadata.summarize(document)
    assert result["passed"]
    assert result["readable_profile_count"] == len(metadata.PROFILES) - 1
    assert result["profile_statuses"][0]["status"] == status


def test_no_completed_query_means_readability_not_tested(document):
    for row in document["profiles"]:
        row["status"] = "UNSUPPORTED"
    result = metadata.summarize(document)
    assert result["passed"]
    assert result["event_readability_tested"] is False


@pytest.mark.parametrize("value", [0, 9, -1, True, "4"])
def test_max_events_is_strictly_bounded(document, value):
    document["profiles"][0]["max_events"] = value
    assert metadata.summarize(document)["passed"] is False


@pytest.mark.parametrize("value", [0, 11, -1, True, "5"])
def test_timeout_is_strictly_bounded(document, value):
    document["profiles"][0]["timeout_seconds"] = value
    assert metadata.summarize(document)["passed"] is False


def test_event_count_cannot_exceed_requested_bound(document):
    row = document["profiles"][0]
    row["max_events"] = 1
    row["status"] = "OK"
    row["events"] = [_event(metadata.PROFILES[0]), _event(metadata.PROFILES[0])]
    assert metadata.summarize(document)["passed"] is False


def test_profile_order_and_identity_are_fixed(document):
    document["profiles"][0], document["profiles"][1] = document["profiles"][1], document["profiles"][0]
    assert metadata.summarize(document)["passed"] is False


def test_event_channel_must_match_profile(document):
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event["channel"] = "Security"
    row["events"] = [event]
    assert metadata.summarize(document)["passed"] is False


def test_event_provider_must_match_profile(document):
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event["provider"] = "Other-Provider"
    row["events"] = [event]
    assert metadata.summarize(document)["passed"] is False


def test_event_id_must_be_allowlisted(document):
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event["event_id"] = 999999
    row["events"] = [event]
    assert metadata.summarize(document)["passed"] is False


@pytest.mark.parametrize("value", [True, "12", -1])
def test_event_id_rejects_invalid_types_and_values(document, value):
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event["event_id"] = value
    row["events"] = [event]
    assert metadata.summarize(document)["passed"] is False


@pytest.mark.parametrize("value", [True, -1, 256, "4"])
def test_level_is_bounded_integer_or_null(document, value):
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event["level"] = value
    row["events"] = [event]
    assert metadata.summarize(document)["passed"] is False


def test_null_level_is_allowed(document):
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event["level"] = None
    row["events"] = [event]
    assert metadata.summarize(document)["passed"] is True


@pytest.mark.parametrize("value", [True, -1, "42"])
def test_record_id_is_nonnegative_integer_or_null(document, value):
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event["record_id"] = value
    row["events"] = [event]
    assert metadata.summarize(document)["passed"] is False


@pytest.mark.parametrize("value", [None, "", "not-a-time", "2026-09-16T11:00:00"])
def test_timestamp_requires_timezone(document, value):
    row = document["profiles"][0]
    row["status"] = "OK"
    event = _event(metadata.PROFILES[0])
    event["time_created_utc"] = value
    row["events"] = [event]
    assert metadata.summarize(document)["passed"] is False


def test_profile_event_id_allowlist_cannot_be_widened(document):
    document["profiles"][0]["event_ids"].append(999999)
    assert metadata.summarize(document)["passed"] is False


def test_profile_extra_field_is_rejected_without_disclosure(document):
    document["profiles"][0]["raw_error"] = "PRIVATE_SENTINEL_VALUE"
    result = metadata.summarize(document)
    assert result["passed"] is False
    assert "PRIVATE_SENTINEL_VALUE" not in json.dumps(result)
