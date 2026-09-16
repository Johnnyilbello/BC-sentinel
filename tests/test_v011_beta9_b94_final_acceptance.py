from copy import deepcopy

from sentinel import beta9_event_metadata as b91
from sentinel import beta9_event_to_incident as b92
from sentinel import beta9_final_acceptance as final
from sentinel import beta9_ransomware_controls as b93
from sentinel import beta9_telemetry_foundation as b90


def inventory():
    states = [
        ("System", "AVAILABLE", True),
        ("Microsoft-Windows-PowerShell/Operational", "AVAILABLE", True),
        ("Microsoft-Windows-Windows Defender/Operational", "AVAILABLE", True),
        ("Microsoft-Windows-Sysmon/Operational", "MISSING", None),
        ("Security", "ACCESS_DENIED", None),
    ]
    return {"schema": b90.SCHEMA, "source": "WINDOWS_CHANNEL_CONFIGURATION",
            "channels": [{"channel": c, "state": s, "enabled": e} for c, s, e in states],
            "boundaries": dict(b90.BOUNDARIES)}


def metadata():
    status = {"system-kernel-general": "EMPTY", "powershell-operational": "EMPTY",
              "defender-operational": "EMPTY", "sysmon-operational": "UNSUPPORTED",
              "security-auditing": "ACCESS_DENIED"}
    rows = []
    for p in b91.PROFILES:
        rows.append({"profile_id": p["profile_id"], "channel": p["channel"], "provider": p["provider"],
                     "event_ids": list(p["event_ids"]), "max_events": 4, "timeout_seconds": 5,
                     "status": status[p["profile_id"]], "events": []})
    return {"schema": b91.SCHEMA, "source": b91.SOURCE, "profiles": rows, "boundaries": dict(b91.BOUNDARIES)}


def exercise():
    return {"schema": b92.SCHEMA, "source": b92.SOURCE,
            "exercise": {"live_observation": True, "child_process_id": 4321, "baseline_record_id": 100,
                         "launched_at_utc": "2026-09-16T12:00:00+00:00",
                         "completed_at_utc": "2026-09-16T12:00:01+00:00", "cleanup_state": "EXITED", "exit_code": 0},
            "event": {"channel": b92.CHANNEL, "provider": b92.PROVIDER, "event_id": 400, "level": 4,
                      "record_id": 101, "process_id": 4321, "time_created_utc": "2026-09-16T12:00:00.500000+00:00"},
            "boundaries": dict(b92.BOUNDARIES)}


def controls():
    def row(cid, w, r, entropy, ext, canary, backup, user, sec):
        return {"control_id": cid, "live_observation": True, "sandbox_scope": "DEDICATED_TEMP_DIRECTORY",
                "observer_backend": "WATCHDOG_LOCAL_FILESYSTEM", "write_event_count": w,
                "rename_event_count": r, "entropy_delta": entropy, "extension_changed": ext,
                "canary_touched": canary, "known_backup_workflow": backup,
                "user_initiated_bulk_operation": user, "started_at_utc": f"2026-09-16T12:01:0{sec}+00:00",
                "completed_at_utc": f"2026-09-16T12:01:0{sec+1}+00:00", "cleanup_state": "CLEAN"}
    return {"schema": b93.SCHEMA, "source": b93.SOURCE,
            "controls": [row("positive-ransomware-like", 24, 18, .42, True, True, False, False, 0),
                         row("administrative-backup-like", 24, 18, .36, True, False, True, True, 2),
                         row("benign-save", 2, 0, .01, False, False, False, False, 4)],
            "boundaries": dict(b93.BOUNDARIES)}


def run(**kw):
    data = {"inventory": inventory(), "metadata": metadata(), "exercise": exercise(),
            "controls": controls(), "live_elapsed_seconds": 10.0}
    data.update(kw)
    return final.summarize(**data)


def test_final_contract_passes():
    result = run()
    assert result["passed"] is True
    assert result["coverage_summary"] == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    assert result["verified_scenario_id"] == "B7-RANSOMWARE-001"
    assert result["broad_protection_claimed"] is False


def test_final_contract_is_deterministic():
    assert run()["core_digest"] == run()["core_digest"]


def test_replayed_event_fails_closed():
    item = exercise()
    item["event"]["record_id"] = item["exercise"]["baseline_record_id"]
    result = run(exercise=item)
    assert result["passed"] is False
    assert "final:b92_event_incident_invalid" in result["failures"]


def test_privacy_boundary_change_fails_closed():
    item = controls()
    item["boundaries"]["personal_data_collected"] = True
    assert run(controls=item)["passed"] is False


def test_live_budget_is_enforced():
    result = run(live_elapsed_seconds=final.MAX_LIVE_PIPELINE_SECONDS + 1)
    assert result["passed"] is False
    assert "final:live_pipeline_budget_exceeded" in result["failures"]


def test_product_authority_remains_false():
    boundaries = run()["boundaries"]
    assert boundaries["local_only"] is True and boundaries["explicit_opt_in_required"] is True
    assert all(value is False for key, value in boundaries.items()
               if key not in {"local_only", "explicit_opt_in_required"})
