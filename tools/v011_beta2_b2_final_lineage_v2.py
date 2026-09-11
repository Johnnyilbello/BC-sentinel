from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from tools.v011_beta2_b2_file_observation_compat import (
    CORE_PRE_SHA256,
    REALTIME_PRE_SHA256,
    MARKER as OBSERVATION_MARKER,
    transform_core_text as transform_observation_core,
    transform_realtime_text,
)
from tools.v011_beta2_b2_watchdog_admission_compat import (
    ADMISSION_MARKER,
    BUCKET_CAPACITY,
    BUCKET_REFILL_PER_SECOND,
    DEDUP_SECONDS,
    transform_core_text as transform_admission_core,
)

PROFILE = "v0.11.0-beta.2"
SERVICE_REL = Path("sentinel") / "protection_service_core.py"
REALTIME_REL = Path("sentinel") / "realtime.py"
PROTOCOL_REL = Path("sentinel") / "protection_protocol.py"
CLIENT_REL = Path("sentinel") / "protection_client.py"
B1B_BACKUP_REL = Path("sentinel") / "protection_service_core.py.v011-beta2-b2-request-op.bak"
OBS_CORE_BACKUP_REL = Path("sentinel") / "protection_service_core.py.pre-v011-beta2-b2-file-observation.bak"
OBS_REALTIME_BACKUP_REL = Path("sentinel") / "realtime.py.pre-v011-beta2-b2-file-observation.bak"
ADMISSION_BACKUP_REL = Path("sentinel") / "protection_service_core.py.pre-v011-beta2-b2-watchdog-admission.bak"

BASE_SERVICE_SHA256 = "d5395dc2bb086941796703910143a0598e8fd4da36e53c19e2a910030498fe46"
EXPECTED_PROTOCOL_SHA256 = "2e39ec0422f820e107832b3ba20c62c103ea15cc99639159ea2ec1be211505b1"
EXPECTED_CLIENT_SHA256 = "6910eb42f6e7c5ba4d87b1f1533dfacff99483fbf4ffb06810595effa66cc9d1"
BUGGY = 'op = str(getattr(request, "operation", "") or "").strip().casefold()'
FIXED = 'op = str(getattr(request, "op", "") or "").strip().casefold()'
SERVICE_MARKER = "bc-sentinel-v011-beta2-b1b-service-v1"
SETTINGS_MARKER = "bc-sentinel-v011-beta2-settings-ownership-v1"
SETTINGS_IMPORT = "from .config import APP_ROOT, DATA_DIR, EXE_DIR, PROGRAM_DATA_DIR, Settings, ensure_service_profile_roots"
DESERIALIZE_MIGRATION = "settings = ensure_service_profile_roots(settings)"
INPLACE_LOAD = "loaded_settings = ensure_service_profile_roots(self.config_store.load())"
INPLACE_COPY = "setattr(self.settings, key, getattr(loaded_settings, key))"
LEGACY_REPLACEMENT = "self.settings = self.config_store.load()"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def verify_lineage(root: Path) -> dict[str, Any]:
    root = root.resolve()
    paths = {
        "service": root / SERVICE_REL,
        "realtime": root / REALTIME_REL,
        "protocol": root / PROTOCOL_REL,
        "client": root / CLIENT_REL,
        "b1b_backup": root / B1B_BACKUP_REL,
        "obs_core_backup": root / OBS_CORE_BACKUP_REL,
        "obs_realtime_backup": root / OBS_REALTIME_BACKUP_REL,
        "admission_backup": root / ADMISSION_BACKUP_REL,
    }
    checks: dict[str, bool] = {f"{name}_exists": path.is_file() for name, path in paths.items()}
    if not all(checks.values()):
        return {"profile": PROFILE, "checkpoint": "B2-final-source-lineage-v2", "passed": False, "checks": checks}

    service_text = _read(paths["service"])
    realtime_text = _read(paths["realtime"])
    protocol_text = _read(paths["protocol"])
    client_text = _read(paths["client"])
    b1b_text = _read(paths["b1b_backup"])
    core_pre = _read(paths["obs_core_backup"])
    realtime_pre = _read(paths["obs_realtime_backup"])
    admission_pre = _read(paths["admission_backup"])

    transform_error = ""
    expected_observation_core = ""
    expected_service = ""
    expected_realtime = ""
    try:
        expected_observation_core = transform_observation_core(core_pre)
        expected_service = transform_admission_core(expected_observation_core)
        expected_realtime = transform_realtime_text(realtime_pre)
    except Exception as exc:
        transform_error = f"{type(exc).__name__}: {exc}"

    parse_ok = True
    parse_error = ""
    try:
        ast.parse(service_text)
        ast.parse(realtime_text)
    except Exception as exc:
        parse_ok = False
        parse_error = f"{type(exc).__name__}: {exc}"

    checks.update({
        "b1b_backup_exact": _sha(b1b_text) == BASE_SERVICE_SHA256,
        "protocol_exact": _sha(protocol_text) == EXPECTED_PROTOCOL_SHA256,
        "client_exact": _sha(client_text) == EXPECTED_CLIENT_SHA256,
        "observation_core_backup_exact": _sha(core_pre) == CORE_PRE_SHA256,
        "observation_realtime_backup_exact": _sha(realtime_pre) == REALTIME_PRE_SHA256,
        "admission_backup_equals_observation_v1": bool(expected_observation_core) and admission_pre == expected_observation_core,
        "service_equals_deterministic_final_transform_v2": bool(expected_service) and service_text == expected_service,
        "realtime_equals_deterministic_observation_transform": bool(expected_realtime) and realtime_text == expected_realtime,
        "service_and_realtime_ast_valid": parse_ok,
        "fixed_request_op_present_once": service_text.count(FIXED) == 1,
        "buggy_request_operation_absent": BUGGY not in service_text,
        "service_marker_count_preserved": service_text.count(SERVICE_MARKER) == 2,
        "settings_ownership_marker_present_once": service_text.count(SETTINGS_MARKER) == 1,
        "settings_profile_root_import_present_once": service_text.count(SETTINGS_IMPORT) == 1,
        "persisted_root_migration_present_once": service_text.count(DESERIALIZE_MIGRATION) == 1,
        "inplace_settings_reload_present_twice": service_text.count(INPLACE_LOAD) == 2,
        "inplace_settings_copy_present_twice": service_text.count(INPLACE_COPY) == 2,
        "legacy_settings_object_replacement_absent": LEGACY_REPLACEMENT not in service_text,
        "core_observation_marker_present_once": service_text.count(OBSERVATION_MARKER) == 1,
        "realtime_observation_marker_present_once": realtime_text.count(OBSERVATION_MARKER) == 1,
        "watchdog_admission_marker_present_once": service_text.count(ADMISSION_MARKER) == 1,
        "watchdog_observation_callback_wired_once": service_text.count("event_callback=self._on_realtime_file_observed") == 1,
        "filesystem_telemetry_category_once": service_text.count('category="filesystem"') == 1,
        "watchdog_source_once": service_text.count('source="watchdog"') == 1,
        "stabilized_observation_emit_once": realtime_text.count("self.event_callback(str(") == 1,
        "existing_file_guard_present_once": service_text.count("if not os_path.isfile(value)") == 1,
        "per_directory_admission_key_present_once": service_text.count("parent = os_path.dirname(normalized) or normalized") == 1,
        "dedup_window_preserved": service_text.count(f"< {DEDUP_SECONDS!r}") == 1,
        "bucket_capacity_preserved": service_text.count(str(BUCKET_CAPACITY)) >= 1,
        "bucket_refill_preserved": service_text.count(str(BUCKET_REFILL_PER_SECOND)) >= 1,
        "suppressed_summary_present_once": service_text.count('"suppressed_same_directory": suppressed_count') == 1,
    })

    return {
        "profile": PROFILE,
        "checkpoint": "B2-final-source-lineage-v2",
        "passed": all(checks.values()),
        "checks": checks,
        "service_sha256": _sha(service_text),
        "realtime_sha256": _sha(realtime_text),
        "expected_service_sha256": _sha(expected_service) if expected_service else "",
        "expected_observation_v1_sha256": _sha(expected_observation_core) if expected_observation_core else "",
        "expected_realtime_sha256": _sha(expected_realtime) if expected_realtime else "",
        "admission_backup_sha256": _sha(admission_pre),
        "observation_core_backup_sha256": _sha(core_pre),
        "observation_realtime_backup_sha256": _sha(realtime_pre),
        "baseline_service_sha256": _sha(b1b_text),
        "protocol_sha256": _sha(protocol_text),
        "client_sha256": _sha(client_text),
        "admission_policy": {
            "scope": "per_directory",
            "dedup_seconds": DEDUP_SECONDS,
            "bucket_capacity": BUCKET_CAPACITY,
            "refill_per_second": BUCKET_REFILL_PER_SECOND,
            "cross_directory_isolation": True,
        },
        "transform_error": transform_error,
        "parse_error": parse_error,
        "automatic_process_kill": False,
        "automatic_file_delete": False,
        "automatic_host_isolation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 strict final source-lineage verifier with bounded watchdog admission")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--output", default="acceptance-v011-beta2-b2-final-lineage-v2.json")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    try:
        result = verify_lineage(root)
    except Exception as exc:
        result = {"profile": PROFILE, "checkpoint": "B2-final-source-lineage-v2", "passed": False, "error": f"{type(exc).__name__}: {exc}"}
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if bool(result.get("passed")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
