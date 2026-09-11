from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE = "v0.11.0-beta.2"
SERVICE_REL = Path("sentinel") / "protection_service_core.py"
PROTOCOL_REL = Path("sentinel") / "protection_protocol.py"
CLIENT_REL = Path("sentinel") / "protection_client.py"
BACKUP_REL = Path("sentinel") / "protection_service_core.py.v011-beta2-b2-request-op.bak"

BASE_SERVICE_SHA256 = "d5395dc2bb086941796703910143a0598e8fd4da36e53c19e2a910030498fe46"
EXPECTED_COMPOSITE_SERVICE_SHA256 = "55302443fd488c4f6da28010f25a23c9e37e930943109ae4984f9719ba4187ed"
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


def _sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def verify_lineage(root: Path) -> dict[str, Any]:
    root = root.resolve()
    service = root / SERVICE_REL
    protocol = root / PROTOCOL_REL
    client = root / CLIENT_REL
    backup = root / BACKUP_REL

    checks: dict[str, bool] = {
        "service_exists": service.is_file(),
        "protocol_exists": protocol.is_file(),
        "client_exists": client.is_file(),
        "backup_exists": backup.is_file(),
    }
    if not all(checks.values()):
        return {
            "profile": PROFILE,
            "checkpoint": "B2-composite-source-lineage",
            "passed": False,
            "checks": checks,
        }

    service_text = _read(service)
    protocol_text = _read(protocol)
    client_text = _read(client)
    backup_text = _read(backup)

    parse_ok = True
    parse_error = ""
    try:
        ast.parse(service_text)
    except Exception as exc:
        parse_ok = False
        parse_error = f"{type(exc).__name__}: {exc}"

    checks.update({
        "backup_is_accepted_b1b": _sha_text(backup_text) == BASE_SERVICE_SHA256,
        "protocol_is_accepted_b1b": _sha_text(protocol_text) == EXPECTED_PROTOCOL_SHA256,
        "client_is_accepted_b1b": _sha_text(client_text) == EXPECTED_CLIENT_SHA256,
        "service_matches_accepted_composite_hash": _sha_text(service_text) == EXPECTED_COMPOSITE_SERVICE_SHA256,
        "service_ast_valid": parse_ok,
        "fixed_request_op_present_once": service_text.count(FIXED) == 1,
        "buggy_request_operation_absent": BUGGY not in service_text,
        "service_marker_count_preserved": service_text.count(SERVICE_MARKER) == 2,
        "settings_ownership_marker_present_once": service_text.count(SETTINGS_MARKER) == 1,
        "settings_profile_root_import_present_once": service_text.count(SETTINGS_IMPORT) == 1,
        "persisted_root_migration_present_once": service_text.count(DESERIALIZE_MIGRATION) == 1,
        "inplace_settings_reload_present_twice": service_text.count(INPLACE_LOAD) == 2,
        "inplace_settings_copy_present_twice": service_text.count(INPLACE_COPY) == 2,
        "legacy_settings_object_replacement_absent": LEGACY_REPLACEMENT not in service_text,
    })

    return {
        "profile": PROFILE,
        "checkpoint": "B2-composite-source-lineage",
        "passed": all(checks.values()),
        "checks": checks,
        "service_sha256": _sha_text(service_text),
        "expected_composite_service_sha256": EXPECTED_COMPOSITE_SERVICE_SHA256,
        "baseline_service_sha256": _sha_text(backup_text),
        "protocol_sha256": _sha_text(protocol_text),
        "client_sha256": _sha_text(client_text),
        "parse_error": parse_error,
        "automatic_process_kill": False,
        "automatic_file_delete": False,
        "automatic_host_isolation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 strict composite source-lineage verifier")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--output", default="acceptance-v011-beta2-b2-composite-lineage.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output

    try:
        result = verify_lineage(root)
    except Exception as exc:
        result = {
            "profile": PROFILE,
            "checkpoint": "B2-composite-source-lineage",
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if bool(result.get("passed")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
