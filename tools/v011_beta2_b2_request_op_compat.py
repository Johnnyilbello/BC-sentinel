from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
from time import sleep
from typing import Any

PROFILE = "v0.11.0-beta.2"
BASE_SERVICE_SHA256 = "d5395dc2bb086941796703910143a0598e8fd4da36e53c19e2a910030498fe46"
EXPECTED_PROTOCOL_SHA256 = "2e39ec0422f820e107832b3ba20c62c103ea15cc99639159ea2ec1be211505b1"
EXPECTED_CLIENT_SHA256 = "6910eb42f6e7c5ba4d87b1f1533dfacff99483fbf4ffb06810595effa66cc9d1"
SERVICE_REL = Path("sentinel") / "protection_service_core.py"
PROTOCOL_REL = Path("sentinel") / "protection_protocol.py"
CLIENT_REL = Path("sentinel") / "protection_client.py"
BACKUP_REL = Path("sentinel") / "protection_service_core.py.v011-beta2-b2-request-op.bak"
BUGGY = 'op = str(getattr(request, "operation", "") or "").strip().casefold()'
FIXED = 'op = str(getattr(request, "op", "") or "").strip().casefold()'
SERVICE_MARKER = "bc-sentinel-v011-beta2-b1b-service-v1"


def _sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".v011-beta2-b2-request-op.tmp")
    tmp.write_text(text, encoding="utf-8")
    last: BaseException | None = None
    for attempt in range(8):
        try:
            os.replace(tmp, path)
            return
        except OSError as exc:
            last = exc
            if attempt + 1 < 8:
                sleep(min(0.05 * (2**attempt), 0.8))
    try:
        tmp.unlink(missing_ok=True)
    except Exception:
        pass
    raise RuntimeError(f"atomic promotion failed for {path}: {last}")


def transform(base: str) -> str:
    if _sha_text(base) != BASE_SERVICE_SHA256:
        raise RuntimeError("service-core is not the accepted B1b baseline")
    if base.count(SERVICE_MARKER) != 2:
        raise RuntimeError("accepted B1b service marker count is invalid")
    if base.count(BUGGY) != 1:
        raise RuntimeError("expected exactly one B1b request.operation dispatcher expression")
    if FIXED in base:
        raise RuntimeError("fixed request.op dispatcher unexpectedly already present in B1b baseline")
    updated = base.replace(BUGGY, FIXED, 1)
    ast.parse(updated)
    return updated


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
        return {"profile": PROFILE, "checkpoint": "B2-request-op-lineage", "passed": False, "checks": checks}

    service_text = _read(service)
    protocol_text = _read(protocol)
    client_text = _read(client)
    backup_text = _read(backup)
    expected = ""
    transform_error = ""
    try:
        expected = transform(backup_text)
    except Exception as exc:
        transform_error = f"{type(exc).__name__}: {exc}"

    checks.update({
        "backup_is_accepted_b1b": _sha_text(backup_text) == BASE_SERVICE_SHA256,
        "protocol_is_accepted_b1b": _sha_text(protocol_text) == EXPECTED_PROTOCOL_SHA256,
        "client_is_accepted_b1b": _sha_text(client_text) == EXPECTED_CLIENT_SHA256,
        "service_equals_single_expected_transform": bool(expected) and service_text == expected,
        "fixed_request_op_present_once": service_text.count(FIXED) == 1,
        "buggy_request_operation_absent": BUGGY not in service_text,
        "service_marker_count_preserved": service_text.count(SERVICE_MARKER) == 2,
    })
    return {
        "profile": PROFILE,
        "checkpoint": "B2-request-op-lineage",
        "passed": all(checks.values()),
        "checks": checks,
        "service_sha256": _sha_text(service_text),
        "baseline_service_sha256": _sha_text(backup_text),
        "protocol_sha256": _sha_text(protocol_text),
        "client_sha256": _sha_text(client_text),
        "transform_error": transform_error,
        "automatic_process_kill": False,
        "automatic_file_delete": False,
        "automatic_host_isolation": False,
    }


def apply(root: Path) -> dict[str, Any]:
    root = root.resolve()
    service = root / SERVICE_REL
    protocol = root / PROTOCOL_REL
    client = root / CLIENT_REL
    backup = root / BACKUP_REL
    if not all(path.is_file() for path in (service, protocol, client)):
        raise RuntimeError("required FULL B1b source file missing")

    protocol_text = _read(protocol)
    client_text = _read(client)
    if _sha_text(protocol_text) != EXPECTED_PROTOCOL_SHA256:
        raise RuntimeError("protocol source is not the accepted B1b version")
    if _sha_text(client_text) != EXPECTED_CLIENT_SHA256:
        raise RuntimeError("client source is not the accepted B1b version")

    current = _read(service)
    current_sha = _sha_text(current)
    if current_sha == BASE_SERVICE_SHA256:
        expected = transform(current)
        if backup.exists():
            existing_backup = _read(backup)
            if existing_backup != current:
                raise RuntimeError("existing lineage backup does not match accepted B1b service baseline")
        else:
            backup.write_text(current, encoding="utf-8")
        _atomic_write(service, expected)
    else:
        existing = verify_lineage(root)
        if not bool(existing.get("passed")):
            raise RuntimeError("service-core is neither accepted B1b baseline nor valid B2 request.op lineage")

    result = verify_lineage(root)
    if not bool(result.get("passed")):
        raise RuntimeError("post-fix B2 request.op lineage verification failed")
    result["applied_or_already_canonical"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 B2 request.op compatibility correction")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--output", default="acceptance-v011-beta2-b2-request-op-lineage.json")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    try:
        result = verify_lineage(root) if args.verify_only else apply(root)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if bool(result.get("passed")) else 2
    except Exception as exc:
        result = {
            "profile": PROFILE,
            "checkpoint": "B2-request-op-lineage",
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
