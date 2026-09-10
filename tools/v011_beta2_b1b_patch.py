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
PROTOCOL_REL = Path("sentinel") / "protection_protocol.py"
SERVICE_REL = Path("sentinel") / "protection_service_core.py"
CLIENT_REL = Path("sentinel") / "protection_client.py"
EXPECTED_PROTOCOL_SHA256 = "cffcdaaea7850f2e0d995a75e14f18471bef9e920b57860b7ad68ce01e43090d"
EXPECTED_SERVICE_SHA256 = "9b3af57236b68de1ed5f7e23808d3d409ad2a64499a484696819467b9d5f0ca3"
EXPECTED_CLIENT_SHA256 = "6910eb42f6e7c5ba4d87b1f1533dfacff99483fbf4ffb06810595effa66cc9d1"
PROTOCOL_MARKER = "bc-sentinel-v011-beta2-b1b-protocol-v1"
SERVICE_MARKER = "bc-sentinel-v011-beta2-b1b-service-v1"
LEGACY_VALIDATE = "_v011_beta2_legacy_validate_payload"
LEGACY_DISPATCH = "_v011_beta2_legacy_dispatch_validated"
LEGACY_PENDING = "_v011_beta2_legacy_pending_threats"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse(text: str, path: Path) -> ast.Module:
    return ast.parse(text, filename=str(path))


def _function(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise RuntimeError(f"function {name} not found; refusing B1b patch")


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise RuntimeError(f"class {name} not found; refusing B1b patch")


def _method(cls: ast.ClassDef, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise RuntimeError(f"method {cls.name}.{name} not found; refusing B1b patch")


def _assignment(tree: ast.Module, name: str) -> ast.Assign | ast.AnnAssign:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                return node
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return node
    raise RuntimeError(f"assignment {name} not found; refusing B1b patch")


def _insert_after(lines: list[str], line_no: int, block: str) -> None:
    lines[line_no:line_no] = block.splitlines(keepends=True)


def _rename_def_line(lines: list[str], node: ast.AST, old: str, new: str) -> None:
    index = int(getattr(node, "lineno")) - 1
    needle = f"def {old}("
    if needle not in lines[index]:
        raise RuntimeError(f"definition line for {old} changed; refusing B1b patch")
    lines[index] = lines[index].replace(needle, f"def {new}(", 1)


def _has_two_arg_protocol_error(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id == "ProtocolError" and len(node.args) >= 2:
            return True
    return False


def _atomic_replace(path: Path, text: str, suffix: str) -> None:
    tmp = path.with_name(path.name + suffix)
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
    raise RuntimeError(f"atomic promotion failed for {path.name}: {last}")


def _protocol_update(original: str, path: Path) -> str:
    tree = _parse(original, path)
    validator = _function(tree, "_validate_payload")
    all_ops = _assignment(tree, "ALL_OPERATIONS")
    _assignment(tree, "READ_OPERATIONS")
    _assignment(tree, "PRIVILEGED_OPERATIONS")
    if validator.decorator_list:
        raise RuntimeError("_validate_payload has decorators; refusing wrapper patch")
    if not _has_two_arg_protocol_error(tree):
        raise RuntimeError("ProtocolError(code,message) shape not proven; refusing B1b patch")

    lines = original.splitlines(keepends=True)
    wrapper = f'''
# {PROTOCOL_MARKER}: strict EDR payload validation
def _validate_payload(op, payload):
    if op not in EDR_READ_OPERATIONS and op not in EDR_PRIVILEGED_OPERATIONS:
        return {LEGACY_VALIDATE}(op, payload)
    if payload is None:
        data = {{}}
    elif isinstance(payload, dict):
        data = dict(payload)
    else:
        raise ProtocolError("invalid_payload", "payload must be an object")

    fields = {{
        "edr_status": frozenset(),
        "edr_timeline": frozenset({{"pid", "category", "since", "until", "limit", "cursor"}}),
        "edr_incidents": frozenset({{"status", "limit"}}),
        "edr_incident_evidence": frozenset({{"incident_id", "limit", "cursor"}}),
        "edr_root_cause": frozenset({{"incident_id"}}),
        "edr_hunt": frozenset({{"indicator", "kind", "since", "until", "limit", "cursor"}}),
        "edr_process_tree": frozenset({{"since"}}),
        "edr_retention_policy": frozenset(),
        "edr_update_retention": frozenset({{"retention_seconds", "max_events", "prune"}}),
    }}
    allowed = fields[op]
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ProtocolError("invalid_payload", "Unknown payload field(s): " + ", ".join(unknown))

    if "limit" in data:
        value = data["limit"]
        if isinstance(value, bool) or not isinstance(value, int) or not (1 <= value <= 500):
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
    if "pid" in data:
        value = data["pid"]
        if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 2147483647):
            raise ProtocolError("invalid_payload", "pid is invalid")
    for key in ("since", "until", "retention_seconds"):
        if key in data:
            value = data[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ProtocolError("invalid_payload", f"{{key}} must be numeric")
            number = float(value)
            if number != number or abs(number) == float("inf"):
                raise ProtocolError("invalid_payload", f"{{key}} must be finite")
            data[key] = number
    if "since" in data and "until" in data and data["since"] > data["until"]:
        raise ProtocolError("invalid_payload", "since must be less than or equal to until")
    if "retention_seconds" in data and not (60.0 <= data["retention_seconds"] <= 7776000.0):
        raise ProtocolError("invalid_payload", "retention_seconds is outside the allowed bounds")
    if "max_events" in data:
        value = data["max_events"]
        if isinstance(value, bool) or not isinstance(value, int) or not (100 <= value <= 1000000):
            raise ProtocolError("invalid_payload", "max_events is outside the allowed bounds")
    if "prune" in data and not isinstance(data["prune"], bool):
        raise ProtocolError("invalid_payload", "prune must be boolean")
    if "cursor" in data:
        value = data["cursor"]
        if not isinstance(value, str) or "\\x00" in value or len(value) > 512:
            raise ProtocolError("invalid_payload", "cursor is invalid or too long")
    for key in ("category", "status"):
        if key in data:
            value = data[key]
            if not isinstance(value, str) or not value.strip() or "\\x00" in value or len(value) > 128:
                raise ProtocolError("invalid_payload", f"{{key}} is invalid")
            data[key] = value.strip()
    if "incident_id" in data:
        value = data["incident_id"]
        if not isinstance(value, str):
            raise ProtocolError("invalid_payload", "incident_id is invalid")
        incident_id = value.strip().upper()
        suffix = incident_id[6:] if incident_id.startswith("BCEDR-") else ""
        if len(suffix) != 20 or any(ch not in "0123456789ABCDEF" for ch in suffix):
            raise ProtocolError("invalid_payload", "incident_id is invalid")
        data["incident_id"] = incident_id
    if "indicator" in data:
        value = data["indicator"]
        if not isinstance(value, str) or not value.strip() or "\\x00" in value or len(value) > 32768:
            raise ProtocolError("invalid_payload", "indicator is invalid or too long")
        data["indicator"] = value.strip()
    if "kind" in data:
        value = data["kind"]
        if not isinstance(value, str) or value.strip().casefold() not in {{"auto", "sha256", "domain", "address", "path"}}:
            raise ProtocolError("invalid_payload", "unsupported EDR indicator kind")
        data["kind"] = value.strip().casefold()
    return data
'''
    _insert_after(lines, int(validator.end_lineno or validator.lineno), wrapper)
    _rename_def_line(lines, validator, "_validate_payload", LEGACY_VALIDATE)

    ops_block = f'''
# {PROTOCOL_MARKER}: authenticated EDR operation allowlists
EDR_READ_OPERATIONS = frozenset({{
    "edr_status", "edr_timeline", "edr_incidents", "edr_incident_evidence",
    "edr_root_cause", "edr_hunt", "edr_process_tree", "edr_retention_policy",
}})
EDR_PRIVILEGED_OPERATIONS = frozenset({{"edr_update_retention"}})
READ_OPERATIONS = frozenset(set(READ_OPERATIONS) | set(EDR_READ_OPERATIONS))
PRIVILEGED_OPERATIONS = frozenset(set(PRIVILEGED_OPERATIONS) | set(EDR_PRIVILEGED_OPERATIONS))
ALL_OPERATIONS = frozenset(set(READ_OPERATIONS) | set(PRIVILEGED_OPERATIONS))
'''
    _insert_after(lines, int(all_ops.end_lineno or all_ops.lineno), ops_block)
    updated = "".join(lines)
    _parse(updated, path)
    return updated


def _service_update(original: str, path: Path) -> str:
    tree = _parse(original, path)
    runtime = _class(tree, "ProtectionRuntime")
    core = _class(tree, "ProtectionServiceCore")
    pending = _method(runtime, "pending_threats")
    dispatch = _method(core, "dispatch_validated")
    if pending.decorator_list or dispatch.decorator_list:
        raise RuntimeError("service target method has decorators; refusing B1b patch")
    if "from .edr_service_bridge import EdrServiceBridge" not in original:
        raise RuntimeError("B1a EdrServiceBridge import missing; refusing B1b patch")

    lines = original.splitlines(keepends=True)
    dispatch_wrapper = f'''
    # {SERVICE_MARKER}: authenticated EDR dispatcher
    def dispatch_validated(self, request, context):
        op = str(getattr(request, "operation", "") or "").strip().casefold()
        if op not in EdrServiceBridge.READ_OPERATIONS and op not in EdrServiceBridge.PRIVILEGED_OPERATIONS:
            return self.{LEGACY_DISPATCH}(request, context)

        # Preserve the existing local-token/identity/admin checks and abuse limits.
        self._authorize(request, context)
        self._enforce_request_rate(request, context)
        payload = getattr(request, "payload", None)
        try:
            if op in EdrServiceBridge.READ_OPERATIONS:
                result = self.runtime.edr_bridge.dispatch_read(op, payload)
            else:
                result = self.runtime.edr_bridge.dispatch_privileged(op, payload)
        except (ValueError, TypeError) as exc:
            return response_error(request.request_id, "invalid_payload", str(exc))
        response = response_ok(request.request_id)
        if isinstance(response, dict) and isinstance(result, dict):
            response.update(result)
        return response
'''
    _insert_after(lines, int(dispatch.end_lineno or dispatch.lineno), dispatch_wrapper)
    _rename_def_line(lines, dispatch, "dispatch_validated", LEGACY_DISPATCH)

    pending_wrapper = f'''
    # {SERVICE_MARKER}: Security Center review-only EDR merge
    def pending_threats(self, limit=100):
        legacy = self.{LEGACY_PENDING}(limit)
        if not isinstance(legacy, list):
            return legacy
        try:
            bounded = max(1, min(int(limit or 100), 500))
            edr_items = self.edr_bridge.security_inbox_items(limit=bounded)
        except Exception:
            edr_items = []
        merged = list(legacy)
        seen = {{str(item.get("incident_id") or "") for item in merged if isinstance(item, dict)}}
        for item in edr_items:
            incident_id = str(item.get("incident_id") or "")
            if incident_id and incident_id not in seen:
                merged.append(item)
                seen.add(incident_id)
            if len(merged) >= bounded:
                break
        return merged[:bounded]
'''
    _insert_after(lines, int(pending.end_lineno or pending.lineno), pending_wrapper)
    _rename_def_line(lines, pending, "pending_threats", LEGACY_PENDING)
    updated = "".join(lines)
    _parse(updated, path)
    return updated


def verify(root: Path) -> dict[str, Any]:
    protocol_path = root / PROTOCOL_REL
    service_path = root / SERVICE_REL
    client_path = root / CLIENT_REL
    if not all(p.is_file() for p in (protocol_path, service_path, client_path)):
        return {"profile": PROFILE, "checkpoint": "B1b", "passed": False, "reason": "required FULL file missing"}
    protocol = protocol_path.read_text(encoding="utf-8")
    service = service_path.read_text(encoding="utf-8")
    client = client_path.read_text(encoding="utf-8")
    checks = {
        "protocol_marker_count": protocol.count(PROTOCOL_MARKER) == 2,
        "service_marker_count": service.count(SERVICE_MARKER) == 2,
        "legacy_validator_present": f"def {LEGACY_VALIDATE}(" in protocol,
        "edr_read_allowlist": "EDR_READ_OPERATIONS = frozenset" in protocol,
        "edr_privileged_allowlist": "EDR_PRIVILEGED_OPERATIONS = frozenset" in protocol and "edr_update_retention" in protocol,
        "strict_unknown_field_rejection": "Unknown payload field(s):" in protocol,
        "legacy_dispatch_present": f"def {LEGACY_DISPATCH}(" in service,
        "dispatch_authorizes": "self._authorize(request, context)" in service,
        "dispatch_rate_limits": "self._enforce_request_rate(request, context)" in service,
        "read_bridge_dispatch": "self.runtime.edr_bridge.dispatch_read(op, payload)" in service,
        "privileged_bridge_dispatch": "self.runtime.edr_bridge.dispatch_privileged(op, payload)" in service,
        "legacy_pending_present": f"def {LEGACY_PENDING}(" in service,
        "security_center_merge": "self.edr_bridge.security_inbox_items(limit=bounded)" in service,
        "client_unchanged": _sha(client) == EXPECTED_CLIENT_SHA256,
        "no_shell_surface_added": all(term not in protocol + service for term in (
            "pickle.loads", "subprocess.Popen", "subprocess.run", "os.system(", "shell=True", "eval(", "exec("
        )),
    }
    return {
        "profile": PROFILE,
        "checkpoint": "B1b",
        "passed": all(checks.values()),
        "checks": checks,
        "protocol_sha256": _sha(protocol),
        "service_sha256": _sha(service),
        "client_sha256": _sha(client),
        "automatic_process_kill": False,
        "automatic_file_delete": False,
        "automatic_host_isolation": False,
    }


def apply(root: Path, *, enforce_hashes: bool = True) -> dict[str, Any]:
    protocol_path = root / PROTOCOL_REL
    service_path = root / SERVICE_REL
    client_path = root / CLIENT_REL
    for path in (protocol_path, service_path, client_path):
        if not path.is_file():
            raise FileNotFoundError(f"required FULL file missing: {path}")

    protocol_original = protocol_path.read_text(encoding="utf-8")
    service_original = service_path.read_text(encoding="utf-8")
    client_original = client_path.read_text(encoding="utf-8")

    if PROTOCOL_MARKER in protocol_original or SERVICE_MARKER in service_original:
        result = verify(root)
        if not result["passed"]:
            raise RuntimeError("existing B1b marker is incomplete; refusing repair-by-guess")
        result.update({"patched": False, "already_compatible": True})
        return result

    if enforce_hashes:
        observed = {
            "protocol": _sha(protocol_original),
            "service": _sha(service_original),
            "client": _sha(client_original),
        }
        expected = {
            "protocol": EXPECTED_PROTOCOL_SHA256,
            "service": EXPECTED_SERVICE_SHA256,
            "client": EXPECTED_CLIENT_SHA256,
        }
        drift = {name: (expected[name], observed[name]) for name in observed if observed[name] != expected[name]}
        if drift:
            raise RuntimeError(f"B1b source drift detected; refusing mutation: {drift}")

    protocol_updated = _protocol_update(protocol_original, protocol_path)
    service_updated = _service_update(service_original, service_path)
    if PROTOCOL_MARKER not in protocol_updated or SERVICE_MARKER not in service_updated:
        raise RuntimeError("generated B1b source is incomplete")

    protocol_backup = protocol_path.with_name(protocol_path.name + ".pre-v011-beta2-b1b.bak")
    service_backup = service_path.with_name(service_path.name + ".pre-v011-beta2-b1b.bak")
    if not protocol_backup.exists():
        protocol_backup.write_text(protocol_original, encoding="utf-8")
    if not service_backup.exists():
        service_backup.write_text(service_original, encoding="utf-8")

    protocol_promoted = False
    try:
        _atomic_replace(protocol_path, protocol_updated, ".v011-beta2-b1b.tmp")
        protocol_promoted = True
        _atomic_replace(service_path, service_updated, ".v011-beta2-b1b.tmp")
    except Exception:
        if protocol_promoted:
            try:
                _atomic_replace(protocol_path, protocol_original, ".v011-beta2-b1b.rollback.tmp")
            except Exception as rollback_exc:
                raise RuntimeError(f"B1b service promotion failed and protocol rollback failed: {rollback_exc}")
        raise

    result = verify(root)
    if not result["passed"]:
        try:
            _atomic_replace(protocol_path, protocol_original, ".v011-beta2-b1b.rollback.tmp")
            _atomic_replace(service_path, service_original, ".v011-beta2-b1b.rollback.tmp")
        finally:
            raise RuntimeError("post-write B1b verification failed; originals restored")
    result.update({
        "patched": True,
        "already_compatible": False,
        "prepatch_protocol_sha256": _sha(protocol_original),
        "prepatch_service_sha256": _sha(service_original),
        "protocol_backup": str(protocol_backup),
        "service_backup": str(service_backup),
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 B1b authenticated EDR IPC patch")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--no-enforce-hashes", action="store_true")
    parser.add_argument("--output", default="integration-v011-beta2-b1b.json")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    try:
        result = verify(root) if args.verify_only else apply(root, enforce_hashes=not args.no_enforce_hashes)
    except Exception as exc:
        result = {
            "profile": PROFILE,
            "checkpoint": "B1b",
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
