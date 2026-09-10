from __future__ import annotations

import argparse
import dis
import json
from pathlib import Path
from types import CodeType
from typing import Any, Iterable

from PyInstaller.archive.readers import CArchiveReader

PROFILE = "v0.11.0-beta.2"


def _walk_code(code: CodeType) -> Iterable[CodeType]:
    yield code
    for value in code.co_consts:
        if isinstance(value, CodeType):
            yield from _walk_code(value)


def _walk_constant_strings(value: Any) -> Iterable[str]:
    """Yield strings recursively from compiler aggregate constants."""
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, CodeType):
        for item in value.co_consts:
            yield from _walk_constant_strings(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_constant_strings(key)
            yield from _walk_constant_strings(item)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            yield from _walk_constant_strings(item)


def _direct_constant_strings(code: CodeType) -> set[str]:
    out: set[str] = set()
    for value in code.co_consts:
        if isinstance(value, str):
            out.add(value)
        elif isinstance(value, (tuple, list, set, frozenset, dict)):
            out.update(_walk_constant_strings(value))
    return out


def _code_summary(code: CodeType) -> dict[str, Any]:
    return {
        "name": code.co_name,
        "qualname": getattr(code, "co_qualname", code.co_name),
        "argcount": code.co_argcount,
        "varnames": list(code.co_varnames[: code.co_argcount + code.co_kwonlyargcount]),
        "names": sorted(set(code.co_names)),
        "strings": sorted(set(_walk_constant_strings(code))),
    }


def _find_code_objects(code: CodeType, name: str) -> list[CodeType]:
    return [obj for obj in _walk_code(code) if obj.co_name == name]


def _string_owners(code: CodeType, needle: str) -> list[dict[str, Any]]:
    owners: list[dict[str, Any]] = []
    for obj in _walk_code(code):
        if needle in _direct_constant_strings(obj):
            owners.append(_code_summary(obj))
    return owners


def _module_store_order(code: CodeType) -> list[dict[str, Any]]:
    interesting = {
        "READ_OPERATIONS",
        "PRIVILEGED_OPERATIONS",
        "ALL_OPERATIONS",
        "EDR_READ_OPERATIONS",
        "EDR_PRIVILEGED_OPERATIONS",
        "_validate_payload",
        "_v011_beta2_legacy_validate_payload",
    }
    out: list[dict[str, Any]] = []
    for index, instruction in enumerate(dis.get_instructions(code)):
        if instruction.opname in {"STORE_NAME", "STORE_GLOBAL"} and str(instruction.argval) in interesting:
            out.append({
                "instruction_index": index,
                "offset": int(instruction.offset),
                "opname": instruction.opname,
                "name": str(instruction.argval),
            })
    return out


def _facts(code: CodeType) -> dict[str, Any]:
    objects = list(_walk_code(code))
    function_names = sorted({obj.co_name for obj in objects})
    names = sorted({name for obj in objects for name in obj.co_names})
    strings = sorted({value for obj in objects for value in _walk_constant_strings(obj)})
    callers = sorted({obj.co_name for obj in objects if "dispatch_validated" in obj.co_names})
    return {
        "function_names": function_names,
        "names": names,
        "strings": strings,
        "dispatch_validated_callers": callers,
    }


def _open_pyz(exe: Path):
    archive = CArchiveReader(str(exe))
    pyz_names = [name for name, entry in archive.toc.items() if entry[-1] == "z"]
    if len(pyz_names) != 1:
        raise RuntimeError(f"expected exactly one embedded PYZ archive, found {len(pyz_names)}: {pyz_names}")
    return archive.open_embedded_archive(pyz_names[0])


def _extract_code(pyz: Any, module: str) -> CodeType:
    if module not in pyz.toc:
        raise RuntimeError(f"frozen module missing: {module}")
    code = pyz.extract(module)
    if not isinstance(code, CodeType):
        raise RuntimeError(f"unexpected frozen object for {module}: {type(code).__name__}")
    return code


def _request_shape_evidence(protocol_code: CodeType) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for obj in _walk_code(protocol_code):
        folded_name = obj.co_name.casefold()
        names = set(obj.co_names)
        strings = set(_walk_constant_strings(obj))
        if (
            "request" in folded_name
            or "operation" in names
            or "op" in names
            or "operation" in strings
            or "op" in strings
        ):
            summary = _code_summary(obj)
            summary["mentions_operation_name"] = "operation" in names or "operation" in strings
            summary["mentions_op_name"] = "op" in names or "op" in strings
            candidates.append(summary)
    return {"candidates": candidates[:40]}


def _dispatch_evidence(service_code: CodeType) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for target in ("dispatch_validated", "_v011_beta2_legacy_dispatch_validated", "dispatch", "dispatch_bytes"):
        matches = _find_code_objects(service_code, target)
        result[target] = [_code_summary(item) for item in matches]
    b1b = _find_code_objects(service_code, "dispatch_validated")
    result["b1b_reads_request_operation"] = any("operation" in item.co_names for item in b1b)
    result["b1b_reads_request_op"] = any("op" in item.co_names for item in b1b)
    return result


def _protocol_evidence(protocol_code: CodeType) -> dict[str, Any]:
    stores = _module_store_order(protocol_code)
    counts: dict[str, int] = {}
    for item in stores:
        name = str(item["name"])
        counts[name] = counts.get(name, 0) + 1
    selected: dict[str, list[dict[str, Any]]] = {}
    for target in ("validate_request", "build_request", "parse_request", "decode_request", "_validate_payload"):
        matches = _find_code_objects(protocol_code, target)
        if matches:
            selected[target] = [_code_summary(item) for item in matches]
    return {
        "module_store_order": stores,
        "module_store_counts": counts,
        "selected_functions": selected,
        "unsupported_operation_string_owners": _string_owners(protocol_code, "Unsupported operation"),
        "unsupported_operation_code_owners": _string_owners(protocol_code, "unsupported_operation"),
    }


def inspect_exe(exe: Path) -> dict[str, Any]:
    pyz = _open_pyz(exe)
    protocol_code = _extract_code(pyz, "sentinel.protection_protocol")
    service_code = _extract_code(pyz, "sentinel.protection_service_core")
    protocol = _facts(protocol_code)
    service = _facts(service_code)

    protocol_functions = set(protocol["function_names"])
    protocol_names = set(protocol["names"])
    protocol_strings = set(protocol["strings"])
    service_functions = set(service["function_names"])
    service_names = set(service["names"])

    checks = {
        "protocol_has_legacy_validator": "_v011_beta2_legacy_validate_payload" in protocol_functions,
        "protocol_has_b1b_validator": "_validate_payload" in protocol_functions,
        "protocol_has_edr_status_literal": "edr_status" in protocol_strings,
        "protocol_has_edr_read_allowlist_symbol": "EDR_READ_OPERATIONS" in protocol_names,
        "protocol_has_edr_privileged_allowlist_symbol": "EDR_PRIVILEGED_OPERATIONS" in protocol_names,
        "service_has_legacy_dispatch": "_v011_beta2_legacy_dispatch_validated" in service_functions,
        "service_has_b1b_dispatch": "dispatch_validated" in service_functions,
        "service_has_legacy_pending": "_v011_beta2_legacy_pending_threats" in service_functions,
        "service_has_b1b_pending": "pending_threats" in service_functions,
        "service_references_edr_bridge": "EdrServiceBridge" in service_names,
        "service_references_dispatch_read": "dispatch_read" in service_names,
        "service_references_dispatch_privileged": "dispatch_privileged" in service_names,
    }

    protocol_ok = all(checks[name] for name in (
        "protocol_has_legacy_validator",
        "protocol_has_b1b_validator",
        "protocol_has_edr_status_literal",
        "protocol_has_edr_read_allowlist_symbol",
        "protocol_has_edr_privileged_allowlist_symbol",
    ))
    service_ok = all(checks[name] for name in (
        "service_has_legacy_dispatch",
        "service_has_b1b_dispatch",
        "service_has_legacy_pending",
        "service_has_b1b_pending",
        "service_references_edr_bridge",
        "service_references_dispatch_read",
        "service_references_dispatch_privileged",
    ))

    if not protocol_ok and not service_ok:
        classification = "frozen_protocol_and_service_pre_b1b_or_incomplete"
    elif not protocol_ok:
        classification = "frozen_protocol_pre_b1b_or_incomplete"
    elif not service_ok:
        classification = "frozen_service_dispatch_pre_b1b_or_incomplete"
    else:
        classification = "frozen_b1b_protocol_and_service_present"

    protection_modules = sorted(name for name in pyz.toc if str(name).startswith("sentinel.protection"))
    return {
        "path": str(exe),
        "classification": classification,
        "passed": protocol_ok and service_ok,
        "checks": checks,
        "protocol_evidence": _protocol_evidence(protocol_code),
        "service_dispatch_validated_callers_in_module": service["dispatch_validated_callers"],
        "dispatch_evidence": _dispatch_evidence(service_code),
        "request_shape_evidence": _request_shape_evidence(protocol_code),
        "protection_modules": protection_modules,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect frozen B1b routing invariants inside the PyInstaller Protection Service")
    parser.add_argument("--exe", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    output = Path(args.output).resolve()
    try:
        result = {
            "profile": PROFILE,
            "probe": "frozen_runtime_b1b",
            **inspect_exe(exe),
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if bool(result.get("passed")) else 2
    except Exception as exc:
        result = {
            "profile": PROFILE,
            "probe": "frozen_runtime_b1b",
            "passed": False,
            "classification": "probe_error",
            "error": f"{type(exc).__name__}: {exc}",
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
