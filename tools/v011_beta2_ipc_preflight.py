from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE = "v0.11.0-beta.2"
PROTOCOL = Path("sentinel") / "protection_protocol.py"
SERVICE = Path("sentinel") / "protection_service_core.py"
CLIENT = Path("sentinel") / "protection_client.py"
EXPECTED_B1A_SERVICE_SHA256 = "9b3af57236b68de1ed5f7e23808d3d409ad2a64499a484696819467b9d5f0ca3"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load(path: Path) -> tuple[str, ast.Module]:
    text = path.read_text(encoding="utf-8")
    return text, ast.parse(text, filename=str(path))


def _literal(node: ast.AST) -> Any:
    try:
        value = ast.literal_eval(node)
    except Exception:
        return None
    try:
        json.dumps(value)
    except Exception:
        return repr(value)
    return value


def _assignments(tree: ast.Module) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for node in tree.body:
        name = None
        value_node = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name, value_node = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name, value_node = node.target.id, node.value
        if not name or value_node is None:
            continue
        folded = name.casefold()
        if any(term in folded for term in ("operation", "schema", "field", "payload", "privileged", "protocol", "max_")):
            out.append({"name": name, "line": int(node.lineno), "value": _literal(value_node)})
    return out


def _functions(tree: ast.Module) -> list[dict[str, Any]]:
    out = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append({"name": node.name, "line": int(node.lineno), "args": [a.arg for a in node.args.args]})
    return out


def _class_method(tree: ast.Module, cls_name: str, method_name: str) -> ast.AST | None:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == cls_name:
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == method_name:
                    return child
    return None


def _strings(node: ast.AST | None, *, limit: int = 200) -> list[dict[str, Any]]:
    if node is None:
        return []
    out = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            value = child.value.strip()
            if value and len(value) <= 180:
                out.append({"line": int(getattr(child, "lineno", 0)), "value": value})
    seen = set()
    unique = []
    for item in sorted(out, key=lambda x: (x["line"], x["value"])):
        key = (item["line"], item["value"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique[:limit]


def _calls(node: ast.AST | None, *, limit: int = 150) -> list[dict[str, Any]]:
    if node is None:
        return []
    out = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Name):
            name = child.func.id
        elif isinstance(child.func, ast.Attribute):
            parts = [child.func.attr]
            cur = child.func.value
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            name = ".".join(reversed(parts))
        else:
            name = ""
        if name:
            out.append({"line": int(getattr(child, "lineno", 0)), "call": name})
    return sorted(out, key=lambda x: (x["line"], x["call"]))[:limit]


def inspect_ipc(root: Path) -> dict[str, Any]:
    protocol_path = (root / PROTOCOL).resolve()
    service_path = (root / SERVICE).resolve()
    client_path = (root / CLIENT).resolve()
    missing = [str(p) for p in (protocol_path, service_path) if not p.is_file()]
    if missing:
        return {"profile": PROFILE, "checkpoint": "B1b-preflight", "passed": False, "missing": missing}

    protocol_text, protocol_tree = _load(protocol_path)
    service_text, service_tree = _load(service_path)
    client_text = ""
    client_tree = None
    if client_path.is_file():
        client_text, client_tree = _load(client_path)

    protocol_functions = _functions(protocol_tree)
    function_names = {item["name"] for item in protocol_functions}
    assignments = _assignments(protocol_tree)
    assignment_names = {item["name"] for item in assignments}
    dispatch = _class_method(service_tree, "ProtectionServiceCore", "dispatch_validated")
    authorize = _class_method(service_tree, "ProtectionServiceCore", "_authorize")

    checks = {
        "protocol_exists": True,
        "service_exists": True,
        "b1a_service_sha_matches": _sha(service_text) == EXPECTED_B1A_SERVICE_SHA256,
        "validate_request_present": "validate_request" in function_names,
        "privileged_operations_present": "PRIVILEGED_OPERATIONS" in assignment_names or "PRIVILEGED_OPERATIONS" in protocol_text,
        "dispatch_validated_present": dispatch is not None,
        "authorize_present": authorize is not None,
        "b1a_runtime_marker_present": "bc-sentinel-v011-beta2-service-runtime-v1" in service_text,
    }

    client_summary = None
    if client_tree is not None:
        client_summary = {
            "path": str(client_path),
            "sha256": _sha(client_text),
            "functions": _functions(client_tree),
            "strings": _strings(client_tree, limit=120),
        }

    return {
        "profile": PROFILE,
        "checkpoint": "B1b-preflight",
        "passed": all(checks.values()),
        "checks": checks,
        "protocol": {
            "path": str(protocol_path),
            "sha256": _sha(protocol_text),
            "functions": protocol_functions,
            "assignments": assignments,
            "interesting_strings": _strings(protocol_tree, limit=250),
        },
        "service": {
            "path": str(service_path),
            "sha256": _sha(service_text),
            "dispatch_validated_strings": _strings(dispatch),
            "dispatch_validated_calls": _calls(dispatch),
            "authorize_strings": _strings(authorize),
            "authorize_calls": _calls(authorize),
        },
        "client": client_summary,
        "automatic_destructive_action": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 B1b IPC preflight")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output", default="preflight-v011-beta2-b1b-ipc.json")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    result = inspect_ipc(root)
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
