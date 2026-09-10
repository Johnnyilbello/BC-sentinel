from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any

TARGET_RELATIVE = Path("sentinel") / "protection_service_core.py"
PROFILE = "v0.11.0-beta.2"
INTERESTING_TERMS = (
    "edr", "event", "incident", "inbox", "security", "dispatch", "operation",
    "request", "status", "etw", "pipe", "retention", "timeline", "hunt",
)


def _load_tree(path: Path) -> tuple[str, ast.AST]:
    text = path.read_text(encoding="utf-8")
    return text, ast.parse(text, filename=str(path))


def _class_summary(node: ast.ClassDef) -> dict[str, Any]:
    methods = []
    for child in node.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods.append({
                "name": child.name,
                "line": int(child.lineno),
                "args": [arg.arg for arg in child.args.args],
            })
    return {"name": node.name, "line": int(node.lineno), "methods": methods}


def _interesting_strings(tree: ast.AST) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value.strip()
        folded = value.casefold()
        if not value or len(value) > 160 or not any(term in folded for term in INTERESTING_TERMS):
            continue
        key = (int(getattr(node, "lineno", 0)), value)
        if key in seen:
            continue
        seen.add(key)
        values.append({"line": key[0], "value": value})
    return sorted(values, key=lambda item: (item["line"], item["value"]))[:100]


def _interesting_calls(tree: ast.AST) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = [node.func.attr]
            cur = node.func.value
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            name = ".".join(reversed(parts))
        if name and any(term in name.casefold() for term in INTERESTING_TERMS):
            out.append({"line": int(getattr(node, "lineno", 0)), "call": name})
    return sorted(out, key=lambda item: (item["line"], item["call"]))[:100]


def _imports(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for node in tree.body:  # type: ignore[attr-defined]
        if isinstance(node, ast.Import):
            out.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                out.append(f"{module}.{alias.name}" if module else alias.name)
    return sorted(set(out))


def inspect_service(root: Path) -> dict[str, Any]:
    target = (root / TARGET_RELATIVE).resolve()
    if not target.is_file():
        return {
            "profile": PROFILE,
            "passed": False,
            "reason": "FULL-only protection_service_core.py not found",
            "target": str(target),
        }

    text, tree = _load_tree(target)
    classes = [_class_summary(node) for node in tree.body if isinstance(node, ast.ClassDef)]  # type: ignore[attr-defined]
    runtime = next((item for item in classes if item["name"] == "ProtectionRuntime"), None)
    runtime_methods = {item["name"] for item in (runtime or {}).get("methods", [])}

    py_files = sorted((root / "sentinel").glob("*.py")) + sorted((root / "packaging").glob("*.py"))
    related_files: list[dict[str, Any]] = []
    for path in py_files:
        try:
            source = path.read_text(encoding="utf-8")
        except Exception:
            continue
        folded = source.casefold()
        markers = [term for term in ("security center", "inbox", "namedpipe", "named_pipe", "dispatch", "event_callback", "incident") if term in folded]
        if markers:
            related_files.append({
                "path": str(path.relative_to(root)),
                "markers": markers,
            })

    checks = {
        "target_exists": True,
        "protection_runtime_class": runtime is not None,
        "runtime_init": "__init__" in runtime_methods,
        "runtime_status": "status" in runtime_methods,
        "event_callback_reference": "event_callback" in text,
        "etw_reference": "ETWMonitor" in text or "etw" in text.casefold(),
        "dispatch_reference": "dispatch" in text.casefold() or "operation" in text.casefold(),
    }
    required_checks = (
        checks["target_exists"],
        checks["protection_runtime_class"],
        checks["runtime_init"],
        checks["runtime_status"],
    )
    passed = all(required_checks)
    return {
        "profile": PROFILE,
        "checkpoint": "B-preflight",
        "passed": passed,
        "checks": checks,
        "diagnostic_only_checks": [
            "event_callback_reference",
            "etw_reference",
            "dispatch_reference",
        ],
        "target": str(target),
        "runtime": runtime,
        "classes": classes,
        "imports": _imports(tree),
        "interesting_calls": _interesting_calls(tree),
        "interesting_strings": _interesting_strings(tree),
        "related_files": related_files[:50],
        "source_sha256": __import__("hashlib").sha256(text.encode("utf-8")).hexdigest(),
        "automatic_destructive_action": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 Protection Service source preflight")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output", default="preflight-v011-beta2-service.json")
    args = parser.parse_args()

    result = inspect_service(Path(args.root).resolve())
    output = Path(args.output)
    if not output.is_absolute():
        output = Path(args.root).resolve() / output
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
