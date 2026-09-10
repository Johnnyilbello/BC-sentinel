from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE = "v0.11.0-beta.2"
TOKENS = (
    "BCS-NetworkMonitor",
    "NetworkMonitor",
    "network_monitor",
    "net_connections",
    "connections(kind=",
    "psutil.net_",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snippet(lines: list[str], start: int, end: int, pad: int = 12) -> dict[str, Any]:
    lo = max(1, start - pad)
    hi = min(len(lines), end + pad)
    return {
        "start_line": lo,
        "end_line": hi,
        "text": "\n".join(f"{idx}: {lines[idx-1]}" for idx in range(lo, hi + 1)),
    }


def _node_contains_token(node: ast.AST, source: str) -> bool:
    try:
        segment = ast.get_source_segment(source, node) or ""
    except Exception:
        segment = ""
    folded = segment.casefold()
    return any(token.casefold() in folded for token in TOKENS)


def _function_facts(tree: ast.AST, source: str, lines: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _node_contains_token(node, source):
            continue
        segment = ast.get_source_segment(source, node) or ""
        sleeps: list[str] = []
        waits: list[str] = []
        loops = 0
        for child in ast.walk(node):
            if isinstance(child, (ast.While, ast.For, ast.AsyncFor)):
                loops += 1
            if isinstance(child, ast.Call):
                func = child.func
                name = ""
                if isinstance(func, ast.Attribute):
                    name = func.attr
                elif isinstance(func, ast.Name):
                    name = func.id
                if name in {"sleep"}:
                    sleeps.append(ast.get_source_segment(source, child) or name)
                if name in {"wait"}:
                    waits.append(ast.get_source_segment(source, child) or name)
        start = int(getattr(node, "lineno", 1))
        end = int(getattr(node, "end_lineno", start))
        out.append({
            "name": node.name,
            "start_line": start,
            "end_line": end,
            "loop_count": loops,
            "sleep_calls": sleeps[:20],
            "wait_calls": waits[:20],
            "mentions": [token for token in TOKENS if token.casefold() in segment.casefold()],
            "snippet": _snippet(lines, start, min(end, start + 120), pad=4),
        })
    return out


def inspect(root: Path) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    search_roots = [root / "sentinel", root / "packaging", root / "tools"]
    for base in search_roots:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            try:
                source = path.read_text(encoding="utf-8")
            except Exception:
                continue
            folded = source.casefold()
            hits = [token for token in TOKENS if token.casefold() in folded]
            if not hits:
                continue
            lines = source.splitlines()
            literal_hits: list[dict[str, Any]] = []
            for idx, line in enumerate(lines, 1):
                if any(token.casefold() in line.casefold() for token in TOKENS):
                    literal_hits.append({"line": idx, "text": line.strip()})
            try:
                tree = ast.parse(source, filename=str(path))
                functions = _function_facts(tree, source, lines)
            except SyntaxError as exc:
                functions = []
                literal_hits.append({"line": int(exc.lineno or 0), "text": f"AST parse error: {exc}"})
            candidates.append({
                "path": str(path.relative_to(root)),
                "sha256": _sha(path),
                "size": path.stat().st_size,
                "token_hits": hits,
                "literal_hits": literal_hits[:80],
                "functions": functions[:40],
            })

    marker_candidates = [
        item for item in candidates
        if "BCS-NetworkMonitor" in item["token_hits"]
    ]
    classification = (
        "network_monitor_source_identified"
        if marker_candidates
        else "network_monitor_marker_not_found"
    )
    return {
        "profile": PROFILE,
        "probe": "idle_hotspot_source",
        "passed": bool(marker_candidates),
        "classification": classification,
        "candidate_count": len(candidates),
        "marker_candidate_count": len(marker_candidates),
        "marker_candidates": marker_candidates,
        "all_candidates": candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Locate BC Sentinel network-monitor idle CPU source without mutating the FULL tree")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output", default="probe-v011-beta2-b2-idle-hotspot.json")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    try:
        result = inspect(root)
    except Exception as exc:
        result = {
            "profile": PROFILE,
            "probe": "idle_hotspot_source",
            "passed": False,
            "classification": "probe_error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
