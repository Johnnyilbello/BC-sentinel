from __future__ import annotations

"""B11-2 reproducible Windows onedir artifact manifest and verifier."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-beta11-onedir-manifest-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b112-reproducible-windows-onedir-build"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b111-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "2d49bc2037d3d1f3fb40280277cf8d53927cc68b"
CANONICAL_ENTRYPOINT: Final[str] = "packaging/beta11_desktop_entry.py"
ARTIFACT_BASENAME: Final[str] = "BC-Sentinel-Beta11"
ARTIFACT_NAME: Final[str] = ARTIFACT_BASENAME + ".exe"
MANIFEST_NAME: Final[str] = "artifact-integrity.json"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = ("B7-POWERSHELL-001", "B7-RANSOMWARE-001")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_inventory(root: Path) -> list[dict[str, Any]]:
    root = root.resolve()
    entries: list[dict[str, Any]] = []
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.relative_to(root).as_posix().lower()):
        rel = path.relative_to(root).as_posix()
        if rel == MANIFEST_NAME:
            continue
        entries.append({"path": rel, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    return entries


def inventory_digest(entries: list[dict[str, Any]]) -> str:
    return _sha256_bytes(_canonical(entries))


def create_manifest(
    root: Path,
    *,
    build_commit: str,
    python_version: str,
    pyinstaller_version: str,
) -> dict[str, Any]:
    root = root.resolve()
    exe = root / ARTIFACT_NAME
    if not exe.is_file():
        raise FileNotFoundError(f"artifact executable missing: {exe}")
    if not _COMMIT_RE.fullmatch(build_commit):
        raise ValueError("build_commit must be an exact lowercase 40-character Git SHA")

    entries = build_inventory(root)
    if not entries:
        raise ValueError("artifact inventory is empty")
    total_bytes = sum(int(item["bytes"]) for item in entries)
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "artifact": ARTIFACT_NAME,
        "artifact_sha256": sha256_file(exe),
        "build_mode": "onedir",
        "windowed": True,
        "canonical_entrypoint": CANONICAL_ENTRYPOINT,
        "build_commit": build_commit,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "python_version": str(python_version),
        "pyinstaller_version": str(pyinstaller_version),
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "tree_digest": inventory_digest(entries),
        "files": entries,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "release_artifact_available": True,
        "installer_available": False,
        "artifact_signed": False,
        "windows_service_installed": False,
        "kernel_driver_installed": False,
        "autostart_registered": False,
        "network_required_for_core_startup": False,
        "cloud_required_for_core_startup": False,
        "startup_authority_expanded": False,
        "coverage_promoted": False,
    }


def write_manifest(
    root: Path,
    *,
    build_commit: str,
    python_version: str,
    pyinstaller_version: str,
) -> Path:
    manifest = create_manifest(
        root,
        build_commit=build_commit,
        python_version=python_version,
        pyinstaller_version=pyinstaller_version,
    )
    path = root / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def validate_manifest(data: object, *, root: Path | None = None, expected_build_commit: str | None = None) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b112:not_object",)
    failures: list[str] = []

    required = {
        "schema", "profile", "artifact", "artifact_sha256", "build_mode", "windowed",
        "canonical_entrypoint", "build_commit", "source_checkpoint", "source_checkpoint_commit",
        "python_version", "pyinstaller_version", "file_count", "total_bytes", "tree_digest", "files",
        "source_coverage", "verified_scenarios", "release_artifact_available", "installer_available",
        "artifact_signed", "windows_service_installed", "kernel_driver_installed", "autostart_registered",
        "network_required_for_core_startup", "cloud_required_for_core_startup",
        "startup_authority_expanded", "coverage_promoted",
    }
    if set(data) != required:
        failures.append("b112:unexpected_or_missing_fields")

    fixed = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "artifact": ARTIFACT_NAME,
        "build_mode": "onedir",
        "windowed": True,
        "canonical_entrypoint": CANONICAL_ENTRYPOINT,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": SOURCE_COVERAGE,
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "release_artifact_available": True,
        "installer_available": False,
        "artifact_signed": False,
        "windows_service_installed": False,
        "kernel_driver_installed": False,
        "autostart_registered": False,
        "network_required_for_core_startup": False,
        "cloud_required_for_core_startup": False,
        "startup_authority_expanded": False,
        "coverage_promoted": False,
    }
    for key, expected in fixed.items():
        if data.get(key) != expected:
            failures.append(f"b112:{key}_invalid")

    build_commit = data.get("build_commit")
    if not isinstance(build_commit, str) or not _COMMIT_RE.fullmatch(build_commit):
        failures.append("b112:build_commit_invalid")
    if expected_build_commit is not None and build_commit != expected_build_commit:
        failures.append("b112:build_commit_mismatch")

    for key in ("artifact_sha256", "tree_digest"):
        value = data.get(key)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            failures.append(f"b112:{key}_invalid")

    files = data.get("files")
    if not isinstance(files, list) or not files:
        failures.append("b112:files_invalid")
    else:
        paths = [item.get("path") for item in files if isinstance(item, dict)]
        if len(paths) != len(files) or paths != sorted(paths, key=lambda x: str(x).lower()) or len(set(paths)) != len(paths):
            failures.append("b112:file_order_invalid")
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
                failures.append("b112:file_entry_invalid")
                continue
            if not isinstance(item.get("path"), str) or not item["path"] or "\\" in item["path"]:
                failures.append("b112:file_path_invalid")
            if not isinstance(item.get("bytes"), int) or item["bytes"] < 0:
                failures.append("b112:file_size_invalid")
            if not isinstance(item.get("sha256"), str) or not _SHA256_RE.fullmatch(item["sha256"]):
                failures.append("b112:file_sha256_invalid")
        if data.get("file_count") != len(files):
            failures.append("b112:file_count_invalid")
        expected_total = sum(int(item.get("bytes", 0)) for item in files if isinstance(item, dict))
        if data.get("total_bytes") != expected_total:
            failures.append("b112:total_bytes_invalid")
        if data.get("tree_digest") != inventory_digest(files):
            failures.append("b112:tree_digest_invalid")

    if root is not None:
        root = root.resolve()
        try:
            actual = build_inventory(root)
        except OSError:
            failures.append("b112:artifact_tree_unreadable")
        else:
            if files != actual:
                failures.append("b112:artifact_tree_changed")
            exe = root / ARTIFACT_NAME
            if not exe.is_file():
                failures.append("b112:artifact_missing")
            else:
                try:
                    if data.get("artifact_sha256") != sha256_file(exe):
                        failures.append("b112:artifact_hash_mismatch")
                except OSError:
                    failures.append("b112:artifact_unreadable")

    return tuple(dict.fromkeys(failures))


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("manifest must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--validate", action="store_true")
    parser.add_argument("--root", required=True)
    parser.add_argument("--build-commit")
    parser.add_argument("--python-version")
    parser.add_argument("--pyinstaller-version")
    args = parser.parse_args()
    root = Path(args.root)

    if args.write:
        if not args.build_commit or not args.python_version or not args.pyinstaller_version:
            parser.error("--write requires --build-commit, --python-version and --pyinstaller-version")
        path = write_manifest(
            root,
            build_commit=args.build_commit,
            python_version=args.python_version,
            pyinstaller_version=args.pyinstaller_version,
        )
        print(path)
        return 0

    path = root / MANIFEST_NAME
    try:
        data = load_manifest(path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        print(json.dumps({"passed": False, "failures": ["b112:manifest_unreadable"]}, indent=2))
        return 1
    failures = validate_manifest(data, root=root, expected_build_commit=args.build_commit)
    result = {
        "passed": not failures,
        "failures": list(failures),
        "schema": SCHEMA,
        "profile": PROFILE,
        "artifact": ARTIFACT_NAME,
        "artifact_sha256": data.get("artifact_sha256"),
        "tree_digest": data.get("tree_digest"),
        "file_count": data.get("file_count"),
        "total_bytes": data.get("total_bytes"),
        "build_commit": data.get("build_commit"),
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "installer_available": False,
        "artifact_signed": False,
        "startup_authority_expanded": False,
        "coverage_promoted": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
