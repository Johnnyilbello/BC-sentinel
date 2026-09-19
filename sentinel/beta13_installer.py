from __future__ import annotations

"""B13-3 Real Windows Installer Foundation.

Defines and verifies the real per-user Windows installer artifact while keeping
BC Sentinel's security data outside the application directory and preserving
unknown files during uninstall. The installer remains unsigned in B13-3; code
signing is a separate release blocker handled by B13-4.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Final

from sentinel import beta13_secure_updates as b132

SCHEMA: Final[str] = "bc-sentinel-beta13-installer-foundation-v1"
PROFILE: Final[str] = "v0.13.0-b133-real-windows-installer-foundation"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v013-b132-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "3e64155858d9b8c7efebc28aecc9689795159ae9"

PRODUCT_NAME: Final[str] = "BC Sentinel"
PUBLISHER: Final[str] = "BC TECH Studio"
PRODUCT_VERSION: Final[str] = "0.13.0"
PRODUCT_EXE: Final[str] = "BC-Sentinel.exe"
PAYLOAD_MANIFEST_NAME: Final[str] = "install-payload-manifest.json"
INSTALLER_EVIDENCE_NAME: Final[str] = "installer-evidence.json"
INSTALLER_FILENAME: Final[str] = "BC-Sentinel-Setup-v0.13.0-b133.exe"
INSTALL_SCOPE: Final[str] = "PER_USER"
DEFAULT_INSTALL_TOKEN: Final[str] = r"{LOCAL_APP_DATA}\Programs\BC Sentinel"
PERSISTENT_DATA_TOKEN: Final[str] = r"{LOCAL_APP_DATA}\BCSentinel"
START_MENU_TOKEN: Final[str] = r"{CURRENT_USER_START_MENU}\Programs\BC Sentinel"
NSIS_VERSION: Final[str] = "3.12"
NSIS_ZIP_SHA256: Final[str] = "56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

BOUNDARIES: Final[dict[str, bool]] = {
    "per_user_install": True,
    "administrator_required": False,
    "service_registration": False,
    "driver_registration": False,
    "defender_exclusion_creation": False,
    "firewall_rule_creation": False,
    "scheduled_task_creation": False,
    "autostart_registration": False,
    "browser_extension_installation": False,
    "certificate_store_mutation": False,
    "environment_path_mutation": False,
    "automatic_update_registration": False,
    "persistent_data_inside_install_root": False,
    "persistent_data_removed_by_default": False,
    "unknown_install_children_removed": False,
    "artifact_signed": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_inventory(root: Path) -> list[dict[str, Any]]:
    resolved = root.resolve()
    entries: list[dict[str, Any]] = []
    for path in sorted(
        (item for item in resolved.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(resolved).as_posix().casefold(),
    ):
        rel = path.relative_to(resolved).as_posix()
        if rel == PAYLOAD_MANIFEST_NAME:
            continue
        entries.append(
            {
                "path": rel,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return entries


def inventory_digest(entries: list[dict[str, Any]]) -> str:
    return _digest(entries)


def build_payload_manifest(root: Path, *, build_commit: str, python_version: str, pyinstaller_version: str) -> dict[str, Any]:
    if not _COMMIT_RE.fullmatch(build_commit):
        raise ValueError("b133:build_commit_invalid")
    resolved = root.resolve()
    exe = resolved / PRODUCT_EXE
    if not exe.is_file():
        raise FileNotFoundError("b133:product_executable_missing")
    files = build_inventory(resolved)
    if not files:
        raise ValueError("b133:payload_empty")
    return {
        "schema": "bc-sentinel-beta13-install-payload-v1",
        "profile": PROFILE,
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "product_exe": PRODUCT_EXE,
        "build_commit": build_commit,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "python_version": str(python_version),
        "pyinstaller_version": str(pyinstaller_version),
        "file_count": len(files),
        "total_bytes": sum(int(item["bytes"]) for item in files),
        "tree_digest": inventory_digest(files),
        "exe_sha256": sha256_file(exe),
        "files": files,
        "install_scope": INSTALL_SCOPE,
        "default_install_token": DEFAULT_INSTALL_TOKEN,
        "persistent_data_token": PERSISTENT_DATA_TOKEN,
        "persistent_data_preserved_by_default": True,
        "artifact_signed": False,
        "service_or_driver_registered": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def write_payload_manifest(root: Path, *, build_commit: str, python_version: str, pyinstaller_version: str) -> Path:
    payload = build_payload_manifest(
        root,
        build_commit=build_commit,
        python_version=python_version,
        pyinstaller_version=pyinstaller_version,
    )
    path = root / PAYLOAD_MANIFEST_NAME
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def validate_payload_manifest(data: object, *, root: Path | None = None, expected_build_commit: str | None = None) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b133:payload_manifest_not_object",)
    failures: list[str] = []
    required = {
        "schema", "profile", "product", "product_version", "product_exe", "build_commit",
        "source_checkpoint", "source_checkpoint_commit", "python_version", "pyinstaller_version",
        "file_count", "total_bytes", "tree_digest", "exe_sha256", "files", "install_scope",
        "default_install_token", "persistent_data_token", "persistent_data_preserved_by_default",
        "artifact_signed", "service_or_driver_registered", "coverage_promoted", "authority_expanded",
    }
    if set(data) != required:
        failures.append("b133:payload_manifest_fields_invalid")
    fixed = {
        "schema": "bc-sentinel-beta13-install-payload-v1",
        "profile": PROFILE,
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "product_exe": PRODUCT_EXE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "install_scope": INSTALL_SCOPE,
        "default_install_token": DEFAULT_INSTALL_TOKEN,
        "persistent_data_token": PERSISTENT_DATA_TOKEN,
        "persistent_data_preserved_by_default": True,
        "artifact_signed": False,
        "service_or_driver_registered": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }
    for key, expected in fixed.items():
        if data.get(key) != expected:
            failures.append(f"b133:payload_{key}_invalid")

    build_commit = data.get("build_commit")
    if not isinstance(build_commit, str) or not _COMMIT_RE.fullmatch(build_commit):
        failures.append("b133:payload_build_commit_invalid")
    if expected_build_commit is not None and build_commit != expected_build_commit:
        failures.append("b133:payload_build_commit_mismatch")

    for key in ("tree_digest", "exe_sha256"):
        value = data.get(key)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            failures.append(f"b133:payload_{key}_invalid")

    files = data.get("files")
    if not isinstance(files, list) or not files:
        failures.append("b133:payload_files_invalid")
    else:
        paths: list[str] = []
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
                failures.append("b133:payload_file_entry_invalid")
                continue
            rel = item.get("path")
            if (
                not isinstance(rel, str)
                or not rel
                or rel.startswith("/")
                or "\\" in rel
                or ".." in Path(rel).parts
            ):
                failures.append("b133:payload_file_path_invalid")
            else:
                paths.append(rel)
            if not isinstance(item.get("bytes"), int) or item["bytes"] < 0:
                failures.append("b133:payload_file_size_invalid")
            if not isinstance(item.get("sha256"), str) or not _SHA256_RE.fullmatch(item["sha256"]):
                failures.append("b133:payload_file_sha256_invalid")
        if len(paths) != len(set(paths)) or paths != sorted(paths, key=str.casefold):
            failures.append("b133:payload_file_inventory_order_invalid")
        if data.get("file_count") != len(files):
            failures.append("b133:payload_file_count_invalid")
        if data.get("total_bytes") != sum(int(item.get("bytes", 0)) for item in files if isinstance(item, dict)):
            failures.append("b133:payload_total_bytes_invalid")
        if inventory_digest(files) != data.get("tree_digest"):
            failures.append("b133:payload_tree_digest_invalid")

    if root is not None:
        resolved = root.resolve()
        try:
            actual = build_inventory(resolved)
        except OSError:
            failures.append("b133:payload_tree_unreadable")
        else:
            if files != actual:
                failures.append("b133:payload_tree_changed")
            exe = resolved / PRODUCT_EXE
            if not exe.is_file():
                failures.append("b133:payload_executable_missing")
            elif data.get("exe_sha256") != sha256_file(exe):
                failures.append("b133:payload_executable_hash_mismatch")
    return tuple(dict.fromkeys(failures))


def uninstall_include(manifest: dict[str, Any]) -> str:
    failures = validate_payload_manifest(manifest)
    if failures:
        raise ValueError("b133:invalid_manifest_for_uninstall_include:" + ",".join(failures))
    files = [str(item["path"]).replace("/", "\\") for item in manifest["files"]]
    directories: set[str] = set()
    for rel in files:
        parent = Path(rel).parent
        while str(parent) not in ("", "."):
            directories.add(str(parent).replace("/", "\\"))
            parent = parent.parent

    lines = [
        "; Generated from install-payload-manifest.json.",
        "; Deletes only manifested product files. Unknown files are preserved.",
    ]
    for rel in sorted(files, key=str.casefold, reverse=True):
        escaped = rel.replace("$", "$$")
        lines.append(f'Delete "$INSTDIR\\{escaped}"')
    for rel in sorted(directories, key=lambda value: (value.count("\\"), value.casefold()), reverse=True):
        escaped = rel.replace("$", "$$")
        lines.append(f'RMDir "$INSTDIR\\{escaped}"')
    lines.append(f'Delete "$INSTDIR\\{PAYLOAD_MANIFEST_NAME}"')
    lines.append('RMDir "$INSTDIR"')
    return "\n".join(lines) + "\n"


def build_installer_evidence(
    installer_path: Path,
    *,
    payload_manifest: dict[str, Any],
    build_commit: str,
    nsis_version: str,
) -> dict[str, Any]:
    installer = installer_path.resolve()
    if not installer.is_file():
        raise FileNotFoundError("b133:installer_missing")
    payload_failures = validate_payload_manifest(payload_manifest, expected_build_commit=build_commit)
    if payload_failures:
        raise ValueError("b133:payload_manifest_invalid")
    if nsis_version != NSIS_VERSION:
        raise ValueError("b133:nsis_version_invalid")
    body = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "installer_filename": installer.name,
        "installer_sha256": sha256_file(installer),
        "installer_bytes": installer.stat().st_size,
        "build_commit": build_commit,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "payload_tree_digest": payload_manifest["tree_digest"],
        "payload_exe_sha256": payload_manifest["exe_sha256"],
        "payload_file_count": payload_manifest["file_count"],
        "nsis_version": nsis_version,
        "nsis_zip_sha256": NSIS_ZIP_SHA256,
        "install_scope": INSTALL_SCOPE,
        "default_install_token": DEFAULT_INSTALL_TOKEN,
        "persistent_data_token": PERSISTENT_DATA_TOKEN,
        "persistent_data_preserved_by_default": True,
        "unknown_install_children_preserved": True,
        "start_menu_shortcut": True,
        "desktop_shortcut_optional": True,
        "uninstaller_available": True,
        "installer_available": True,
        "installer_execution_capable": True,
        "uninstaller_execution_capable": True,
        "lifecycle_execution_verified_in_artifact_evidence": False,
        "artifact_signed": False,
        "signing_deferred_to_b134": True,
        "service_or_driver_registered": False,
        "autostart_registered": False,
        "network_required_at_runtime": False,
        "cloud_required_at_runtime": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }
    return {**body, "evidence_digest": _digest(body)}


def validate_installer_evidence(data: object, *, installer_path: Path | None = None, expected_build_commit: str | None = None) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b133:installer_evidence_not_object",)
    failures: list[str] = []
    body = dict(data)
    evidence_digest = body.pop("evidence_digest", None)
    if not isinstance(evidence_digest, str) or not _SHA256_RE.fullmatch(evidence_digest) or evidence_digest != _digest(body):
        failures.append("b133:installer_evidence_digest_invalid")
    fixed = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "nsis_version": NSIS_VERSION,
        "nsis_zip_sha256": NSIS_ZIP_SHA256,
        "install_scope": INSTALL_SCOPE,
        "default_install_token": DEFAULT_INSTALL_TOKEN,
        "persistent_data_token": PERSISTENT_DATA_TOKEN,
        "persistent_data_preserved_by_default": True,
        "unknown_install_children_preserved": True,
        "start_menu_shortcut": True,
        "desktop_shortcut_optional": True,
        "uninstaller_available": True,
        "installer_available": True,
        "installer_execution_capable": True,
        "uninstaller_execution_capable": True,
        "lifecycle_execution_verified_in_artifact_evidence": False,
        "artifact_signed": False,
        "signing_deferred_to_b134": True,
        "service_or_driver_registered": False,
        "autostart_registered": False,
        "network_required_at_runtime": False,
        "cloud_required_at_runtime": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }
    for key, expected in fixed.items():
        if data.get(key) != expected:
            failures.append(f"b133:evidence_{key}_invalid")
    build_commit = data.get("build_commit")
    if not isinstance(build_commit, str) or not _COMMIT_RE.fullmatch(build_commit):
        failures.append("b133:evidence_build_commit_invalid")
    if expected_build_commit is not None and build_commit != expected_build_commit:
        failures.append("b133:evidence_build_commit_mismatch")
    for key in ("installer_sha256", "payload_tree_digest", "payload_exe_sha256"):
        value = data.get(key)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            failures.append(f"b133:evidence_{key}_invalid")
    if data.get("installer_filename") != INSTALLER_FILENAME:
        failures.append("b133:evidence_installer_filename_invalid")
    if not isinstance(data.get("installer_bytes"), int) or data["installer_bytes"] <= 0:
        failures.append("b133:evidence_installer_bytes_invalid")
    if not isinstance(data.get("payload_file_count"), int) or data["payload_file_count"] <= 0:
        failures.append("b133:evidence_payload_file_count_invalid")
    if installer_path is not None:
        installer = installer_path.resolve()
        if not installer.is_file():
            failures.append("b133:evidence_installer_missing")
        else:
            if data.get("installer_sha256") != sha256_file(installer):
                failures.append("b133:evidence_installer_hash_mismatch")
            if data.get("installer_bytes") != installer.stat().st_size:
                failures.append("b133:evidence_installer_size_mismatch")
    return tuple(dict.fromkeys(failures))


def projected_readiness() -> dict[str, Any]:
    baseline = b132.projected_readiness()
    counts = dict(baseline["pillar_counts"])
    blockers = list(baseline["release_blockers"])
    if "INSTALLER_LIFECYCLE" in blockers:
        blockers.remove("INSTALLER_LIFECYCLE")
        counts["READY"] += 1
        counts["BLOCKED"] -= 1
    return {
        "schema": "bc-sentinel-beta13-readiness-projection-v3",
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "pillar_counts": counts,
        "release_blockers": blockers,
        "release_blocker_count": len(blockers),
        "ready_for_public_launch": not blockers,
        "ready_for_paid_launch": not blockers,
        "resolved_by_b133": ["INSTALLER_LIFECYCLE"],
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "product": PRODUCT_NAME,
        "publisher": PUBLISHER,
        "product_version": PRODUCT_VERSION,
        "product_exe": PRODUCT_EXE,
        "installer_filename": INSTALLER_FILENAME,
        "install_scope": INSTALL_SCOPE,
        "default_install_token": DEFAULT_INSTALL_TOKEN,
        "persistent_data_token": PERSISTENT_DATA_TOKEN,
        "nsis_version": NSIS_VERSION,
        "nsis_zip_sha256": NSIS_ZIP_SHA256,
        "boundaries": dict(BOUNDARIES),
        "readiness_projection": projected_readiness(),
    }


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures: list[str] = []
    readiness = projected_readiness()
    if first != second:
        failures.append("b133:contract_not_deterministic")
    if readiness["pillar_counts"] != {"READY": 7, "PARTIAL": 1, "BLOCKED": 2}:
        failures.append("b133:readiness_counts_invalid")
    if readiness["release_blockers"] != ["CODE_SIGNING", "LICENSING_TRIAL", "PRIVACY_SUPPORT"]:
        failures.append("b133:readiness_blockers_invalid")
    if readiness["release_blocker_count"] != 3:
        failures.append("b133:readiness_blocker_count_invalid")
    for key, value in BOUNDARIES.items():
        expected_true = {
            "per_user_install",
        }
        if key in expected_true:
            if value is not True:
                failures.append(f"b133:{key}_invalid")
        elif value is not False:
            failures.append(f"b133:{key}_unexpectedly_enabled")
    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "contract_digest": _digest(first),
        "deterministic_contract": first == second,
        "readiness_projection": readiness,
        "installer_foundation_ready": True,
        "per_user_install": True,
        "administrator_required": False,
        "persistent_data_preserved_by_default": True,
        "unknown_install_children_preserved": True,
        "artifact_signed": False,
        "signing_deferred_to_b134": True,
        "service_registration": False,
        "driver_registration": False,
        "autostart_registration": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--write-payload-manifest", action="store_true")
    actions.add_argument("--write-installer-evidence", action="store_true")
    actions.add_argument("--validate-payload-manifest", action="store_true")
    actions.add_argument("--validate-installer-evidence", action="store_true")
    parser.add_argument("--root")
    parser.add_argument("--installer")
    parser.add_argument("--payload-manifest")
    parser.add_argument("--output")
    parser.add_argument("--build-commit")
    parser.add_argument("--python-version")
    parser.add_argument("--pyinstaller-version")
    parser.add_argument("--nsis-version", default=NSIS_VERSION)
    args = parser.parse_args()

    if not any((
        args.write_payload_manifest,
        args.write_installer_evidence,
        args.validate_payload_manifest,
        args.validate_installer_evidence,
    )):
        report = self_check()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1

    if args.write_payload_manifest:
        if not all((args.root, args.build_commit, args.python_version, args.pyinstaller_version)):
            parser.error("--write-payload-manifest requires --root --build-commit --python-version --pyinstaller-version")
        path = write_payload_manifest(
            Path(args.root),
            build_commit=args.build_commit,
            python_version=args.python_version,
            pyinstaller_version=args.pyinstaller_version,
        )
        print(path)
        return 0

    if args.validate_payload_manifest:
        if not args.payload_manifest:
            parser.error("--validate-payload-manifest requires --payload-manifest")
        data = _load_json(Path(args.payload_manifest))
        failures = validate_payload_manifest(
            data,
            root=Path(args.root) if args.root else None,
            expected_build_commit=args.build_commit,
        )
        print(json.dumps({"passed": not failures, "failures": list(failures)}, indent=2, sort_keys=True))
        return 0 if not failures else 1

    if args.write_installer_evidence:
        if not all((args.installer, args.payload_manifest, args.output, args.build_commit)):
            parser.error("--write-installer-evidence requires --installer --payload-manifest --output --build-commit")
        payload = _load_json(Path(args.payload_manifest))
        evidence = build_installer_evidence(
            Path(args.installer),
            payload_manifest=payload,
            build_commit=args.build_commit,
            nsis_version=args.nsis_version,
        )
        Path(args.output).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(args.output)
        return 0

    if not all((args.installer, args.output)):
        parser.error("--validate-installer-evidence requires --installer and --output")
    evidence = _load_json(Path(args.output))
    failures = validate_installer_evidence(
        evidence,
        installer_path=Path(args.installer),
        expected_build_commit=args.build_commit,
    )
    print(json.dumps({"passed": not failures, "failures": list(failures)}, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
