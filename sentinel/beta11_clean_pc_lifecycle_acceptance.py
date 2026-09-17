from __future__ import annotations

"""B11-8 clean/disposable Windows lifecycle acceptance.

Install, upgrade and uninstall semantics execute against a real filesystem only
inside an explicitly confirmed disposable OS-temp workspace.  The harness never
maps fixture resources to real Program Files, ProgramData, HKLM, Start Menu,
services, drivers, autostart, Defender, firewall or user documents.
"""

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Final

from sentinel import beta11_install_lifecycle_contract as install_contract
from sentinel import beta11_persistent_data_model as persistent
from sentinel import beta11_release_provenance as provenance
from sentinel import beta11_upgrade_migration_contract as migration

SCHEMA: Final[str] = "bc-sentinel-beta11-clean-pc-lifecycle-acceptance-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b118-clean-pc-install-upgrade-uninstall-acceptance"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b117-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "c7ca5e86af196863cc980bcd1e8616447d9f3d8a"
SOURCE_B113_CONTRACT_DIGEST: Final[str] = "f084b67d16b87e17722e70890be13ba33fcd10d7c3ece43b499fcb01020e5aa6"
SOURCE_B115_MODEL_DIGEST: Final[str] = "38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08"
SOURCE_B116_CONTRACT_DIGEST: Final[str] = "d2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9"
SOURCE_B117_CONTRACT_DIGEST: Final[str] = "a19d1ea8ad887b670cbbb9aef1a09db17e806fd59e5e89b603f9574c1912f109"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

EXECUTION_SCOPE: Final[str] = "EXPLICIT_DISPOSABLE_TEMP_WORKSPACE_ONLY"
WORKSPACE_PREFIX: Final[str] = "BCSentinel-b118-"
MARKER_FILENAME: Final[str] = ".bc-sentinel-b118-disposable.json"
OWNERSHIP_MANIFEST_REL: Final[str] = "ProgramFiles/BC Sentinel/lifecycle-ownership.json"
PERSISTENT_ROOT_REL: Final[str] = "ProgramData/BC Sentinel"
ARTIFACT_FIXTURE_REL: Final[str] = "ProgramFiles/BC Sentinel/BC-Sentinel-Beta11.exe.fixture"
RUNTIME_IDENTITY_REL: Final[str] = "ProgramFiles/BC Sentinel/runtime-identity.json"
SHORTCUT_FIXTURE_REL: Final[str] = "CommonPrograms/BC Sentinel/BC Sentinel.lnk.fixture"
UNINSTALL_METADATA_REL: Final[str] = (
    "RegistryMirror/HKLM/Software/Microsoft/Windows/CurrentVersion/Uninstall/BCSentinel/uninstall.json"
)

LIFECYCLE_POLICY: Final[dict[str, Any]] = {
    "execution_scope": EXECUTION_SCOPE,
    "explicit_confirmation_required": True,
    "workspace_must_be_under_os_temp": True,
    "workspace_prefix_required": WORKSPACE_PREFIX,
    "workspace_marker_required": True,
    "clean_install_requires_marker_only_workspace": True,
    "exact_ownership_manifest_required": True,
    "managed_file_hash_verification_required": True,
    "upgrade_staging_hash_verification_required": True,
    "upgrade_keeps_previous_payload": True,
    "persistent_data_preserved_across_upgrade": True,
    "persistent_data_preserved_on_uninstall": True,
    "unknown_children_preserved_on_uninstall": True,
    "path_escape_fails_closed": True,
    "symlink_workspace_fails_closed": True,
    "tampered_managed_file_fails_closed": True,
    "real_registry_mutation": False,
    "real_program_files_mutation": False,
    "real_program_data_mutation": False,
    "real_start_menu_mutation": False,
}

IMPLEMENTATION_STATE: Final[dict[str, bool]] = {
    "disposable_workspace_lifecycle_execution_available": True,
    "host_machine_scope_install_execution_available": False,
    "host_machine_scope_upgrade_execution_available": False,
    "host_machine_scope_uninstall_execution_available": False,
    "host_registry_mutation_available": False,
    "host_program_files_mutation_available": False,
    "host_program_data_mutation_available": False,
    "host_start_menu_mutation_available": False,
    "privilege_elevation_available": False,
    "service_registration_available": False,
    "driver_registration_available": False,
    "autostart_registration_available": False,
    "automatic_update_execution_available": False,
    "defender_exclusion_mutation_available": False,
    "firewall_mutation_available": False,
    "user_documents_mutation_available": False,
    "artifact_signing_execution_available": False,
    "release_publication_execution_available": False,
    "network_required": False,
    "cloud_required": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


class LifecycleSafetyError(RuntimeError):
    """Raised before mutation whenever the disposable lifecycle boundary fails."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and path.exists() and is_junction())


def _allowed_temp_roots() -> tuple[Path, ...]:
    values = [Path(tempfile.gettempdir()).resolve()]
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        candidate = Path(runner_temp).resolve()
        if candidate not in values:
            values.append(candidate)
    return tuple(values)


def _workspace_root(root: str | os.PathLike[str]) -> Path:
    path = Path(root)
    if not path.exists() or not path.is_dir():
        raise LifecycleSafetyError("b118:workspace_missing")
    if _is_link_or_junction(path):
        raise LifecycleSafetyError("b118:workspace_symlink_rejected")
    resolved = path.resolve()
    if resolved == Path(resolved.anchor):
        raise LifecycleSafetyError("b118:filesystem_root_rejected")
    if not resolved.name.startswith(WORKSPACE_PREFIX):
        raise LifecycleSafetyError("b118:workspace_prefix_invalid")
    if not any(_is_relative_to(resolved, allowed) and resolved != allowed for allowed in _allowed_temp_roots()):
        raise LifecycleSafetyError("b118:workspace_outside_os_temp")
    return resolved


def _safe_path(root: Path, relative: str) -> Path:
    """Return a bounded lexical child path without Windows short-name re-resolution.

    `root` may be represented by Windows using an 8.3 component (for example
    RUNNER~1). Resolving a deeper existing child can expand that component and
    make a purely lexical `Path.relative_to` check fail even though the child is
    still inside the same workspace. We therefore reject absolute/parent/drive
    syntax up front and walk existing ancestors for symlink/junction escapes,
    without re-resolving the candidate path.
    """

    candidate_rel = Path(relative)
    parts = candidate_rel.parts
    if (
        not parts
        or candidate_rel.is_absolute()
        or any(part in {"..", "", "."} or ":" in part for part in parts)
    ):
        raise LifecycleSafetyError("b118:path_escape_rejected")

    current = root
    for part in parts[:-1]:
        current = current / part
        if current.exists() and _is_link_or_junction(current):
            raise LifecycleSafetyError("b118:path_escape_rejected")

    candidate = root.joinpath(*parts)
    if candidate == root:
        raise LifecycleSafetyError("b118:path_escape_rejected")
    return candidate


def _marker_payload() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "purpose": "B11-8-DISPOSABLE-LIFECYCLE",
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "execution_scope": EXECUTION_SCOPE,
    }


def initialize_disposable_workspace(
    root: str | os.PathLike[str], *, confirmed: bool
) -> dict[str, Any]:
    if confirmed is not True:
        raise LifecycleSafetyError("b118:explicit_confirmation_required")
    workspace = _workspace_root(root)
    if any(workspace.iterdir()):
        raise LifecycleSafetyError("b118:workspace_not_clean")
    marker = _safe_path(workspace, MARKER_FILENAME)
    marker.write_text(_canonical(_marker_payload()), encoding="utf-8")
    return {"workspace_initialized": True, "marker_digest": _sha256_file(marker)}


def _verify_workspace(root: str | os.PathLike[str]) -> Path:
    workspace = _workspace_root(root)
    marker = _safe_path(workspace, MARKER_FILENAME)
    if not marker.is_file() or _is_link_or_junction(marker):
        raise LifecycleSafetyError("b118:workspace_marker_missing")
    try:
        observed = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LifecycleSafetyError("b118:workspace_marker_invalid") from exc
    if observed != _marker_payload():
        raise LifecycleSafetyError("b118:workspace_marker_invalid")
    return workspace


def _write_bytes(root: Path, relative: str, payload: bytes) -> dict[str, Any]:
    target = _safe_path(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    if _is_link_or_junction(target):
        raise LifecycleSafetyError("b118:managed_target_symlink_rejected")
    target.write_bytes(payload)
    return {"path": relative, "sha256": _sha256_bytes(payload)}


def _fixture_payload(version: str) -> dict[str, tuple[str, bytes]]:
    runtime = _canonical(
        {
            "artifact": "BC-Sentinel-Beta11.exe",
            "fixture_only": True,
            "version": version,
            "runtime_identity": "BC_SENTINEL_DESKTOP",
        }
    ).encode("utf-8")
    uninstall = _canonical(
        {
            "display_name": "BC Sentinel",
            "fixture_only": True,
            "version": version,
            "uninstall_scope": EXECUTION_SCOPE,
        }
    ).encode("utf-8")
    return {
        ARTIFACT_FIXTURE_REL: (
            "APPLICATION_PAYLOAD",
            f"BC Sentinel fixture payload {version}\n".encode("utf-8"),
        ),
        RUNTIME_IDENTITY_REL: ("APPLICATION_PAYLOAD", runtime),
        SHORTCUT_FIXTURE_REL: (
            "START_MENU_SHORTCUT",
            b"BC Sentinel disposable shortcut fixture\n",
        ),
        UNINSTALL_METADATA_REL: ("UNINSTALL_METADATA", uninstall),
    }


def _manifest_payload(version: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "bc-sentinel-beta11-b118-ownership-manifest-v1",
        "product": "BC Sentinel",
        "version": version,
        "execution_scope": EXECUTION_SCOPE,
        "managed_files": sorted(entries, key=lambda item: item["path"]),
        "persistent_root": PERSISTENT_ROOT_REL,
        "persistent_data_removed_by_default": False,
        "unknown_children_preserved": True,
    }


def _write_manifest(root: Path, version: str, entries: list[dict[str, Any]]) -> str:
    manifest = _manifest_payload(version, entries)
    target = _safe_path(root, OWNERSHIP_MANIFEST_REL)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_canonical(manifest), encoding="utf-8")
    return _digest(manifest)


def _read_manifest(root: Path) -> dict[str, Any]:
    target = _safe_path(root, OWNERSHIP_MANIFEST_REL)
    if not target.is_file() or _is_link_or_junction(target):
        raise LifecycleSafetyError("b118:ownership_manifest_missing")
    try:
        manifest = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LifecycleSafetyError("b118:ownership_manifest_invalid") from exc
    required = {
        "schema",
        "product",
        "version",
        "execution_scope",
        "managed_files",
        "persistent_root",
        "persistent_data_removed_by_default",
        "unknown_children_preserved",
    }
    if set(manifest) != required:
        raise LifecycleSafetyError("b118:ownership_manifest_invalid")
    if (
        manifest.get("schema") != "bc-sentinel-beta11-b118-ownership-manifest-v1"
        or manifest.get("product") != "BC Sentinel"
        or manifest.get("execution_scope") != EXECUTION_SCOPE
        or manifest.get("persistent_root") != PERSISTENT_ROOT_REL
        or manifest.get("persistent_data_removed_by_default") is not False
        or manifest.get("unknown_children_preserved") is not True
        or not isinstance(manifest.get("managed_files"), list)
    ):
        raise LifecycleSafetyError("b118:ownership_manifest_invalid")
    return manifest


def _verify_managed_files(root: Path, manifest: dict[str, Any]) -> None:
    seen: set[str] = set()
    for entry in manifest["managed_files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "resource_id"}:
            raise LifecycleSafetyError("b118:ownership_entry_invalid")
        relative = str(entry["path"])
        if relative in seen:
            raise LifecycleSafetyError("b118:duplicate_owned_path")
        seen.add(relative)
        target = _safe_path(root, relative)
        if not target.is_file() or _is_link_or_junction(target):
            raise LifecycleSafetyError("b118:managed_file_missing")
        if _sha256_file(target) != entry["sha256"]:
            raise LifecycleSafetyError("b118:managed_file_hash_mismatch")


def install_fixture(
    root: str | os.PathLike[str], *, version: str = "0.11.0-b118-a"
) -> dict[str, Any]:
    workspace = _verify_workspace(root)
    unexpected = [item for item in workspace.iterdir() if item.name != MARKER_FILENAME]
    if unexpected:
        raise LifecycleSafetyError("b118:clean_install_workspace_not_empty")

    entries: list[dict[str, Any]] = []
    for relative, (resource_id, payload) in sorted(_fixture_payload(version).items()):
        written = _write_bytes(workspace, relative, payload)
        entries.append({**written, "resource_id": resource_id})
    manifest_digest = _write_manifest(workspace, version, entries)
    return {
        "operation": "INSTALL",
        "version": version,
        "managed_file_count": len(entries),
        "ownership_manifest_digest": manifest_digest,
    }


def _tree_digest(root: Path, relative_root: str) -> str:
    base = _safe_path(root, relative_root)
    if not base.exists():
        return _digest([])
    if not base.is_dir() or _is_link_or_junction(base):
        raise LifecycleSafetyError("b118:tree_root_invalid")
    inventory: list[dict[str, str]] = []
    for path in sorted(base.rglob("*"), key=lambda item: item.as_posix()):
        if _is_link_or_junction(path):
            raise LifecycleSafetyError("b118:tree_symlink_rejected")
        if path.is_file():
            inventory.append(
                {
                    "path": path.relative_to(base).as_posix(),
                    "sha256": _sha256_file(path),
                }
            )
    return _digest(inventory)


def seed_runtime_persistent_data(root: str | os.PathLike[str]) -> dict[str, Any]:
    workspace = _verify_workspace(root)
    _read_manifest(workspace)
    payloads = {
        f"{PERSISTENT_ROOT_REL}/state/settings.json": b'{"schema":"bc-sentinel-config-state-v1","mode":"local"}',
        f"{PERSISTENT_ROOT_REL}/logs/session.log": b"B11-8 persistent log fixture\n",
        f"{PERSISTENT_ROOT_REL}/quarantine/metadata/index.json": b'{"records":1}',
        f"{PERSISTENT_ROOT_REL}/quarantine/payloads/sample.quarantine": b"inert-quarantine-fixture",
        f"{PERSISTENT_ROOT_REL}/lifecycle/state.json": b'{"owner":"BC Sentinel","fixture":true}',
    }
    for relative, payload in sorted(payloads.items()):
        _write_bytes(workspace, relative, payload)
    return {
        "operation": "RUNTIME_DATA_SEED",
        "persistent_file_count": len(payloads),
        "persistent_tree_digest": _tree_digest(workspace, PERSISTENT_ROOT_REL),
    }


def upgrade_fixture(
    root: str | os.PathLike[str], *, target_version: str = "0.11.0-b118-b"
) -> dict[str, Any]:
    workspace = _verify_workspace(root)
    manifest = _read_manifest(workspace)
    _verify_managed_files(workspace, manifest)
    source_version = str(manifest["version"])
    if source_version == target_version:
        raise LifecycleSafetyError("b118:upgrade_target_not_new")

    persistent_before = _tree_digest(workspace, PERSISTENT_ROOT_REL)
    staging_rel = f".b118-staging/{target_version}"
    staging = _safe_path(workspace, staging_rel)
    if staging.exists():
        raise LifecycleSafetyError("b118:staging_already_exists")
    staging.mkdir(parents=True, exist_ok=False)

    staged: dict[str, tuple[str, bytes, str]] = {}
    target_fixture = _fixture_payload(target_version)
    try:
        for relative, (resource_id, payload) in sorted(target_fixture.items()):
            staged_rel = f"{staging_rel}/{relative}"
            written = _write_bytes(workspace, staged_rel, payload)
            if written["sha256"] != _sha256_bytes(payload):
                raise LifecycleSafetyError("b118:staging_hash_mismatch")
            staged[relative] = (resource_id, payload, written["sha256"])

        kept_entries: list[dict[str, Any]] = []
        for relative in (ARTIFACT_FIXTURE_REL, RUNTIME_IDENTITY_REL):
            current = _safe_path(workspace, relative)
            previous_rel = (
                f"ProgramFiles/BC Sentinel/.previous/{source_version}/{Path(relative).name}"
            )
            previous = _safe_path(workspace, previous_rel)
            previous.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(current, previous)
            kept_entries.append(
                {
                    "path": previous_rel,
                    "sha256": _sha256_file(previous),
                    "resource_id": "APPLICATION_PAYLOAD_KEPT_SOURCE",
                }
            )

        new_entries: list[dict[str, Any]] = []
        for relative, (resource_id, _payload, expected_hash) in sorted(staged.items()):
            staged_file = _safe_path(workspace, f"{staging_rel}/{relative}")
            if _sha256_file(staged_file) != expected_hash:
                raise LifecycleSafetyError("b118:staging_hash_mismatch")
            target = _safe_path(workspace, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(staged_file, target)
            if _sha256_file(target) != expected_hash:
                raise LifecycleSafetyError("b118:activated_hash_mismatch")
            new_entries.append(
                {"path": relative, "sha256": expected_hash, "resource_id": resource_id}
            )

        manifest_digest = _write_manifest(
            workspace, target_version, new_entries + kept_entries
        )
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        staging_parent = _safe_path(workspace, ".b118-staging")
        if staging_parent.exists() and not any(staging_parent.iterdir()):
            staging_parent.rmdir()

    persistent_after = _tree_digest(workspace, PERSISTENT_ROOT_REL)
    if persistent_after != persistent_before:
        raise LifecycleSafetyError("b118:persistent_data_changed_during_upgrade")

    return {
        "operation": "UPGRADE",
        "source_version": source_version,
        "target_version": target_version,
        "kept_source_file_count": len(kept_entries),
        "persistent_tree_digest_before": persistent_before,
        "persistent_tree_digest_after": persistent_after,
        "ownership_manifest_digest": manifest_digest,
    }


def _remove_empty_parents(path: Path, stop: Path) -> None:
    current = path
    while current != stop and _is_relative_to(current, stop):
        if (
            not current.exists()
            or not current.is_dir()
            or _is_link_or_junction(current)
            or any(current.iterdir())
        ):
            return
        current.rmdir()
        current = current.parent


def uninstall_fixture(root: str | os.PathLike[str]) -> dict[str, Any]:
    workspace = _verify_workspace(root)
    manifest = _read_manifest(workspace)
    _verify_managed_files(workspace, manifest)
    persistent_before = _tree_digest(workspace, PERSISTENT_ROOT_REL)

    entries = list(manifest["managed_files"])
    for entry in sorted(
        entries, key=lambda item: len(Path(item["path"]).parts), reverse=True
    ):
        target = _safe_path(workspace, str(entry["path"]))
        target.unlink()
        _remove_empty_parents(target.parent, workspace)

    manifest_path = _safe_path(workspace, OWNERSHIP_MANIFEST_REL)
    if manifest_path.exists():
        manifest_path.unlink()
        _remove_empty_parents(manifest_path.parent, workspace)

    persistent_after = _tree_digest(workspace, PERSISTENT_ROOT_REL)
    if persistent_after != persistent_before:
        raise LifecycleSafetyError("b118:persistent_data_changed_during_uninstall")

    return {
        "operation": "UNINSTALL",
        "removed_managed_file_count": len(entries),
        "ownership_manifest_removed": not manifest_path.exists(),
        "persistent_tree_digest_before": persistent_before,
        "persistent_tree_digest_after": persistent_after,
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_b113_contract_digest": install_contract.self_check()["contract_digest"],
        "source_b115_model_digest": persistent.self_check()["model_digest"],
        "source_b116_contract_digest": migration.self_check()["contract_digest"],
        "source_b117_contract_digest": provenance.self_check()["contract_digest"],
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "execution_scope": EXECUTION_SCOPE,
        "lifecycle_policy": dict(LIFECYCLE_POLICY),
        "implementation_state": dict(IMPLEMENTATION_STATE),
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b118:not_object",)
    failures: list[str] = []
    expected_keys = {
        "schema",
        "profile",
        "source_checkpoint",
        "source_checkpoint_commit",
        "source_b113_contract_digest",
        "source_b115_model_digest",
        "source_b116_contract_digest",
        "source_b117_contract_digest",
        "source_coverage",
        "verified_scenarios",
        "execution_scope",
        "lifecycle_policy",
        "implementation_state",
    }
    if set(data) != expected_keys:
        failures.append("b118:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("b118:identity_invalid")
    if (
        data.get("source_checkpoint") != SOURCE_CHECKPOINT
        or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT
    ):
        failures.append("b118:source_checkpoint_invalid")
    bindings = {
        "source_b113_contract_digest": SOURCE_B113_CONTRACT_DIGEST,
        "source_b115_model_digest": SOURCE_B115_MODEL_DIGEST,
        "source_b116_contract_digest": SOURCE_B116_CONTRACT_DIGEST,
        "source_b117_contract_digest": SOURCE_B117_CONTRACT_DIGEST,
    }
    for key, expected in bindings.items():
        if data.get(key) != expected:
            failures.append(f"b118:accepted_binding_invalid:{key}")
    if data.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b118:coverage_changed")
    if tuple(data.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b118:verified_scenarios_changed")
    if (
        data.get("execution_scope") != EXECUTION_SCOPE
        or data.get("lifecycle_policy") != LIFECYCLE_POLICY
    ):
        failures.append("b118:lifecycle_policy_changed")
    state = data.get("implementation_state")
    if state != IMPLEMENTATION_STATE:
        failures.append("b118:implementation_state_changed")
    elif state.get("disposable_workspace_lifecycle_execution_available") is not True:
        failures.append("b118:disposable_execution_missing")
    elif any(
        value
        for key, value in state.items()
        if key != "disposable_workspace_lifecycle_execution_available"
    ):
        failures.append("b118:host_authority_or_claim_expanded")
    return tuple(dict.fromkeys(failures))


def run_disposable_acceptance() -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    outside_canary_preserved = False
    unknown_child_preserved = False
    persistent_data_preserved = False
    unsafe_scope_rejected = False

    with tempfile.TemporaryDirectory(prefix="BCSentinel-b118-parent-") as parent_text:
        parent = Path(parent_text)
        workspace = parent / f"{WORKSPACE_PREFIX}workspace"
        workspace.mkdir()
        outside_canary = parent / "outside-canary.txt"
        outside_canary.write_text("outside-workspace-canary", encoding="utf-8")

        initialize_disposable_workspace(workspace, confirmed=True)
        events.append(install_fixture(workspace))
        seeded = seed_runtime_persistent_data(workspace)
        events.append(seeded)

        unknown = _safe_path(
            workspace, "ProgramFiles/BC Sentinel/operator-owned.keep"
        )
        unknown.parent.mkdir(parents=True, exist_ok=True)
        unknown.write_text("must survive product uninstall", encoding="utf-8")

        events.append(upgrade_fixture(workspace))
        events.append(uninstall_fixture(workspace))

        unknown_child_preserved = (
            unknown.read_text(encoding="utf-8") == "must survive product uninstall"
        )
        persistent_after = _tree_digest(workspace, PERSISTENT_ROOT_REL)
        persistent_data_preserved = (
            persistent_after == seeded["persistent_tree_digest"]
        )
        outside_canary_preserved = (
            outside_canary.read_text(encoding="utf-8") == "outside-workspace-canary"
        )

        unsafe = parent / "not-a-b118-workspace"
        unsafe.mkdir()
        try:
            initialize_disposable_workspace(unsafe, confirmed=True)
        except LifecycleSafetyError:
            unsafe_scope_rejected = True

    transcript_digest = _digest(events)
    passed = all(
        (
            unknown_child_preserved,
            persistent_data_preserved,
            outside_canary_preserved,
            unsafe_scope_rejected,
            len(events) == 4,
        )
    )
    return {
        "passed": passed,
        "event_count": len(events),
        "events": events,
        "transcript_digest": transcript_digest,
        "unknown_child_preserved": unknown_child_preserved,
        "persistent_data_preserved": persistent_data_preserved,
        "outside_canary_preserved": outside_canary_preserved,
        "unsafe_scope_rejected": unsafe_scope_rejected,
    }


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic_contract = first == second and _digest(first) == _digest(second)
    if not deterministic_contract:
        failures.append("b118:contract_not_deterministic")

    lifecycle = run_disposable_acceptance()
    if not lifecycle["passed"]:
        failures.append("b118:disposable_lifecycle_failed")

    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_b113_contract_digest": first["source_b113_contract_digest"],
        "source_b115_model_digest": first["source_b115_model_digest"],
        "source_b116_contract_digest": first["source_b116_contract_digest"],
        "source_b117_contract_digest": first["source_b117_contract_digest"],
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "execution_scope": EXECUTION_SCOPE,
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic_contract,
        "lifecycle_event_count": lifecycle["event_count"],
        "lifecycle_transcript_digest": lifecycle["transcript_digest"],
        "unknown_child_preserved": lifecycle["unknown_child_preserved"],
        "persistent_data_preserved": lifecycle["persistent_data_preserved"],
        "outside_canary_preserved": lifecycle["outside_canary_preserved"],
        "unsafe_scope_rejected": lifecycle["unsafe_scope_rejected"],
        "disposable_workspace_lifecycle_execution_available": True,
        "host_machine_scope_install_execution_available": False,
        "host_machine_scope_upgrade_execution_available": False,
        "host_machine_scope_uninstall_execution_available": False,
        "host_registry_mutation_available": False,
        "privilege_elevation_available": False,
        "service_or_driver_registration_available": False,
        "autostart_registration_available": False,
        "network_required": False,
        "cloud_required": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-disposable-acceptance", action="store_true")
    args = parser.parse_args(argv)
    if not args.run_disposable_acceptance:
        print(
            json.dumps(
                {
                    "passed": False,
                    "failures": ["b118:explicit_execution_flag_required"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
