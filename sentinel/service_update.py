from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import time
from typing import Any, BinaryIO, Iterator

from .service_hardening import (
    INTEGRITY_KEY_PATH,
    IntegrityVerifier,
    MANIFEST_FILENAME,
    ensure_integrity_key,
)
from .path_security import has_reparse_component, is_reparse_point

UPDATE_DATA_DIR_NAME = "Updates"
LEGACY_AUTHENTICATED_BASELINE_VERSION = "0.6.1-beta.5"
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)(?:\.(\d+))?)?$", re.I)
_JOURNAL_SCHEMA = 2
_RETRYABLE_WINERRORS = {5, 32, 33}  # access denied / sharing / lock violation


class UpdateError(RuntimeError):
    pass


def version_key(value: str) -> tuple[int, int, int, int, int]:
    match = _VERSION_RE.fullmatch(str(value).strip())
    if not match:
        raise UpdateError(f"unsupported BC Sentinel version: {value}")
    major, minor, patch = map(int, match.group(1, 2, 3))
    label = (match.group(4) or "stable").lower()
    ordinal = int(match.group(5) or 0)
    rank = {"alpha": 0, "beta": 1, "rc": 2, "stable": 3}[label]
    return major, minor, patch, rank, ordinal


def _safe_manifest_rel(value: str) -> Path:
    raw = str(value or "")
    posix = PurePosixPath(raw)
    if not raw or posix.is_absolute() or ".." in posix.parts or any(part in {"", "."} for part in posix.parts):
        raise UpdateError(f"unsafe manifest path: {raw!r}")
    if "\\" in raw or ":" in raw:
        raise UpdateError(f"unsafe manifest path: {raw!r}")
    return Path(*posix.parts)


def _manifest_path(root: Path) -> Path:
    return root / MANIFEST_FILENAME


def _read_manifest_bytes(root: Path) -> bytes:
    path = _manifest_path(root)
    if is_reparse_point(path):
        raise UpdateError("update manifest cannot be a reparse point")
    try:
        with path.open("rb") as handle:
            return handle.read()
    except Exception as exc:
        raise UpdateError(f"cannot read update manifest: {exc}") from exc


def _manifest_digest(root: Path) -> str:
    return hashlib.sha256(_read_manifest_bytes(root)).hexdigest()


def read_manifest(root: str | Path, *, allow_legacy_version: bool = False) -> dict[str, Any]:
    root = Path(root).resolve()
    try:
        obj = json.loads(_read_manifest_bytes(root).decode("utf-8"))
    except UpdateError:
        raise
    except Exception as exc:
        raise UpdateError(f"cannot read update manifest: {exc}") from exc
    if not isinstance(obj, dict) or obj.get("schema") != 1 or not isinstance(obj.get("files"), dict):
        raise UpdateError("update manifest schema is invalid")
    version = str(obj.get("product_version") or "").strip()
    if not version and allow_legacy_version:
        obj["product_version"] = LEGACY_AUTHENTICATED_BASELINE_VERSION
    else:
        version_key(version)
    for rel, expected in obj["files"].items():
        _safe_manifest_rel(rel)
        if not isinstance(expected, dict):
            raise UpdateError(f"invalid manifest entry: {rel}")
        digest = str(expected.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise UpdateError(f"invalid manifest hash: {rel}")
        try:
            size = int(expected.get("size", -1))
        except Exception as exc:
            raise UpdateError(f"invalid manifest size: {rel}") from exc
        if size < 0:
            raise UpdateError(f"invalid manifest size: {rel}")
    return obj


def manifest_version(root: str | Path) -> str:
    return str(read_manifest(root)["product_version"])


def _path_identity(path: Path) -> tuple[int, int, int, int]:
    st = path.stat()
    return (
        int(getattr(st, "st_dev", 0) or 0),
        int(getattr(st, "st_ino", 0) or 0),
        int(getattr(st, "st_ctime_ns", 0) or 0),
        int(getattr(st, "st_mtime_ns", 0) or 0),
    )


def _is_root_path(path: Path) -> bool:
    resolved = path.resolve()
    return resolved == Path(resolved.anchor)


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def _assert_disjoint_paths(*paths: Path) -> None:
    resolved = [p.resolve() for p in paths]
    for p in resolved:
        if _is_root_path(p):
            raise UpdateError(f"transaction path cannot be a filesystem root: {p}")
    for i, left in enumerate(resolved):
        for right in resolved[i + 1:]:
            if left == right or _contains(left, right) or _contains(right, left):
                raise UpdateError(f"update transaction paths overlap: {left} <-> {right}")


@dataclass(slots=True)
class UpdatePlan:
    mode: str
    source: str
    target: str
    current_version: str
    target_version: str
    source_files_checked: int
    source_manifest_ok: bool
    source_manifest_sha256: str = ""
    current_manifest_sha256: str = ""
    source_identity: tuple[int, int, int, int] = (0, 0, 0, 0)
    target_identity: tuple[int, int, int, int] = (0, 0, 0, 0)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_update_source(
    source: str | Path,
    target: str | Path,
    *,
    mode: str = "upgrade",
    current_key_path: Path = INTEGRITY_KEY_PATH,
    current_signature_path: Path | None = None,
) -> UpdatePlan:
    source = Path(source).resolve()
    target = Path(target).resolve()
    mode = str(mode).strip().lower()
    if mode not in {"upgrade", "repair"}:
        raise UpdateError("mode must be upgrade or repair")
    _assert_disjoint_paths(source, target)
    if has_reparse_component(source, include_leaf=True) or is_reparse_point(source):
        raise UpdateError("update source cannot traverse a reparse point")
    if has_reparse_component(target, include_leaf=True) or is_reparse_point(target):
        raise UpdateError("protected target cannot traverse a reparse point")
    if not source.is_dir():
        raise UpdateError("update source directory does not exist")
    if not target.is_dir():
        raise UpdateError("current protected install directory does not exist")

    src_manifest = read_manifest(source)
    current_verifier = IntegrityVerifier(
        target,
        key_path=current_key_path,
        signature_path=current_signature_path or current_key_path.with_name("protection-integrity.sig"),
    )
    current_auth = current_verifier.verify(require_signature=True, full=False)
    if not current_auth.ok:
        raise UpdateError("current protected install is not authenticated/healthy: " + "; ".join(current_auth.issues[:8]))
    current_manifest = read_manifest(target, allow_legacy_version=True)
    source_version = str(src_manifest["product_version"])
    current_version = str(current_manifest["product_version"])
    src_key = version_key(source_version)
    current_key = version_key(current_version)
    if mode == "upgrade" and src_key <= current_key:
        raise UpdateError(f"anti-downgrade: upgrade target {source_version} must be newer than {current_version}")
    if mode == "repair" and src_key != current_key:
        raise UpdateError(f"repair requires the same version ({current_version}), got {source_version}")

    verifier = IntegrityVerifier(source)
    result = verifier.verify(require_signature=False, full=True)
    if not result.ok:
        raise UpdateError("source integrity verification failed: " + "; ".join(result.issues[:8]))
    return UpdatePlan(
        mode=mode,
        source=str(source),
        target=str(target),
        current_version=current_version,
        target_version=source_version,
        source_files_checked=result.checked_files,
        source_manifest_ok=True,
        source_manifest_sha256=_manifest_digest(source),
        current_manifest_sha256=_manifest_digest(target),
        source_identity=_path_identity(source),
        target_identity=_path_identity(target),
    )


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_retryable_replace_error(exc: OSError) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if getattr(exc, "winerror", None) in _RETRYABLE_WINERRORS:
        return True
    return exc.errno in {errno.EACCES, errno.EPERM, errno.EBUSY}


def _replace_with_retry(source: Path, target: Path, *, attempts: int = 7, delay: float = 0.04) -> None:
    last: OSError | None = None
    for index in range(max(1, attempts)):
        try:
            os.replace(source, target)
            return
        except OSError as exc:
            last = exc
            if not _is_retryable_replace_error(exc) or index + 1 >= attempts:
                raise
            time.sleep(delay * (index + 1))
    if last is not None:
        raise last


def _signed_journal_write(path: Path, body: dict[str, Any]) -> None:
    key = ensure_integrity_key(INTEGRITY_KEY_PATH)
    payload = dict(body)
    payload.pop("hmac", None)
    payload["hmac"] = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique temporary journal names avoid collision with a still-open prior temp file.
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    with tmp.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    _replace_with_retry(tmp, path)


def verify_signed_journal(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise UpdateError("update transaction journal schema is invalid")
    supplied = str(obj.pop("hmac", ""))
    expected = hmac.new(ensure_integrity_key(INTEGRITY_KEY_PATH), _canonical(obj), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise UpdateError("update transaction journal HMAC verification failed")
    obj["hmac"] = supplied
    return obj


@contextmanager
def _transaction_lock(target: Path) -> Iterator[None]:
    lock_path = target.parent / f".{target.name}.bc-update.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise UpdateError("another BC Sentinel update transaction is active") from exc
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise UpdateError("another BC Sentinel update transaction is active") from exc
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        handle.close()


def _clone_staging_dacl(source: Path, staging: Path) -> None:
    """Copy the protected directory DACL on Windows; sibling inheritance is not trusted blindly."""
    if os.name != "nt":
        return
    try:
        import win32security
        info = win32security.DACL_SECURITY_INFORMATION
        sd = win32security.GetFileSecurity(str(source), info)
        win32security.SetFileSecurity(str(staging), info, sd)
    except Exception as exc:
        raise UpdateError(f"cannot apply protected staging DACL: {type(exc).__name__}: {exc}") from exc


def _open_bound_source_files(source: Path, manifest: dict[str, Any]) -> list[tuple[str, dict[str, Any], BinaryIO]]:
    opened: list[tuple[str, dict[str, Any], BinaryIO]] = []
    try:
        for rel, expected in sorted(manifest["files"].items()):
            relative = _safe_manifest_rel(rel)
            path = source / relative
            if has_reparse_component(path, include_leaf=True) or is_reparse_point(path):
                raise UpdateError(f"source manifest entry traverses a reparse point: {rel}")
            handle = path.open("rb")
            try:
                st = os.fstat(handle.fileno())
                if int(st.st_size) != int(expected["size"]):
                    raise UpdateError(f"source size changed after approval: {rel}")
            except Exception:
                handle.close()
                raise
            opened.append((rel, expected, handle))
        return opened
    except Exception:
        for _, _, handle in opened:
            try:
                handle.close()
            except Exception:
                pass
        raise


def _copy_bound_source_tree(source: Path, staging: Path, *, expected_manifest_sha256: str, expected_identity: tuple[int, int, int, int]) -> int:
    if _path_identity(source) != tuple(expected_identity):
        raise UpdateError("update source root identity changed after approval")
    manifest_bytes = _read_manifest_bytes(source)
    actual_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if not hmac.compare_digest(actual_manifest_sha256, expected_manifest_sha256):
        raise UpdateError("update source manifest changed after approval")
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    # Validate the already-bound manifest object without reopening via read_manifest.
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict):
        raise UpdateError("bound source manifest schema is invalid")

    staging.mkdir(parents=False, exist_ok=False)
    opened = _open_bound_source_files(source, manifest)
    copied = 0
    try:
        for rel, expected, handle in opened:
            relative = _safe_manifest_rel(rel)
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            size = 0
            with destination.open("xb") as out:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            if size != int(expected["size"]) or not hmac.compare_digest(digest.hexdigest(), str(expected["sha256"]).lower()):
                raise UpdateError(f"source file changed during pinned copy: {rel}")
            copied += 1
        (staging / MANIFEST_FILENAME).write_bytes(manifest_bytes)
    finally:
        for _, _, handle in opened:
            try:
                handle.close()
            except Exception:
                pass
    if _path_identity(source) != tuple(expected_identity):
        raise UpdateError("update source root identity changed during staging")
    return copied


def _verify_tree_against_manifest(root: Path, expected_manifest_sha256: str) -> None:
    actual = _manifest_digest(root)
    if not hmac.compare_digest(actual, str(expected_manifest_sha256)):
        raise UpdateError("tree manifest identity does not match the approved transaction")
    result = IntegrityVerifier(root).verify(require_signature=False, full=True)
    if not result.ok:
        raise UpdateError("tree integrity verification failed: " + "; ".join(result.issues[:8]))


def apply_update_transaction(
    source: str | Path,
    target: str | Path,
    backup_root: str | Path,
    *,
    mode: str = "upgrade",
    current_key_path: Path = INTEGRITY_KEY_PATH,
    current_signature_path: Path | None = None,
) -> dict[str, Any]:
    source = Path(source).resolve()
    target = Path(target).resolve()
    backup_root = Path(backup_root).resolve()
    _assert_disjoint_paths(source, target, backup_root)
    if has_reparse_component(backup_root, include_leaf=False) or is_reparse_point(backup_root):
        raise UpdateError("backup/journal root cannot traverse a reparse point")
    backup_root.mkdir(parents=True, exist_ok=True)

    with _transaction_lock(target):
        plan = validate_update_source(
            source, target, mode=mode,
            current_key_path=current_key_path,
            current_signature_path=current_signature_path,
        )
        stamp = time.strftime("%Y%m%d-%H%M%S")
        transaction_id = f"BCU-{stamp}-{os.getpid()}-{secrets.token_hex(4)}"
        # Promotion and restoration use sibling renames so the previous deployment
        # remains atomically recoverable if the new tree cannot be promoted.
        backup = target.parent / f"{target.name}.backup-{transaction_id}"
        staging = target.parent / f"{target.name}.update-{transaction_id}"
        journal = backup_root / f"{transaction_id}.json"
        _assert_disjoint_paths(source, target, backup_root, backup, staging)
        if backup.exists() or staging.exists() or journal.exists():
            raise UpdateError("update transaction paths already exist")

        body: dict[str, Any] = {
            "schema": _JOURNAL_SCHEMA,
            "transaction_id": transaction_id,
            "mode": plan.mode,
            "status": "prepared",
            "created_unix": time.time(),
            "source": str(source),
            "target": str(target),
            "backup": str(backup),
            "staging": str(staging),
            "journal_root": str(backup_root),
            "current_version": plan.current_version,
            "target_version": plan.target_version,
            "source_manifest_sha256": plan.source_manifest_sha256,
            "current_manifest_sha256": plan.current_manifest_sha256,
            "source_identity": list(plan.source_identity),
            "target_identity": list(plan.target_identity),
        }
        _signed_journal_write(journal, body)
        promoted_old = False
        try:
            copied = _copy_bound_source_tree(
                source, staging,
                expected_manifest_sha256=plan.source_manifest_sha256,
                expected_identity=plan.source_identity,
            )
            _clone_staging_dacl(target, staging)
            _verify_tree_against_manifest(staging, plan.source_manifest_sha256)
            body["status"] = "staged"
            body["staged_files"] = copied
            _signed_journal_write(journal, body)

            # Revalidate the original installed tree identity immediately before rename.
            if _path_identity(target) != tuple(plan.target_identity):
                raise UpdateError("protected target identity changed after approval")
            if not hmac.compare_digest(_manifest_digest(target), plan.current_manifest_sha256):
                raise UpdateError("protected target manifest changed after approval")

            os.replace(target, backup)
            promoted_old = True
            body["backup_manifest_sha256"] = _manifest_digest(backup)
            if not hmac.compare_digest(body["backup_manifest_sha256"], plan.current_manifest_sha256):
                raise UpdateError("backup identity mismatch after atomic rename")
            body["status"] = "old_tree_preserved"
            _signed_journal_write(journal, body)

            try:
                os.replace(staging, target)
            except Exception:
                # Never leave the protected deployment absent after promotion failure.
                if not target.exists() and backup.exists():
                    os.replace(backup, target)
                    promoted_old = False
                raise

            deployed = IntegrityVerifier(target).verify(require_signature=False, full=True)
            if not deployed.ok:
                raise UpdateError("deployed tree integrity failed: " + "; ".join(deployed.issues[:8]))
            body["deployed_manifest_sha256"] = _manifest_digest(target)
            if not hmac.compare_digest(body["deployed_manifest_sha256"], plan.source_manifest_sha256):
                raise UpdateError("deployed manifest differs from approved source")
            body["status"] = "deployed_unsealed"
            body["deployed_unix"] = time.time()
            _signed_journal_write(journal, body)
            return {**body, "journal": str(journal), "source_files_checked": plan.source_files_checked}
        except Exception as exc:
            restore_error = ""
            try:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)
                if promoted_old and backup.exists():
                    if target.exists():
                        failed_tree = target.parent / f"{target.name}.failed-{transaction_id}"
                        if failed_tree.exists():
                            shutil.rmtree(failed_tree, ignore_errors=True)
                        os.replace(target, failed_tree)
                        shutil.rmtree(failed_tree, ignore_errors=True)
                    os.replace(backup, target)
                    promoted_old = False
                if target.exists() and _manifest_digest(target) == plan.current_manifest_sha256:
                    body["status"] = "apply_failed_restored"
                else:
                    body["status"] = "apply_failed"
            except Exception as restore_exc:
                restore_error = f"{type(restore_exc).__name__}: {restore_exc}"
                body["status"] = "apply_failed_restore_failed"
            finally:
                body["failed_unix"] = time.time()
                body["failure"] = f"{type(exc).__name__}: {exc}"[:1000]
                if restore_error:
                    body["restore_failure"] = restore_error[:1000]
                _signed_journal_write(journal, body)
            raise


def mark_transaction(journal: str | Path, status: str, **extra: Any) -> dict[str, Any]:
    path = Path(journal)
    body = verify_signed_journal(path)
    body.pop("hmac", None)
    body["status"] = str(status)
    body["updated_unix"] = time.time()
    body.update(extra)
    _signed_journal_write(path, body)
    return verify_signed_journal(path)


def _validated_schema2_journal(path: Path) -> dict[str, Any]:
    body = verify_signed_journal(path)
    if int(body.get("schema") or 0) != _JOURNAL_SCHEMA:
        raise UpdateError("legacy update journal is not eligible for automatic rollback")
    required = (
        "transaction_id", "target", "backup", "staging", "current_version", "target_version",
        "source_manifest_sha256", "current_manifest_sha256",
    )
    missing = [name for name in required if not str(body.get(name) or "")]
    if missing:
        raise UpdateError("update journal is missing immutable transaction fields: " + ", ".join(missing))
    return body


def rollback_transaction(journal: str | Path) -> dict[str, Any]:
    path = Path(journal)
    body = _validated_schema2_journal(path)
    target = Path(body["target"]).resolve()
    backup = Path(body["backup"]).resolve()
    staging = Path(body["staging"]).resolve()
    _assert_disjoint_paths(target, backup, staging, path.parent.resolve())

    with _transaction_lock(target):
        # Idempotent retry: an already-restored target is a successful no-op.
        if target.is_dir():
            try:
                target_digest = _manifest_digest(target)
            except Exception:
                target_digest = ""
            if body.get("status") == "rolled_back" and hmac.compare_digest(target_digest, str(body["current_manifest_sha256"])):
                return verify_signed_journal(path)

        if not backup.is_dir():
            raise UpdateError("rollback backup is missing")
        backup_digest = _manifest_digest(backup)
        expected_backup = str(body.get("backup_manifest_sha256") or body["current_manifest_sha256"])
        if not hmac.compare_digest(backup_digest, expected_backup):
            raise UpdateError("rollback backup manifest identity does not match authenticated journal")
        _verify_tree_against_manifest(backup, expected_backup)

        if target.exists():
            current_digest = _manifest_digest(target)
            expected_deployed = str(body.get("deployed_manifest_sha256") or body["source_manifest_sha256"])
            if not hmac.compare_digest(current_digest, expected_deployed):
                raise UpdateError("rollback refused: installed release is unrelated to this transaction")
            displaced = target.parent / f"{target.name}.rollback-displaced-{body['transaction_id']}"
            if displaced.exists():
                shutil.rmtree(displaced, ignore_errors=True)
            os.replace(target, displaced)
        else:
            displaced = None

        try:
            os.replace(backup, target)
            _verify_tree_against_manifest(target, str(body["current_manifest_sha256"]))
        except Exception:
            if displaced is not None and displaced.exists() and not target.exists():
                os.replace(displaced, target)
            raise
        if displaced is not None and displaced.exists():
            shutil.rmtree(displaced, ignore_errors=True)
        return mark_transaction(path, "rolled_back", rollback_unix=time.time())


def recover_transaction(journal: str | Path) -> dict[str, Any]:
    """Idempotently restore a missing/failed target from a schema-2 authenticated backup."""
    path = Path(journal)
    body = _validated_schema2_journal(path)
    target = Path(body["target"]).resolve()
    backup = Path(body["backup"]).resolve()
    if target.is_dir():
        digest = _manifest_digest(target)
        if digest in {str(body["current_manifest_sha256"]), str(body.get("deployed_manifest_sha256") or body["source_manifest_sha256"])}:
            return body
        raise UpdateError("recovery refused: target contains an unrelated release")
    if not backup.is_dir():
        raise UpdateError("recovery backup is missing")
    expected = str(body.get("backup_manifest_sha256") or body["current_manifest_sha256"])
    _verify_tree_against_manifest(backup, expected)
    os.replace(backup, target)
    _verify_tree_against_manifest(target, str(body["current_manifest_sha256"]))
    return mark_transaction(path, "recovered", recovery_unix=time.time())
