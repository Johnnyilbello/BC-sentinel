from __future__ import annotations
import hashlib
import os
import string
import uuid
from pathlib import Path

from .config import (
    APP_ROOT,
    DATA_DIR,
    EXE_DIR,
    KEY_PATH,
    PROGRAM_DATA_DIR,
    QUARANTINE_DIR,
    ensure_dirs,
)
from .database import Database
from .path_security import (
    absolute_lexical_path,
    ensure_regular_non_reparse_file,
    is_reparse_point,
    is_within,
    is_within_any,
    secure_write_parent,
    same_file_snapshot,
)


class QuarantineManager:
    def __init__(
        self,
        db: Database | None = None,
        *,
        quarantine_dir: str | Path | None = None,
        key_path: str | Path | None = None,
        managed_roots: tuple[str | Path, ...] | None = None,
    ):
        ensure_dirs()
        self.db = db or Database()
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir is not None else QUARANTINE_DIR
        self.key_path = Path(key_path) if key_path is not None else KEY_PATH
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.quarantine_dir, 0o700)
        except OSError:
            pass
        self.managed_roots = tuple(managed_roots or (APP_ROOT, EXE_DIR, DATA_DIR, PROGRAM_DATA_DIR))
        self._fernet = self._load_fernet()

    def _managed_roots(self):
        return self.managed_roots

    def _is_protected_destination(self, path: str | Path) -> bool:
        return is_within_any(path, self._managed_roots())

    @staticmethod
    def _is_windows_protected_system_path(path: str | Path) -> bool:
        """Fail closed for destructive response inside the Windows OS tree.

        The Protection Service is intentionally not a generic privileged file
        remover.  WINDIR/SystemRoot are kernel/user-session supplied anchors on
        Windows; tests may also inject them explicitly.  Boundary-safe
        containment is delegated to ``is_within`` rather than string prefixes.
        """
        roots: list[str] = []
        for key in ("WINDIR", "SystemRoot"):
            value = str(os.environ.get(key) or "").strip()
            if value and value not in roots:
                roots.append(value)
        return any(is_within(path, root) for root in roots)

    def _load_fernet(self):
        from cryptography.fernet import Fernet

        if is_reparse_point(self.key_path):
            raise ValueError("Quarantine key cannot be a symlink/reparse point.")
        if self.key_path.exists():
            key = self.key_path.read_bytes()
        else:
            secure_write_parent(self.key_path)
            key = Fernet.generate_key()
            try:
                with self.key_path.open("xb") as handle:
                    handle.write(key)
                    handle.flush()
                    os.fsync(handle.fileno())
            except FileExistsError:
                key = self.key_path.read_bytes()
            try:
                os.chmod(self.key_path, 0o600)
            except OSError:
                pass
        # Constructor validates malformed/corrupted key material.
        return Fernet(key)

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()

    @staticmethod
    def _validate_item_id(item_id: str) -> str:
        value = str(item_id or "").strip().casefold()
        if len(value) != 32 or any(c not in string.hexdigits.casefold() for c in value):
            raise ValueError("Invalid quarantine item id.")
        return value

    _same_snapshot = staticmethod(same_file_snapshot)

    def _stored_file(self, stored_path: str | Path) -> Path:
        stored = absolute_lexical_path(stored_path)
        if not is_within(stored, self.quarantine_dir):
            raise ValueError("Quarantine record points outside the managed quarantine directory.")
        return ensure_regular_non_reparse_file(stored)

    def quarantine(
        self,
        source: str | Path,
        score: int,
        reason: str,
        *,
        expected_sha256: str = "",
    ) -> str:
        lexical = absolute_lexical_path(source)
        if is_reparse_point(lexical):
            raise ValueError("Refusing to quarantine a symlink/reparse point.")
        try:
            src = lexical.resolve(strict=True)
        except FileNotFoundError:
            raise FileNotFoundError(str(lexical))
        if not src.is_file():
            raise FileNotFoundError(str(src))
        if self._is_protected_destination(src):
            raise ValueError("Refusing to quarantine BC Sentinel managed files.")
        if self._is_windows_protected_system_path(src):
            raise ValueError("Refusing to quarantine files inside the protected Windows system tree.")

        before = src.stat()
        data = src.read_bytes()
        after_read = src.stat()
        if not self._same_snapshot(before, after_read):
            raise OSError("Source changed while quarantine was reading it.")

        digest = self._sha256(data)
        expected = str(expected_sha256 or "").strip().casefold()
        if expected:
            if len(expected) != 64 or any(c not in string.hexdigits.casefold() for c in expected):
                raise ValueError("Expected SHA-256 is invalid.")
            if digest.casefold() != expected:
                raise ValueError("Detected file identity changed; quarantine refused.")
        item_id = uuid.uuid4().hex
        target = self.quarantine_dir / f"{item_id}.bcsq"
        secure_write_parent(target)
        encrypted = self._fernet.encrypt(data)

        try:
            with target.open("xb") as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass

            # Verify the persisted encrypted object before changing the source.
            persisted = target.read_bytes()
            if self._sha256(self._fernet.decrypt(persisted)) != digest:
                raise ValueError("Quarantine write verification failed.")

            self.db.execute(
                "INSERT INTO quarantine(id,original_path,stored_path,sha256,score,reason) VALUES(?,?,?,?,?,?)",
                (item_id, str(src), str(target), digest, int(score), str(reason or "")),
            )

            # Final snapshot check closes the common write/swap race before unlink.
            before_unlink = src.stat()
            if not self._same_snapshot(before, before_unlink):
                raise OSError("Source changed before quarantine could remove it.")
            src.unlink()
            return item_id
        except Exception:
            # Never claim an item is quarantined if the original could not be
            # removed or the encrypted object failed integrity verification.
            try:
                self.db.execute("DELETE FROM quarantine WHERE id=?", (item_id,))
            except Exception:
                pass
            try:
                if target.exists() and not is_reparse_point(target):
                    target.unlink()
            except OSError:
                pass
            raise

    def restore(self, item_id: str, destination: str | Path | None = None) -> Path:
        item_id = self._validate_item_id(item_id)
        rows = self.db.execute("SELECT * FROM quarantine WHERE id=? AND deleted=0", (item_id,))
        if not rows:
            raise KeyError(item_id)
        row = rows[0]
        stored = self._stored_file(row["stored_path"])
        data = self._fernet.decrypt(stored.read_bytes())
        if self._sha256(data) != row["sha256"]:
            raise ValueError("Quarantine integrity check failed.")

        raw_destination = destination if destination is not None else row["original_path"]
        dst = absolute_lexical_path(raw_destination)
        if self._is_protected_destination(dst):
            raise ValueError("Refusing to restore into BC Sentinel managed paths.")
        if is_reparse_point(dst):
            raise ValueError("Refusing to restore onto a symlink/reparse point.")

        dst.parent.mkdir(parents=True, exist_ok=True)
        secure_write_parent(dst)
        if dst.exists():
            raise FileExistsError(str(dst))

        try:
            # Exclusive creation prevents overwrite races. A failed/partial write
            # is removed before the operation is reported as unsuccessful.
            with dst.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if self._sha256_file(dst) != row["sha256"]:
                raise ValueError("Restored file failed SHA-256 verification.")
        except Exception:
            try:
                if dst.exists() and not is_reparse_point(dst):
                    dst.unlink()
            except OSError:
                pass
            raise

        self.db.execute("UPDATE quarantine SET restored=1 WHERE id=?", (item_id,))
        self.db.update_detection_action(row["sha256"], "restored")
        return dst

    def delete_detected_file(self, source: str | Path, expected_sha256: str) -> Path:
        """Permanently delete one detected file after identity revalidation.

        This is intentionally separate from quarantine deletion. The caller must
        obtain explicit user confirmation. BC Sentinel re-checks path safety,
        file snapshots and SHA-256 immediately before unlink so a swapped file
        is never destroyed under a stale detection decision.
        """
        expected = str(expected_sha256 or "").strip().casefold()
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise ValueError("A valid expected SHA-256 is required for permanent deletion.")
        lexical = absolute_lexical_path(source)
        if is_reparse_point(lexical):
            raise ValueError("Refusing permanent deletion of a symlink/reparse point.")
        try:
            src = lexical.resolve(strict=True)
        except FileNotFoundError:
            raise FileNotFoundError(str(lexical))
        if not src.is_file():
            raise FileNotFoundError(str(src))
        if self._is_protected_destination(src):
            raise ValueError("Refusing permanent deletion of BC Sentinel managed files.")
        if self._is_windows_protected_system_path(src):
            raise ValueError("Refusing permanent deletion inside the protected Windows system tree.")

        before = src.stat()
        digest = self._sha256_file(src)
        after_hash = src.stat()
        if not self._same_snapshot(before, after_hash):
            raise OSError("Source changed while permanent deletion was validating it.")
        if digest.casefold() != expected:
            raise ValueError("Detected file identity changed; permanent deletion refused.")
        before_unlink = src.stat()
        if not self._same_snapshot(before, before_unlink):
            raise OSError("Source changed before permanent deletion could remove it.")
        src.unlink()
        return src

    def delete_permanently(self, item_id: str):
        item_id = self._validate_item_id(item_id)
        rows = self.db.execute("SELECT stored_path,sha256 FROM quarantine WHERE id=?", (item_id,))
        if not rows:
            raise KeyError(item_id)
        row = rows[0]
        try:
            p = self._stored_file(row["stored_path"])
        except FileNotFoundError:
            p = None
        if p is not None and p.exists():
            p.unlink()
        self.db.execute("UPDATE quarantine SET deleted=1 WHERE id=?", (item_id,))
        self.db.update_detection_action(row["sha256"], "deleted")

    def list_items(self, include_restored: bool = False):
        if include_restored:
            return self.db.execute("SELECT * FROM quarantine WHERE deleted=0 ORDER BY ts DESC")
        return self.db.execute(
            "SELECT * FROM quarantine WHERE deleted=0 AND restored=0 ORDER BY ts DESC"
        )

    def list_restored(self):
        return self.db.execute(
            "SELECT * FROM quarantine WHERE deleted=0 AND restored=1 ORDER BY ts DESC"
        )
