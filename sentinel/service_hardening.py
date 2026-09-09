from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from typing import Any, Iterable

from .config import APP_VERSION, PROGRAM_DATA_DIR
from .path_security import has_reparse_component, is_reparse_point, secure_write_parent

PROTECTION_DATA_DIR = PROGRAM_DATA_DIR / "Protection"
INTEGRITY_KEY_PATH = PROTECTION_DATA_DIR / "protection-integrity.key"
INTEGRITY_SIGNATURE_PATH = PROTECTION_DATA_DIR / "protection-integrity.sig"
AUDIT_CHAIN_STATE_PATH = PROTECTION_DATA_DIR / "service-audit.chain"
MANIFEST_FILENAME = "protection-integrity.json"

LOW_PRIVILEGE_SIDS = {
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\\Users
}

# Principals intentionally allowed to hold write/control rights on protected
# BC Sentinel service resources.  Keep this list narrow: standard Users and
# Authenticated Users must never become trusted writers.  Per-service SIDs
# (S-1-5-80-*) are accepted separately by ``windows_acl_posture``.
TRUSTED_WRITE_SIDS = {
    "S-1-5-18",      # LocalSystem
    "S-1-5-32-544", # BUILTIN\\Administrators
}

# Rights that are dangerous on a protected binary/configuration tree.
_DANGEROUS_READ_MASK = (
    0x10000000  # GENERIC_ALL
    | 0x80000000  # GENERIC_READ
    | 0x00020000  # READ_CONTROL
    | 0x00000001  # FILE_READ_DATA / FILE_LIST_DIRECTORY
    | 0x00000008  # FILE_READ_EA
    | 0x00000080  # FILE_READ_ATTRIBUTES
)

_DANGEROUS_WRITE_MASK = (
    0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
)


def _atomic_bytes(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    secure_write_parent(path)
    if is_reparse_point(path):
        raise ValueError(f"Refusing reparse-point target: {path}")
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists():
        if is_reparse_point(tmp):
            raise ValueError(f"Refusing reparse-point temp target: {tmp}")
        tmp.unlink()
    with tmp.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def ensure_integrity_key(path: Path = INTEGRITY_KEY_PATH) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if has_reparse_component(path, include_leaf=False) or is_reparse_point(path):
        raise ValueError("Integrity key path cannot traverse a reparse point.")
    if path.exists():
        raw = path.read_bytes().strip()
        if len(raw) == 64:
            try:
                return bytes.fromhex(raw.decode("ascii"))
            except ValueError as exc:
                raise ValueError("Integrity key is malformed.") from exc
        raise ValueError("Integrity key is malformed.")
    key = secrets.token_bytes(32)
    try:
        with path.open("xb") as handle:
            handle.write(key.hex().encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        return ensure_integrity_key(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _windows_change_time_ns(path: Path) -> int | None:
    """Return the NTFS/Windows file ChangeTime in nanoseconds.

    Python's ``st_ctime_ns`` is not a reliable mutation cookie on Windows: on
    current Python/Windows it represents file creation time.  FILE_BASIC_INFO
    exposes the kernel-maintained ChangeTime, which changes when file data or
    metadata changes and is not reset by restoring LastWriteTime with utime.
    
    ``None`` is fail-safe: callers must not trust an incremental cache entry
    when the change cookie cannot be obtained.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        FILE_READ_ATTRIBUTES = 0x0080
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_BASIC_INFO_CLASS = 0

        class FILE_BASIC_INFO(ctypes.Structure):
            _fields_ = [
                ("CreationTime", ctypes.c_longlong),
                ("LastAccessTime", ctypes.c_longlong),
                ("LastWriteTime", ctypes.c_longlong),
                ("ChangeTime", ctypes.c_longlong),
                ("FileAttributes", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        get_info = kernel32.GetFileInformationByHandleEx
        get_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        get_info.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        handle = create_file(
            str(path),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in (None, 0, invalid):
            return None
        try:
            info = FILE_BASIC_INFO()
            if not get_info(handle, FILE_BASIC_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)):
                return None
            # FILETIME/LARGE_INTEGER timestamps are in 100 ns ticks.  Only
            # monotonic change detection is needed, so epoch conversion is
            # intentionally unnecessary.
            return int(info.ChangeTime) * 100
        finally:
            close_handle(handle)
    except Exception:
        return None


def _reliable_change_cookie(path: Path, st: os.stat_result) -> int | None:
    if os.name == "nt":
        return _windows_change_time_ns(path)
    value = int(getattr(st, "st_ctime_ns", 0) or 0)
    return value or None


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_candidates(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in {MANIFEST_FILENAME, "protection-integrity.sig"}:
            continue
        rel = path.relative_to(root)
        # Never package mutable runtime output as part of immutable install state.
        if any(part.lower() in {"__pycache__", ".pytest_cache", "logs"} for part in rel.parts):
            continue
        yield path


def build_integrity_manifest(root: str | Path) -> dict[str, Any]:
    root = Path(root).resolve()
    files: dict[str, dict[str, Any]] = {}
    for path in _manifest_candidates(root):
        rel = path.relative_to(root).as_posix()
        st = path.stat()
        files[rel] = {
            "sha256": sha256_file(path),
            "size": int(st.st_size),
        }
    return {
        "schema": 1,
        "algorithm": "sha256",
        "product_version": APP_VERSION,
        "created_unix": int(time.time()),
        "files": files,
    }


def write_integrity_manifest(root: str | Path) -> Path:
    root = Path(root).resolve()
    manifest_path = root / MANIFEST_FILENAME
    payload = json.dumps(
        build_integrity_manifest(root), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    _atomic_bytes(manifest_path, payload, mode=0o644)
    return manifest_path


@dataclass(slots=True)
class IntegrityResult:
    ok: bool
    checked_files: int
    issues: list[str]
    manifest_authenticated: bool = False
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IntegrityVerifier:
    """Authenticates and verifies the immutable Protection Service install tree.

    The build manifest lives beside the frozen service. At install time it is
    authenticated with a machine-local key stored under ProgramData and denied
    to standard users. Runtime checks reuse stat snapshots so unchanged files
    are not re-hashed every cycle.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        key_path: Path = INTEGRITY_KEY_PATH,
        signature_path: Path = INTEGRITY_SIGNATURE_PATH,
    ):
        self.root = Path(root).resolve()
        self.manifest_path = self.root / MANIFEST_FILENAME
        self.key_path = Path(key_path)
        self.signature_path = Path(signature_path)
        self._cache: dict[str, tuple[int, int, int, int, int, str]] = {}
        self._lock = threading.RLock()

    def _key(self) -> bytes:
        return ensure_integrity_key(self.key_path)

    def _manifest_bytes(self) -> bytes:
        if is_reparse_point(self.manifest_path):
            raise ValueError("Integrity manifest cannot be a reparse point.")
        return self.manifest_path.read_bytes()

    def seal(self) -> IntegrityResult:
        # Never authenticate a manifest until all files match it once.
        result = self.verify(require_signature=False, full=True)
        if not result.ok:
            return result
        payload = self._manifest_bytes()
        signature = hmac.new(self._key(), payload, hashlib.sha256).hexdigest().encode("ascii")
        self.signature_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_bytes(self.signature_path, signature, mode=0o600)
        return self.verify(require_signature=True, full=False)

    def _authenticate_manifest(self, payload: bytes) -> bool:
        if is_reparse_point(self.signature_path):
            return False
        try:
            supplied = self.signature_path.read_text(encoding="ascii").strip()
        except OSError:
            return False
        expected = hmac.new(self._key(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(supplied, expected)

    def verify(self, *, require_signature: bool = True, full: bool = False) -> IntegrityResult:
        started = time.perf_counter()
        issues: list[str] = []
        checked = 0
        with self._lock:
            try:
                if has_reparse_component(self.root, include_leaf=True):
                    issues.append("install tree traverses a reparse point")
                payload = self._manifest_bytes()
                authenticated = self._authenticate_manifest(payload) if require_signature else False
                if require_signature and not authenticated:
                    issues.append("integrity manifest authentication failed")
                raw = json.loads(payload.decode("utf-8"))
                if not isinstance(raw, dict) or raw.get("schema") != 1 or not isinstance(raw.get("files"), dict):
                    issues.append("integrity manifest schema is invalid")
                    files = {}
                else:
                    files = raw["files"]
                for rel, expected in files.items():
                    if not isinstance(rel, str) or rel.startswith(("/", "\\")) or ".." in Path(rel).parts:
                        issues.append(f"unsafe manifest path: {rel!r}")
                        continue
                    path = self.root / Path(rel)
                    if is_reparse_point(path):
                        issues.append(f"reparse point detected: {rel}")
                        continue
                    try:
                        st = path.stat()
                    except OSError:
                        issues.append(f"missing protected file: {rel}")
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        issues.append(f"protected path is not a regular file: {rel}")
                        continue
                    size = int(st.st_size)
                    expected_size = int(expected.get("size", -1)) if isinstance(expected, dict) else -1
                    expected_hash = str(expected.get("sha256", "")) if isinstance(expected, dict) else ""
                    if size != expected_size:
                        issues.append(f"size mismatch: {rel}")
                        continue
                    change_cookie = _reliable_change_cookie(path, st)
                    snapshot = (
                        int(getattr(st, "st_mtime_ns", 0)),
                        int(change_cookie or 0),
                        size,
                        int(getattr(st, "st_dev", 0) or 0),
                        int(getattr(st, "st_ino", 0) or 0),
                    )
                    cached = self._cache.get(rel)
                    # On Windows, never trust mtime/size alone.  If the native
                    # ChangeTime lookup fails, re-hash rather than accepting a
                    # potentially restored timestamp cache entry.
                    cache_trustworthy = change_cookie is not None
                    if full or not cache_trustworthy or cached is None or cached[:5] != snapshot:
                        digest = sha256_file(path)
                        if cache_trustworthy:
                            self._cache[rel] = (*snapshot, digest)
                        else:
                            self._cache.pop(rel, None)
                        checked += 1
                    else:
                        digest = cached[5]
                    if not expected_hash or not hmac.compare_digest(digest, expected_hash):
                        issues.append(f"hash mismatch: {rel}")

                expected_paths = set(files)
                dangerous_extra_suffixes = {".exe", ".dll", ".pyd", ".sys", ".py", ".pyc", ".yar", ".yara"}
                for actual in self.root.rglob("*"):
                    try:
                        rel_actual = actual.relative_to(self.root).as_posix()
                    except Exception:
                        continue
                    if actual.is_symlink() or is_reparse_point(actual):
                        issues.append(f"unexpected reparse point in install tree: {rel_actual}")
                        continue
                    if actual.is_file() and rel_actual not in expected_paths and actual.name != MANIFEST_FILENAME:
                        if actual.suffix.lower() in dangerous_extra_suffixes:
                            issues.append(f"unexpected executable/rule file in install tree: {rel_actual}")
                return IntegrityResult(
                    ok=not issues,
                    checked_files=checked,
                    issues=issues[:100],
                    manifest_authenticated=bool(authenticated) if require_signature else True,
                    elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
                )
            except Exception as exc:
                return IntegrityResult(
                    ok=False,
                    checked_files=checked,
                    issues=[f"integrity verifier error: {type(exc).__name__}: {exc}"],
                    manifest_authenticated=False,
                    elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
                )


@dataclass(slots=True)
class AclPosture:
    ok: bool
    path: str
    dangerous_sids: list[str]
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def windows_acl_posture(path: str | Path, *, forbid_untrusted_read: bool = False) -> AclPosture:
    """Detect low-privilege write grants on a Windows path DACL.

    This is read-only and uses pywin32 security APIs; it does not infer safety
    from localized icacls text.
    """
    p = str(Path(path))
    if os.name != "nt":
        return AclPosture(True, p, [], "non-Windows development environment")
    try:
        import win32security

        sd = win32security.GetFileSecurity(p, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return AclPosture(False, p, ["NULL_DACL"], "path has a NULL DACL")
        dangerous: list[str] = []
        allowed_types = {
            int(getattr(win32security, "ACCESS_ALLOWED_ACE_TYPE", 0)),
            int(getattr(win32security, "ACCESS_ALLOWED_OBJECT_ACE_TYPE", 5)),
        }
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            ace_type = int(ace[0][0])
            if ace_type not in allowed_types:
                continue
            mask = int(ace[1])
            sid = win32security.ConvertSidToStringSid(ace[-1])
            trusted_write = sid in TRUSTED_WRITE_SIDS or sid.startswith("S-1-5-80-")
            if (mask & _DANGEROUS_WRITE_MASK) and not trusted_write:
                dangerous.append(sid)
                continue
            if forbid_untrusted_read and (mask & _DANGEROUS_READ_MASK) and not trusted_write:
                dangerous.append(sid)
        detail = "" if not dangerous else (
            "untrusted read/write grant detected" if forbid_untrusted_read else "untrusted write grant detected"
        )
        return AclPosture(not dangerous, p, sorted(set(dangerous)), detail)
    except Exception as exc:
        return AclPosture(False, p, [], f"ACL inspection failed: {type(exc).__name__}: {exc}")


class AuditChainWriter:
    """Append-only HMAC hash-chain for privileged/lifecycle service audit."""

    def __init__(self, path: Path, *, key_path: Path = INTEGRITY_KEY_PATH, state_path: Path = AUDIT_CHAIN_STATE_PATH):
        self.path = Path(path)
        self.key_path = Path(key_path)
        self.state_path = Path(state_path)
        self._lock = threading.RLock()

    def _key(self) -> bytes:
        return ensure_integrity_key(self.key_path)

    def _previous(self) -> str:
        if self.state_path.exists():
            value = self.state_path.read_text(encoding="ascii").strip()
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value.lower()):
                raise ValueError("audit chain state is invalid")
            return value.lower()
        if self.path.exists() and self.path.stat().st_size > 0:
            raise ValueError("audit chain state is missing for a non-empty audit log")
        return "0" * 64

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if is_reparse_point(self.path) or is_reparse_point(self.state_path):
                raise ValueError("audit path cannot be a reparse point")
            previous = self._previous()
            body = dict(record)
            body["prev_hmac"] = previous
            canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            chain = hmac.new(self._key(), canonical, hashlib.sha256).hexdigest()
            body["hmac"] = chain
            line = json.dumps(body, ensure_ascii=False, separators=(",", ":")) + "\n"
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            _atomic_bytes(self.state_path, chain.encode("ascii"), mode=0o600)
            return body


def verify_audit_chain(
    path: Path,
    *,
    key_path: Path = INTEGRITY_KEY_PATH,
    state_path: Path = AUDIT_CHAIN_STATE_PATH,
) -> tuple[bool, str, int]:
    key = ensure_integrity_key(key_path)
    previous = "0" * 64
    count = 0
    if not path.exists():
        return True, "empty", 0
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            supplied = str(obj.pop("hmac", ""))
            if obj.get("prev_hmac") != previous:
                return False, f"chain predecessor mismatch at record {count + 1}", count
            canonical = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(supplied, expected):
                return False, f"record HMAC mismatch at record {count + 1}", count
            previous = supplied
            count += 1
        try:
            state = Path(state_path).read_text(encoding="ascii").strip()
        except OSError:
            state = previous if count == 0 else ""
        if count and state != previous:
            return False, "audit chain state does not match the final record", count
        return True, "ok", count
    except Exception as exc:
        return False, f"audit verification failed: {type(exc).__name__}: {exc}", count

@dataclass(slots=True)
class ServicePosture:
    ok: bool
    service_name: str
    binary_path: str = ""
    start_type: str = ""
    account: str = ""
    recovery_configured: bool = False
    issues: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["issues"] = list(self.issues or [])
        return data


def windows_service_posture(service_name: str, *, expected_binary: str | Path | None = None) -> ServicePosture:
    if os.name != "nt":
        return ServicePosture(True, service_name, issues=[], start_type="development")
    issues: list[str] = []
    scm = service = None
    try:
        import win32service
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = win32service.OpenService(scm, service_name, win32service.SERVICE_QUERY_CONFIG)
        cfg = win32service.QueryServiceConfig(service)
        start_type_value = int(cfg[1])
        binary = str(cfg[3] or "").strip().strip('"')
        account = str(cfg[7] or "")
        if start_type_value != int(win32service.SERVICE_AUTO_START):
            issues.append("service startup is not automatic")
        if account.lower() not in {"localsystem", ".\\localsystem"}:
            issues.append(f"unexpected service account: {account}")
        if expected_binary is not None:
            try:
                expected = os.path.normcase(os.path.normpath(str(Path(expected_binary).resolve())))
                actual = os.path.normcase(os.path.normpath(str(Path(binary).resolve())))
                if actual != expected:
                    issues.append("service binary path differs from protected install binary")
            except Exception:
                issues.append("service binary path comparison failed")
        recovery = False
        try:
            failure = win32service.QueryServiceConfig2(service, win32service.SERVICE_CONFIG_FAILURE_ACTIONS)
            text = repr(failure).lower()
            recovery = "restart" in text or "1" in text
        except Exception:
            # Older pywin32 builds may not expose QueryServiceConfig2 uniformly.
            recovery = False
        start_name = "AUTO_START" if start_type_value == int(win32service.SERVICE_AUTO_START) else str(start_type_value)
        return ServicePosture(not issues, service_name, binary, start_name, account, recovery, issues)
    except Exception as exc:
        return ServicePosture(False, service_name, issues=[f"SCM inspection failed: {type(exc).__name__}: {exc}"])
    finally:
        try:
            if service is not None:
                import win32service
                win32service.CloseServiceHandle(service)
        except Exception:
            pass
        try:
            if scm is not None:
                import win32service
                win32service.CloseServiceHandle(scm)
        except Exception:
            pass
