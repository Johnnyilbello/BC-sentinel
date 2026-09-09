from __future__ import annotations

import hashlib
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, asdict
from pathlib import Path

from .database import Database
from .path_security import canonical_path, is_reparse_point, same_file_snapshot
from .reputation import ReputationEngine, SIGNED_EXTENSIONS, inspect_authenticode


@dataclass(slots=True)
class ProcessIdentity:
    path: str = ""
    sha256: str = ""
    signature_status: str = ""
    signer: str = ""
    mtime_ns: int = 0
    size: int = 0
    cached: bool = False

    def to_dict(self):
        return asdict(self)


class ProcessIdentityResolver:
    """Background executable identity enrichment for ETW/psutil telemetry.

    Hashing and Authenticode checks never run on the ETW callback thread.
    Executable bytes are re-hashed for each new enrichment request; only the
    post-hash identity/signature result is cached by path + metadata + SHA-256.
    """

    def __init__(self, db: Database | None = None, max_workers: int = 2, max_cache: int = 4096):
        self.db = db
        self.reputation = ReputationEngine(db) if db is not None else None
        self.max_cache = max(256, int(max_cache))
        self._cache: dict[tuple[str, int, int, str], ProcessIdentity] = {}
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=max(1, int(max_workers)), thread_name_prefix="BCS-Identity")

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()

    def resolve(self, path: str | Path) -> ProcessIdentity:
        p = Path(path).expanduser()
        if not str(p):
            return ProcessIdentity()
        try:
            if is_reparse_point(p):
                return ProcessIdentity(path=canonical_path(p))
            st = p.stat()
            canonical = canonical_path(p)
            mtime_ns = int(st.st_mtime_ns)
            size = int(st.st_size)
        except (OSError, ValueError):
            return ProcessIdentity(path=str(p))

        # Process identity is security-sensitive and therefore never trusts a
        # persistent mtime+size hash cache. Hash the executable bytes for each
        # new process-enrichment request; the work already runs off the ETW
        # callback thread. This closes timestamp-restoration/PID-reuse bypasses.
        try:
            sha256 = self._sha256(p)
            after = p.stat()
            if not same_file_snapshot(st, after):
                return ProcessIdentity(path=canonical)
        except OSError:
            return ProcessIdentity(path=canonical)

        key = (canonical, mtime_ns, size, sha256)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                out = ProcessIdentity(**cached.to_dict())
                out.cached = True
                return out

        status = ""
        signer = ""
        if p.suffix.casefold() in SIGNED_EXTENSIONS:
            if self.reputation is not None:
                result = self.reputation.assess_file(p, sha256, base_score=0, force_signature=True)
                status = result.signature_status
                signer = result.publisher
                if not status and result.local_trust == "allowlisted":
                    status, signer = inspect_authenticode(p)
            else:
                status, signer = inspect_authenticode(p)

        identity = ProcessIdentity(
            path=canonical, sha256=sha256, signature_status=status, signer=signer,
            mtime_ns=mtime_ns, size=size, cached=False,
        )
        with self._lock:
            self._cache[key] = identity
            if len(self._cache) > self.max_cache:
                for old_key in list(self._cache)[: max(1, self.max_cache // 4)]:
                    self._cache.pop(old_key, None)
        return identity

    def submit(self, path: str | Path) -> Future:
        return self._pool.submit(self.resolve, path)

    def shutdown(self, wait: bool = False) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=True)
