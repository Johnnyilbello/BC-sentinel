from __future__ import annotations
import hashlib
import math
import mimetypes
import os
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable
from .config import (
    POTENTIALLY_EXECUTABLE, SCRIPT_EXTENSIONS, Settings,
    APP_ROOT, EXE_DIR, DATA_DIR, QUARANTINE_DIR, PROGRAM_DATA_DIR
)
from .database import Database
from .path_security import canonical_path, is_reparse_point, is_within, is_within_any, same_file_snapshot
from .scoring import Signal, ThreatAssessment, assess
from .yara_engine import YaraEngine
from .reputation import ReputationEngine

# Canonical harmless EICAR antivirus test string.
# Detection is intentionally exact in v0.1.1 to prevent BC Sentinel from
# detecting its own source code or documentation merely for mentioning EICAR.
EICAR_TEST_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "URLDownloadToFile", "WinExec", "ShellExecute"
}
ENCODED_PS = re.compile(rb"(?i)(?:powershell(?:\.exe)?\s+.*?(?:-enc|-encodedcommand)\s+)[A-Za-z0-9+/=]{24,}")
OBFUSCATION = re.compile(rb"(?i)(frombase64string|invoke-expression|iex\s*\(|downloadstring|bitsadmin|certutil\s+-decode)")
DOUBLE_EXT = re.compile(r"(?i)\.(pdf|docx?|xlsx?|jpg|jpeg|png|txt)\.(exe|scr|com|bat|cmd|js|vbs|ps1)$")

@dataclass(slots=True)
class FileReport:
    path: str
    size: int
    sha256: str
    sha1: str
    entropy: float
    mime: str
    extension: str
    mtime: float
    is_pe: bool
    pe_entrypoint: int | None
    pe_sections: list[dict]
    pe_imports: list[str]
    assessment: ThreatAssessment
    reputation: dict | None = None
    hashes_cached: bool = False

    def to_dict(self):
        return asdict(self)

class ScanCancelled(Exception):
    """Internal cooperative-cancellation signal for manual scans."""

def _check_cancelled(cancelled: Callable[[], bool] | None) -> None:
    if cancelled and cancelled():
        raise ScanCancelled()

def hash_file(
    path: Path,
    algo: str = "sha256",
    chunk: int = 1024 * 1024,
    cancelled: Callable[[], bool] | None = None,
) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        while True:
            _check_cancelled(cancelled)
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def hash_file_multi(
    path: Path,
    algos: tuple[str, ...] = ("sha256", "sha1"),
    chunk: int = 1024 * 1024,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, str]:
    """Compute multiple digests in one I/O pass."""
    hashes = {name: hashlib.new(name) for name in algos}
    with path.open("rb") as f:
        while True:
            _check_cancelled(cancelled)
            block = f.read(chunk)
            if not block:
                break
            for h in hashes.values():
                h.update(block)
    return {name: h.hexdigest() for name, h in hashes.items()}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts if c)

def sample_entropy(path: Path, cap: int = 4 * 1024 * 1024, cancelled: Callable[[], bool] | None = None) -> float:
    _check_cancelled(cancelled)
    with path.open("rb") as f:
        data = f.read(cap)
    _check_cancelled(cancelled)
    return shannon_entropy(data)

def is_exact_eicar(data: bytes) -> bool:
    # CR/LF is tolerated because some editors append a newline.
    return data.rstrip(b"\r\n") == EICAR_TEST_STRING

def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False

def is_self_managed_path(path: str | Path) -> bool:
    """Paths BC Sentinel owns and must not scan as ordinary user content."""
    try:
        return is_within_any(
            path,
            (APP_ROOT, EXE_DIR, DATA_DIR, QUARANTINE_DIR, PROGRAM_DATA_DIR),
        )
    except (OSError, ValueError):
        return False

def _pe_metadata(path: Path):
    try:
        import pefile
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imports = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode(errors="ignore"))
        sections = []
        for sec in pe.sections:
            sections.append({
                "name": sec.Name.rstrip(b"\x00").decode(errors="ignore"),
                "size": int(sec.SizeOfRawData),
                "entropy": round(float(sec.get_entropy()), 3),
            })
        ep = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        return True, ep, sections, imports
    except Exception:
        return False, None, [], []

class StaticScanner:
    def __init__(
        self,
        settings: Settings | None = None,
        yara_engine: YaraEngine | None = None,
        reputation_engine: ReputationEngine | None = None,
        db: Database | None = None,
    ):
        self.settings = settings or Settings.defaults()
        self.yara = yara_engine or YaraEngine()
        self.db = db or getattr(reputation_engine, "db", None)
        self.reputation = reputation_engine
        if self.reputation is None and self.db is not None and getattr(self.settings, "reputation_enabled", True):
            self.reputation = ReputationEngine(self.db)
        self._cache_batch = None
        self._profile_enabled = False
        self._profile_totals: dict[str, float] = {}
        self._profile_files = 0
        self._allowlist = list(self.db.list_allowlist()) if self.db is not None else []
        self._allowlist_refreshed = time.monotonic()
        self._allowlist_refresh_seconds = 2.0
        self._allowlist_revision_seen = int(getattr(self.db, "allowlist_revision", 0)) if self.db is not None else 0
        self._ioc_revision_seen = -1
        self._ioc_hashes: dict[str, dict] = {}
        self._refresh_ioc_hashes()
        self._hash_memory: dict[str, tuple[int, int, str, str, int, str]] = {}
        if self.db is not None:
            try:
                for row in self.db.recent_hash_cache(limit=50000):
                    self._hash_memory[str(row["path"])] = (
                        int(row["mtime_ns"]), int(row["size"]), str(row["sha256"]),
                        str(row["sha1"] or ""), int(row["score"] or 0),
                        str(row["level"] or "UNKNOWN"),
                    )
            except Exception:
                self._hash_memory = {}

    def enable_profiling(self, enabled: bool = True) -> None:
        self._profile_enabled = bool(enabled)

    def reset_profile(self) -> None:
        self._profile_totals = {}
        self._profile_files = 0

    def profile_snapshot(self) -> dict:
        files = max(1, int(self._profile_files))
        return {
            "files": int(self._profile_files),
            "totals_ms": {k: round(v * 1000.0, 3) for k, v in sorted(self._profile_totals.items())},
            "avg_ms_per_file": {k: round((v * 1000.0) / files, 6) for k, v in sorted(self._profile_totals.items())},
        }

    def _profile_add(self, phase: str, started: float) -> None:
        if not self._profile_enabled:
            return
        self._profile_totals[phase] = self._profile_totals.get(phase, 0.0) + (time.perf_counter() - started)

    def _refresh_ioc_hashes(self) -> None:
        if self.db is None or not hasattr(self.db, "list_ioc_entries"):
            self._ioc_hashes = {}
            self._ioc_revision_seen = 0
            return
        try:
            rows = self.db.list_ioc_entries(limit=1000)
            self._ioc_hashes = {
                str(row["value"]).casefold(): dict(row)
                for row in rows if str(row["kind"] or "").casefold() == "sha256"
            }
            self._ioc_revision_seen = int(getattr(self.db, "ioc_revision", 0))
        except Exception:
            self._ioc_hashes = {}

    def _match_signed_ioc_hash(self, sha256: str):
        if self.db is None:
            return None
        revision = int(getattr(self.db, "ioc_revision", 0))
        if revision != self._ioc_revision_seen:
            self._refresh_ioc_hashes()
        return self._ioc_hashes.get(str(sha256 or "").casefold())

    def refresh_allowlist(self) -> None:
        self._allowlist = list(self.db.list_allowlist()) if self.db is not None else []
        self._allowlist_refreshed = time.monotonic()
        self._allowlist_revision_seen = int(getattr(self.db, "allowlist_revision", 0)) if self.db is not None else 0

    def _maybe_refresh_allowlist(self) -> bool:
        if self.db is None:
            return False
        revision = int(getattr(self.db, "allowlist_revision", 0))
        if revision != self._allowlist_revision_seen:
            self.refresh_allowlist()
            return True
        if time.monotonic() - self._allowlist_refreshed < self._allowlist_refresh_seconds:
            return False
        self.refresh_allowlist()
        return True

    def _allowlist_match(self, path: str | Path, sha256: str = "", publisher: str = ""):
        p = canonical_path(path)
        digest = str(sha256 or "").casefold()
        pub = str(publisher or "").strip().casefold()
        for row in self._allowlist:
            kind = str(row["kind"] or "").casefold()
            value = str(row["value"] or "")
            if kind == "file" and p == canonical_path(value):
                return row
            if kind == "directory" and is_within(p, value):
                return row
            if digest and kind == "hash" and digest == value.casefold():
                return row
            if pub and kind == "publisher" and pub == value.casefold():
                return row
        # Refresh the in-memory snapshot at a bounded interval rather than
        # opening SQLite once per scanned file on every hash miss. New trust
        # entries become visible within a couple of seconds while bulk scanning
        # stays transaction-efficient.
        if self._maybe_refresh_allowlist():
            for row in self._allowlist:
                kind = str(row["kind"] or "").casefold()
                value = str(row["value"] or "")
                if kind == "file" and p == canonical_path(value):
                    return row
                if kind == "directory" and is_within(p, value):
                    return row
                if digest and kind == "hash" and digest == value.casefold():
                    return row
                if pub and kind == "publisher" and pub == value.casefold():
                    return row
        return None

    def _path_allowlisted(self, path: str | Path) -> bool:
        match = self._allowlist_match(path)
        return bool(match and str(match["kind"]).casefold() in {"file", "directory"})

    def should_skip(self, path: str | Path) -> bool:
        if self.settings.exclude_self and is_self_managed_path(path):
            return True
        return self._path_allowlisted(path)

    def _hashes(self, path: Path, st, cancelled=None) -> tuple[str, str, bool, int, str]:
        key = canonical_path(path)
        cached = self._hash_memory.get(key)
        # Security-sensitive/executable content is always re-hashed. mtime+size
        # alone is not a trustworthy content identity because an attacker can
        # restore timestamps after changing bytes. The cache still accelerates
        # the large majority of ordinary data files.
        cache_allowed = path.suffix.casefold() not in POTENTIALLY_EXECUTABLE
        if (
            cache_allowed and cached
            and cached[0] == int(st.st_mtime_ns)
            and cached[1] == int(st.st_size)
            and cached[2] and cached[3]
        ):
            return cached[2], cached[3], True, cached[4], cached[5]

        digests = hash_file_multi(path, cancelled=cancelled)
        after = path.stat()
        if not same_file_snapshot(st, after):
            raise OSError("File changed or was replaced while hashing; scan discarded.")
        return digests["sha256"], digests["sha1"], False, 0, "UNKNOWN"

    def _store_hash_cache(self, *, path, st, sha256, sha1, score, level, force=False):
        if self.db is None:
            return
        key = canonical_path(path)
        self._hash_memory[key] = (
            int(st.st_mtime_ns), int(st.st_size), str(sha256), str(sha1 or ""),
            int(score), str(level),
        )
        entry = {
            "path": key, "mtime_ns": int(st.st_mtime_ns), "size": int(st.st_size),
            "sha256": sha256, "sha1": sha1, "score": int(score), "level": str(level),
        }
        if self._cache_batch is not None:
            self._cache_batch.append(entry)
            if len(self._cache_batch) >= 256:
                self.db.upsert_hash_cache_batch(self._cache_batch)
                self._cache_batch.clear()
        else:
            self.db.upsert_hash_cache(**entry)

    def _flush_hash_cache(self):
        if self.db is not None and self._cache_batch:
            self.db.upsert_hash_cache_batch(self._cache_batch)
            self._cache_batch.clear()

    def scan_file(self, file_path: str | Path, cancelled: Callable[[], bool] | None = None) -> FileReport:
        path = Path(file_path).expanduser()
        _check_cancelled(cancelled)

        if self.settings.exclude_self and is_self_managed_path(path):
            raise ValueError("BC Sentinel self-managed path excluded from normal scanning.")
        if self._path_allowlisted(path):
            raise ValueError("Path excluded by BC Sentinel allowlist.")

        # Check the lexical leaf before exists()/resolve() follows any link.
        if is_reparse_point(path):
            raise ValueError("Refusing to scan symlink/reparse-point path directly.")
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(str(path))

        st = path.stat()
        if st.st_size > self.settings.scan_size_limit_mb * 1024 * 1024:
            raise ValueError(f"File exceeds configured size limit ({self.settings.scan_size_limit_mb} MB).")

        total_started = time.perf_counter() if self._profile_enabled else 0.0
        phase_started = time.perf_counter() if self._profile_enabled else 0.0
        sha256, sha1, hashes_cached, cached_score, cached_level = self._hashes(path, st, cancelled=cancelled)
        if self._profile_enabled:
            self._profile_add("hash_identity", phase_started)
        ext = path.suffix.lower()
        mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"

        # A valid signed IOC has precedence over an ordinary hash allowlist so
        # a newly published known-bad identity cannot be silently hidden by an
        # older local exception. The operator can still make an explicit fresh
        # decision after seeing the signed-feed evidence.
        signed_ioc = self._match_signed_ioc_hash(sha256)

        # Hash allowlists are intentionally checked before content/YARA parsing
        # only when no active signed IOC targets the same immutable content.
        if self.db is not None and signed_ioc is None:
            match = self._allowlist_match(path, sha256=sha256)
            if match and str(match["kind"]).casefold() == "hash":
                # Never grant immutable hash trust solely from a metadata cache.
                # Re-read the current bytes before applying the bypass.
                if hashes_cached:
                    verified = hash_file_multi(path, cancelled=cancelled)
                    after_verify = path.stat()
                    if not same_file_snapshot(st, after_verify):
                        raise OSError("File changed or was replaced while verifying allowlisted hash.")
                    sha256, sha1 = verified["sha256"], verified["sha1"]
                    hashes_cached = False
                    if sha256.casefold() != str(match["value"]).casefold():
                        match = self._allowlist_match(path, sha256=sha256)
                if match and str(match["kind"]).casefold() == "hash" and sha256.casefold() == str(match["value"]).casefold():
                    assessment = ThreatAssessment(0, "SAFE", ["Hash presente nella allowlist locale."], [])
                    reputation_data = {"local_trust": "allowlisted", "allowlist_kind": "hash"}
                    if not hashes_cached or cached_score != 0 or cached_level != "SAFE":
                        self._store_hash_cache(
                            path=path, st=st, sha256=sha256, sha1=sha1, score=0, level="SAFE"
                        )
                    return FileReport(
                        str(path.resolve()), st.st_size, sha256, sha1, 0.0, mime, ext, st.st_mtime,
                        False, None, [], [], assessment, reputation_data, hashes_cached,
                    )

        # Read the analysis sample once. Historically entropy sampling reopened
        # the file and the content/YARA stage opened it again immediately. One
        # bounded 4 MiB read preserves the exact entropy cap while the first
        # 2 MiB remain the heuristic/YARA head. This is an I/O optimization,
        # not a verdict cache: content is still deterministically re-inspected.
        _check_cancelled(cancelled)
        phase_started = time.perf_counter() if self._profile_enabled else 0.0
        with path.open("rb") as f:
            analysis_sample = f.read(min(st.st_size, 4 * 1024 * 1024))
        if self._profile_enabled:
            self._profile_add("content_read", phase_started)
        _check_cancelled(cancelled)
        phase_started = time.perf_counter() if self._profile_enabled else 0.0
        entropy = shannon_entropy(analysis_sample)
        if self._profile_enabled:
            self._profile_add("entropy_sample", phase_started)
        head = analysis_sample[: min(len(analysis_sample), 2 * 1024 * 1024)]

        signals: list[Signal] = []
        if signed_ioc is not None:
            label = str(signed_ioc.get("label") or "Indicatore hash presente nella denylist IOC firmata.")
            signals.append(Signal("signed_ioc_sha256", 100, label, "signed-ioc"))
        name = path.name

        if DOUBLE_EXT.search(name):
            signals.append(Signal("double_extension", 18, "Il file usa una doppia estensione potenzialmente ingannevole."))
        if ext in POTENTIALLY_EXECUTABLE and any(
            t in str(path).lower() for t in ("\\temp\\", "/tmp/", "\\appdata\\local\\temp\\")
        ):
            signals.append(Signal("temp_execution_candidate", 10, "File eseguibile o script presente in una cartella temporanea."))
        if entropy >= 7.45 and st.st_size > 20_000:
            signals.append(Signal("high_entropy", 8, "Entropia elevata: il contenuto potrebbe essere compresso, cifrato o packed."))

        _check_cancelled(cancelled)

        # Avoid invoking pefile on every ordinary document/data file. A valid
        # PE image always begins with the DOS MZ signature, so this cheap byte
        # gate preserves renamed-PE coverage while removing thousands of
        # exception-heavy parser attempts from large warm/cold scans.
        phase_started = time.perf_counter() if self._profile_enabled else 0.0
        if head.startswith(b"MZ"):
            is_pe, ep, sections, imports = _pe_metadata(path)
        else:
            is_pe, ep, sections, imports = False, None, [], []
        if self._profile_enabled:
            self._profile_add("pe_parse", phase_started)

        exact_eicar = st.st_size <= 256 and is_exact_eicar(head)
        if exact_eicar:
            signals.append(Signal("eicar", 100, "Rilevato il file di test antivirus EICAR.", "test-signature"))

        if ext in SCRIPT_EXTENSIONS or b"powershell" in head.lower():
            if ENCODED_PS.search(head):
                signals.append(Signal("encoded_powershell", 20, "PowerShell usa un comando codificato."))
            if OBFUSCATION.search(head):
                signals.append(Signal("script_obfuscation", 15, "Lo script contiene primitive spesso associate a offuscamento o download dinamico."))
            if re.search(rb"[A-Za-z0-9+/]{400,}={0,2}", head):
                signals.append(Signal("large_base64_blob", 8, "Lo script contiene un blocco Base64 insolitamente lungo."))

        if is_pe:
            suspicious = sorted({api for api in imports if api in SUSPICIOUS_APIS})
            if suspicious:
                signals.append(Signal(
                    "sensitive_pe_imports",
                    min(12, 3 + len(suspicious) * 2),
                    "L'eseguibile importa API Windows sensibili: " + ", ".join(suspicious[:5]) + "."
                ))
            if any(sec.get("entropy", 0) > 7.6 for sec in sections):
                signals.append(Signal("packed_pe_section", 8, "Una sezione PE presenta entropia compatibile con packing/compressione."))

        if not exact_eicar:
            phase_started = time.perf_counter() if self._profile_enabled else 0.0
            if st.st_size <= len(head) and hasattr(self.yara, "scan_data"):
                signals.extend(self.yara.scan_data(head))
            else:
                signals.extend(self.yara.scan(str(path)))
            if self._profile_enabled:
                self._profile_add("yara", phase_started)

        assessment = assess(signals)
        reputation_data = {}

        if self.reputation is not None and getattr(self.settings, "reputation_enabled", True):
            _check_cancelled(cancelled)
            phase_started = time.perf_counter() if self._profile_enabled else 0.0
            rep = self.reputation.assess_file(path, sha256, base_score=assessment.score)
            if self._profile_enabled:
                self._profile_add("reputation", phase_started)
            reputation_data = rep.to_dict()

            # Publisher allowlisting is only evaluated after local Authenticode
            # verification has supplied the signer identity.
            if (
                self.db is not None
                and rep.signature_status == "Valid"
                and rep.publisher
                and self._allowlist_match(path, sha256=sha256, publisher=rep.publisher) is not None
            ):
                assessment = ThreatAssessment(
                    0, "SAFE", ["Publisher presente nella allowlist locale."], []
                )
            else:
                if rep.score_delta > 0:
                    reason = next(iter(rep.reasons or []), "Reputazione locale sospetta")
                    signals.append(Signal("local_reputation", rep.score_delta, reason, "local-reputation"))
                elif rep.signature_status == "Valid" and assessment.score < 70 and not exact_eicar:
                    # A valid signature is supporting context, never a blanket
                    # bypass. It only dampens weak heuristic-only noise.
                    signals.append(Signal(
                        "valid_authenticode", -6,
                        "Firma Authenticode valida; ridotta la confidenza delle sole euristiche deboli.",
                        "local-trust",
                    ))
                if rep.score_delta or (rep.signature_status == "Valid" and assessment.score < 70 and not exact_eicar):
                    assessment = assess(signals)

        # Reject reports built while the file was still mutating. This also
        # prevents caching a verdict for a different byte sequence at same path.
        after = path.stat()
        if not same_file_snapshot(st, after):
            raise OSError("File changed or was replaced during scan; verdict discarded.")

        if self.db is not None and (
            not hashes_cached
            or cached_score != assessment.score
            or cached_level != assessment.level
        ):
            self._store_hash_cache(
                path=path, st=st, sha256=sha256, sha1=sha1,
                score=assessment.score, level=assessment.level,
            )

        if self._profile_enabled:
            self._profile_files += 1
            self._profile_add("total", total_started)
        return FileReport(
            str(path.resolve()), st.st_size, sha256, sha1, entropy, mime, ext, st.st_mtime,
            is_pe, ep, sections, imports, assessment, reputation_data, hashes_cached,
        )

    def scan_paths(
        self,
        roots: list[str | Path],
        progress: Callable[[int, int, str], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ):
        """
        Enumerate and scan cooperatively.

        Cancellation is checked during directory walking, between filenames,
        while hashing large files, during entropy sampling, and before content
        heuristics. The worker therefore does not need QThread.terminate().
        """
        files: list[Path] = []
        previous_batch = self._cache_batch
        self._cache_batch = [] if self.db is not None else None

        try:
            for root in roots:
                _check_cancelled(cancelled)
                p = Path(root)

                if self.should_skip(p):
                    continue

                if p.is_file():
                    files.append(p)
                    continue

                if not p.is_dir():
                    continue

                for base, dirs, names in os.walk(p):
                    _check_cancelled(cancelled)
                    base_path = Path(base)

                    dirs[:] = [
                        d for d in dirs
                        if not self.should_skip(base_path / d)
                        and not is_reparse_point(base_path / d)
                        and d not in {".git", "__pycache__"}
                    ]

                    for idx, name in enumerate(names):
                        if idx % 32 == 0:
                            _check_cancelled(cancelled)
                        candidate = base_path / name
                        if not self.should_skip(candidate):
                            files.append(candidate)

            total = len(files)

            for i, path in enumerate(files, start=1):
                _check_cancelled(cancelled)

                if progress:
                    progress(i, total, str(path))

                try:
                    yield self.scan_file(path, cancelled=cancelled)
                except ScanCancelled:
                    return
                except (OSError, ValueError):
                    continue

        except ScanCancelled:
            return
        finally:
            self._flush_hash_cache()
            self._cache_batch = previous_batch
