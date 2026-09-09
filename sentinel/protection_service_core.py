from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any

from .config import APP_ROOT, DATA_DIR, EXE_DIR, PROGRAM_DATA_DIR, Settings
from .core.events import SecurityEvent
from .correlation import FileProcessCorrelator
from .correlation_engine import BehavioralCorrelationEngine
from .database import Database
from .etw_monitor import ETWMonitor
from .firewall_policy import FirewallManager, create_firewall_backend
from .incident_engine import IncidentCorrelationEngine
from .ioc_denylist import SignedIOCVerifier
from .threat_packages import SignedThreatPackageVerifier, ThreatPackageManager, ThreatPackageError
from .threat_trust import ThreatTrustStore, ThreatTrustError
from .threat_retrieval import SecureThreatRetriever
from .threat_index import SignedThreatIndexVerifier, ThreatContentCache, ThreatIndexStore
from .threat_scheduler import ThreatCheckScheduler, ThreatRemoteCoordinator
from .network_intelligence import NetworkReputationEngine
from .network_monitor import NetworkMonitor
from .web_protection import DNSCorrelationCache, WebProtectionEngine, normalize_domain
from .web_download_protection import BrowserDownloadCorrelation
from .web_response import (
    WEB_RESPONSE_PROFILE, WEB_CONTAINMENT_TTL_MIN, WEB_CONTAINMENT_TTL_MAX, qualify_web_containment,
)
from .web_clone_scam import CLONE_SCAM_PROFILE, assess_page_context
from .path_security import is_reparse_point, secure_write_parent
from .persistence_monitor import PersistenceMonitor
from .antispyware import AntispywareEngine
from .antispyware_remediation import AntispywareRemediationManager
from .advanced_antimalware import AdvancedAntimalwareEngine
from .process_identity import ProcessIdentityResolver
from .process_monitor import ProcessMonitor
from .process_tree import ProcessTree
from .protection_constants import (
    PIPE_NAME, SERVICE_AUDIT_PATH, SERVICE_CONFIG_PATH, SERVICE_CONFIG_SIG_PATH,
    SERVICE_DB_PATH, SERVICE_DIR, SERVICE_DISPLAY_NAME, SERVICE_NAME,
    SERVICE_QUARANTINE_DIR, SERVICE_QUARANTINE_KEY_PATH, SERVICE_SECRET_PATH, THREAT_INTELLIGENCE_DIR, ANTISPYWARE_REMEDIATION_DIR,
)
from .privileged_broker import PrivilegeTicketStore
from .protection_protocol import (
    ClientContext,
    PRIVILEGED_OPERATIONS,
    ProtocolError,
    ValidatedRequest,
    authorized_token,
    decode_request,
    response_error,
    response_ok,
    validate_request,
)
from .quarantine import QuarantineManager
from .rate_limit import SlidingWindowRateLimiter
from .realtime import RealtimeMonitor
from .response_engine import ResponseEngine
from .service_hardening import (
    AuditChainWriter,
    INTEGRITY_KEY_PATH,
    IntegrityVerifier,
    ensure_integrity_key,
    verify_audit_chain,
    windows_acl_posture,
    windows_service_posture,
)

SERVICE_HARDENING_INTERVAL_SECONDS = 30.0

CONFIG_FIELDS = (
    "realtime_enabled",
    "ransomware_enabled",
    "behavior_enabled",
    "auto_quarantine_threshold",
    "scan_size_limit_mb",
    "monitored_dirs",
    "ransomware_dirs",
    "ransomware_startup_grace_seconds",
    "etw_enabled",
    "persistence_enabled",
    "network_enabled",
    "reputation_enabled",
    "exclude_self",
)


class ServiceHealth(str, Enum):
    STARTING = "STARTING"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


@dataclass(slots=True)
class ComponentState:
    enabled: bool
    running: bool
    critical: bool = False
    detail: str = ""

    def to_dict(self):
        return asdict(self)


class EventBuffer:
    def __init__(self, max_events: int = 12000):
        from collections import deque

        self._events = deque(maxlen=max_events)
        self._seq = 0
        self._lock = threading.RLock()

    def append(self, event: SecurityEvent, chain: str = ""):
        payload = event.to_dict()
        with self._lock:
            self._seq += 1
            payload["seq"] = self._seq
            if chain:
                payload.setdefault("data", {})["chain"] = chain
            self._events.append(payload)

    def since(self, seq: int, limit: int = 250):
        with self._lock:
            rows = [x for x in self._events if int(x.get("seq", 0)) > int(seq)]
            return rows[: max(1, min(int(limit), 500))]

    @property
    def sequence(self) -> int:
        with self._lock:
            return self._seq


def _ensure_service_dir() -> None:
    SERVICE_DIR.mkdir(parents=True, exist_ok=True)
    if is_reparse_point(SERVICE_DIR):
        raise ValueError("Protection service directory cannot be a reparse point.")
    try:
        os.chmod(SERVICE_DIR, 0o700)
    except OSError:
        pass


def ensure_service_secret() -> str:
    _ensure_service_dir()
    path = SERVICE_SECRET_PATH
    if is_reparse_point(path):
        raise ValueError("Protection service secret cannot be a reparse point.")
    secure_write_parent(path)
    if path.exists():
        value = path.read_text(encoding="ascii").strip()
        if len(value) >= 64:
            return value
        raise ValueError("Protection service secret exists but is invalid.")
    value = secrets.token_hex(32)
    try:
        with path.open("x", encoding="ascii") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        existing = path.read_text(encoding="ascii").strip()
        if len(existing) >= 64:
            return existing
        raise ValueError("Protection service secret exists but is invalid.")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


def _settings_to_dict(settings: Settings) -> dict[str, Any]:
    return {key: getattr(settings, key) for key in CONFIG_FIELDS}


def _settings_from_dict(raw: dict[str, Any]) -> Settings:
    settings = Settings.defaults()
    for key in CONFIG_FIELDS:
        if key in raw:
            setattr(settings, key, raw[key])
    settings.monitored_dirs = [str(x) for x in settings.monitored_dirs if str(x)]
    settings.ransomware_dirs = [str(x) for x in settings.ransomware_dirs if str(x)]
    return settings


class ProtectionConfigStore:
    """Atomic, HMAC-integrity-checked service configuration.

    The HMAC is not presented as kernel-grade anti-tamper. It detects offline
    or accidental edits before the privileged service consumes configuration.
    ACL hardening is applied by the Windows installer.
    """

    def __init__(self, secret: str | bytes | None = None):
        if secret is None:
            self.secret = ensure_integrity_key(INTEGRITY_KEY_PATH)
        elif isinstance(secret, bytes):
            self.secret = secret
        else:
            self.secret = str(secret).encode("ascii")
        self.path = SERVICE_CONFIG_PATH
        self.sig_path = SERVICE_CONFIG_SIG_PATH
        self._lock = threading.RLock()

    def _signature(self, payload: bytes) -> str:
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def save(self, settings: Settings) -> None:
        _ensure_service_dir()
        payload = json.dumps(
            _settings_to_dict(settings), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        signature = self._signature(payload).encode("ascii")
        with self._lock:
            for path in (self.path, self.sig_path):
                if is_reparse_point(path):
                    raise ValueError("Protection configuration cannot use reparse points.")
                secure_write_parent(path)
            data_tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            sig_tmp = self.sig_path.with_suffix(self.sig_path.suffix + ".tmp")
            for tmp in (data_tmp, sig_tmp):
                if tmp.exists() and not is_reparse_point(tmp):
                    tmp.unlink()
            with data_tmp.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            with sig_tmp.open("xb") as handle:
                handle.write(signature)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(data_tmp, self.path)
            os.replace(sig_tmp, self.sig_path)
            for path in (self.path, self.sig_path):
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass

    def seed_if_missing(self, settings: Settings | None = None) -> Settings:
        with self._lock:
            if self.path.exists() and self.sig_path.exists():
                return self.load()
            seeded = settings or Settings.defaults()
            self.save(seeded)
            return seeded

    def load(self) -> Settings:
        with self._lock:
            if is_reparse_point(self.path) or is_reparse_point(self.sig_path):
                raise ValueError("Protection configuration cannot use reparse points.")
            payload = self.path.read_bytes()
            supplied = self.sig_path.read_text(encoding="ascii").strip()
            expected = self._signature(payload)
            if not hmac.compare_digest(supplied, expected):
                raise ValueError("Protection configuration integrity verification failed.")
            raw = json.loads(payload.decode("utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("Protection configuration must be a JSON object.")
            return _settings_from_dict(raw)

    def update(self, changes: dict[str, Any]) -> Settings:
        with self._lock:
            settings = self.load()
            for key, value in changes.items():
                if key not in CONFIG_FIELDS:
                    raise ValueError(f"Unsupported protection setting: {key}")
                setattr(settings, key, value)
            self.save(settings)
            return settings


class EngineInstanceGuard:
    """Best-effort cross-process duplicate-engine guard.

    Windows uses a global named mutex. POSIX is only a test/development
    fallback and uses an exclusive lock file in the service directory.
    """

    def __init__(self, name: str = "BCSentinelProtectionEngine-v060"):
        safe = "".join(ch for ch in str(name) if ch.isalnum() or ch in "-_")[:96] or "BCSentinelProtectionEngine-v060"
        self.name = safe
        self._handle = None
        self._fd = None
        self._path = SERVICE_DIR / f"{safe}.lock"

    def acquire(self) -> bool:
        if self._handle is not None or self._fd is not None:
            return True
        _ensure_service_dir()
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
            kernel32.CreateMutexW.restype = wintypes.HANDLE
            handle = kernel32.CreateMutexW(None, False, f"Global\\{self.name}")
            if not handle:
                return False
            ERROR_ALREADY_EXISTS = 183
            if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
                kernel32.CloseHandle(handle)
                return False
            self._handle = handle
            return True
        try:
            import fcntl

            fd = os.open(self._path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                return False
            self._fd = fd
            return True
        except Exception:
            return False

    def release(self):
        if os.name == "nt" and self._handle is not None:
            try:
                import ctypes

                ctypes.windll.kernel32.ReleaseMutex(self._handle)
                ctypes.windll.kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None
        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None


class ProtectionRuntime:
    def __init__(self, *, db_path: str | Path = SERVICE_DB_PATH, config_store: ProtectionConfigStore | None = None):
        # IPC token remains readable by the interactive client, while the
        # configuration/integrity HMAC key is machine-private under ProgramData.
        self.secret = ensure_service_secret()
        self.integrity_key = ensure_integrity_key(INTEGRITY_KEY_PATH)
        self.config_store = config_store or ProtectionConfigStore(self.integrity_key)
        self.config_error = ""
        try:
            self.settings = self.config_store.seed_if_missing()
        except Exception as exc:
            self.settings = Settings.defaults()
            self.config_error = str(exc)

        self.db = Database(db_path)
        self.ioc_verifier = SignedIOCVerifier()
        self.threat_trust = ThreatTrustStore(THREAT_INTELLIGENCE_DIR / "Trust", integrity_key=self.integrity_key)
        self.threat_package_verifier = SignedThreatPackageVerifier(trust_store=self.threat_trust)
        self.threat_intel = ThreatPackageManager(
            THREAT_INTELLIGENCE_DIR, db=self.db, verifier=self.threat_package_verifier, integrity_key=self.integrity_key
        )
        self.threat_index_verifier = SignedThreatIndexVerifier()
        self.threat_index = ThreatIndexStore(
            THREAT_INTELLIGENCE_DIR / "RemoteIndex", verifier=self.threat_index_verifier, integrity_key=self.integrity_key
        )
        self.threat_cache = ThreatContentCache(THREAT_INTELLIGENCE_DIR / "ThreatCache")
        self.threat_scheduler = ThreatCheckScheduler(
            THREAT_INTELLIGENCE_DIR / "RemoteIndex", integrity_key=self.integrity_key
        )
        self.events = EventBuffer()
        self.process_tree = ProcessTree(max_nodes=10000)
        self.identity_resolver = ProcessIdentityResolver(self.db)
        self.correlator = FileProcessCorrelator(max_events=16000, process_tree=self.process_tree)
        self.correlation_engine = BehavioralCorrelationEngine(window_seconds=45.0)
        self.incident_engine = IncidentCorrelationEngine(
            self.db, process_tree=self.process_tree, incident_window_seconds=90.0
        )
        self.network_intelligence = NetworkReputationEngine(self.db)
        self.web_protection = WebProtectionEngine(self.db)
        self.dns_cache = DNSCorrelationCache()
        self.download_correlation = BrowserDownloadCorrelation(self.web_protection)
        self.quarantine = QuarantineManager(
            self.db,
            quarantine_dir=SERVICE_QUARANTINE_DIR,
            key_path=SERVICE_QUARANTINE_KEY_PATH,
            managed_roots=(APP_ROOT, EXE_DIR, DATA_DIR, PROGRAM_DATA_DIR, SERVICE_DIR),
        )
        self.response_engine = ResponseEngine(self.db, self.quarantine)

        self.realtime = RealtimeMonitor(
            self.settings,
            self.db,
            callback=self._on_realtime_detection,
            ransomware_callback=self._on_ransomware_detection,
            correlator=self.correlator,
        )
        self.procmon = ProcessMonitor(
            self.db,
            process_tree=self.process_tree,
            event_callback=self._on_event,
            identity_resolver=self.identity_resolver,
        )
        self.etw = ETWMonitor(
            self.process_tree,
            self.correlator,
            event_callback=self._on_event,
            identity_resolver=self.identity_resolver,
            dns_cache=self.dns_cache,
            web_engine=self.web_protection,
        )
        self.persistence = PersistenceMonitor(self.db, callback=self._on_event, interval=15.0)
        self.antispyware = AntispywareEngine(self.db, interval=300.0, callback=self._on_event)
        self.antispyware_remediation = AntispywareRemediationManager(
            self.db, integrity_key=self.integrity_key, vault_dir=ANTISPYWARE_REMEDIATION_DIR / "Vault"
        )
        self.advanced_antimalware = AdvancedAntimalwareEngine(self.db, window_seconds=60.0)
        self.network = NetworkMonitor(
            callback=self._on_event,
            interval=2.0,
            process_tree=self.process_tree,
            identity_resolver=self.identity_resolver,
            intelligence=self.network_intelligence,
            dns_cache=self.dns_cache,
            web_engine=self.web_protection,
        )
        self.firewall = FirewallManager(
            create_firewall_backend(),
            event_callback=self._on_event,
            desired_state_store=self.db,
        )

        self._guard = EngineInstanceGuard()
        self._lock = threading.RLock()
        self._health = ServiceHealth.STOPPED
        self._components: dict[str, ComponentState] = {}
        self._started_at = 0.0
        self._last_error = ""
        self._protection_enabled = True
        self.audit_writer = AuditChainWriter(SERVICE_AUDIT_PATH, key_path=INTEGRITY_KEY_PATH)
        self.integrity_verifier = IntegrityVerifier(EXE_DIR, key_path=INTEGRITY_KEY_PATH)
        self._hardening_stop = threading.Event()
        self._hardening_thread: threading.Thread | None = None
        self._hardening_status: dict[str, Any] = {
            "ok": True, "mode": "development", "issues": [], "last_check": 0.0
        }
        self._firewall_drift_status: dict[str, Any] = {
            "ok": True, "expected_rules": 0, "observed_owned_rules": 0, "issues": []
        }
        self._firewall_conflict_status: dict[str, Any] = {
            "ok": True, "blocking_conflicts": [], "advisories": [], "blocking_count": 0, "advisory_count": 0
        }

    @property
    def health(self) -> ServiceHealth:
        with self._lock:
            return self._health

    def _set_component(self, name: str, enabled: bool, running: bool, *, critical=False, detail=""):
        self._components[name] = ComponentState(bool(enabled), bool(running), bool(critical), str(detail or ""))

    def _derive_health(self) -> ServiceHealth:
        if self._health in {ServiceHealth.STARTING, ServiceHealth.STOPPING, ServiceHealth.ERROR, ServiceHealth.STOPPED}:
            return self._health
        critical = [v for v in self._components.values() if v.enabled and v.critical]
        if critical and any(not x.running for x in critical):
            return ServiceHealth.DEGRADED
        enabled = [v for v in self._components.values() if v.enabled]
        if enabled and any(not x.running for x in enabled):
            return ServiceHealth.DEGRADED
        return ServiceHealth.HEALTHY

    def _persist_event(self, event: SecurityEvent, correlation=None, ancestry=None):
        try:
            if event.category == "network":
                self.db.record_network_event(event)
            if correlation is not None and getattr(correlation, "reasons", None):
                self.db.record_correlation_event(
                    category="behavioral_correlation_v2",
                    source_event_category=event.category,
                    source_event_action=event.action,
                    pid=event.pid,
                    process_name=event.process_name,
                    score_delta=correlation.score_delta,
                    confidence=correlation.confidence,
                    chain=correlation.chain,
                    reasons=correlation.reasons,
                    data={
                        "path": event.path,
                        "severity": correlation.severity,
                        "stages": correlation.stages,
                        "evidence_families": correlation.evidence_families,
                        "sequence": correlation.sequence,
                        "incident_id": correlation.incident_id,
                        "total_score": correlation.total_score,
                    },
                )
            incident = self.incident_engine.ingest(event, correlation=correlation, ancestry=ancestry or [])
            if incident is not None:
                event.data = dict(event.data or {})
                event.data.update({
                    "incident_id": incident.incident_id,
                    "incident_score": incident.score,
                    "incident_level": incident.level,
                    "incident_confidence": incident.confidence,
                    "incident_status": incident.status,
                    "incident_suppressed": incident.suppressed,
                    "incident_categories": list(incident.categories),
                    "incident_reasons": list(incident.reasons),
                    "incident_recommended_actions": list(incident.recommended_actions),
                })
            self.db.record_security_event(event)
        except Exception:
            # Detection/telemetry must continue if persistence is temporarily
            # unavailable; health will expose the database issue on explicit ops.
            pass

    def _enrich_web_download_event(self, event: SecurityEvent) -> str:
        """Attach browser-download provenance without changing the file verdict.

        Network observations are PID-scoped. File events are considered download
        candidates only when an exact known browser executable wrote them and a
        recent same-PID domain connection exists. Process execution of a tracked
        download becomes behavioral incident evidence, never an automatic file
        malware verdict.
        """
        data = dict(event.data or {})
        if event.category == "network":
            try:
                self.download_correlation.observe_network(event)
            except Exception:
                pass
            return ""

        if event.category == "file":
            try:
                correlated = self.download_correlation.correlate_file(event)
            except Exception:
                correlated = None
            if correlated is None or not correlated.matched:
                return ""
            download_id = "BCD-" + secrets.token_hex(10).upper()
            evidence = {
                "same_pid": True,
                "browser_exact_classification": True,
                "origin_only_never_file_malicious": True,
                "network_observed_at": float(correlated.observed_at or 0),
                "file_event_action": str(event.action or ""),
            }
            stored = self.db.record_web_download(
                download_id=download_id, created_at=time.time(), domain=correlated.domain,
                remote_address=correlated.remote_address, browser_pid=correlated.browser_pid,
                browser_family=correlated.browser_family, browser_process_name=correlated.browser_process_name,
                browser_process_path=correlated.browser_process_path, file_path=str(event.path or ""),
                stage=correlated.stage, origin_score=correlated.origin_score, origin_status=correlated.origin_status,
                origin_source=correlated.origin_source, origin_signed_ioc=correlated.origin_signed_ioc,
                evidence_json=json.dumps(evidence, ensure_ascii=False, sort_keys=True),
            )
            actual = str(stored.get("download_id") or download_id)
            data.update({
                "web_download_id": actual,
                "download_domain": correlated.domain,
                "download_remote_address": correlated.remote_address,
                "download_browser_family": correlated.browser_family,
                "download_stage": correlated.stage,
                "download_origin_score": int(correlated.origin_score),
                "download_origin_status": correlated.origin_status,
                "download_origin_source": correlated.origin_source,
                "download_origin_signed_ioc": bool(correlated.origin_signed_ioc),
                "download_file_verdict_separate": True,
            })
            event.data = data
            if correlated.origin_signed_ioc:
                event.reasons = list(dict.fromkeys((event.reasons or []) + [
                    "Download attribuito allo stesso browser/PID da un dominio IOC firmato; il file richiede comunque un verdict indipendente"
                ]))
            return actual

        if event.category == "process" and str(event.action or "").casefold() == "start":
            path = str(event.process_path or event.path or "")
            if not path:
                return ""
            row = self.db.web_download_by_path(path, max_age_seconds=7 * 24 * 3600) if hasattr(self.db, "web_download_by_path") else None
            if row is None:
                return ""
            item = self._row_dict(row)
            download_id = str(item.get("download_id") or "")
            signed_origin = bool(item.get("origin_signed_ioc"))
            bump = 35 if signed_origin else 12
            event.score = min(100, int(event.score or 0) + bump)
            event.reasons = list(dict.fromkeys((event.reasons or []) + [
                "Esecuzione di un file precedentemente tracciato come download browser"
            ] + (["Il download proveniva da un dominio IOC firmato"] if signed_origin else [])))
            data.update({
                "web_download_id": download_id,
                "download_domain": str(item.get("domain") or ""),
                "download_remote_address": str(item.get("remote_address") or ""),
                "download_browser_family": str(item.get("browser_family") or ""),
                "download_origin_score": int(item.get("origin_score") or 0),
                "download_origin_signed_ioc": signed_origin,
                "download_file_score": int(item.get("file_score") or 0),
                "download_file_level": str(item.get("file_level") or "UNSCANNED"),
                "download_execution": True,
            })
            event.data = data
            return download_id
        return ""

    def _record_actionable_web_finding(self, event: SecurityEvent) -> str:
        data = dict(event.data or {})
        if event.category not in {"web", "network"}:
            return ""
        score = int(event.score or 0)
        web_decision = str(data.get("web_decision") or "")
        domain = str(data.get("remote_domain") or (event.path if event.category == "web" else "") or "").strip().rstrip(".").casefold()
        remote_address = str(data.get("remote_addr") or "")
        if not domain and str(data.get("web_source") or "") == "signed_ioc_network":
            domain = remote_address
        if not domain or "." not in domain:
            return ""
        if not remote_address:
            addresses = data.get("resolved_addresses") or []
            if isinstance(addresses, list) and addresses:
                remote_address = str(addresses[0] or "")
        source = str(data.get("web_source") or event.source or "")
        try:
            self.db.record_web_domain_observation(
                domain=domain, score=score, status=str(data.get("web_status") or "unknown"), source=source,
                process_name=str(event.process_name or ""), process_path=str(event.process_path or ""),
                remote_address=remote_address, observed_at=time.time(),
            )
        except Exception:
            pass
        if score < 20 and web_decision not in {"review", "containment_recommended", "review_shared_infrastructure"}:
            return ""
        level = str(data.get("web_level") or ("CRITICAL" if score >= 85 else "HIGH" if score >= 70 else "LOW"))
        block_recommended = bool(data.get("web_block_recommended"))
        shared_ip = bool(data.get("dns_shared_ip") or data.get("web_shared_ip_guard"))
        # A DNS resolution alone is evidence, not proof that the process actually
        # connected to the resolved address. Domain-derived IP containment is
        # enabled only after a same-PID network connection is observed.
        if event.category == "web" and block_recommended:
            block_recommended = False
            web_decision = "await_connection"
        if shared_ip and source == "signed_ioc_domain":
            block_recommended = False
            web_decision = "review_shared_infrastructure"
        finding_id = "BCW-" + secrets.token_hex(10).upper()
        evidence = {
            "event_category": event.category,
            "event_action": event.action,
            "remote_port": data.get("remote_port"),
            "dns_correlated": bool(data.get("dns_correlated")),
            "dns_domain_count": int(data.get("dns_domain_count") or 0),
            "dns_pid_count": int(data.get("dns_pid_count") or 0),
            "dns_domains": list(data.get("dns_domains") or [])[:12],
            "signed_ioc": bool(data.get("web_signed_ioc")),
            "endpoint_source": str(data.get("endpoint_source") or ""),
            "incident_id": str(data.get("incident_id") or ""),
            "is_browser": bool(data.get("is_browser")),
            "browser_family": str(data.get("browser_family") or ""),
            "browser_executable": str(data.get("browser_executable") or ""),
            "process_sha256": str(data.get("process_sha256") or ""),
            "signature_status": str(data.get("signature_status") or ""),
            "signer": str(data.get("signer") or ""),
        }
        stored = self.db.record_web_finding(
            finding_id=finding_id, created_at=time.time(), domain=domain, remote_address=remote_address,
            pid=int(event.pid) if event.pid else None, process_name=str(event.process_name or ""),
            process_path=str(event.process_path or ""), score=score, level=level, source=source,
            reasons_json=json.dumps(list(event.reasons or []), ensure_ascii=False),
            evidence_json=json.dumps(evidence, ensure_ascii=False, sort_keys=True),
            shared_ip=shared_ip, block_recommended=block_recommended,
            decision=web_decision or ("review" if score >= 20 else "observe"),
        )
        actual_id = str(stored.get("finding_id") or finding_id)
        event.data = data
        event.data["web_finding_id"] = actual_id
        return actual_id

    def _on_event(self, event: SecurityEvent):
        if not self._protection_enabled:
            return
        try:
            try:
                self._enrich_web_download_event(event)
            except Exception as download_exc:
                event.data = dict(event.data or {})
                event.data["web_download_error"] = str(download_exc)[:256]
            ancestry = self.process_tree.ancestry(int(event.pid), max_depth=8) if event.pid else []
            antimalware = self.advanced_antimalware.assess_event(event, ancestry=ancestry)
            correlation = self.correlation_engine.assess(event, ancestry=ancestry)
            event.data = dict(event.data or {})
            event.data["service_processed"] = True
            if antimalware.score > 0:
                event.data["advanced_antimalware"] = antimalware.to_dict()
            if correlation.reasons:
                event.data.update(
                    {
                        "correlation_score_delta": correlation.score_delta,
                        "correlation_confidence": correlation.confidence,
                        "correlation_severity": correlation.severity,
                        "correlation_stages": correlation.stages,
                        "correlation_evidence_families": correlation.evidence_families,
                        "correlation_sequence": correlation.sequence,
                        "correlation_incident_id": correlation.incident_id,
                        "correlation_total_score": correlation.total_score,
                    }
                )
            chain = self.process_tree.describe_chain(event.pid) if event.pid else ""
            try:
                self._record_actionable_web_finding(event)
            except Exception as web_exc:
                event.data["web_finding_error"] = str(web_exc)[:256]
            self._persist_event(event, correlation=correlation, ancestry=ancestry)
            if event.category == "process" and bool((event.data or {}).get("download_execution")):
                try:
                    self.db.mark_web_download_executed(
                        str(event.process_path or event.path or ""), executed_pid=event.pid,
                        incident_id=str((event.data or {}).get("incident_id") or (event.data or {}).get("correlation_incident_id") or ""),
                    )
                except Exception:
                    pass
            self.events.append(event, chain=chain)
        except Exception as exc:
            self._last_error = f"event pipeline: {exc}"

    def _on_realtime_detection(self, report):
        assessment = getattr(report, "assessment", None)
        event = SecurityEvent(
            category="file",
            action="realtime_detection",
            source="protection_service",
            score=int(getattr(assessment, "score", 0) or 0),
            path=str(getattr(report, "path", "") or ""),
            reasons=list(getattr(assessment, "reasons", []) or []),
            data={
                "sha256": str(getattr(report, "sha256", "") or ""),
                "level": str(getattr(assessment, "level", "") or ""),
                "realtime": True,
            },
        )
        try:
            if hasattr(self.db, "update_web_download_file_verdict"):
                download_id = self.db.update_web_download_file_verdict(
                    event.path, sha256=str(event.data.get("sha256") or ""), score=event.score,
                    level=str(event.data.get("level") or "SAFE"),
                )
                if download_id:
                    event.data["web_download_id"] = download_id
                    row = self.db.web_download(download_id) if hasattr(self.db, "web_download") else None
                    if row is not None:
                        item = self._row_dict(row)
                        event.data.update({
                            "download_domain": str(item.get("domain") or ""),
                            "download_browser_family": str(item.get("browser_family") or ""),
                            "download_origin_signed_ioc": bool(item.get("origin_signed_ioc")),
                            "download_file_verdict_separate": True,
                        })
            import json as _json
            if event.score >= 50 and event.data.get("sha256"):
                self.db.add_detection(
                    event.path, str(event.data.get("sha256") or ""), event.score,
                    str(event.data.get("level") or ""), _json.dumps(event.reasons or []),
                    "logged", dedupe_minutes=10,
                )
        except Exception:
            pass
        self._on_event(event)

    def _on_ransomware_detection(self, path, result, attribution=None):
        data = {"ransomware": True, "service_processed": True}
        pid = None
        process_name = ""
        process_path = ""
        if attribution is not None:
            pid = getattr(attribution, "pid", None)
            process_name = getattr(attribution, "name", "") or ""
            process_path = getattr(attribution, "path", "") or ""
            try:
                data["attribution"] = attribution.to_dict()
            except Exception:
                pass
        event = SecurityEvent(
            category="ransomware",
            action="heuristic_alert",
            source="protection_service",
            score=int(getattr(result, "score", 0) or 0),
            path=str(path or ""),
            pid=pid,
            process_name=process_name,
            process_path=process_path,
            reasons=list(getattr(result, "reasons", []) or []),
            data=data,
        )
        self._on_event(event)

    def _hardening_required(self) -> bool:
        import sys
        return os.name == "nt" and bool(getattr(sys, "frozen", False))

    def _check_hardening(self, *, full: bool = False) -> dict[str, Any]:
        issues: list[str] = []
        required = self._hardening_required()
        integrity = {"ok": True, "issues": [], "mode": "development"}
        manifest = EXE_DIR / "protection-integrity.json"
        if required or manifest.exists():
            result = self.integrity_verifier.verify(require_signature=True, full=full)
            integrity = result.to_dict()
            if not result.ok:
                issues.extend([f"integrity: {x}" for x in result.issues])
        try:
            self.config_store.load()
            config_ok = True
            config_detail = "HMAC verified"
        except Exception as exc:
            config_ok = False
            config_detail = str(exc)
            issues.append(f"config: {exc}")

        acl_install = windows_acl_posture(EXE_DIR)
        acl_data = windows_acl_posture(SERVICE_DIR)
        acl_key = windows_acl_posture(INTEGRITY_KEY_PATH, forbid_untrusted_read=True) if INTEGRITY_KEY_PATH.exists() else None
        for acl in (acl_install, acl_data, acl_key):
            if acl is not None and not acl.ok:
                issues.append(f"acl: {acl.path}: {acl.detail or ','.join(acl.dangerous_sids)}")

        scm = windows_service_posture(SERVICE_NAME, expected_binary=Path(os.sys.executable)) if required else None
        if scm is not None and not scm.ok:
            issues.extend([f"scm: {x}" for x in (scm.issues or [])])

        audit_ok, audit_detail, audit_records = verify_audit_chain(SERVICE_AUDIT_PATH, key_path=INTEGRITY_KEY_PATH)
        if not audit_ok:
            issues.append(f"audit: {audit_detail}")

        status = {
            "ok": not issues,
            "mode": "sealed" if required else "development",
            "issues": issues[:100],
            "last_check": time.time(),
            "integrity": integrity,
            "config": {"ok": config_ok, "detail": config_detail},
            "acl": {
                "install": acl_install.to_dict(),
                "data": acl_data.to_dict(),
                "integrity_key": acl_key.to_dict() if acl_key is not None else None,
            },
            "scm": scm.to_dict() if scm is not None else {"ok": True, "mode": "development"},
            "audit": {"ok": audit_ok, "detail": audit_detail, "records": audit_records},
        }
        self._hardening_status = status
        self._set_component("self_protection", True, not issues, critical=True, detail="; ".join(issues[:4]))
        if issues and self._health in {ServiceHealth.HEALTHY, ServiceHealth.DEGRADED}:
            self._health = ServiceHealth.DEGRADED
            self._last_error = "; ".join(issues[:4])
        return status

    def _hardening_loop(self):
        cycle = 0
        while not self._hardening_stop.wait(SERVICE_HARDENING_INTERVAL_SECONDS):
            try:
                cycle += 1
                # Stat/file-identity checks run every cycle; a full content hash
                # refresh runs periodically to prevent timestamp-restoration
                # tricks from becoming a long-lived integrity bypass.
                self._check_hardening(full=(cycle % 10 == 0))
                try:
                    self.expire_containment_leases()
                except Exception as lease_exc:
                    self._last_error = f"containment lease expiry: {lease_exc}"
                try:
                    self._firewall_drift_status = self.firewall.drift_report()
                except Exception as drift_exc:
                    self._firewall_drift_status = {
                        "ok": False, "issues": [{"type": "inspection_error", "detail": str(drift_exc)}]
                    }
                try:
                    self._firewall_conflict_status = self.firewall.policy_conflict_report()
                except Exception as conflict_exc:
                    self._firewall_conflict_status = {
                        "ok": False,
                        "blocking_conflicts": [{"type": "inspection_error", "detail": str(conflict_exc)}],
                        "advisories": [],
                        "blocking_count": 1,
                        "advisory_count": 0,
                    }
            except Exception as exc:
                with self._lock:
                    self._hardening_status = {
                        "ok": False, "mode": "sealed", "issues": [str(exc)], "last_check": time.time()
                    }
                    self._set_component("self_protection", True, False, critical=True, detail=str(exc))
                    if self._health == ServiceHealth.HEALTHY:
                        self._health = ServiceHealth.DEGRADED

    def _start_hardening_monitor(self):
        self._hardening_stop.clear()
        if self._hardening_thread and self._hardening_thread.is_alive():
            return
        self._hardening_thread = threading.Thread(
            target=self._hardening_loop, name="BCS-SelfProtection", daemon=True
        )
        self._hardening_thread.start()

    def _stop_hardening_monitor(self):
        self._hardening_stop.set()
        thread = self._hardening_thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self._hardening_thread = None

    def audit_lifecycle(self, action: str, detail: str = "") -> None:
        try:
            self.audit_writer.append({
                "ts": time.time(),
                "kind": "service_lifecycle",
                "action": str(action),
                "detail": str(detail or ""),
                "pid": os.getpid(),
            })
        except Exception:
            pass

    def start(self) -> bool:
        with self._lock:
            if self._health in {ServiceHealth.STARTING, ServiceHealth.HEALTHY, ServiceHealth.DEGRADED}:
                return True
            self._health = ServiceHealth.STARTING
            self._last_error = ""
            if not self._guard.acquire():
                self._health = ServiceHealth.ERROR
                self._last_error = "another BC Sentinel protection engine already owns the global guard"
                return False
            try:
                if self.config_error:
                    self._last_error = self.config_error
                try:
                    self.settings = self.config_store.load()
                except Exception as exc:
                    self._last_error = f"config: {exc}"
                    self._health = ServiceHealth.ERROR
                    self._guard.release()
                    return False

                hardening = self._check_hardening(full=True)
                if self._hardening_required() and not hardening.get("integrity", {}).get("ok", False):
                    self._last_error = "; ".join(hardening.get("issues", [])[:4]) or "self-protection integrity failed"
                    self._health = ServiceHealth.ERROR
                    self._guard.release()
                    return False

                self._protection_enabled = True
                realtime_running = bool(self.realtime.start()) if self.settings.realtime_enabled else False
                self._set_component("realtime", self.settings.realtime_enabled, realtime_running, critical=True)

                if self.settings.behavior_enabled:
                    self.procmon.start()
                    proc_running = bool(self.procmon._thread and self.procmon._thread.is_alive())
                else:
                    proc_running = False
                self._set_component("behavior", self.settings.behavior_enabled, proc_running, critical=True)

                etw_running = bool(self.etw.start()) if self.settings.etw_enabled else False
                self._set_component(
                    "etw", self.settings.etw_enabled, etw_running, critical=False,
                    detail=str(self.etw.error or ""),
                )

                persistence_running = bool(self.persistence.start()) if self.settings.persistence_enabled else False
                self._set_component("persistence", self.settings.persistence_enabled, persistence_running)
                antispyware_running = bool(self.antispyware.start()) if self.settings.persistence_enabled else False
                self._set_component("antispyware", self.settings.persistence_enabled, antispyware_running, critical=False)

                network_running = bool(self.network.start()) if self.settings.network_enabled else False
                self._set_component("network", self.settings.network_enabled, network_running)

                try:
                    fw_status = self.firewall.status()
                    fw_running = bool(fw_status.get("available"))
                    fw_detail = f"mode={fw_status.get('mode')}; managed_rules={fw_status.get('managed_rules', 0)}"
                except Exception as exc:
                    fw_running = False
                    fw_detail = str(exc)
                self._set_component("firewall", True, fw_running, critical=False, detail=fw_detail)
                try:
                    recovery = self.recover_web_containment_state()
                    if recovery.get("expired") or recovery.get("stale"):
                        self.db.record_security_event(SecurityEvent(
                            category="containment", action="startup_recovery", source="protection_service",
                            data=recovery,
                        ))
                except Exception as recovery_exc:
                    self._last_error = f"web containment recovery: {recovery_exc}"

                self._set_component("reputation", self.settings.reputation_enabled, self.settings.reputation_enabled)
                self._set_component("correlation", True, True, critical=True)
                self._set_component("incident_response", True, True)
                self._started_at = time.time()
                self._health = ServiceHealth.HEALTHY
                self._health = self._derive_health()
                self._start_hardening_monitor()
                self.audit_lifecycle("runtime_started", self._health.value)
                return True
            except Exception as exc:
                self._last_error = str(exc)
                self._health = ServiceHealth.ERROR
                try:
                    self._stop_components()
                finally:
                    self._guard.release()
                return False

    def _stop_components(self, *, shutdown_identity: bool = True, stop_hardening: bool = True):
        if stop_hardening:
            self._stop_hardening_monitor()
        for component, stop_name in (
            (self.network, "stop"),
            (self.antispyware, "stop"),
            (self.persistence, "stop"),
            (self.etw, "stop"),
            (self.procmon, "stop"),
            (self.realtime, "stop"),
        ):
            try:
                getattr(component, stop_name)()
            except Exception:
                pass
        if shutdown_identity:
            try:
                self.identity_resolver.shutdown(wait=False)
            except Exception:
                pass

    def stop(self):
        with self._lock:
            if self._health == ServiceHealth.STOPPED:
                return
            self._health = ServiceHealth.STOPPING
        try:
            self._stop_components()
        finally:
            with self._lock:
                for name, state in list(self._components.items()):
                    self._components[name] = ComponentState(state.enabled, False, state.critical, state.detail)
                self._health = ServiceHealth.STOPPED
                self.audit_lifecycle("runtime_stopped")
                self._guard.release()

    def set_network_collection(self, enabled: bool) -> bool:
        with self._lock:
            self.settings.network_enabled = bool(enabled)
            self.config_store.save(self.settings)
            if enabled and self._protection_enabled:
                running = bool(self.network.start())
            else:
                self.network.stop()
                running = False
            self._set_component("network", enabled, running)
            if self._health not in {ServiceHealth.ERROR, ServiceHealth.STOPPED, ServiceHealth.STOPPING}:
                self._health = ServiceHealth.HEALTHY
                self._health = self._derive_health()
            return running == bool(enabled)

    def set_protection_enabled(self, enabled: bool) -> bool:
        # v0.6 keeps the service process alive while allowing monitored
        # backends to be suspended/resumed through one deterministic gate.
        enabled = bool(enabled)
        with self._lock:
            if enabled == self._protection_enabled:
                return True
            if not enabled:
                self._protection_enabled = False
                self._stop_components(shutdown_identity=False, stop_hardening=False)
                for name, state in list(self._components.items()):
                    # Self-protection and already-installed firewall rules remain
                    # active. Firewall enforcement has its own explicit managed
                    # enable/disable operation and is never silently toggled by
                    # the legacy monitor pause switch.
                    if name in {"self_protection", "firewall"}:
                        continue
                    self._components[name] = ComponentState(state.enabled, False, state.critical, "suspended by operator")
                self._health = ServiceHealth.DEGRADED
                return True
            # Resume using persisted settings.
            self._protection_enabled = True
            self.settings = self.config_store.load()
            realtime_running = bool(self.realtime.start()) if self.settings.realtime_enabled else False
            self._set_component("realtime", self.settings.realtime_enabled, realtime_running, critical=True)
            if self.settings.behavior_enabled:
                self.procmon.start()
            self._set_component("behavior", self.settings.behavior_enabled, bool(self.procmon._thread and self.procmon._thread.is_alive()), critical=True)
            etw_running = bool(self.etw.start()) if self.settings.etw_enabled else False
            self._set_component("etw", self.settings.etw_enabled, etw_running, detail=self.etw.error or "")
            persistence_running = bool(self.persistence.start()) if self.settings.persistence_enabled else False
            self._set_component("persistence", self.settings.persistence_enabled, persistence_running)
            antispyware_running = bool(self.antispyware.start()) if self.settings.persistence_enabled else False
            self._set_component("antispyware", self.settings.persistence_enabled, antispyware_running, critical=False)
            network_running = bool(self.network.start()) if self.settings.network_enabled else False
            self._set_component("network", self.settings.network_enabled, network_running)
            try:
                fw_status = self.firewall.status()
                fw_running = bool(fw_status.get("available"))
                fw_detail = f"mode={fw_status.get('mode')}; managed_rules={fw_status.get('managed_rules', 0)}"
            except Exception as exc:
                fw_running = False
                fw_detail = str(exc)
            self._set_component("firewall", True, fw_running, critical=False, detail=fw_detail)
            self._set_component("reputation", self.settings.reputation_enabled, self.settings.reputation_enabled)
            self._set_component("correlation", True, True, critical=True)
            self._set_component("incident_response", True, True)
            self._health = ServiceHealth.HEALTHY
            self._health = self._derive_health()
            return self._health in {ServiceHealth.HEALTHY, ServiceHealth.DEGRADED}

    def update_config(self, changes: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.settings = self.config_store.update(changes)
            # Changes to monitor topology are deliberately applied on explicit
            # service restart in v0.6 except network, which has a safe hot toggle.
            if "network_enabled" in changes:
                self.set_network_collection(bool(changes["network_enabled"]))
            return _settings_to_dict(self.settings)

    def status(self) -> dict[str, Any]:
        with self._lock:
            derived = self._derive_health()
            if self._health in {ServiceHealth.HEALTHY, ServiceHealth.DEGRADED}:
                self._health = derived
            return {
                "service": SERVICE_NAME,
                "display_name": SERVICE_DISPLAY_NAME,
                "pid": os.getpid(),
                "health": self._health.value,
                "protection_enabled": bool(self._protection_enabled),
                "components": {name: state.to_dict() for name, state in self._components.items()},
                # compatibility fields used by the v0.5 GUI during migration
                "advanced": bool(self._components.get("etw") and self._components["etw"].running),
                "etw": {
                    **self.etw.status(),
                    "running": bool(self._components.get("etw") and self._components["etw"].running),
                },
                "persistence": bool(self._components.get("persistence") and self._components["persistence"].running),
                "antispyware": self.antispyware_status(),
                "advanced_antimalware": self.advanced_antimalware_status(),
                "network": bool(self._components.get("network") and self._components["network"].running),
                "firewall": self._firewall_status_safe(),
                "ioc": self.db.ioc_status(),
                "threat_intelligence": self.threat_intel.status(),
                "containment": {"active_leases": len(self.db.active_containment_leases())},
                "web_protection": self.web_status(),
                "realtime": bool(self._components.get("realtime") and self._components["realtime"].running),
                "behavior": bool(self._components.get("behavior") and self._components["behavior"].running),
                "sequence": self.events.sequence,
                "started_at": self._started_at,
                "last_error": self._last_error,
                "config_integrity": bool(self._hardening_status.get("config", {}).get("ok", not bool(self.config_error))),
                "hardening": dict(self._hardening_status),
                "transport": "windows_named_pipe" if os.name == "nt" else "direct_test_only",
            }

    def _firewall_status_safe(self) -> dict[str, Any]:
        try:
            return self.firewall.status()
        except Exception as exc:
            return {
                "available": False,
                "mode": "unavailable",
                "managed_group": "BC Sentinel Managed Protection",
                "managed_rules": 0,
                "managed_enabled": False,
                "error": str(exc),
            }

    def firewall_status(self) -> dict[str, Any]:
        return self._firewall_status_safe()

    def firewall_rules(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.firewall.list_rules(limit)

    def firewall_block_remote(self, payload: dict[str, Any]) -> dict[str, Any]:
        rule = self.firewall.block_remote(
            remote_address=payload["remote_address"],
            direction=payload["direction"],
            protocol=payload["protocol"],
            remote_port=payload.get("remote_port"),
            application_path=payload.get("application_path", ""),
            reason=payload.get("reason", ""),
            incident_id=payload.get("incident_id", ""),
        )
        incident_id = str(payload.get("incident_id") or "").strip()
        if incident_id:
            try:
                self.db.record_incident_action(
                    incident_id=incident_id,
                    action="firewall_block_remote",
                    status="success",
                    detail={
                        "rule_id": rule.get("rule_id"),
                        "remote_address": rule.get("remote_address"),
                        "direction": rule.get("direction"),
                        "protocol": rule.get("protocol"),
                        "remote_port": rule.get("remote_port"),
                    },
                )
            except Exception:
                pass
        return rule

    def firewall_remove_rule(self, rule_id: str) -> bool:
        return self.firewall.remove_rule(rule_id)

    def firewall_set_managed_enabled(self, enabled: bool) -> int:
        return self.firewall.set_managed_enabled(enabled)

    def firewall_drift(self) -> dict[str, Any]:
        self._firewall_drift_status = self.firewall.drift_report()
        return dict(self._firewall_drift_status)

    def firewall_reconcile(self, *, approved: bool) -> dict[str, Any]:
        return self.firewall.reconcile_drift(approved=approved)

    def firewall_conflicts(self) -> dict[str, Any]:
        return self.firewall.policy_conflict_report()

    def threat_file_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        action = str(payload.get("action") or "")
        path = str(payload.get("path") or "")
        sha256 = str(payload.get("sha256") or "").casefold()
        score = int(payload.get("score") or 0)
        level = str(payload.get("level") or "").strip().upper()
        reasons = [str(x) for x in (payload.get("reasons") or [])][:16]
        if score < 70 or level not in {"HIGH", "CRITICAL"}:
            raise PermissionError(
                "Threat file response is restricted to qualified HIGH/CRITICAL detections."
            )
        reason_text = "; ".join(reasons[:4]) or f"Threat decision {level}"
        if action == "quarantine":
            item_id = self.quarantine.quarantine(
                path,
                score,
                reason_text,
                expected_sha256=sha256,
            )
            self.db.update_detection_action(sha256, "quarantined")
            result = {"action": action, "status": "success", "quarantine_id": item_id, "path": path}
        elif action == "delete":
            removed = self.quarantine.delete_detected_file(path, sha256)
            self.db.update_detection_action(sha256, "deleted")
            result = {"action": action, "status": "success", "deleted_path": str(removed), "path": path}
        else:
            raise ValueError("unsupported threat file action")
        self.db.record_security_event(SecurityEvent(
            category="threat_decision",
            action=action,
            source="protection_service",
            score=score,
            path=path,
            reasons=reasons,
            data={
                "status": result["status"],
                "sha256": sha256,
                "level": level,
                "explicit_user_decision": True,
                "privileged_service_action": True,
            },
        ))
        return result

    def acknowledge_threat_decision(self, sha256: str, action: str, detail: str = "") -> dict[str, Any]:
        digest = str(sha256 or "").casefold()
        self.db.update_detection_action(digest, str(action))
        self.db.record_security_event(SecurityEvent(
            category="threat_decision", action=str(action), source="protection_service_ack",
            data={
                "sha256": digest, "detail": str(detail or ""),
                "explicit_user_decision": True, "file_mutation": False,
            },
        ))
        return {"sha256": digest, "action": str(action), "status": "recorded"}

    def pending_threats(self, limit: int = 100) -> list[dict[str, Any]]:
        return [self._row_dict(row) for row in self.db.pending_threat_decisions(limit)]

    def advanced_antimalware_status(self) -> dict[str, Any]:
        return self.advanced_antimalware.status() if hasattr(self, "advanced_antimalware") else {"supported": False}

    def advanced_antimalware_findings(self, limit: int = 200, min_score: int = 0) -> list[dict[str, Any]]:
        rows = self.db.recent_advanced_antimalware_findings(limit, min_score=min_score) if hasattr(self.db, "recent_advanced_antimalware_findings") else []
        out = []
        for row in rows:
            item = self._row_dict(row)
            try:
                item["reasons"] = json.loads(item.get("reasons_json") or "[]")
            except Exception:
                item["reasons"] = []
            try:
                item["evidence"] = json.loads(item.get("evidence_json") or "{}")
            except Exception:
                item["evidence"] = {}
            item["automatic_destructive_action"] = False
            out.append(item)
        return out

    def antispyware_status(self) -> dict[str, Any]:
        status = self.antispyware.status() if hasattr(self, "antispyware") else {}
        status["single_persistence_signal_is_malware"] = False
        status["multi_signal_correlation"] = True
        status["persistence_remediation_mode"] = "explicit_reversible_disable_restore"
        status["remediation"] = self.antispyware_remediation.status()
        status["pup_adware_response"] = "review_or_explicit_reversible_plan"
        return status

    def antispyware_findings(self, limit: int = 200, min_score: int = 0) -> list[dict[str, Any]]:
        rows = self.db.recent_antispyware_findings(limit, min_score=min_score) if hasattr(self.db, "recent_antispyware_findings") else []
        out = []
        for row in rows:
            item = self._row_dict(row)
            try:
                item["reasons"] = json.loads(item.get("reasons_json") or "[]")
            except Exception:
                item["reasons"] = []
            try:
                item["evidence"] = json.loads(item.get("evidence_json") or "{}")
            except Exception:
                item["evidence"] = {}
            if item.get("target_exists") is not None:
                item["target_exists"] = bool(item.get("target_exists"))
            item["user_writable"] = bool(item.get("user_writable"))
            item["automatic_destructive_action"] = False
            out.append(item)
        return out

    def antispyware_remediation_status(self) -> dict[str, Any]:
        return self.antispyware_remediation.status()

    def antispyware_remediation_plan(self, finding_id: str) -> dict[str, Any]:
        return self.antispyware_remediation.create_plan(finding_id)

    def antispyware_remediation_plans(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.antispyware_remediation.plans(limit)

    def antispyware_remediation_apply(self, plan_id: str, *, approved: bool) -> dict[str, Any]:
        result = self.antispyware_remediation.apply(plan_id, approved=approved)
        self._on_event(SecurityEvent(
            category="antispyware", action="persistence_disabled", source="antispyware_remediation",
            score=0, data={
                "plan_id": plan_id, "finding_id": result.get("finding_id"),
                "explicit_user_decision": True, "reversible": True,
                "automatic_destructive_action": False,
            },
        ))
        return result

    def antispyware_remediation_restore(self, plan_id: str, *, approved: bool) -> dict[str, Any]:
        result = self.antispyware_remediation.restore(plan_id, approved=approved)
        self._on_event(SecurityEvent(
            category="antispyware", action="persistence_restored", source="antispyware_remediation",
            score=0, data={
                "plan_id": plan_id, "finding_id": result.get("finding_id"),
                "explicit_user_decision": True, "reversible": True,
                "automatic_destructive_action": False,
            },
        ))
        return result

    def web_status(self) -> dict[str, Any]:
        try:
            etw_status = self.etw.status()
        except Exception:
            etw_status = {}
        pending = self.db.recent_web_findings(500, min_score=0, status="pending") if hasattr(self.db, "recent_web_findings") else []
        trust_conflicts = self.db.web_domain_trust_conflicts(limit=100) if hasattr(self.db, "web_domain_trust_conflicts") else []
        return {
            "mode": "active_reversible",
            "enabled": bool(self.settings.network_enabled and self.settings.etw_enabled),
            "dns_etw": bool(etw_status.get("dns_tracking")),
            "pid_scoped_dns": True,
            "mitm_https": False,
            "auto_block": False,
            "shared_ip_guard": True,
            "actionable_findings": len(pending),
            "domain_iocs": self.db.ioc_kind_count("domain") if hasattr(self.db, "ioc_kind_count") else 0,
            "trusted_domains": self.db.web_domain_trust_count() if hasattr(self.db, "web_domain_trust_count") else 0,
            "trust_conflicts": len(trust_conflicts),
            "domain_trust_exact_only": True,
            "signed_ioc_overrides_trust": True,
            "reputation_domains": self.db.web_domain_reputation_count() if hasattr(self.db, "web_domain_reputation_count") else 0,
            "tracked_downloads": self.db.web_download_count() if hasattr(self.db, "web_download_count") else 0,
            "download_tracking": True,
            "download_origin_never_overrides_file_verdict": True,
            "download_correlation": self.download_correlation.status() if hasattr(self, "download_correlation") else {},
            "dns_cache": self.dns_cache.status() if hasattr(self, "dns_cache") else {},
            "deception_profile": "v0.10.0-beta.1",
            "response_profile": WEB_RESPONSE_PROFILE,
            "response_mode": "operator_approved_reversible",
            "web_containment_ttl_min_seconds": WEB_CONTAINMENT_TTL_MIN,
            "web_containment_ttl_max_seconds": WEB_CONTAINMENT_TTL_MAX,
            "duplicate_rule_prevention": True,
            "restart_recovery": True,
            "stale_rule_cleanup": True,
            "shared_ip_never_address_blocked": True,
            "mixed_script_detection": True,
            "lookalike_detection": True,
            "typosquat_detection": True,
            "scam_lure_context": True,
            "lure_requires_structural_risk": True,
            "redirect_chain_analysis": True,
            "stable_heuristic_fingerprint": True,
            "heuristic_score_cap": 49,
            "heuristic_can_qualify_high": False,
            "heuristic_auto_block": False,
            "cloud_dependency_required": False,
            "clone_scam_profile": CLONE_SCAM_PROFILE,
            "clone_site_context_analysis": True,
            "sensitive_form_destination_analysis": True,
            "scam_fraud_multi_signal_analysis": True,
            "scam_text_alone_never_blocks": True,
            "page_context_auto_block": False,
        }

    def web_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.recent_web_findings(limit, min_score=0) if hasattr(self.db, "recent_web_findings") else []
        out = []
        for row in rows:
            item = self._row_dict(row)
            for field, target, default in (("reasons_json", "reasons", []), ("evidence_json", "evidence", {})):
                raw = item.get(field)
                try:
                    item[target] = json.loads(raw or json.dumps(default))
                except Exception:
                    item[target] = default
            item["shared_ip"] = bool(item.get("shared_ip"))
            item["block_recommended"] = bool(item.get("block_recommended"))
            domain = str(item.get("domain") or "")
            trust = self.db.match_web_domain_trust(domain) if hasattr(self.db, "match_web_domain_trust") else None
            signed = self.db.match_ioc_endpoint(domain) if domain and hasattr(self.db, "match_ioc_endpoint") else None
            item["trusted_domain"] = bool(trust)
            item["trust_overridden"] = bool(trust and signed is not None and str(signed.get("kind") or "") == "domain")
            item["trust_scope"] = "exact" if trust else ""
            out.append(item)
        return out

    def web_downloads(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.recent_web_downloads(limit) if hasattr(self.db, "recent_web_downloads") else []
        out: list[dict[str, Any]] = []
        for row in rows:
            item = self._row_dict(row)
            try:
                item["evidence"] = json.loads(str(item.get("evidence_json") or "{}"))
            except Exception:
                item["evidence"] = {}
            item["origin_signed_ioc"] = bool(item.get("origin_signed_ioc"))
            item["file_verdict_separate"] = True
            out.append(item)
        return out

    def web_download_detail(self, download_id: str) -> dict[str, Any] | None:
        row = self.db.web_download(download_id) if hasattr(self.db, "web_download") else None
        if row is None:
            return None
        item = self._row_dict(row)
        try:
            item["evidence"] = json.loads(str(item.get("evidence_json") or "{}"))
        except Exception:
            item["evidence"] = {}
        item["origin_signed_ioc"] = bool(item.get("origin_signed_ioc"))
        item["file_verdict_separate"] = True
        return item

    def web_domain_trust(self, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.db.list_web_domain_trust(limit) if hasattr(self.db, "list_web_domain_trust") else []
        out: list[dict[str, Any]] = []
        for row in rows:
            item = self._row_dict(row)
            match = self.db.match_ioc_endpoint(str(item.get("domain") or "")) if hasattr(self.db, "match_ioc_endpoint") else None
            overridden = bool(match is not None and str(match.get("kind") or "") == "domain")
            item["overridden_by_signed_ioc"] = overridden
            if overridden:
                item["ioc"] = {
                    "severity": str(match.get("severity") or ""),
                    "label": str(match.get("label") or ""),
                    "bundle_id": str(match.get("bundle_id") or ""),
                    "expires_at": float(match.get("expires_at") or 0),
                }
            out.append(item)
        return out

    def web_domain_reputation(self, domain: str) -> dict[str, Any]:
        normalized = normalize_domain(domain)
        if not normalized:
            raise ValueError("valid domain is required")
        reputation = self.db.web_domain_reputation(normalized) if hasattr(self.db, "web_domain_reputation") else {"domain": normalized, "observed": False}
        assessment = self.web_protection.assess_domain(normalized).to_dict()
        reputation["current_assessment"] = assessment
        reputation["trusted_domain"] = bool(self.db.match_web_domain_trust(normalized)) if hasattr(self.db, "match_web_domain_trust") else False
        reputation["signed_ioc_active"] = bool(assessment.get("signed_ioc"))
        return reputation

    def add_web_domain_trust(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not bool(payload.get("approved")):
            raise PermissionError("Explicit operator approval is required for persistent domain trust.")
        normalized = normalize_domain(str(payload.get("domain") or ""))
        if not normalized:
            raise ValueError("trusted domain is invalid")
        if str(payload.get("domain") or "").strip().startswith("*."):
            raise ValueError("wildcard domain trust is not supported")
        signed = self.db.match_ioc_endpoint(normalized) if hasattr(self.db, "match_ioc_endpoint") else None
        if signed is not None and str(signed.get("kind") or "") == "domain":
            raise PermissionError("Signed malicious IOC overrides local domain trust; this domain cannot be trusted while the IOC is active.")
        existing_trust = self.db.match_web_domain_trust(normalized) if hasattr(self.db, "match_web_domain_trust") else None
        if existing_trust is None and hasattr(self.db, "web_domain_trust_count") and self.db.web_domain_trust_count() >= 512:
            raise ValueError("persistent domain trust limit reached (512 exact domains)")
        finding_id = str(payload.get("finding_id") or "").strip().upper()
        if finding_id:
            row = self.db.web_finding(finding_id)
            if row is None:
                raise KeyError("web finding not found")
            if normalize_domain(str(row["domain"] or "")) != normalized:
                raise PermissionError("finding/domain mismatch; persistent trust refused")
        reason = str(payload.get("reason") or "Operator trusted exact domain")[:256]
        trust = self.db.add_web_domain_trust(normalized, reason=reason, source_finding_id=finding_id)
        resolved = self.db.resolve_pending_web_findings_by_domain(
            normalized, status="trusted_domain", resolution="persistent exact-domain trust approved"
        ) if hasattr(self.db, "resolve_pending_web_findings_by_domain") else 0
        self.db.record_security_event(SecurityEvent(
            category="web", action="domain_trust_added", source="protection_service_policy",
            score=0, path=normalized, reasons=["Persistent exact-domain trust explicitly approved"],
            data={
                "domain": normalized, "scope": "exact", "source_finding_id": finding_id,
                "resolved_findings": int(resolved), "explicit_user_decision": True,
                "persistent_trust": True, "signed_ioc_precedence": True,
            },
        ))
        return {"trust": trust, "resolved_findings": int(resolved), "precedence": "signed_ioc>local_domain_trust>heuristics"}

    def remove_web_domain_trust(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not bool(payload.get("approved")):
            raise PermissionError("Explicit operator approval is required to change persistent domain trust.")
        normalized = normalize_domain(str(payload.get("domain") or ""))
        if not normalized:
            raise ValueError("trusted domain is invalid")
        removed = bool(self.db.remove_web_domain_trust(normalized))
        if removed:
            self.db.record_security_event(SecurityEvent(
                category="web", action="domain_trust_removed", source="protection_service_policy",
                score=0, path=normalized, reasons=["Persistent exact-domain trust revoked"],
                data={"domain": normalized, "scope": "exact", "explicit_user_decision": True, "persistent_trust": False},
            ))
        return {"domain": normalized, "removed": removed}

    def decide_web_finding(self, finding_id: str, action: str, detail: str = "") -> dict[str, Any]:
        row = self.db.web_finding(str(finding_id))
        if row is None:
            raise KeyError("web finding not found")
        if str(row["status"] or "") != "pending":
            return {"finding_id": str(finding_id), "status": str(row["status"] or "resolved"), "idempotent": True}
        action = str(action or "").strip().casefold()
        if action not in {"ignore_once", "reviewed"}:
            raise ValueError("unsupported web finding decision")
        status = "ignored_once" if action == "ignore_once" else "reviewed"
        self.db.resolve_web_finding(str(finding_id), status=status, resolution=str(detail or action))
        self.db.record_security_event(SecurityEvent(
            category="web", action=f"finding_{status}", source="protection_service_decision",
            score=int(row["score"] or 0), path=str(row["domain"] or ""), pid=row["pid"],
            process_name=str(row["process_name"] or ""), process_path=str(row["process_path"] or ""),
            reasons=["Explicit operator web finding decision"],
            data={"finding_id": str(finding_id), "decision": action, "detail": str(detail or ""), "explicit_user_decision": True},
        ))
        return {"finding_id": str(finding_id), "status": status, "action": action}

    def web_assess(self, value: str) -> dict[str, Any]:
        raw = str(value or "").strip()
        if not raw:
            raise ValueError("web assessment value is required")
        result = self.web_protection.assess_url(raw if "://" in raw else "https://" + raw)
        payload = result.to_dict()
        domain = normalize_domain(str(payload.get("indicator") or ""))
        if domain and hasattr(self.db, "web_domain_reputation"):
            payload["reputation"] = self.db.web_domain_reputation(domain)
        return payload

    def web_clone_scam_assess(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = assess_page_context(
            url=str(payload.get("url") or ""),
            declared_identity=str(payload.get("declared_identity") or ""),
            page_title=str(payload.get("page_title") or ""),
            visible_text=str(payload.get("visible_text") or ""),
            form_action=str(payload.get("form_action") or ""),
            form_fields=payload.get("form_fields") or (),
            payment_methods=payload.get("payment_methods") or (),
            link_hosts=payload.get("link_hosts") or (),
            redirect_chain=payload.get("redirect_chain") or (),
        )
        return result.to_dict()

    def ioc_status(self) -> dict[str, Any]:
        return self.db.ioc_status()

    def ioc_entries(self, limit: int = 500) -> list[dict[str, Any]]:
        return [self._row_dict(row) for row in self.db.list_ioc_entries(limit)]

    def threat_intel_status(self) -> dict[str, Any]:
        status = self.threat_intel.status()
        status["ioc_overlay"] = self.db.threat_package_ioc_status() if hasattr(self.db, "threat_package_ioc_status") else {}
        status["trust"] = self.threat_trust.status()
        status["retrieval_policy"] = SecureThreatRetriever.policy()
        status["remote_index"] = self.threat_index.status()
        status["remote_cache"] = self.threat_cache.status()
        status["scheduler"] = self.threat_scheduler.status()
        status["remote_channel_policy"] = ThreatRemoteCoordinator.policy()
        status["signed_reputation_entries"] = self.db.threat_package_reputation_count() if hasattr(self.db, "threat_package_reputation_count") else 0
        return status

    def threat_intel_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.threat_intel.history(limit)

    def validate_threat_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        verified = self.threat_package_verifier.verify(payload["package"], payload["signature"])
        return {
            "valid": True,
            "package_id": verified.package_id,
            "sequence": verified.sequence,
            "payload_sha256": verified.payload_sha256,
            "key_fingerprint": verified.key_fingerprint,
            "signing_key_id": verified.signing_key_id,
            "component_hashes": dict(verified.component_hashes),
            "components": {
                "ioc_entries": len(verified.ioc_entries),
                "yara_rules": len(verified.yara_rules),
                "behavior_rules": len(verified.behavior_rules),
                "reputation_entries": len(verified.reputation_entries),
            },
        }

    def validate_threat_keyset(self, payload: dict[str, Any]) -> dict[str, Any]:
        verified = self.threat_trust.validate_keyset(payload["keyset"], payload["signature"])
        return {"valid": True, **verified.to_dict()}

    def validate_threat_index(self, payload: dict[str, Any]) -> dict[str, Any]:
        verified = self.threat_index_verifier.verify(payload["index"], payload["signature"])
        return {"valid": True, **verified.to_dict()}

    def install_threat_keyset(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not payload.get("approved"):
            raise PermissionError("Explicit operator approval is required to install a threat trust keyset.")
        result = self.threat_trust.install_keyset(payload["keyset"], payload["signature"])
        return {"result": result, "trust": self.threat_trust.status()}

    def stage_threat_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not payload.get("approved"):
            raise PermissionError("Explicit operator approval is required to stage signed threat content.")
        return self.threat_intel.stage(payload["package"], payload["signature"])

    def activate_threat_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not payload.get("approved"):
            raise PermissionError("Explicit operator approval is required to activate signed threat content.")
        return self.threat_intel.activate(payload["stage_id"])

    def install_threat_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not payload.get("approved"):
            raise PermissionError("Explicit operator approval is required to install signed threat content.")
        staged = self.threat_intel.stage(payload["package"], payload["signature"])
        activated = self.threat_intel.activate(staged["stage_id"])
        return {"stage": staged, "activation": activated}

    def rollback_threat_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not payload.get("approved"):
            raise PermissionError("Explicit operator approval is required for threat-content rollback.")
        return self.threat_intel.rollback_last_known_good()

    def import_ioc_bundle(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not bool(payload.get("approved")):
            raise PermissionError("Explicit operator approval is required for IOC feed import.")
        verified = self.ioc_verifier.verify(
            dict(payload.get("bundle") or {}),
            str(payload.get("signature") or ""),
        )
        result = self.db.install_ioc_bundle(verified)
        status = self.db.ioc_status()
        trust_conflicts = self.db.web_domain_trust_conflicts(limit=100) if hasattr(self.db, "web_domain_trust_conflicts") else []
        self.db.record_security_event(SecurityEvent(
            category="ioc", action="signed_bundle_imported", source="protection_service",
            score=0, reasons=["Ed25519 signature verified", "anti-rollback sequence accepted"],
            data={
                "bundle_id": verified.bundle_id, "sequence": verified.sequence,
                "payload_sha256": verified.payload_sha256, "entries": len(verified.entries),
                "idempotent": bool(result.get("idempotent")), "explicit_user_decision": True,
            },
        ))
        if trust_conflicts:
            self.db.record_security_event(SecurityEvent(
                category="web", action="domain_trust_overridden", source="protection_service", score=85,
                reasons=["Signed IOC precedence over local domain trust"],
                data={
                    "conflict_count": len(trust_conflicts),
                    "domains": [str(item.get("domain") or "") for item in trust_conflicts[:20]],
                    "bundle_id": verified.bundle_id, "sequence": verified.sequence,
                },
            ))
        return {**result, "status": status, "domain_trust_conflicts": len(trust_conflicts)}

    def containment_leases(self) -> list[dict[str, Any]]:
        return [self._row_dict(row) for row in self.db.active_containment_leases()]

    def _create_containment_lease_qualified(
        self, *, remote_address: str, ttl: int, reason: str, incident_id: str,
        qualification: str, ioc_label: str = "", finding_id: str = "",
    ) -> dict[str, Any]:
        created = time.time()
        expires = created + int(ttl)
        lease_id = secrets.token_hex(16)
        rule = self.firewall.block_remote(
            remote_address=str(remote_address), direction="outbound", protocol="any",
            reason=f"lease:{lease_id} {reason}"[:256], incident_id=str(incident_id or ""),
        )
        rule_id = str(rule.get("rule_id") or "")
        try:
            self.db.add_containment_lease(
                lease_id=lease_id, rule_id=rule_id,
                remote_address=str(rule.get("remote_address") or remote_address or ""),
                incident_id=str(incident_id or ""), reason=str(reason or ""), created_at=created, expires_at=expires,
            )
        except Exception:
            try:
                self.firewall.remove_rule(rule_id)
            finally:
                raise
        self.db.record_security_event(SecurityEvent(
            category="containment", action="lease_created", source="protection_service",
            score=0, reasons=["Temporary BLOCK rule with bounded TTL"],
            data={
                "lease_id": lease_id, "rule_id": rule_id, "remote_address": rule.get("remote_address"),
                "expires_at": expires, "ttl_seconds": int(ttl), "incident_id": str(incident_id or ""),
                "qualification": str(qualification), "ioc_label": str(ioc_label or ""),
                "finding_id": str(finding_id or ""), "explicit_user_decision": True,
            },
        ))
        return {
            "lease_id": lease_id, "rule_id": rule_id, "remote_address": rule.get("remote_address"),
            "created_at": created, "expires_at": expires, "ttl_seconds": int(ttl), "status": "active",
            "qualification": str(qualification), "finding_id": str(finding_id or ""),
        }

    def create_containment_lease(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not bool(payload.get("approved")):
            raise PermissionError("Explicit operator approval is required for containment.")
        ttl = int(payload.get("ttl_seconds") or 0)
        if not 60 <= ttl <= 86400:
            raise ValueError("containment lease TTL is outside the supported range")
        reason = str(payload.get("reason") or "Temporary containment lease")
        incident_id = str(payload.get("incident_id") or "")
        remote_address = str(payload.get("remote_address") or "")
        signed_ioc = self.db.match_ioc_endpoint(remote_address) if hasattr(self.db, "match_ioc_endpoint") else None
        incident = self.db.get_incident(incident_id) if incident_id else None
        incident_score = int(incident["score"] or 0) if incident is not None else 0
        if signed_ioc is None and incident_score < 70:
            raise PermissionError(
                "Containment lease requires an active signed IOC or a verified incident with score >= 70."
            )
        return self._create_containment_lease_qualified(
            remote_address=remote_address, ttl=ttl, reason=reason, incident_id=incident_id,
            qualification="signed_ioc" if signed_ioc is not None else "high_score_incident",
            ioc_label=str((signed_ioc or {}).get("label") or ""),
        )

    def _lease_payload(self, row, *, idempotent: bool = False, reused_existing: bool = False) -> dict[str, Any]:
        data = self._row_dict(row)
        created = float(data.get("created_at") or 0.0)
        expires = float(data.get("expires_at") or 0.0)
        data["ttl_seconds"] = max(0, int(round(expires - created)))
        data["idempotent"] = bool(idempotent)
        data["reused_existing"] = bool(reused_existing)
        return data

    def create_web_containment(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not bool(payload.get("approved")):
            raise PermissionError("Explicit operator approval is required for Web Protection containment.")
        ttl = int(payload.get("ttl_seconds") or 0)
        if not WEB_CONTAINMENT_TTL_MIN <= ttl <= WEB_CONTAINMENT_TTL_MAX:
            raise ValueError(
                f"web containment TTL must be between {WEB_CONTAINMENT_TTL_MIN} and {WEB_CONTAINMENT_TTL_MAX} seconds"
            )
        finding_id = str(payload.get("finding_id") or "")
        row = self.db.web_finding(finding_id)
        if row is None:
            raise KeyError("web finding not found")

        # Idempotent retry: a repeated operator/UI request must never create a
        # second Windows Firewall rule for the same finding.
        if str(row["status"] or "") == "contained" and str(row["lease_id"] or ""):
            existing = self.db.containment_lease(str(row["lease_id"]))
            if existing is not None and str(existing["status"] or "") == "active":
                return self._lease_payload(existing, idempotent=True)
        if str(row["status"] or "") != "pending":
            raise PermissionError("web finding is no longer pending")

        domain = str(row["domain"] or "").casefold()
        remote_address = str(row["remote_address"] or "")
        source = str(row["source"] or "")
        try:
            evidence = json.loads(str(row["evidence_json"] or "{}"))
        except Exception:
            evidence = {}

        context = self.dns_cache.lookup_context(row["pid"], remote_address) if remote_address else None
        dns_domain = str(getattr(context, "domain", "") or "")
        shared = bool(row["shared_ip"]) or bool(getattr(context, "shared_ip", False))
        endpoint = self.db.match_ioc_endpoint(remote_address) if remote_address and hasattr(self.db, "match_ioc_endpoint") else None
        signed_network_active = bool(endpoint and str(endpoint.get("kind") or "") == "network")
        assessment = self.web_protection.assess_domain(domain) if domain else None
        signed_domain_active = bool(assessment and assessment.signed_ioc)

        qualified = qualify_web_containment(
            source=source,
            score=int(row["score"] or 0),
            block_recommended=bool(row["block_recommended"]),
            event_category=str(evidence.get("event_category") or ""),
            domain=domain,
            remote_address=remote_address,
            dns_domain=dns_domain,
            shared_ip=shared,
            signed_network_active=signed_network_active,
            signed_domain_active=signed_domain_active,
        )
        if not qualified.eligible:
            legacy_messages = {
                "shared_ip_guard": "shared/CDN IP guard blocked address containment",
                "finding_not_qualified": "web finding is not qualified for containment",
                "same_pid_dns_revalidation_failed": "PID-scoped DNS correlation expired or changed; reassess before containment",
                "network_observation_required": "domain containment requires an observed same-PID network connection",
            }
            raise PermissionError(legacy_messages.get(qualified.reason, f"web containment denied: {qualified.reason}"))

        # Address-level dedupe across separate findings. Reuse the exact active
        # lease and bind this finding to it instead of creating another rule.
        existing_remote = self.db.active_containment_lease_for_remote(remote_address)
        if existing_remote is not None:
            lease_id = str(existing_remote["lease_id"] or "")
            self.db.resolve_web_finding(
                finding_id, status="contained", resolution="reused existing temporary containment", lease_id=lease_id
            )
            return self._lease_payload(existing_remote, idempotent=True, reused_existing=True)

        ioc_label = ""
        if qualified.qualification == "signed_network_ioc":
            ioc_label = str((endpoint or {}).get("label") or "")
        elif assessment is not None:
            ioc_label = assessment.reasons[0] if assessment.reasons else ""

        reason = str(payload.get("reason") or f"Web Protection finding {finding_id}")
        lease = self._create_containment_lease_qualified(
            remote_address=remote_address, ttl=ttl, reason=reason, incident_id="",
            qualification=qualified.qualification, ioc_label=ioc_label, finding_id=finding_id,
        )
        lease["response_profile"] = WEB_RESPONSE_PROFILE
        lease["qualification_policy"] = qualified.to_dict()
        self.db.resolve_web_finding(
            finding_id, status="contained", resolution="temporary containment approved", lease_id=str(lease.get("lease_id") or "")
        )
        return lease

    def recover_web_containment_state(self) -> dict[str, Any]:
        """Conservative restart recovery for Beta2 managed temporary rules."""
        now = time.time()
        expired: list[str] = []
        stale: list[str] = []
        active: list[str] = []
        observed = {str(row.get("rule_id") or "") for row in self.firewall.list_rules(500)}
        for row in list(self.db.active_containment_leases()):
            lease_id = str(row["lease_id"] or "")
            rule_id = str(row["rule_id"] or "")
            if float(row["expires_at"] or 0.0) <= now:
                self._release_containment_lease(lease_id, reason="startup_ttl_expired")
                expired.append(lease_id)
                continue
            if rule_id not in observed:
                # Never recreate an address block merely because protected state
                # says one used to exist. Clear stale desired state and release.
                self.db.delete_firewall_expected_rule(rule_id)
                self.db.mark_containment_lease_released(lease_id, reason="startup_missing_rule", released_at=now)
                try:
                    self.db.resolve_web_findings_by_lease(
                        lease_id, status="released", resolution="containment released: startup_missing_rule", resolved_at=now
                    )
                except Exception:
                    pass
                stale.append(lease_id)
                continue
            active.append(lease_id)
        return {"active": active, "expired": expired, "stale": stale, "ok": True}

    def _release_containment_lease(self, lease_id: str, *, reason: str) -> dict[str, Any]:
        row = self.db.containment_lease(lease_id)
        if row is None:
            raise KeyError("containment lease not found")
        if str(row["status"] or "") != "active":
            return {"lease_id": lease_id, "status": str(row["status"] or "released"), "removed": False}
        rule_id = str(row["rule_id"] or "")
        removed = bool(self.firewall.remove_rule(rule_id))
        if not removed:
            # A missing/tampered rule must not keep a stale desired-state record
            # after its approved lease has expired or been explicitly released.
            self.db.delete_firewall_expected_rule(rule_id)
        released_at = time.time()
        self.db.mark_containment_lease_released(lease_id, reason=reason, released_at=released_at)
        try:
            self.db.resolve_web_findings_by_lease(
                lease_id, status="released", resolution=f"containment released: {reason}", resolved_at=released_at
            )
        except Exception:
            pass
        self.db.record_security_event(SecurityEvent(
            category="containment", action="lease_released", source="protection_service",
            data={
                "lease_id": lease_id, "rule_id": rule_id, "removed": removed,
                "release_reason": reason, "released_at": released_at,
            },
        ))
        return {"lease_id": lease_id, "rule_id": rule_id, "status": "released", "removed": removed, "release_reason": reason}

    def release_containment_lease(self, lease_id: str, *, approved: bool) -> dict[str, Any]:
        if not approved:
            raise PermissionError("Explicit operator approval is required to release containment.")
        return self._release_containment_lease(str(lease_id), reason="operator_release")

    def expire_containment_leases(self) -> list[dict[str, Any]]:
        now = time.time()
        released: list[dict[str, Any]] = []
        for row in self.db.active_containment_leases():
            if float(row["expires_at"] or 0.0) > now:
                continue
            released.append(self._release_containment_lease(str(row["lease_id"]), reason="ttl_expired"))
        return released

    def attribute(self, path: str):
        attribution = self.correlator.attribute(path, max_age=5.0)
        result = attribution.to_dict()
        if attribution.pid:
            result["chain"] = self.process_tree.describe_chain(attribution.pid)
        return result

    def process_chain(self, pid: int):
        return [
            {
                "pid": node.pid,
                "ppid": node.ppid,
                "name": node.name,
                "path": node.path,
                "cmdline": node.cmdline,
                "risk_score": node.risk_score,
                "reasons": node.reasons,
                "create_time": node.create_time,
                "sha256": node.sha256,
                "signature_status": node.signature_status,
                "signer": node.signer,
                "modified_files": list(node.modified_files),
            }
            for node in self.process_tree.ancestry(int(pid), max_depth=10)
        ]

    @staticmethod
    def _row_dict(row):
        return {key: row[key] for key in row.keys()}

    def incident(self, incident_id: str):
        row = self.db.get_incident(incident_id)
        return self._row_dict(row) if row is not None else None

    def incidents(self, limit=100, min_score=0):
        rows = self.db.recent_incidents(limit=int(limit), include_suppressed=True)
        return [self._row_dict(row) for row in rows if int(row["score"] or 0) >= int(min_score)]

    def quarantine_items(self):
        return [self._row_dict(row) for row in self.quarantine.list_items(include_restored=True)]

    def incident_payload(self, incident_id: str) -> dict[str, Any] | None:
        row = self.db.get_incident(incident_id)
        if row is None:
            return None
        def loads(name, default):
            try:
                return json.loads(row[name] or "")
            except Exception:
                return default
        return {
            "incident_id": row["incident_id"],
            "pid": row["pid"],
            "ppid": row["ppid"],
            "process_name": row["process_name"] or "",
            "process_path": row["process_path"] or "",
            "process_sha256": row["process_sha256"] or "",
            "signature_status": row["signature_status"] or "",
            "signer": row["signer"] or "",
            "score": int(row["score"] or 0),
            "level": row["level"] or "SAFE",
            "confidence": float(row["confidence"] or 0.0),
            "reasons": loads("reasons_json", []),
            "data": loads("data_json", {}),
            "recommended_actions": loads("recommended_actions_json", []),
            "status": row["status"] or "open",
            "suppressed": bool(row["suppressed"]),
        }


class ProtectionServiceCore:
    """Validated command surface for the privileged protection runtime.

    This class contains no socket/TCP server. Production transport is the
    Windows named-pipe server in `protection_transport_windows.py`.
    """

    def __init__(self, runtime: ProtectionRuntime | None = None, *, secret: str | None = None):
        self.runtime = runtime or ProtectionRuntime()
        self.secret = secret or self.runtime.secret
        self._audit_lock = threading.RLock()
        self._privilege_tickets = PrivilegeTicketStore()
        self._request_limiter = SlidingWindowRateLimiter()
        self._abuse_limiter = SlidingWindowRateLimiter()
        self._audit_writer = getattr(
            self.runtime,
            "audit_writer",
            AuditChainWriter(SERVICE_AUDIT_PATH, key_path=INTEGRITY_KEY_PATH),
        )

    @staticmethod
    def _client_rate_key(context: ClientContext) -> tuple[object, ...]:
        return (
            str(context.sid or "unknown"),
            int(context.session_id) if context.session_id is not None else -1,
            str(context.transport or "direct"),
        )

    def _enforce_request_rate(self, request: ValidatedRequest, context: ClientContext) -> dict[str, Any] | None:
        op = request.op
        # Ticket-result polling is intentionally excluded; the standard-user
        # client polls a short-lived result while a UAC action completes.
        if op == "privileged_ticket_result":
            return None
        key = self._client_rate_key(context)
        if op == "prepare_privileged_action":
            limits = ((4, 5.0, "broker_burst"), (18, 60.0, "broker_minute"))
        elif op in {"threat_decision_ack", "web_finding_decide"}:
            limits = ((8, 5.0, "decision_burst"), (40, 60.0, "decision_minute"))
        elif op in {"firewall_block_remote", "firewall_remove_rule", "firewall_set_managed_enabled", "firewall_reconcile", "containment_lease_create", "containment_lease_release", "web_containment_create"}:
            limits = ((6, 5.0, "firewall_burst"), (24, 60.0, "firewall_minute"))
        elif op in {"threat_file_action", "quarantine_file", "restore_quarantine", "add_exclusion", "remove_exclusion", "ioc_import", "web_domain_trust_add", "web_domain_trust_remove", "threat_package_stage", "threat_package_install", "threat_package_activate", "threat_package_rollback", "threat_keyset_install"}:
            limits = ((5, 5.0, "response_burst"), (20, 60.0, "response_minute"))
        elif op in PRIVILEGED_OPERATIONS:
            limits = ((10, 5.0, "privileged_burst"), (40, 60.0, "privileged_minute"))
        else:
            return None
        for limit, window, bucket in limits:
            decision = self._request_limiter.check((bucket, key), limit=limit, window_seconds=window)
            if not decision.allowed:
                self._audit(context, request, "blocked", f"rate limit {bucket}")
                return response_error(
                    request.request_id,
                    "rate_limited",
                    "request rate limit exceeded; retry after the bounded cooldown",
                    retry_after_seconds=round(decision.retry_after_seconds, 3),
                    limit=decision.limit,
                    window_seconds=decision.window_seconds,
                )
        return None

    def _audit(self, context: ClientContext, request: ValidatedRequest, status: str, detail: str = ""):
        if request.op not in PRIVILEGED_OPERATIONS:
            return
        record = {
            "ts": time.time(),
            "request_id": request.request_id,
            "op": request.op,
            "status": status,
            "detail": detail,
            "client_sid": context.sid,
            "client_admin": bool(context.is_admin),
            "transport": context.transport,
        }
        try:
            _ensure_service_dir()
            with self._audit_lock:
                self._audit_writer.append(record)
        except Exception:
            pass

    def _authorize(self, request: ValidatedRequest, context: ClientContext):
        if not context.local:
            raise ProtocolError("unauthorized", "remote clients are not accepted")
        if not authorized_token(request.token, self.secret):
            raise ProtocolError("unauthorized", "installation token verification failed")
        if request.op in {"prepare_privileged_action", "privileged_ticket_result"}:
            if not context.authenticated or not context.sid:
                raise ProtocolError("unauthorized", "broker requests require an authenticated local Windows identity")
        if request.op in {"threat_decision_ack", "web_finding_decide"} and not context.authenticated:
            raise ProtocolError("unauthorized", "operator decision acknowledgement requires an authenticated local identity")
        if request.op in PRIVILEGED_OPERATIONS:
            if not context.authenticated:
                raise ProtocolError("unauthorized", "transport did not authenticate the local client")
            if not context.is_admin:
                raise ProtocolError("admin_required", "this operation requires an elevated Windows administrator token")

    def _audit_broker(self, *, event: str, context: ClientContext, ticket=None, detail: str = "") -> None:
        record = {
            "ts": time.time(),
            "event": str(event),
            "op": getattr(ticket, "op", ""),
            "ticket_id_hash": hashlib.sha256(str(getattr(ticket, "ticket_id", "")).encode("utf-8")).hexdigest()[:24] if ticket else "",
            "detail": str(detail or ""),
            "client_sid": context.sid,
            "client_admin": bool(context.is_admin),
            "client_session_id": context.session_id,
            "client_process_id": context.process_id,
            "requester_sid": getattr(ticket, "requester_sid", "") if ticket else context.sid,
            "requester_session_id": getattr(ticket, "requester_session_id", None) if ticket else context.session_id,
            "transport": context.transport,
        }
        try:
            _ensure_service_dir()
            with self._audit_lock:
                self._audit_writer.append(record)
        except Exception:
            pass

    def dispatch_validated(self, request: ValidatedRequest, context: ClientContext) -> dict[str, Any]:
        try:
            self._authorize(request, context)
            limited = self._enforce_request_rate(request, context)
            if limited is not None:
                return limited
            p = request.payload
            op = request.op
            if op in {"ping", "status"}:
                status = dict(self.runtime.status())
                status["privileged_broker"] = self._privilege_tickets.metrics()
                status["abuse_protection"] = {
                    "request_rate_limiter": self._request_limiter.metrics(),
                    "invalid_message_limiter": self._abuse_limiter.metrics(),
                }
                return response_ok(request.request_id, status=status)
            if op == "events":
                return response_ok(
                    request.request_id,
                    events=self.runtime.events.since(p["since"], p["limit"]),
                    sequence=self.runtime.events.sequence,
                )
            if op == "attribute":
                return response_ok(request.request_id, attribution=self.runtime.attribute(p["path"]))
            if op == "process_chain":
                return response_ok(request.request_id, chain=self.runtime.process_chain(p["pid"]))
            if op == "incident":
                return response_ok(request.request_id, incident=self.runtime.incident(p["incident_id"]))
            if op == "incidents":
                return response_ok(request.request_id, incidents=self.runtime.incidents(p["limit"], p["min_score"]))
            if op == "quarantine_items":
                return response_ok(request.request_id, items=self.runtime.quarantine_items())
            if op == "hardening_status":
                return response_ok(request.request_id, hardening=dict(getattr(self.runtime, "_hardening_status", {})))
            if op == "firewall_status":
                return response_ok(request.request_id, firewall=self.runtime.firewall_status())
            if op == "firewall_rules":
                return response_ok(request.request_id, rules=self.runtime.firewall_rules(p["limit"]))
            if op == "firewall_drift":
                return response_ok(request.request_id, drift=self.runtime.firewall_drift())
            if op == "firewall_conflicts":
                return response_ok(request.request_id, conflicts=self.runtime.firewall_conflicts())
            if op == "antispyware_status":
                return response_ok(request.request_id, antispyware=self.runtime.antispyware_status())
            if op == "advanced_antimalware_status":
                return response_ok(request.request_id, advanced_antimalware=self.runtime.advanced_antimalware_status())
            if op == "advanced_antimalware_findings":
                return response_ok(request.request_id, findings=self.runtime.advanced_antimalware_findings(p["limit"], p["min_score"]))
            if op == "antispyware_findings":
                return response_ok(request.request_id, findings=self.runtime.antispyware_findings(p["limit"], p["min_score"]))
            if op == "antispyware_remediation_plan":
                try:
                    plan = self.runtime.antispyware_remediation_plan(p["finding_id"])
                except (KeyError, ValueError, PermissionError, RuntimeError) as exc:
                    return response_error(request.request_id, "remediation_plan_unavailable", str(exc))
                return response_ok(request.request_id, remediation_plan=plan)
            if op == "antispyware_remediation_plans":
                return response_ok(request.request_id, remediation_plans=self.runtime.antispyware_remediation_plans(p["limit"]))
            if op == "web_status":
                return response_ok(request.request_id, web=self.runtime.web_status())
            if op == "web_findings":
                return response_ok(request.request_id, findings=self.runtime.web_findings(p["limit"]))
            if op == "web_downloads":
                return response_ok(request.request_id, downloads=self.runtime.web_downloads(p["limit"]))
            if op == "web_download_detail":
                return response_ok(request.request_id, download=self.runtime.web_download_detail(p["download_id"]))
            if op == "web_assess":
                return response_ok(request.request_id, assessment=self.runtime.web_assess(p["value"]))
            if op == "web_clone_scam_assess":
                return response_ok(request.request_id, assessment=self.runtime.web_clone_scam_assess(p))
            if op == "web_domain_trust":
                return response_ok(request.request_id, trust=self.runtime.web_domain_trust())
            if op == "web_domain_reputation":
                return response_ok(request.request_id, reputation=self.runtime.web_domain_reputation(p["domain"]))
            if op == "web_finding_decide":
                decision = self.runtime.decide_web_finding(p["finding_id"], p["action"], p.get("detail", ""))
                return response_ok(request.request_id, decision=decision)
            if op == "ioc_status":
                return response_ok(request.request_id, ioc=self.runtime.ioc_status())
            if op == "ioc_entries":
                return response_ok(request.request_id, entries=self.runtime.ioc_entries(p["limit"]))
            if op == "threat_intel_status":
                return response_ok(request.request_id, threat_intelligence=self.runtime.threat_intel_status())
            if op == "threat_intel_history":
                return response_ok(request.request_id, history=self.runtime.threat_intel_history(p["limit"]))
            if op == "threat_package_validate":
                return response_ok(request.request_id, validation=self.runtime.validate_threat_package(p))
            if op == "threat_keyset_validate":
                return response_ok(request.request_id, validation=self.runtime.validate_threat_keyset(p))
            if op == "threat_index_validate":
                return response_ok(request.request_id, validation=self.runtime.validate_threat_index(p))
            if op == "containment_leases":
                return response_ok(request.request_id, leases=self.runtime.containment_leases())
            if op == "pending_threats":
                return response_ok(request.request_id, threats=self.runtime.pending_threats())
            if op == "threat_decision_ack":
                decision = self.runtime.acknowledge_threat_decision(p["sha256"], p["action"], p.get("detail", ""))
                return response_ok(request.request_id, decision=decision)
            if op == "prepare_privileged_action":
                try:
                    ticket = self._privilege_tickets.issue(context, p["action"], p["payload"])
                except PermissionError as exc:
                    return response_error(request.request_id, "unauthorized", str(exc))
                except RuntimeError as exc:
                    return response_error(request.request_id, "broker_busy", str(exc))
                self._audit_broker(event="privileged_action_prepared", context=context, ticket=ticket)
                return response_ok(
                    request.request_id,
                    ticket_id=ticket.ticket_id,
                    action=ticket.op,
                    action_digest=ticket.payload_digest,
                    expires_at=ticket.expires_at,
                )
            if op == "privileged_ticket_result":
                try:
                    result = self._privilege_tickets.result_for(p["ticket_id"], context)
                    status = self._privilege_tickets.status_for(p["ticket_id"], context)
                except PermissionError as exc:
                    return response_error(request.request_id, "unauthorized", str(exc))
                if status is None:
                    return response_error(request.request_id, "ticket_not_found", "privileged ticket not found or expired")
                return response_ok(request.request_id, pending=result is None, ticket=status, action_result=result)
            if op == "execute_privileged_ticket":
                try:
                    ticket = self._privilege_tickets.consume(p["ticket_id"], context)
                except KeyError as exc:
                    self._audit_broker(event="privileged_action_rejected", context=context, detail=str(exc))
                    return response_error(request.request_id, "ticket_not_found", str(exc))
                except PermissionError as exc:
                    self._audit_broker(event="privileged_action_rejected", context=context, detail=str(exc))
                    return response_error(request.request_id, "ticket_rejected", str(exc))
                self._audit_broker(event="privileged_action_elevated", context=context, ticket=ticket)
                inner_request = ValidatedRequest(
                    version=request.version,
                    request_id=(request.request_id[:48] + ".broker"),
                    op=ticket.op,
                    token=request.token,
                    payload=dict(ticket.payload),
                )
                inner_result = self.dispatch_validated(inner_request, context)
                self._privilege_tickets.complete(ticket.ticket_id, inner_result)
                self._audit_broker(
                    event="privileged_action_completed",
                    context=context,
                    ticket=ticket,
                    detail="success" if inner_result.get("ok") else "failed",
                )
                return response_ok(
                    request.request_id,
                    action=ticket.op,
                    action_digest=ticket.payload_digest,
                    action_ok=bool(inner_result.get("ok")),
                    action_result=inner_result,
                )
            if op == "set_network_collection":
                ok = self.runtime.set_network_collection(p["enabled"])
                self._audit(context, request, "success" if ok else "failed")
                return response_ok(request.request_id, network=bool(self.runtime.status().get("network")))
            if op == "set_protection_enabled":
                ok = self.runtime.set_protection_enabled(p["enabled"])
                self._audit(context, request, "success" if ok else "failed")
                return response_ok(request.request_id, protection_enabled=self.runtime.status()["protection_enabled"])
            if op == "set_protection_config":
                settings = self.runtime.update_config(p["settings"])
                self._audit(context, request, "success")
                return response_ok(request.request_id, settings=settings, restart_recommended=True)
            if op == "ioc_import":
                result = self.runtime.import_ioc_bundle(p)
                self._audit(context, request, "success", f"signed IOC sequence={result.get('sequence')}")
                return response_ok(request.request_id, ioc=result)
            if op == "threat_keyset_install":
                result = self.runtime.install_threat_keyset(p)
                self._audit(context, request, "success", f"threat keyset sequence={(result.get('trust') or {}).get('keyset_sequence')}")
                return response_ok(request.request_id, threat_trust=result)
            if op == "threat_package_stage":
                result = self.runtime.stage_threat_package(p)
                self._audit(context, request, "success", f"threat package staged={result.get('stage_id')}")
                return response_ok(request.request_id, threat_package=result)
            if op == "threat_package_install":
                result = self.runtime.install_threat_package(p)
                active = (result.get("activation") or {}).get("active") or {}
                self._audit(context, request, "success", f"threat package installed={active.get('package_id')} seq={active.get('sequence')}")
                return response_ok(request.request_id, threat_package=result)
            if op == "threat_package_activate":
                result = self.runtime.activate_threat_package(p)
                active = result.get("active") or {}
                self._audit(context, request, "success", f"threat package activated={active.get('package_id')} seq={active.get('sequence')}")
                return response_ok(request.request_id, threat_package=result)
            if op == "threat_package_rollback":
                result = self.runtime.rollback_threat_package(p)
                active = result.get("active") or {}
                self._audit(context, request, "success", f"threat package rollback active={active.get('package_id')}")
                return response_ok(request.request_id, threat_package=result)
            if op == "antispyware_remediation_apply":
                if not p["approved"]:
                    self._audit(context, request, "blocked", "explicit operator approval required")
                    return response_error(request.request_id, "approval_required", "explicit operator approval is required")
                try:
                    result = self.runtime.antispyware_remediation_apply(p["plan_id"], approved=True)
                except Exception as exc:
                    self._audit(context, request, "blocked", str(exc))
                    return response_error(request.request_id, "remediation_apply_failed", str(exc))
                self._audit(context, request, "success", f"antispyware remediation applied={p['plan_id']}")
                return response_ok(request.request_id, remediation_plan=result)
            if op == "antispyware_remediation_restore":
                if not p["approved"]:
                    self._audit(context, request, "blocked", "explicit operator approval required")
                    return response_error(request.request_id, "approval_required", "explicit operator approval is required")
                try:
                    result = self.runtime.antispyware_remediation_restore(p["plan_id"], approved=True)
                except Exception as exc:
                    self._audit(context, request, "blocked", str(exc))
                    return response_error(request.request_id, "remediation_restore_failed", str(exc))
                self._audit(context, request, "success", f"antispyware remediation restored={p['plan_id']}")
                return response_ok(request.request_id, remediation_plan=result)
            if op == "containment_lease_create":
                lease = self.runtime.create_containment_lease(p)
                self._audit(context, request, "success", f"containment lease={lease.get('lease_id')}")
                return response_ok(request.request_id, lease=lease)
            if op == "containment_lease_release":
                lease = self.runtime.release_containment_lease(p["lease_id"], approved=p["approved"])
                self._audit(context, request, "success", f"containment lease released={p['lease_id']}")
                return response_ok(request.request_id, lease=lease)
            if op == "web_containment_create":
                lease = self.runtime.create_web_containment(p)
                self._audit(context, request, "success", f"web containment finding={p['finding_id']} lease={lease.get('lease_id')}")
                return response_ok(request.request_id, lease=lease)
            if op == "web_domain_trust_add":
                result = self.runtime.add_web_domain_trust(p)
                self._audit(context, request, "success", f"web domain trust added={p['domain']}")
                return response_ok(request.request_id, domain_trust=result)
            if op == "web_domain_trust_remove":
                result = self.runtime.remove_web_domain_trust(p)
                self._audit(context, request, "success", f"web domain trust removed={p['domain']}")
                return response_ok(request.request_id, domain_trust=result)
            if op == "firewall_block_remote":
                if not p["approved"]:
                    self._audit(context, request, "blocked", "explicit operator approval required")
                    return response_error(request.request_id, "approval_required", "explicit operator approval is required")
                rule = self.runtime.firewall_block_remote(p)
                self._audit(context, request, "success", f"firewall rule={rule.get('rule_id')} remote={rule.get('remote_address')}")
                return response_ok(request.request_id, rule=rule, firewall=self.runtime.firewall_status())
            if op == "firewall_remove_rule":
                if not p["approved"]:
                    self._audit(context, request, "blocked", "explicit operator approval required")
                    return response_error(request.request_id, "approval_required", "explicit operator approval is required")
                removed = self.runtime.firewall_remove_rule(p["rule_id"])
                if not removed:
                    self._audit(context, request, "blocked", "managed firewall rule not found")
                    return response_error(request.request_id, "firewall_rule_not_found", "managed firewall rule not found")
                self._audit(context, request, "success", f"firewall rule={p['rule_id']}")
                return response_ok(request.request_id, removed=True, rule_id=p["rule_id"], firewall=self.runtime.firewall_status())
            if op == "firewall_set_managed_enabled":
                if not p["approved"]:
                    self._audit(context, request, "blocked", "explicit operator approval required")
                    return response_error(request.request_id, "approval_required", "explicit operator approval is required")
                affected = self.runtime.firewall_set_managed_enabled(p["enabled"])
                self._audit(context, request, "success", f"managed firewall enabled={p['enabled']} affected={affected}")
                return response_ok(request.request_id, enabled=p["enabled"], affected_rules=affected, firewall=self.runtime.firewall_status())
            if op == "firewall_reconcile":
                if not p["approved"]:
                    self._audit(context, request, "blocked", "explicit operator approval required")
                    return response_error(request.request_id, "approval_required", "explicit operator approval is required")
                result = self.runtime.firewall_reconcile(approved=True)
                self._audit(context, request, "success" if result.get("ok") else "partial", f"firewall reconciliation actions={len(result.get('actions') or [])}")
                return response_ok(request.request_id, reconciliation=result, firewall=self.runtime.firewall_status())
            if op == "terminate_process":
                incident = self.runtime.incident_payload(p["incident_id"])
                if incident is None:
                    self._audit(context, request, "blocked", "incident not found")
                    return response_error(request.request_id, "incident_not_found", "incident not found")
                result = self.runtime.response_engine.terminate_process(incident, approved=p["approved"])
                self._audit(context, request, result.status, result.detail)
                return response_ok(request.request_id, result=result.to_dict())
            if op == "quarantine_file":
                incident = self.runtime.incident_payload(p["incident_id"])
                if incident is None:
                    self._audit(context, request, "blocked", "incident not found")
                    return response_error(request.request_id, "incident_not_found", "incident not found")
                result = self.runtime.response_engine.quarantine_file(
                    incident,
                    candidate_path=p.get("candidate_path") or None,
                    approved=p["approved"],
                )
                self._audit(context, request, result.status, result.detail)
                return response_ok(request.request_id, result=result.to_dict())
            if op == "restore_quarantine":
                if not p["approved"]:
                    self._audit(context, request, "blocked", "explicit operator approval required")
                    return response_error(request.request_id, "approval_required", "explicit operator approval is required")
                restored = self.runtime.quarantine.restore(p["item_id"], p.get("destination") or None)
                self._audit(context, request, "success", str(restored))
                return response_ok(request.request_id, restored_path=str(restored))
            if op == "threat_file_action":
                if not p["approved"]:
                    self._audit(context, request, "blocked", "explicit operator approval required")
                    return response_error(request.request_id, "approval_required", "explicit operator approval is required")
                try:
                    result = self.runtime.threat_file_action(p)
                except PermissionError as exc:
                    self._audit(context, request, "blocked", str(exc))
                    return response_error(request.request_id, "threat_action_not_qualified", str(exc))
                self._audit(context, request, "success", f"threat action={p['action']} path={p['path']}")
                return response_ok(request.request_id, result=result)
            if op == "add_exclusion":
                ident = self.runtime.db.add_allowlist(p["kind"], p["value"])
                self._audit(context, request, "success", f"allowlist id={ident}")
                return response_ok(request.request_id, id=ident)
            if op == "remove_exclusion":
                self.runtime.db.remove_allowlist(p["id"])
                self._audit(context, request, "success", f"allowlist id={p['id']}")
                return response_ok(request.request_id, removed=True)
            return response_error(request.request_id, "unsupported_operation", "Unsupported operation")
        except ProtocolError as exc:
            self._audit(context, request, "blocked", exc.message)
            return response_error(request.request_id, exc.code, exc.message)
        except Exception as exc:
            self._audit(context, request, "failed", str(exc))
            return response_error(request.request_id, "operation_failed", str(exc))

    def dispatch(self, request: dict[str, Any], context: ClientContext | None = None) -> dict[str, Any]:
        request_id = str(request.get("request_id") or "unknown") if isinstance(request, dict) else "unknown"
        try:
            validated = validate_request(request)
        except ProtocolError as exc:
            return response_error(request_id, exc.code, exc.message)
        return self.dispatch_validated(validated, context or ClientContext())

    def dispatch_bytes(self, raw: bytes, context: ClientContext | None = None) -> dict[str, Any]:
        request_id = "unknown"
        context = context or ClientContext()
        try:
            validated = decode_request(raw)
            request_id = validated.request_id
        except ProtocolError as exc:
            key = self._client_rate_key(context)
            decision = self._abuse_limiter.record_failure(key, limit=24, window_seconds=30.0)
            if not decision.allowed:
                return response_error(
                    request_id,
                    "rate_limited",
                    "too many invalid IPC messages from this authenticated client context",
                    retry_after_seconds=round(decision.retry_after_seconds, 3),
                )
            return response_error(request_id, exc.code, exc.message)
        return self.dispatch_validated(validated, context)
