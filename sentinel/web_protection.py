from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import re
import threading
import time
from urllib.parse import urlsplit

from .database import Database
from .web_deception import (
    HEURISTIC_PROFILE,
    HEURISTIC_SCORE_CAP,
    assess_local_url,
    bounded_heuristic_score,
    domain_deception_signals,
    serialize_signals,
    stable_deception_fingerprint,
)

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)

_BROWSER_EXECUTABLES = {
    "chrome.exe": "Chrome",
    "msedge.exe": "Edge",
    "firefox.exe": "Firefox",
    "brave.exe": "Brave",
    "opera.exe": "Opera",
    "opera_gx.exe": "Opera GX",
    "vivaldi.exe": "Vivaldi",
    "arc.exe": "Arc",
}


def classify_browser_process(process_name: str = "", process_path: str = "", signer: str = "") -> dict[str, object]:
    """Return bounded browser context from process identity without guessing.

    Classification is exact-executable based. Signer text is evidence only and
    never upgrades an unknown process into a browser.
    """
    import os as _os
    name = str(process_name or "").strip().casefold()
    if not name and process_path:
        name = _os.path.basename(str(process_path)).casefold()
    family = _BROWSER_EXECUTABLES.get(name, "")
    return {
        "is_browser": bool(family),
        "browser_family": family,
        "browser_executable": name if family else "",
        "signer": str(signer or "")[:256],
    }



@dataclass(slots=True)
class WebAssessment:
    indicator: str = ""
    kind: str = "domain"
    normalized_url: str = ""
    score: int = 0
    level: str = "SAFE"
    status: str = "unknown"
    source: str = "local_heuristics"
    reasons: list[str] = field(default_factory=list)
    signed_ioc: bool = False
    block_recommended: bool = False
    decision: str = "observe"
    trusted_domain: bool = False
    trust_scope: str = ""
    provenance: list[dict[str, object]] = field(default_factory=list)
    risk_families: list[str] = field(default_factory=list)
    signal_codes: list[str] = field(default_factory=list)
    heuristic_profile: str = HEURISTIC_PROFILE
    identity_context: dict[str, object] = field(default_factory=dict)
    heuristic_fingerprint: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass(slots=True, frozen=True)
class DNSCorrelationContext:
    pid: int
    address: str
    domain: str = ""
    shared_ip: bool = False
    domain_count: int = 0
    pid_count: int = 0
    domains: tuple[str, ...] = ()
    observed_at: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_domain(value: str) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw or len(raw) > 253 or "\x00" in raw:
        return ""
    try:
        ascii_name = raw.encode("idna").decode("ascii").casefold()
    except Exception:
        return ""
    labels = ascii_name.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return ""
    return ascii_name


def extract_ip_addresses(value: object) -> list[str]:
    """Extract canonical IP addresses from DNS ETW QueryResults safely."""
    if value is None:
        return []
    chunks = [str(item) for item in value] if isinstance(value, (list, tuple, set)) else [str(value)]
    found: list[str] = []
    for chunk in chunks:
        for token in re.split(r"[\s,;|=()\[\]{}]+", chunk):
            token = token.strip().strip("'\"")
            if not token:
                continue
            try:
                ip = ipaddress.ip_address(token.split("%", 1)[0])
            except ValueError:
                continue
            text = str(ip)
            if text not in found:
                found.append(text)
    return found


@dataclass(slots=True)
class _DNSMapping:
    pid: int
    domain: str
    address: str
    expires_at: float
    observed_at: float


class DNSCorrelationCache:
    """Short-lived PID-scoped DNS→connection cache with shared-IP awareness.

    Attribution remains strictly PID-scoped: `lookup()` never borrows a domain
    from another process. Beta 2 additionally keeps a bounded recent history per
    IP so containment can fail closed when one address is serving multiple
    domains/processes (CDN/shared-hosting risk).
    """

    def __init__(self, *, ttl_seconds: float = 180.0, max_entries: int = 8192):
        self.ttl_seconds = max(15.0, min(float(ttl_seconds), 900.0))
        self.max_entries = max(256, min(int(max_entries), 65536))
        self._lock = threading.RLock()
        self._by_pid_ip: dict[tuple[int, str], _DNSMapping] = {}
        self._history: dict[tuple[int, str, str], _DNSMapping] = {}

    @staticmethod
    def _canonical_ip(address: str) -> str:
        return str(ipaddress.ip_address(str(address).split("%", 1)[0]))

    def observe(self, pid: int | None, domain: str, addresses: list[str] | tuple[str, ...], *, now: float | None = None) -> int:
        try:
            pid_value = int(pid or 0)
        except Exception:
            return 0
        normalized = normalize_domain(domain)
        if pid_value <= 0 or not normalized:
            return 0
        ts = time.time() if now is None else float(now)
        expiry = ts + self.ttl_seconds
        inserted = 0
        with self._lock:
            self._prune_locked(ts)
            for raw in addresses:
                try:
                    address = self._canonical_ip(str(raw))
                except ValueError:
                    continue
                mapping = _DNSMapping(pid_value, normalized, address, expiry, ts)
                self._by_pid_ip[(pid_value, address)] = mapping
                self._history[(pid_value, address, normalized)] = mapping
                inserted += 1
            self._trim_locked()
        return inserted

    def lookup(self, pid: int | None, address: str, *, now: float | None = None) -> str:
        return self.lookup_context(pid, address, now=now).domain

    def lookup_context(self, pid: int | None, address: str, *, now: float | None = None) -> DNSCorrelationContext:
        try:
            pid_value = int(pid or 0)
            ip = self._canonical_ip(address)
        except Exception:
            return DNSCorrelationContext(pid=0, address="")
        if pid_value <= 0:
            return DNSCorrelationContext(pid=pid_value, address=ip)
        ts = time.time() if now is None else float(now)
        with self._lock:
            self._prune_locked(ts)
            current = self._by_pid_ip.get((pid_value, ip))
            domain = current.domain if current is not None else ""
            observed_at = current.observed_at if current is not None else 0.0
            mappings = [item for item in self._history.values() if item.address == ip]
            domains = tuple(sorted({item.domain for item in mappings}))
            pids = {item.pid for item in mappings}
            # More than one recently observed exact domain on one address is a
            # conservative shared-infrastructure signal. False "shared" is
            # safer than blocking a CDN/shared host from domain-only evidence.
            shared = len(domains) > 1
            return DNSCorrelationContext(
                pid=pid_value,
                address=ip,
                domain=domain,
                shared_ip=shared,
                domain_count=len(domains),
                pid_count=len(pids),
                domains=domains[:12],
                observed_at=observed_at,
            )

    def _prune_locked(self, now: float) -> None:
        for key, value in list(self._by_pid_ip.items()):
            if value.expires_at <= now:
                self._by_pid_ip.pop(key, None)
        for key, value in list(self._history.items()):
            if value.expires_at <= now:
                self._history.pop(key, None)

    def _trim_locked(self) -> None:
        if len(self._history) <= self.max_entries:
            return
        oldest = sorted(self._history.items(), key=lambda item: item[1].observed_at)
        for key, _ in oldest[: len(self._history) - self.max_entries]:
            self._history.pop(key, None)

    def status(self) -> dict:
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            address_domains: dict[str, set[str]] = {}
            for item in self._history.values():
                address_domains.setdefault(item.address, set()).add(item.domain)
            return {
                "active_mappings": len(self._by_pid_ip),
                "history_mappings": len(self._history),
                "shared_ip_addresses": sum(1 for values in address_domains.values() if len(values) > 1),
                "ttl_seconds": self.ttl_seconds,
                "pid_scoped": True,
                "shared_ip_guard": True,
            }


class WebProtectionEngine:
    """Local explainable Web Protection decision engine.

    Structural phishing signals remain advisory. Signed domain/network evidence
    may recommend containment, but Beta 2 never mutates the firewall itself;
    the privileged service performs a second, current-time eligibility check.
    """

    def __init__(self, db: Database | None = None):
        self.db = db or Database()

    @staticmethod
    def _level(score: int) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 50:
            return "SUSPICIOUS"
        if score >= 20:
            return "LOW"
        return "SAFE"

    def assess_domain(self, domain: str) -> WebAssessment:
        original = str(domain or "").strip().rstrip(".")
        normalized = normalize_domain(original)
        if not normalized:
            return WebAssessment(indicator=original, status="invalid", reasons=["Nome dominio non valido"], score=0)

        reasons: list[str] = []
        score = 0
        signed = None
        trusted = None
        try:
            signed = self.db.match_ioc_endpoint(normalized)
        except Exception:
            signed = None
        try:
            trusted = self.db.match_web_domain_trust(normalized)
        except Exception:
            trusted = None
        if signed is not None and str(signed.get("kind") or "") == "domain":
            score = 90 if str(signed.get("severity") or "").casefold() == "critical" else 85
            reasons.append(str(signed.get("label") or "Dominio presente nella denylist IOC firmata"))
            provenance = [{
                "tier": "signed_ioc",
                "bundle_id": str(signed.get("bundle_id") or ""),
                "severity": str(signed.get("severity") or ""),
                "expires_at": float(signed.get("expires_at") or 0),
                "label": str(signed.get("label") or ""),
            }]
            if trusted is not None:
                provenance.append({
                    "tier": "local_domain_trust",
                    "state": "overridden_by_signed_ioc",
                    "scope": "exact",
                    "created_at": float(trusted.get("created_at") or 0),
                    "reason": str(trusted.get("reason") or ""),
                })
                reasons.append("La fiducia locale esistente è ignorata perché un IOC firmato ha precedenza")
            return WebAssessment(
                indicator=normalized,
                score=score,
                level=self._level(score),
                status="malicious",
                source="signed_ioc",
                reasons=reasons,
                signed_ioc=True,
                block_recommended=True,
                decision="containment_recommended",
                trusted_domain=bool(trusted),
                trust_scope="exact" if trusted else "",
                provenance=provenance,
            )

        if trusted is not None:
            return WebAssessment(
                indicator=normalized,
                score=0,
                level="SAFE",
                status="trusted",
                source="local_domain_trust",
                reasons=[str(trusted.get("reason") or "Dominio consentito esplicitamente dall'operatore")],
                signed_ioc=False,
                block_recommended=False,
                decision="allow_trusted",
                trusted_domain=True,
                trust_scope="exact",
                provenance=[{
                    "tier": "local_domain_trust",
                    "scope": "exact",
                    "created_at": float(trusted.get("created_at") or 0),
                    "reason": str(trusted.get("reason") or ""),
                    "source_finding_id": str(trusted.get("source_finding_id") or ""),
                }],
            )

        signals = domain_deception_signals(original, normalized)
        score = bounded_heuristic_score(signals)
        reasons = list(dict.fromkeys(signal.reason for signal in signals))
        families = list(dict.fromkeys(signal.family for signal in signals))
        codes = list(dict.fromkeys(signal.code for signal in signals))
        return WebAssessment(
            indicator=normalized,
            score=score,
            level=self._level(score),
            status="suspicious" if score >= 20 else "unknown",
            source="local_heuristics",
            reasons=reasons,
            signed_ioc=False,
            block_recommended=False,
            decision="review" if score >= 20 else "observe",
            provenance=[{
                "tier": "local_heuristics",
                "profile": HEURISTIC_PROFILE,
                "signals": reasons,
                "signal_details": serialize_signals(signals),
            }],
            risk_families=families,
            signal_codes=codes,
            heuristic_fingerprint=stable_deception_fingerprint(normalized, codes),
        )

    def assess_connection(
        self,
        *,
        domain: str,
        address: str,
        shared_ip: bool = False,
        domain_count: int = 1,
        pid_count: int = 1,
    ) -> WebAssessment:
        normalized = normalize_domain(domain)
        try:
            ip = str(ipaddress.ip_address(str(address).split("%", 1)[0]))
        except ValueError:
            ip = ""

        # A signed network IOC targets the address itself, so shared hosting is
        # not a reason to suppress a temporary address containment recommendation.
        if ip:
            try:
                endpoint = self.db.match_ioc_endpoint(ip)
            except Exception:
                endpoint = None
            if endpoint is not None and str(endpoint.get("kind") or "") == "network":
                score = 95 if str(endpoint.get("severity") or "").casefold() == "critical" else 88
                return WebAssessment(
                    indicator=normalized or ip,
                    kind="connection",
                    score=score,
                    level=self._level(score),
                    status="malicious",
                    source="signed_ioc_network",
                    reasons=[str(endpoint.get("label") or "IP/rete presente nella denylist IOC firmata")],
                    signed_ioc=True,
                    block_recommended=True,
                    decision="containment_recommended",
                    provenance=[{
                        "tier": "signed_ioc",
                        "kind": "network",
                        "bundle_id": str(endpoint.get("bundle_id") or ""),
                        "severity": str(endpoint.get("severity") or ""),
                        "expires_at": float(endpoint.get("expires_at") or 0),
                        "label": str(endpoint.get("label") or ""),
                    }],
                )

        result = self.assess_domain(normalized) if normalized else WebAssessment(indicator=ip, kind="connection")
        result.kind = "connection"
        if result.signed_ioc:
            result.source = "signed_ioc_domain"
            if shared_ip:
                result.block_recommended = False
                result.decision = "review_shared_infrastructure"
                result.reasons.append(
                    f"IP condiviso/CDN: {max(2, int(domain_count or 0))} domini recenti su questo indirizzo"
                )
                if int(pid_count or 0) > 1:
                    result.reasons.append(f"IP osservato da {int(pid_count)} processi distinti")
        result.reasons = list(dict.fromkeys(result.reasons))
        return result

    def assess_url(
        self,
        value: str,
        *,
        declared_identity: str = "",
        redirect_chain: list[str] | tuple[str, ...] | None = None,
    ) -> WebAssessment:
        raw = str(value or "").strip()
        if not raw:
            return WebAssessment(kind="url", status="invalid", reasons=["URL vuoto"])
        candidate = raw if "://" in raw else "https://" + raw
        try:
            parsed = urlsplit(candidate)
        except Exception:
            return WebAssessment(indicator=raw, kind="url", status="invalid", reasons=["URL non valido"])
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return WebAssessment(indicator=raw, kind="url", status="invalid", reasons=["Sono supportati solo URL HTTP/HTTPS"])

        host = parsed.hostname or ""
        try:
            ipaddress.ip_address(host.split("%", 1)[0])
            is_ip = True
        except ValueError:
            is_ip = False

        local = assess_local_url(
            candidate,
            declared_identity=declared_identity,
            redirect_chain=redirect_chain,
        )
        local_reasons = [
            str(item.get("reason") or "")
            for item in local.signals
            if str(item.get("reason") or "")
        ]

        if is_ip:
            return WebAssessment(
                indicator=local.observed_host or host,
                kind="url",
                normalized_url=candidate,
                score=local.score,
                level=self._level(local.score),
                status=local.status,
                source="local_heuristics",
                reasons=list(dict.fromkeys(local_reasons)),
                signed_ioc=False,
                block_recommended=False,
                decision=local.decision,
                provenance=[{
                    "tier": "local_heuristics",
                    "profile": HEURISTIC_PROFILE,
                    "signals": list(dict.fromkeys(local_reasons)),
                    "signal_details": list(local.signals),
                }],
                risk_families=list(local.risk_families),
                signal_codes=list(local.signal_codes),
                identity_context=dict(local.identity_context),
                heuristic_fingerprint=local.heuristic_fingerprint,
            )

        result = self.assess_domain(host)
        result.kind = "url"
        result.normalized_url = candidate
        result.identity_context = dict(local.identity_context)
        result.heuristic_fingerprint = local.heuristic_fingerprint

        # Precedenza deterministica invariata:
        # IOC firmato > trust exact locale > euristiche advisory.
        if result.signed_ioc or result.trusted_domain:
            return result

        if local.signals:
            details = [item for item in local.signals if isinstance(item, dict)]
            reasons = list(dict.fromkeys(result.reasons + local_reasons))
            result.score = min(HEURISTIC_SCORE_CAP, max(result.score, local.score))
            result.level = self._level(result.score)
            result.status = "suspicious" if result.score >= 20 else "unknown"
            result.decision = "review" if result.score >= 20 else "observe"
            result.block_recommended = False
            result.reasons = reasons
            result.risk_families = list(dict.fromkeys(result.risk_families + list(local.risk_families)))
            result.signal_codes = list(dict.fromkeys(result.signal_codes + list(local.signal_codes)))
            result.provenance = [{
                "tier": "local_heuristics",
                "profile": HEURISTIC_PROFILE,
                "signals": reasons,
                "signal_details": details,
            }]
        return result
