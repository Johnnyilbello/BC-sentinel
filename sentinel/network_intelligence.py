from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import ipaddress
from typing import Protocol
from time import monotonic

from .database import Database
from .core.events import SecurityEvent

HIGH_RISK_INTERPRETERS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe",
}

NOISY_NETWORK_CLIENTS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    "steam.exe", "epicgameslauncher.exe", "onedrive.exe", "dropbox.exe",
    "teams.exe", "discord.exe", "spotify.exe",
}

DEVELOPER_NETWORK_CLIENTS = {
    "code.exe", "devenv.exe", "git.exe", "python.exe", "pythonw.exe",
    "node.exe", "npm.exe", "docker.exe", "com.docker.backend.exe",
    "wsl.exe", "ssh.exe", "curl.exe",
}

ADMIN_PORTS = {
    445: (18, "Connessione SMB verso endpoint Internet"),
    3389: (14, "Connessione RDP verso endpoint Internet"),
    5985: (12, "Connessione WinRM verso endpoint Internet"),
    5986: (12, "Connessione WinRM TLS verso endpoint Internet"),
    23: (14, "Connessione Telnet verso endpoint Internet"),
}


class ThreatIntelProvider(Protocol):
    """Raw-indicator-minimizing optional provider contract.

    Implementations receive SHA-256(normalized indicator), never the raw
    IP/domain. This is pseudonymization/data minimization, not anonymity: IP
    hashes can be enumerated. No external provider is configured in v0.4.
    """

    def lookup_indicator_hash(self, kind: str, indicator_sha256: str) -> dict | None:
        ...


@dataclass(slots=True)
class EndpointReputationResult:
    indicator: str = ""
    kind: str = "unknown"
    address_class: str = "unknown"
    status: str = "unknown"
    source: str = "local"
    score_delta: int = 0
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    connection_count: int = 0
    process_count: int = 0
    cached: bool = False

    def to_dict(self):
        return asdict(self)


class NetworkReputationEngine:
    """Local-first endpoint reputation and explainable network risk.

    v0.4 does not block traffic and performs no raw-indicator cloud lookups.
    Known endpoint verdicts may be inserted locally (future signed feeds) and an
    optional provider can operate on hashed indicators only. Hashing minimizes
    raw disclosure but is not treated as anonymous threat-intelligence lookup.
    """

    def __init__(self, db: Database | None = None, provider: ThreatIntelProvider | None = None):
        self.db = db or Database()
        self.provider = provider
        self._endpoint_cache = {}
        self._endpoint_cache_ttl = 30.0

    @staticmethod
    def normalize_indicator(value: str) -> tuple[str, str]:
        raw = str(value or "").strip().rstrip(".")
        if not raw:
            return "", "unknown"
        # IPv6 may arrive with a scope id from psutil.
        candidate = raw.split("%", 1)[0]
        try:
            return str(ipaddress.ip_address(candidate)), "ip"
        except ValueError:
            domain = raw.casefold()
            if len(domain) > 253 or " " in domain or "." not in domain:
                return domain, "unknown"
            return domain, "domain"

    @staticmethod
    def _address_class(indicator: str, kind: str) -> str:
        if kind != "ip":
            return "domain" if kind == "domain" else "unknown"
        try:
            ip = ipaddress.ip_address(indicator)
        except ValueError:
            return "unknown"
        if ip.is_loopback:
            return "loopback"
        if ip.is_private:
            return "private"
        if ip.is_link_local:
            return "link_local"
        if ip.is_multicast:
            return "multicast"
        if ip.is_reserved:
            return "reserved"
        if ip.is_unspecified:
            return "unspecified"
        if ip.is_global:
            return "global"
        return "special"

    @staticmethod
    def _process_key(event: SecurityEvent) -> str:
        data = event.data or {}
        sha = str(data.get("process_sha256") or "").casefold()
        if sha:
            return f"sha256:{sha}"
        path = str(event.process_path or "").casefold()
        if path:
            return f"path:{path}"
        name = str(event.process_name or "").casefold()
        return f"name:{name or 'unknown'}"

    def _provider_lookup(self, kind: str, indicator: str) -> dict | None:
        if self.provider is None or kind not in {"ip", "domain"}:
            return None
        digest = hashlib.sha256(indicator.encode("utf-8", errors="ignore")).hexdigest()
        try:
            return self.provider.lookup_indicator_hash(kind, digest)
        except Exception:
            return None

    def assess_endpoint(self, indicator: str, *, process_key: str = "") -> EndpointReputationResult:
        normalized, kind = self.normalize_indicator(indicator)
        address_class = self._address_class(normalized, kind)
        if not normalized:
            return EndpointReputationResult()

        observation = self.db.observe_network_endpoint(normalized, process_key or "unknown")
        cache_key=(kind,normalized)
        now=monotonic()
        entry=self._endpoint_cache.get(cache_key)
        if entry is not None and now-entry[0] < self._endpoint_cache_ttl:
            cached=entry[1]
        else:
            cached=self.db.get_endpoint_reputation(normalized, kind)
            self._endpoint_cache[cache_key]=(now,cached)
        source = "local"
        status = "unknown"
        confidence = 0.0
        reasons: list[str] = []
        score = 0
        cached_hit = False
        signed_ioc = self.db.match_ioc_endpoint(normalized) if hasattr(self.db, "match_ioc_endpoint") else None
        signed_reputation = self.db.match_signed_reputation(normalized) if hasattr(self.db, "match_signed_reputation") else None

        if signed_ioc is not None:
            status = "malicious"
            source = "signed_ioc"
            confidence = 1.0
            score = 70
            reasons.append(str(signed_ioc.get("label") or "Endpoint presente nella denylist IOC firmata"))
        elif signed_reputation is not None:
            status = str(signed_reputation.get("status") or "suspicious").casefold()
            source = "signed_reputation"
            confidence = max(0.0, min(1.0, float(signed_reputation.get("confidence") or 0) / 100.0))
            score = 55 if status == "malicious" else 25
            reasons.append(str(signed_reputation.get("label") or "Endpoint presente nella reputazione firmata"))
        elif cached:
            cached_hit = True
            status = str(cached["status"] or "unknown").casefold()
            source = str(cached["source"] or "local")
            confidence = float(cached["confidence"] or 0.0)
        else:
            provider = self._provider_lookup(kind, normalized)
            if provider:
                status = str(provider.get("status") or "unknown").casefold()
                source = str(provider.get("source") or "hashed_provider")
                confidence = max(0.0, min(1.0, float(provider.get("confidence") or 0.0)))
                self.db.upsert_endpoint_reputation(
                    indicator=normalized,
                    kind=kind,
                    status=status,
                    source=source,
                    confidence=confidence,
                    details=provider.get("details") or {},
                )
                self._endpoint_cache.pop(cache_key,None)

        if signed_ioc is not None:
            # Signature-backed IOC evidence takes precedence over generic address
            # classification, while loopback/multicast were already rejected at
            # signed-bundle validation time.
            pass
        elif signed_reputation is not None:
            # Signed reputation is advisory evidence. It affects risk scoring but
            # never becomes an enforcement decision by itself.
            pass
        elif address_class in {"loopback", "private", "link_local"}:
            reasons.append(f"Endpoint {address_class.replace('_', ' ')} locale")
        elif status in {"malicious", "blocked"}:
            score += 60
            reasons.append("Endpoint presente nella reputazione locale come malevolo")
        elif status in {"suspicious", "watch"}:
            score += 25
            reasons.append("Endpoint presente nella watchlist locale")
        elif status in {"trusted", "allowlisted"}:
            reasons.append("Endpoint presente nella reputazione locale attendibile")

        return EndpointReputationResult(
            indicator=normalized,
            kind=kind,
            address_class=address_class,
            status=status,
            source=source,
            score_delta=min(70, score),
            confidence=confidence,
            reasons=reasons,
            first_seen=str(observation.get("first_seen") or ""),
            last_seen=str(observation.get("last_seen") or ""),
            connection_count=int(observation.get("connection_count") or 0),
            process_count=int(observation.get("process_count") or 0),
            cached=cached_hit,
        )

    def assess_event(self, event: SecurityEvent) -> EndpointReputationResult:
        data = dict(event.data or {})
        remote = str(data.get("remote_domain") or data.get("remote_addr") or "")
        result = self.assess_endpoint(remote, process_key=self._process_key(event))

        proc = str(event.process_name or "").casefold()
        path = str(event.process_path or "").casefold()
        signature = str(data.get("signature_status") or "")
        remote_port = int(data.get("remote_port") or 0)

        reasons = list(result.reasons)
        delta = int(result.score_delta)
        global_endpoint = result.address_class in {"global", "domain"}
        noisy = proc in NOISY_NETWORK_CLIENTS
        developer = proc in DEVELOPER_NETWORK_CLIENTS

        # Generic outbound Internet use is never suspicious by itself. Add
        # context only when the process/port/location increases confidence.
        if global_endpoint and proc in HIGH_RISK_INTERPRETERS:
            delta += 8
            reasons.append(f"Interprete script con endpoint Internet ({proc})")

        if global_endpoint and remote_port in ADMIN_PORTS and not noisy:
            weight, reason = ADMIN_PORTS[remote_port]
            # SSH is deliberately excluded from ADMIN_PORTS: developer tooling
            # commonly uses it and network-only evidence would be too noisy.
            delta += weight
            reasons.append(reason)

        sensitive_path = any(x in path for x in ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\", "/temp/", "/downloads/", "/appdata/local/temp/"))
        if global_endpoint and sensitive_path and signature in {"NotSigned", "HashMismatch", "NotTrusted", "UnknownError", ""}:
            # Browsers/launchers/updaters are high-volume clients. Do not give
            # them generic path-based penalties; known-bad endpoint verdicts
            # still apply above without suppression.
            if not noisy:
                delta += 8
                reasons.append("Processo non attendibile da percorso temporaneo con connessione Internet")

        # Repeated prevalence is context, not a verdict. A brand-new endpoint is
        # only mentioned when paired with another meaningful signal.
        if global_endpoint and result.connection_count <= 2 and delta >= 8 and not (noisy or developer):
            delta += 3
            reasons.append("Endpoint osservato per la prima volta localmente")

        result.score_delta = min(80, max(0, delta))
        result.reasons = list(dict.fromkeys(reasons))
        if result.score_delta and result.confidence == 0.0:
            result.confidence = min(0.9, 0.45 + result.score_delta / 150.0)
        return result
