from __future__ import annotations

from dataclasses import asdict, dataclass, field
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Any, Iterable

from .database import Database
from .reputation import inspect_authenticode_details
from .scoring import Signal, assess, level_for
from .core.events import SecurityEvent


SUSPICIOUS_INTERPRETERS = {
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "cmd.exe",
}
USER_WRITABLE_MARKERS = (
    "\\appdata\\", "\\users\\public\\", "\\windows\\temp\\", "\\temp\\",
    "/appdata/", "/users/public/", "/temp/",
)
HIGH_RISK_MARKERS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
    "/appdata/local/temp/", "/windows/temp/", "/users/public/",
)
PUP_NAME_MARKERS = (
    "browserassistant", "searchprotect", "searchmanager", "coupon", "toolbar",
    "webcompanion", "shoppingassistant", "browserhelper",
)
BROWSER_POLICY_ROOTS = (
    ("chrome", r"Software\Policies\Google\Chrome"),
    ("edge", r"Software\Policies\Microsoft\Edge"),
    ("firefox", r"Software\Policies\Mozilla\Firefox"),
)
RUN_KEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)


@dataclass(slots=True)
class PersistenceEntry:
    kind: str
    location: str
    name: str
    command: str = ""
    target_path: str = ""
    target_exists: bool | None = None
    user_writable: bool = False
    signature_status: str = ""
    signer: str = ""
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def entry_id(self) -> str:
        canonical = "\0".join((self.kind, self.location, self.name)).casefold()
        return "BCP-" + hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:20].upper()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["entry_id"] = self.entry_id
        return payload


@dataclass(slots=True)
class PersistenceAssessment:
    entry: PersistenceEntry
    score: int
    level: str
    reasons: list[str]
    signals: list[Signal]
    confidence: float
    evidence_count: int
    remediation: str = "review"
    classification: str = "persistence"
    pup_adware_candidate: bool = False
    automatic_destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry.to_dict(),
            "score": int(self.score),
            "level": str(self.level),
            "reasons": list(self.reasons),
            "signals": [asdict(s) for s in self.signals],
            "confidence": float(self.confidence),
            "evidence_count": int(self.evidence_count),
            "remediation": self.remediation,
            "classification": self.classification,
            "pup_adware_candidate": bool(self.pup_adware_candidate),
            "automatic_destructive_action": False,
        }


def _expand_environment(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    return os.path.expandvars(raw)


def extract_command_target(command: str) -> str:
    """Best-effort executable target extraction without executing the command."""
    raw = _expand_environment(command).strip()
    if not raw:
        return ""
    if raw.startswith('"'):
        end = raw.find('"', 1)
        return raw[1:end].strip() if end > 1 else ""
    # Windows executable paths may contain spaces without quotes. Prefer the
    # first explicit executable/script suffix before falling back to token 0.
    match = re.match(r"(?i)^(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|dll|scr|msi))(?:\s|$)", raw)
    if match:
        return match.group(1).strip()
    return raw.split()[0].strip() if raw.split() else ""


def _path_flags(path: str) -> tuple[bool, bool]:
    text = str(path or "").replace("/", "\\").casefold()
    return any(x in text for x in USER_WRITABLE_MARKERS), any(x in text for x in HIGH_RISK_MARKERS)


def _command_basename(command: str, target_path: str = "") -> str:
    candidate = target_path or extract_command_target(command)
    return Path(candidate.replace('"', '')).name.casefold() if candidate else ""


def assess_persistence_entry(entry: PersistenceEntry, *, network_recent: bool = False, file_malicious: bool = False) -> PersistenceAssessment:
    signals: list[Signal] = []
    kind = str(entry.kind or "unknown").casefold()
    base_weights = {
        "registry_run": 8,
        "registry_runonce": 10,
        "startup": 7,
        "scheduled_task": 8,
        "service_auto": 8,
        "wmi_subscription": 18,
        "browser_policy": 6,
        "proxy_config": 5,
        "dns_config": 4,
    }
    signals.append(Signal(f"persistence:{kind}", base_weights.get(kind, 7), f"Persistenza osservata: {kind}", "persistence"))

    target = entry.target_path or extract_command_target(entry.command)
    user_writable, high_risk = _path_flags(target or entry.command)
    user_writable = bool(entry.user_writable or user_writable)
    if user_writable:
        signals.append(Signal("persistence:user-writable", 15, "Target di persistenza in percorso modificabile dall'utente", "persistence"))
    if high_risk:
        signals.append(Signal("persistence:high-risk-path", 18, "Target di persistenza in percorso temporaneo/pubblico ad alto rischio", "persistence"))
    if entry.target_exists is False and target:
        signals.append(Signal("persistence:missing-target", 12, "La persistenza punta a un target mancante", "persistence"))

    base = _command_basename(entry.command, target)
    if base in SUSPICIOUS_INTERPRETERS:
        signals.append(Signal("persistence:interpreter", 15, f"Persistenza avvia un interprete/loader sensibile: {base}", "behavior"))
    command_cf = str(entry.command or "").casefold()
    if "-encodedcommand" in command_cf or " -enc " in command_cf or "frombase64string" in command_cf:
        signals.append(Signal("persistence:encoded-command", 22, "Comando di persistenza contiene payload codificato", "behavior"))

    sig = str(entry.signature_status or "").casefold()
    if sig == "valid":
        signals.append(Signal("persistence:valid-signature", -8, "Target con firma Authenticode valida", "trust"))
    elif sig == "notsigned" and target:
        signals.append(Signal("persistence:unsigned", 9, "Target di persistenza senza firma Authenticode", "reputation"))
    elif sig and sig not in {"unsupported", "unknownerror", "unknown"}:
        signals.append(Signal("persistence:bad-signature", 18, f"Firma Authenticode non valida: {entry.signature_status}", "reputation"))

    metadata = dict(entry.metadata or {})
    policy_name = f"{entry.location} {entry.name}".casefold()
    if kind == "browser_policy" and any(x in policy_name for x in ("extensioninstallforcelist", "homepage", "defaultsearchprovider", "proxy")):
        signals.append(Signal("browser:forced-policy", 10, "Policy browser persistente/forzata da verificare", "browser_integrity"))
    if kind == "browser_policy" and "extensioninstallforcelist" in policy_name:
        value_cf = str(entry.command or "").casefold()
        if ";http" in value_cf and not any(host in value_cf for host in ("clients2.google.com", "edge.microsoft.com", "addons.mozilla.org")):
            signals.append(Signal("browser:nonstandard-extension-source", 12, "Estensione browser forzata da sorgente non standard", "pup_adware"))
    if kind == "browser_policy" and any(x in policy_name for x in ("homepage", "defaultsearchprovider")) and str(entry.command or "").strip():
        signals.append(Signal("browser:search-home-override", 8, "Homepage/search provider imposto via policy: verificare provenienza", "pup_adware"))
    pup_text = f"{entry.name} {entry.command} {entry.target_path}".casefold()
    if any(marker in pup_text for marker in PUP_NAME_MARKERS):
        signals.append(Signal("pup:name-pattern", 10, "Nome/comando compatibile con software potenzialmente indesiderato", "pup_adware"))
    if kind == "proxy_config" and metadata.get("changed"):
        signals.append(Signal("network:proxy-changed", 12, "Configurazione proxy modificata rispetto alla baseline", "network_config"))
    if kind == "dns_config" and metadata.get("changed"):
        signals.append(Signal("network:dns-changed", 10, "Configurazione DNS modificata rispetto alla baseline", "network_config"))
    if kind == "wmi_subscription":
        signals.append(Signal("persistence:wmi-permanent", 10, "Sottoscrizione WMI permanente richiede verifica", "persistence"))

    if network_recent:
        signals.append(Signal("correlation:recent-network", 12, "Il target persistente ha attività di rete recente", "network"))
    if file_malicious:
        signals.append(Signal("correlation:file-verdict", 65, "Il file target ha un verdetto malware qualificato", "signature"))

    assessment = assess(signals)
    # Persistence alone, even if unusual, must not become a destructive malware
    # verdict. A deterministic file verdict can still push the incident high.
    if not file_malicious and assessment.score >= 70:
        assessment.score = 69
        assessment.level = level_for(assessment.score)
    pup_adware = any(s.source == "pup_adware" for s in signals)
    classification = "malware_correlated" if file_malicious else ("pup_adware_candidate" if pup_adware else "persistence")
    remediation = "review"
    if assessment.score >= 50 or (pup_adware and assessment.score >= 25):
        remediation = "reversible_plan_recommended"
    elif assessment.score < 25:
        remediation = "observe"
    return PersistenceAssessment(
        entry=entry,
        score=assessment.score,
        level=assessment.level,
        reasons=assessment.reasons,
        signals=signals,
        confidence=assessment.confidence,
        evidence_count=assessment.evidence_count,
        remediation=remediation,
        classification=classification,
        pup_adware_candidate=pup_adware,
        automatic_destructive_action=False,
    )


class WindowsPersistenceCollector:
    """Bounded, read-only Windows persistence inventory for antispyware analysis."""

    def __init__(self, *, authenticode: bool = True, command_timeout: float = 6.0, max_entries: int = 2048):
        self.authenticode = bool(authenticode)
        self.command_timeout = max(1.0, min(float(command_timeout), 15.0))
        self.max_entries = max(64, min(int(max_entries), 4096))

    @staticmethod
    def supported() -> bool:
        return os.name == "nt"

    def _decorate_target(self, entry: PersistenceEntry) -> PersistenceEntry:
        target = entry.target_path or extract_command_target(entry.command)
        entry.target_path = target
        if target:
            try:
                p = Path(target)
                entry.target_exists = p.exists()
            except Exception:
                entry.target_exists = None
            entry.user_writable = _path_flags(target)[0]
            if self.authenticode and entry.target_exists and Path(target).suffix.casefold() in {".exe", ".dll", ".msi", ".sys", ".ocx", ".cpl"}:
                details = inspect_authenticode_details(Path(target))
                entry.signature_status = details.status
                entry.signer = details.publisher
        return entry

    def _registry_values(self, hive, hive_name: str, path: str, *, recursive: bool = False, max_values: int = 256) -> list[tuple[str, str, Any]]:
        import winreg
        out: list[tuple[str, str, Any]] = []
        stack = [(path, path)]
        while stack and len(out) < max_values:
            current, display = stack.pop()
            try:
                with winreg.OpenKey(hive, current, 0, winreg.KEY_READ) as key:
                    i = 0
                    while len(out) < max_values:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                        except OSError:
                            break
                        out.append((f"{hive_name}\\{display}", str(name or "(Default)"), value))
                        i += 1
                    if recursive:
                        j = 0
                        while True:
                            try:
                                sub = winreg.EnumKey(key, j)
                            except OSError:
                                break
                            stack.append((current + "\\" + sub, display + "\\" + sub))
                            j += 1
            except OSError:
                continue
        return out

    def registry_run_entries(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        import winreg
        out: list[PersistenceEntry] = []
        for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
            for key_path in RUN_KEYS:
                kind = "registry_runonce" if key_path.endswith("RunOnce") else "registry_run"
                for location, name, value in self._registry_values(hive, hive_name, key_path, max_values=128):
                    out.append(self._decorate_target(PersistenceEntry(kind, location, name, command=str(value))))
        # The service runs as LocalSystem, so enumerate loaded interactive-user
        # hives explicitly instead of assuming HKCU represents the logged-in user.
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, "", 0, winreg.KEY_READ) as users:
                i = 0
                while len(out) < self.max_entries:
                    try:
                        sid = winreg.EnumKey(users, i)
                    except OSError:
                        break
                    i += 1
                    if not re.fullmatch(r"S-1-5-21-[0-9-]+", sid):
                        continue
                    for key_path in RUN_KEYS:
                        kind = "registry_runonce" if key_path.endswith("RunOnce") else "registry_run"
                        user_path = sid + "\\" + key_path
                        for location, name, value in self._registry_values(winreg.HKEY_USERS, "HKU", user_path, max_values=128):
                            out.append(self._decorate_target(PersistenceEntry(
                                kind, location, name, command=str(value), metadata={"user_sid": sid}
                            )))
        except OSError:
            pass
        return out[: self.max_entries]

    def startup_entries(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        folders = []
        if os.getenv("APPDATA"):
            folders.append(Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
        if os.getenv("PROGRAMDATA"):
            folders.append(Path(os.environ["PROGRAMDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
        out = []
        for folder in folders:
            try:
                for item in folder.iterdir():
                    if item.is_file():
                        out.append(self._decorate_target(PersistenceEntry("startup", str(folder), item.name, command=str(item), target_path=str(item))))
            except OSError:
                pass
        return out[: self.max_entries]

    def scheduled_tasks(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(
                ["schtasks.exe", "/Query", "/FO", "CSV", "/V"], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=self.command_timeout, creationflags=flags, check=False,
            )
        except Exception:
            return []
        if proc.returncode != 0:
            return []
        out = []
        for row in csv.DictReader(io.StringIO(proc.stdout)):
            name = row.get("TaskName") or row.get("Nome attività") or row.get("Task Name") or ""
            command = row.get("Task To Run") or row.get("Attività da eseguire") or row.get("Actions") or ""
            if name:
                out.append(self._decorate_target(PersistenceEntry("scheduled_task", "Task Scheduler", str(name), command=str(command), metadata={"status": row.get("Status") or row.get("Stato") or ""})))
            if len(out) >= self.max_entries:
                break
        return out

    def auto_services(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        import winreg
        root = r"SYSTEM\CurrentControlSet\Services"
        out: list[PersistenceEntry] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root, 0, winreg.KEY_READ) as services:
                i = 0
                while len(out) < self.max_entries:
                    try:
                        name = winreg.EnumKey(services, i)
                    except OSError:
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(services, name, 0, winreg.KEY_READ) as key:
                            start = int(winreg.QueryValueEx(key, "Start")[0])
                            if start != 2:
                                continue
                            try:
                                image = str(winreg.QueryValueEx(key, "ImagePath")[0] or "")
                            except OSError:
                                image = ""
                            out.append(self._decorate_target(PersistenceEntry("service_auto", f"HKLM\\{root}\\{name}", name, command=image, metadata={"start": start})))
                    except (OSError, ValueError, TypeError):
                        continue
        except OSError:
            return []
        return out

    def wmi_subscriptions(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$o=@();"
            "$o+=Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object {"
            "[pscustomobject]@{Type='CommandLineEventConsumer';Name=$_.Name;Command=[string]$_.CommandLineTemplate;Extra=[string]$_.ExecutablePath}};"
            "$o+=Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object {"
            "[pscustomobject]@{Type='ActiveScriptEventConsumer';Name=$_.Name;Command=[string]$_.ScriptText;Extra=[string]$_.ScriptingEngine}};"
            "$o+=Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object {"
            "[pscustomobject]@{Type='EventFilter';Name=$_.Name;Command=[string]$_.Query;Extra=[string]$_.EventNamespace}};"
            "$o+=Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ForEach-Object {"
            "[pscustomobject]@{Type='FilterToConsumerBinding';Name='binding';Command=[string]$_.Consumer;Extra=[string]$_.Filter}};"
            "$o|ConvertTo-Json -Compress"
        )
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=self.command_timeout, creationflags=flags, check=False)
            if proc.returncode != 0 or not proc.stdout.strip():
                return []
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception:
            return []
        rows = payload if isinstance(payload, list) else [payload]
        out = []
        for row in rows[: self.max_entries]:
            if not isinstance(row, dict):
                continue
            consumer_type = str(row.get("Type") or "WMI")
            name = str(row.get("Name") or consumer_type)
            command = str(row.get("Command") or "")
            extra = str(row.get("Extra") or "")
            entry = PersistenceEntry("wmi_subscription", "root/subscription", name, command=command, metadata={"wmi_type": consumer_type, "extra": extra})
            if consumer_type == "CommandLineEventConsumer":
                entry = self._decorate_target(entry)
            out.append(entry)
        return out

    def browser_policies(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        import winreg
        out = []
        for browser, path in BROWSER_POLICY_ROOTS:
            for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
                for location, name, value in self._registry_values(hive, hive_name, path, recursive=True, max_values=256):
                    out.append(PersistenceEntry("browser_policy", location, name, command=str(value), metadata={"browser": browser}))
                    if len(out) >= self.max_entries:
                        return out
        return out

    def proxy_config(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        import winreg
        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        wanted = {"proxyenable", "proxyserver", "autoconfigurl"}
        out = []
        for location, name, value in self._registry_values(winreg.HKEY_CURRENT_USER, "HKCU", path, max_values=64):
            if name.casefold() in wanted:
                out.append(PersistenceEntry("proxy_config", location, name, command=str(value), metadata={"changed": False}))
        return out

    def dns_config(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | "
            "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress"
        )
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=self.command_timeout, creationflags=flags, check=False)
            if proc.returncode != 0 or not proc.stdout.strip():
                return []
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception:
            return []
        rows = payload if isinstance(payload, list) else [payload]
        out = []
        for row in rows[: self.max_entries]:
            if not isinstance(row, dict):
                continue
            alias = str(row.get("InterfaceAlias") or "interface")
            addresses = row.get("ServerAddresses") or []
            if isinstance(addresses, str):
                addresses = [addresses]
            out.append(PersistenceEntry("dns_config", "DnsClient", alias, command=",".join(str(x) for x in addresses), metadata={"changed": False, "servers": list(addresses)}))
        return out

    def collect(self) -> list[PersistenceEntry]:
        if not self.supported():
            return []
        out: list[PersistenceEntry] = []
        for func in (
            self.registry_run_entries, self.startup_entries, self.scheduled_tasks, self.auto_services,
            self.wmi_subscriptions, self.browser_policies, self.proxy_config, self.dns_config,
        ):
            try:
                out.extend(func())
            except Exception:
                continue
            if len(out) >= self.max_entries:
                break
        # De-duplicate exact entry IDs and keep bounded output.
        unique: dict[str, PersistenceEntry] = {}
        for entry in out:
            unique.setdefault(entry.entry_id, entry)
        return list(unique.values())[: self.max_entries]


class AntispywareEngine:
    """Detection-first persistence/spyware inventory. Never mutates persistence."""

    def __init__(self, db: Database | None = None, *, collector: WindowsPersistenceCollector | None = None, interval: float = 300.0, callback=None):
        self.db = db or Database()
        self.collector = collector or WindowsPersistenceCollector()
        self.interval = max(60.0, float(interval))
        self.callback = callback
        self._emitted_scores: dict[str, int] = {}
        self._baseline_values: dict[str, str] = {}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._last_scan = 0.0
        self._last_error = ""
        self._last_count = 0
        self._running = False

    def scan(self, entries: Iterable[PersistenceEntry] | None = None) -> list[PersistenceAssessment]:
        inventory = list(entries) if entries is not None else self.collector.collect()
        assessments: list[PersistenceAssessment] = []
        for entry in inventory[:4096]:
            slot = entry.entry_id
            current_value = str(entry.command or entry.target_path or "")
            previous_value = self._baseline_values.get(slot)
            if previous_value is not None and previous_value != current_value:
                entry.metadata = dict(entry.metadata or {})
                entry.metadata["changed"] = True
                entry.metadata["previous_value"] = previous_value[:2048]
            elif "changed" not in (entry.metadata or {}):
                entry.metadata = dict(entry.metadata or {})
                entry.metadata["changed"] = False
            self._baseline_values[slot] = current_value
            assessment = assess_persistence_entry(entry)
            assessments.append(assessment)
            if hasattr(self.db, "record_antispyware_finding"):
                self.db.record_antispyware_finding(assessment)
            if self.callback and assessment.score >= 50:
                previous = self._emitted_scores.get(entry.entry_id)
                if previous != assessment.score:
                    data = {
                        "finding_id": entry.entry_id,
                        "persistence_kind": entry.kind,
                        "location": entry.location,
                        "target_path": entry.target_path,
                        "target_exists": entry.target_exists,
                        "user_writable": entry.user_writable,
                        "signature_status": entry.signature_status,
                        "signer": entry.signer,
                        "remediation": assessment.remediation,
                        "automatic_destructive_action": False,
                        "antispyware_detection": True,
                    }
                    self.callback(SecurityEvent(
                        category="antispyware", action="persistence_finding", source="antispyware_engine",
                        score=assessment.score, path=entry.target_path or entry.location,
                        process_name=Path(entry.target_path).name if entry.target_path else "",
                        process_path=entry.target_path, reasons=list(assessment.reasons), data=data,
                    ))
                    self._emitted_scores[entry.entry_id] = assessment.score
        with self._lock:
            self._last_scan = time.time()
            self._last_count = len(assessments)
            self._last_error = ""
        return assessments

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan()
            except Exception as exc:
                with self._lock:
                    self._last_error = str(exc)[:500]
            if self._stop.wait(self.interval):
                break

    def start(self) -> bool:
        if not self.collector.supported():
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._stop.clear()
        self._running = True
        self._thread = threading.Thread(target=self._run, name="BCS-Antispyware", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None
        self._running = False

    def status(self) -> dict[str, Any]:
        with self._lock:
            summary = self.db.antispyware_summary() if hasattr(self.db, "antispyware_summary") else {}
            return {
                "schema": 1,
                "mode": "detection_first",
                "supported": self.collector.supported(),
                "running": bool(self._thread and self._thread.is_alive()),
                "last_scan": self._last_scan,
                "last_inventory_count": self._last_count,
                "last_error": self._last_error,
                "coverage": [
                    "run_runonce", "startup_folders", "scheduled_tasks", "auto_services",
                    "wmi_permanent_consumers", "browser_policies", "proxy_config", "dns_config",
                ],
                "automatic_registry_delete": False,
                "automatic_task_delete": False,
                "automatic_service_delete": False,
                "automatic_wmi_delete": False,
                "automatic_destructive_action": False,
                "reversible_remediation_plans": True,
                "summary": summary,
            }
