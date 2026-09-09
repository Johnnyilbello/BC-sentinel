from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess
import time

from .config import APP_ROOT
from .path_security import is_reparse_point
from .protection_protocol import build_request, encode_message, MAX_MESSAGE_BYTES
from .protection_constants import PIPE_NAME, SERVICE_NAME, SERVICE_SECRET_PATH


class ProtectionServiceClient:
    def __init__(self, timeout: float = 0.75):
        self.timeout = max(0.1, float(timeout))
        self.last_error = ""

    def _secret(self) -> str:
        try:
            path = SERVICE_SECRET_PATH
            if is_reparse_point(path):
                return ""
            value = path.read_text(encoding="ascii").strip()
            return value if len(value) >= 64 else ""
        except Exception:
            return ""

    @staticmethod
    def _error_text(result: dict) -> str:
        error = result.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("code") or "")
        return str(error or "")

    def request(self, op: str, **payload):
        token = self._secret()
        if not token:
            self.last_error = "Servizio di protezione non configurato."
            return {"ok": False, "error": {"code": "secret_unavailable", "message": self.last_error}}
        try:
            request = build_request(op, token, **payload)
        except Exception as exc:
            self.last_error = str(exc)
            return {"ok": False, "error": {"code": "invalid_request", "message": self.last_error}}

        if os.name != "nt":
            self.last_error = "BC Sentinel Protection Service è disponibile solo su Windows."
            return {"ok": False, "error": {"code": "windows_only", "message": self.last_error}}

        try:
            import win32con
            import win32file
            import win32pipe

            timeout_ms = max(100, int(self.timeout * 1000))
            # pywin32 WaitNamedPipe returns None on success and raises on
            # timeout/failure, so do not interpret the return value as bool.
            win32pipe.WaitNamedPipe(PIPE_NAME, timeout_ms)
            handle = win32file.CreateFile(
                PIPE_NAME,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0,
                None,
                win32con.OPEN_EXISTING,
                0,
                None,
            )
            try:
                win32file.WriteFile(handle, encode_message(request))
                chunks = []
                total = 0
                ERROR_MORE_DATA = 234
                import pywintypes
                while True:
                    try:
                        hr, data = win32file.ReadFile(handle, min(65536, MAX_MESSAGE_BYTES + 1 - total))
                        chunks.append(bytes(data))
                        total += len(data)
                        if total > MAX_MESSAGE_BYTES:
                            raise ValueError("service response exceeds maximum size")
                        if hr == 0:
                            break
                        if hr != ERROR_MORE_DATA:
                            raise OSError(f"ReadFile returned error code {hr}")
                    except pywintypes.error as exc:
                        code=int(getattr(exc,"winerror",exc.args[0] if exc.args else -1))
                        if code != ERROR_MORE_DATA:
                            raise
                        data=exc.args[2] if len(exc.args)>2 and isinstance(exc.args[2],(bytes,bytearray)) else b""
                        if data:
                            chunks.append(bytes(data)); total += len(data)
                            if total > MAX_MESSAGE_BYTES:
                                raise ValueError("service response exceeds maximum size")
                raw = b"".join(chunks)
            finally:
                win32file.CloseHandle(handle)
            result = json.loads(raw.decode("utf-8"))
            self.last_error = "" if result.get("ok") else self._error_text(result)
            return result
        except Exception as exc:
            self.last_error = str(exc)
            return {"ok": False, "error": {"code": "service_unavailable", "message": self.last_error}}

    def status(self):
        result = self.request("status")
        return result.get("status") if result.get("ok") else None

    def events(self, since: int = 0, limit: int = 250):
        result = self.request("events", since=int(since), limit=int(limit))
        if not result.get("ok"):
            return [], since
        return result.get("events") or [], int(result.get("sequence") or since)

    def attribute(self, path: str):
        result = self.request("attribute", path=str(path))
        return result.get("attribution") if result.get("ok") else {}

    def process_chain(self, pid: int):
        result = self.request("process_chain", pid=int(pid))
        return result.get("chain") if result.get("ok") else []

    def quarantine_items(self):
        result = self.request("quarantine_items")
        return result.get("items") if result.get("ok") else []

    def hardening_status(self):
        result = self.request("hardening_status")
        return result.get("hardening") if result.get("ok") else None

    def firewall_status(self):
        result = self.request("firewall_status")
        return result.get("firewall") if result.get("ok") else None

    def firewall_rules(self, limit: int = 200):
        result = self.request("firewall_rules", limit=int(limit))
        return result.get("rules") if result.get("ok") else []

    def firewall_drift(self):
        result = self.request("firewall_drift")
        return result.get("drift") if result.get("ok") else None

    def firewall_conflicts(self):
        result = self.request("firewall_conflicts")
        return result.get("conflicts") if result.get("ok") else None

    def antispyware_status(self):
        result = self.request("antispyware_status")
        return result.get("antispyware") if result.get("ok") else {}

    def advanced_antimalware_status(self):
        result = self.request("advanced_antimalware_status")
        return result.get("advanced_antimalware") if result.get("ok") else {}

    def advanced_antimalware_findings(self, limit: int = 200, min_score: int = 0):
        result = self.request("advanced_antimalware_findings", limit=int(limit), min_score=int(min_score))
        return result.get("findings") if result.get("ok") else []

    def antispyware_findings(self, limit: int = 200, min_score: int = 0):
        result = self.request("antispyware_findings", limit=int(limit), min_score=int(min_score))
        return result.get("findings") or [] if result.get("ok") else []

    def antispyware_remediation_plan(self, finding_id: str):
        result = self.request("antispyware_remediation_plan", finding_id=str(finding_id))
        return result.get("remediation_plan") if result.get("ok") else None

    def antispyware_remediation_plans(self, limit: int = 100):
        result = self.request("antispyware_remediation_plans", limit=max(1, min(int(limit), 500)))
        return result.get("remediation_plans") or [] if result.get("ok") else []

    def antispyware_remediation_apply(self, plan_id: str, *, approved: bool = True):
        return self.request("antispyware_remediation_apply", plan_id=str(plan_id), approved=bool(approved))

    def antispyware_remediation_restore(self, plan_id: str, *, approved: bool = True):
        return self.request("antispyware_remediation_restore", plan_id=str(plan_id), approved=bool(approved))

    def web_status(self):
        result = self.request("web_status")
        return result.get("web") if result.get("ok") else None

    def web_findings(self, limit: int = 100):
        result = self.request("web_findings", limit=max(1, min(int(limit), 500)))
        return result.get("findings") if result.get("ok") else []

    def web_downloads(self, limit: int = 100):
        result = self.request("web_downloads", limit=max(1, min(int(limit), 500)))
        return result.get("downloads") if result.get("ok") else []

    def web_download_detail(self, download_id: str):
        result = self.request("web_download_detail", download_id=str(download_id))
        return result.get("download") if result.get("ok") else None

    def web_assess(self, value: str):
        result = self.request("web_assess", value=str(value))
        return result.get("assessment") if result.get("ok") else None

    def web_domain_trust(self):
        result = self.request("web_domain_trust")
        return result.get("trust") if result.get("ok") else []

    def web_domain_reputation(self, domain: str):
        result = self.request("web_domain_reputation", domain=str(domain))
        return result.get("reputation") if result.get("ok") else None

    def web_finding_decide(self, finding_id: str, action: str, detail: str = ""):
        return self.request(
            "web_finding_decide", finding_id=str(finding_id), action=str(action), detail=str(detail or "")
        )

    def ioc_status(self):
        result = self.request("ioc_status")
        return result.get("ioc") if result.get("ok") else None

    def ioc_entries(self, limit: int = 500):
        result = self.request("ioc_entries", limit=max(1, min(int(limit), 1000)))
        return result.get("entries") if result.get("ok") else []

    def threat_intel_status(self):
        result = self.request("threat_intel_status")
        return result.get("threat_intelligence") if result.get("ok") else None

    def threat_intel_history(self, limit: int = 50):
        result = self.request("threat_intel_history", limit=max(1, min(int(limit), 200)))
        return result.get("history") if result.get("ok") else []

    def validate_threat_package(self, package: dict, signature: str):
        result = self.request("threat_package_validate", package=dict(package), signature=str(signature))
        return result.get("validation") if result.get("ok") else None

    def validate_threat_keyset(self, keyset: dict, signature: str):
        result = self.request("threat_keyset_validate", keyset=dict(keyset), signature=str(signature))
        return result.get("validation") if result.get("ok") else None

    def validate_threat_index(self, index: dict, signature: str):
        result = self.request("threat_index_validate", index=dict(index), signature=str(signature))
        return result.get("validation") if result.get("ok") else None

    def containment_leases(self):
        result = self.request("containment_leases")
        return result.get("leases") if result.get("ok") else []

    def pending_threats(self):
        result = self.request("pending_threats")
        return result.get("threats") if result.get("ok") else []

    def acknowledge_threat_decision(self, sha256: str, action: str, detail: str = ""):
        return self.request(
            "threat_decision_ack", sha256=str(sha256), action=str(action), detail=str(detail or "")
        )

    def incidents(self, limit: int = 100, min_score: int = 0):
        result = self.request("incidents", limit=int(limit), min_score=int(min_score))
        return result.get("incidents") if result.get("ok") else []

    @staticmethod
    def _error_code(result: dict) -> str:
        error = result.get("error")
        return str(error.get("code") or "") if isinstance(error, dict) else ""

    def _privileged_request(self, op: str, **payload):
        """Use the current token when elevated; otherwise elevate one sealed action only."""
        direct = self.request(op, **payload)
        if direct.get("ok") or self._error_code(direct) != "admin_required":
            return direct
        launched = self.request_privileged_via_uac(op, **payload)
        if not launched.get("ok"):
            return launched
        ticket_id = str(launched.get("ticket_id") or "")
        deadline = time.monotonic() + 75.0
        while time.monotonic() < deadline:
            result = self.privileged_ticket_result(ticket_id)
            if result.get("ok") and not result.get("pending"):
                action_result = result.get("action_result")
                if isinstance(action_result, dict):
                    self.last_error = "" if action_result.get("ok") else self._error_text(action_result)
                    return action_result
                return {"ok": False, "error": {"code": "broker_result_invalid", "message": "Invalid broker result"}}
            if not result.get("ok") and self._error_code(result) not in {"ticket_not_found"}:
                self.last_error = self._error_text(result)
                return result
            time.sleep(0.25)
        self.last_error = "La richiesta UAC è scaduta o non è stata completata."
        return {"ok": False, "error": {"code": "broker_timeout", "message": self.last_error}}

    def set_network_collection(self, enabled: bool) -> bool:
        result = self._privileged_request("set_network_collection", enabled=bool(enabled))
        return bool(result.get("ok") and result.get("network") == bool(enabled))

    def set_protection_enabled(self, enabled: bool) -> bool:
        result = self._privileged_request("set_protection_enabled", enabled=bool(enabled))
        return bool(result.get("ok") and result.get("protection_enabled") == bool(enabled))

    def set_protection_config(self, settings: dict) -> bool:
        result = self._privileged_request("set_protection_config", settings=dict(settings))
        return bool(result.get("ok"))

    def terminate_process(self, incident_id: str, *, approved: bool):
        return self._privileged_request("terminate_process", incident_id=str(incident_id), approved=bool(approved))

    def quarantine_file(self, incident_id: str, *, approved: bool, candidate_path: str = ""):
        payload = {"incident_id": str(incident_id), "approved": bool(approved)}
        if candidate_path:
            payload["candidate_path"] = str(candidate_path)
        return self._privileged_request("quarantine_file", **payload)

    def restore_quarantine(self, item_id: str, *, approved: bool, destination: str = ""):
        payload = {"item_id": str(item_id), "approved": bool(approved)}
        if destination:
            payload["destination"] = str(destination)
        return self._privileged_request("restore_quarantine", **payload)

    def threat_file_action(
        self,
        action: str,
        path: str,
        sha256: str,
        *,
        score: int,
        level: str,
        reasons: list[str] | tuple[str, ...],
        approved: bool,
    ):
        return self._privileged_request(
            "threat_file_action",
            action=str(action),
            path=str(path),
            sha256=str(sha256),
            score=int(score),
            level=str(level),
            reasons=[str(item) for item in reasons][:16],
            approved=bool(approved),
        )

    def add_exclusion(self, kind: str, value: str):
        return self._privileged_request("add_exclusion", kind=str(kind), value=str(value))

    def remove_exclusion(self, item_id: int):
        return self._privileged_request("remove_exclusion", id=int(item_id))

    def firewall_block_remote(
        self,
        remote_address: str,
        *,
        approved: bool,
        direction: str = "outbound",
        protocol: str = "any",
        remote_port: int | None = None,
        application_path: str = "",
        reason: str = "",
        incident_id: str = "",
    ):
        payload = {
            "remote_address": str(remote_address),
            "direction": str(direction),
            "protocol": str(protocol),
            "approved": bool(approved),
        }
        if remote_port is not None:
            payload["remote_port"] = int(remote_port)
        if application_path:
            payload["application_path"] = str(application_path)
        if reason:
            payload["reason"] = str(reason)
        if incident_id:
            payload["incident_id"] = str(incident_id)
        return self._privileged_request("firewall_block_remote", **payload)

    def firewall_remove_rule(self, rule_id: str, *, approved: bool):
        return self._privileged_request(
            "firewall_remove_rule", rule_id=str(rule_id), approved=bool(approved)
        )

    def firewall_set_managed_enabled(self, enabled: bool, *, approved: bool):
        return self._privileged_request(
            "firewall_set_managed_enabled", enabled=bool(enabled), approved=bool(approved)
        )

    def firewall_reconcile(self, *, approved: bool):
        return self._privileged_request("firewall_reconcile", approved=bool(approved))


    def import_ioc_bundle(self, bundle: dict, signature: str, *, approved: bool = True):
        return self._privileged_request(
            "ioc_import", bundle=dict(bundle), signature=str(signature), approved=bool(approved)
        )

    def install_threat_keyset(self, keyset: dict, signature: str, *, approved: bool = True):
        return self._privileged_request(
            "threat_keyset_install", keyset=dict(keyset), signature=str(signature), approved=bool(approved)
        )

    def stage_threat_package(self, package: dict, signature: str, *, approved: bool = True):
        return self._privileged_request(
            "threat_package_stage", package=dict(package), signature=str(signature), approved=bool(approved)
        )

    def install_threat_package(self, package: dict, signature: str, *, approved: bool = True):
        return self._privileged_request(
            "threat_package_install", package=dict(package), signature=str(signature), approved=bool(approved)
        )

    def activate_threat_package(self, stage_id: str, *, approved: bool = True):
        return self._privileged_request(
            "threat_package_activate", stage_id=str(stage_id), approved=bool(approved)
        )

    def rollback_threat_package(self, *, approved: bool = True):
        return self._privileged_request("threat_package_rollback", approved=bool(approved))

    def containment_lease_create(
        self, remote_address: str, *, ttl_seconds: int, approved: bool,
        reason: str = "", incident_id: str = "",
    ):
        return self._privileged_request(
            "containment_lease_create", remote_address=str(remote_address),
            ttl_seconds=int(ttl_seconds), reason=str(reason), incident_id=str(incident_id),
            approved=bool(approved),
        )

    def web_containment_create(
        self, finding_id: str, *, ttl_seconds: int = 900, approved: bool = True, reason: str = ""
    ):
        return self._privileged_request(
            "web_containment_create", finding_id=str(finding_id), ttl_seconds=int(ttl_seconds),
            reason=str(reason or ""), approved=bool(approved),
        )

    def web_domain_trust_add(
        self, domain: str, *, reason: str = "", finding_id: str = "", approved: bool = True
    ):
        return self._privileged_request(
            "web_domain_trust_add", domain=str(domain), reason=str(reason or ""),
            finding_id=str(finding_id or ""), approved=bool(approved),
        )

    def web_domain_trust_remove(self, domain: str, *, approved: bool = True):
        return self._privileged_request(
            "web_domain_trust_remove", domain=str(domain), approved=bool(approved),
        )

    def containment_lease_release(self, lease_id: str, *, approved: bool):
        return self._privileged_request(
            "containment_lease_release", lease_id=str(lease_id), approved=bool(approved)
        )

    def prepare_privileged_action(self, op: str, **payload):
        """Ask the service to seal one exact privileged action into a short-lived ticket."""
        return self.request("prepare_privileged_action", action=str(op), payload=dict(payload))

    def execute_privileged_ticket(self, ticket_id: str):
        """Broker-only call. The service still verifies the elevated Windows token."""
        return self.request("execute_privileged_ticket", ticket_id=str(ticket_id))

    def privileged_ticket_result(self, ticket_id: str):
        return self.request("privileged_ticket_result", ticket_id=str(ticket_id))

    @staticmethod
    def installed_broker_path() -> Path:
        program_files = Path(os.getenv("ProgramFiles", r"C:\Program Files"))
        return program_files / "BC Sentinel" / "Protection" / "BC-Sentinel-Broker" / "BC-Sentinel-Broker.exe"

    def launch_privileged_ticket(self, ticket_id: str) -> bool:
        """Launch the narrow one-action broker through the Windows UAC consent flow."""
        if os.name != "nt":
            self.last_error = "Il broker privilegiato è disponibile solo su Windows."
            return False
        broker = self.installed_broker_path()
        if not broker.exists() or is_reparse_point(broker):
            self.last_error = f"Broker privilegiato non disponibile: {broker}"
            return False
        args = f'--ticket "{str(ticket_id)}"'
        try:
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", str(broker), args, str(broker.parent), 0
            )
            if int(result) <= 32:
                self.last_error = f"UAC broker launch failed ({int(result)})."
                return False
            self.last_error = ""
            return True
        except Exception as exc:
            self.last_error = str(exc)
            return False

    def request_privileged_via_uac(self, op: str, **payload):
        """Prepare + launch one privileged action without elevating the whole GUI.

        The returned ticket can be polled with ``privileged_ticket_result``.
        """
        prepared = self.prepare_privileged_action(op, **payload)
        if not prepared.get("ok"):
            return prepared
        ticket_id = str(prepared.get("ticket_id") or "")
        if not ticket_id or not self.launch_privileged_ticket(ticket_id):
            return {
                "ok": False,
                "error": {"code": "uac_launch_failed", "message": self.last_error or "UAC broker launch failed"},
                "ticket_id": ticket_id,
            }
        return {
            "ok": True,
            "pending": True,
            "ticket_id": ticket_id,
            "action": prepared.get("action"),
            "action_digest": prepared.get("action_digest"),
            "expires_at": prepared.get("expires_at"),
        }

    def service_installed(self) -> bool:
        if os.name != "nt":
            return False
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            p = subprocess.run(
                ["sc.exe", "query", SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=flags,
                check=False,
            )
            return p.returncode == 0
        except Exception:
            return False

    def launch_installer(self, remove: bool = False) -> bool:
        if os.name != "nt":
            return False
        script = APP_ROOT / "INSTALLA-SERVIZIO-PROTEZIONE.ps1"
        if not script.exists():
            self.last_error = f"Script non trovato: {script}"
            return False
        args = f'-NoProfile -ExecutionPolicy Bypass -File "{script}"'
        if remove:
            args += " -Remove"
        try:
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell.exe", args, str(APP_ROOT), 1
            )
            return int(result) > 32
        except Exception as exc:
            self.last_error = str(exc)
            return False
