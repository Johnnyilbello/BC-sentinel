from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
from typing import Any

from .path_security import has_reparse_component, is_reparse_point, secure_write_parent


PLAN_SCHEMA = 1
PLAN_PREFIX = "BCR-"
PLAN_ID_RE = re.compile(r"^BCR-[0-9A-F]{20}$")
SUPPORTED_REMEDIATION_KINDS = frozenset({
    "registry_run",
    "registry_runonce",
    "startup",
    "scheduled_task",
    "service_auto",
    "browser_policy",
})
REVIEW_ONLY_KINDS = frozenset({"wmi_subscription", "proxy_config", "dns_config"})


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _json_safe_registry_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return {"__bytes_hex__": value.hex()}
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value]
    return str(value)


def _registry_value_from_json(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {"__bytes_hex__"}:
        return bytes.fromhex(str(value["__bytes_hex__"]))
    return value


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _finding_digest(finding: dict[str, Any]) -> str:
    payload = {
        "finding_id": str(finding.get("finding_id") or ""),
        "kind": str(finding.get("kind") or ""),
        "location": str(finding.get("location") or ""),
        "name": str(finding.get("name") or ""),
        "command": str(finding.get("command") or ""),
        "target_path": str(finding.get("target_path") or ""),
        "score": int(finding.get("score") or 0),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


class RemediationConflict(RuntimeError):
    pass


class UnsupportedRemediation(RuntimeError):
    pass


class WindowsRemediationBackend:
    """Exact, bounded Windows persistence mutations. No arbitrary shell surface."""

    def __init__(self, *, command_timeout: float = 8.0):
        self.command_timeout = max(2.0, min(float(command_timeout), 15.0))

    @staticmethod
    def supported() -> bool:
        return os.name == "nt"

    @staticmethod
    def _registry_location(location: str):
        if os.name != "nt":
            raise UnsupportedRemediation("Windows registry remediation requires Windows")
        import winreg

        raw = str(location or "").strip().replace("/", "\\")
        upper = raw.upper()
        roots = (
            ("HKLM\\", winreg.HKEY_LOCAL_MACHINE),
            ("HKEY_LOCAL_MACHINE\\", winreg.HKEY_LOCAL_MACHINE),
            ("HKCU\\", winreg.HKEY_CURRENT_USER),
            ("HKEY_CURRENT_USER\\", winreg.HKEY_CURRENT_USER),
            ("HKU\\", winreg.HKEY_USERS),
            ("HKEY_USERS\\", winreg.HKEY_USERS),
        )
        for prefix, hive in roots:
            if upper.startswith(prefix):
                return hive, raw[len(prefix):]
        raise UnsupportedRemediation("unsupported registry hive")

    def _capture_registry(self, finding: dict[str, Any]) -> dict[str, Any]:
        import winreg

        hive, subkey = self._registry_location(str(finding.get("location") or ""))
        name = str(finding.get("name") or "")
        if not name or name == "(Default)":
            raise UnsupportedRemediation("default registry values are not remediated in v0.9 Beta2")
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_QUERY_VALUE) as key:
                value, reg_type = winreg.QueryValueEx(key, name)
        except OSError as exc:
            raise RemediationConflict("registry value no longer exists") from exc
        expected = str(finding.get("command") or "")
        if expected and str(value) != expected:
            raise RemediationConflict("registry value changed since antispyware finding")
        return {
            "backend": "registry_value",
            "location": str(finding.get("location") or ""),
            "name": name,
            "value": _json_safe_registry_value(value),
            "registry_type": int(reg_type),
        }

    def _capture_startup(self, finding: dict[str, Any]) -> dict[str, Any]:
        path = Path(str(finding.get("target_path") or finding.get("command") or ""))
        if not path.is_absolute() or not path.exists() or not path.is_file():
            raise RemediationConflict("startup file is missing")
        if is_reparse_point(path) or has_reparse_component(path, include_leaf=True):
            raise RemediationConflict("refusing startup remediation through a reparse point")
        return {
            "backend": "startup_file",
            "path": str(path),
            "sha256": _sha256_file(path),
            "size": int(path.stat().st_size),
        }

    def _query_task_xml(self, name: str) -> str:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            ["schtasks.exe", "/Query", "/TN", name, "/XML"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=self.command_timeout, creationflags=flags, check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            raise RemediationConflict("scheduled task no longer exists")
        return proc.stdout

    def _capture_task(self, finding: dict[str, Any]) -> dict[str, Any]:
        name = str(finding.get("name") or "").strip()
        if not name or len(name) > 512:
            raise UnsupportedRemediation("invalid scheduled task name")
        xml = self._query_task_xml(name)
        enabled = "<Enabled>false</Enabled>" not in xml
        return {
            "backend": "scheduled_task",
            "task_name": name,
            "xml_sha256": hashlib.sha256(xml.encode("utf-8", errors="replace")).hexdigest(),
            "was_enabled": bool(enabled),
        }

    def _capture_service(self, finding: dict[str, Any]) -> dict[str, Any]:
        import winreg

        name = str(finding.get("name") or "").strip()
        if not name or "\\" in name or "/" in name or len(name) > 256:
            raise UnsupportedRemediation("invalid service name")
        subkey = rf"SYSTEM\CurrentControlSet\Services\{name}"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_QUERY_VALUE) as key:
                start = int(winreg.QueryValueEx(key, "Start")[0])
                try:
                    image = str(winreg.QueryValueEx(key, "ImagePath")[0] or "")
                except OSError:
                    image = ""
        except OSError as exc:
            raise RemediationConflict("service no longer exists") from exc
        if start != 2:
            raise RemediationConflict("service is no longer configured for automatic start")
        expected = str(finding.get("command") or "")
        if expected and image and image != expected:
            raise RemediationConflict("service image path changed since finding")
        return {
            "backend": "service_start",
            "service_name": name,
            "start": start,
            "image_path": image,
        }

    def capture(self, finding: dict[str, Any]) -> dict[str, Any]:
        if not self.supported():
            raise UnsupportedRemediation("native persistence remediation requires Windows")
        kind = str(finding.get("kind") or "").casefold()
        if kind in {"registry_run", "registry_runonce", "browser_policy"}:
            return self._capture_registry(finding)
        if kind == "startup":
            return self._capture_startup(finding)
        if kind == "scheduled_task":
            return self._capture_task(finding)
        if kind == "service_auto":
            return self._capture_service(finding)
        raise UnsupportedRemediation(f"{kind or 'unknown'} is review-only in v0.9 Beta2")

    def _apply_registry(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        import winreg

        hive, subkey = self._registry_location(str(snapshot["location"]))
        name = str(snapshot["name"])
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                current, current_type = winreg.QueryValueEx(key, name)
                if _json_safe_registry_value(current) != snapshot["value"] or int(current_type) != int(snapshot["registry_type"]):
                    raise RemediationConflict("registry value changed after plan creation")
                winreg.DeleteValue(key, name)
        except FileNotFoundError as exc:
            raise RemediationConflict("registry value already missing") from exc
        return {"disabled": True, "mutation": "registry_value_removed"}

    def _restore_registry(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        import winreg

        hive, subkey = self._registry_location(str(snapshot["location"]))
        name = str(snapshot["name"])
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            try:
                current, current_type = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                current = None
                current_type = None
            if current_type is not None:
                if _json_safe_registry_value(current) == snapshot["value"] and int(current_type) == int(snapshot["registry_type"]):
                    return {"restored": True, "already_restored": True}
                raise RemediationConflict("restore refused because registry value is occupied by different data")
            winreg.SetValueEx(
                key, name, 0, int(snapshot["registry_type"]), _registry_value_from_json(snapshot["value"])
            )
        return {"restored": True, "mutation": "registry_value_restored"}

    @staticmethod
    def _vault_path(vault_dir: Path, plan_id: str, source: Path) -> Path:
        suffix = source.suffix[:16]
        return vault_dir / f"{plan_id}{suffix}.disabled"

    def _apply_startup(self, snapshot: dict[str, Any], *, vault_dir: Path, plan_id: str) -> dict[str, Any]:
        source = Path(str(snapshot["path"]))
        if not source.exists() or not source.is_file() or is_reparse_point(source):
            raise RemediationConflict("startup file is no longer a regular file")
        if _sha256_file(source) != str(snapshot["sha256"]):
            raise RemediationConflict("startup file content changed after plan creation")
        vault_dir.mkdir(parents=True, exist_ok=True)
        secure_write_parent(vault_dir / "probe")
        if is_reparse_point(vault_dir) or has_reparse_component(vault_dir, include_leaf=True):
            raise RemediationConflict("remediation vault is a reparse point")
        destination = self._vault_path(vault_dir, plan_id, source)
        if destination.exists():
            raise RemediationConflict("remediation vault destination already exists")
        os.replace(source, destination)
        if _sha256_file(destination) != str(snapshot["sha256"]):
            raise RuntimeError("startup vault integrity verification failed")
        return {"disabled": True, "mutation": "startup_file_vaulted", "vaulted_path": str(destination)}

    def _restore_startup(self, snapshot: dict[str, Any], *, vault_dir: Path, plan_id: str) -> dict[str, Any]:
        destination = Path(str(snapshot["path"]))
        source = self._vault_path(vault_dir, plan_id, destination)
        if destination.exists():
            if destination.is_file() and not is_reparse_point(destination) and _sha256_file(destination) == str(snapshot["sha256"]):
                return {"restored": True, "already_restored": True}
            raise RemediationConflict("restore refused because original startup path is occupied")
        if not source.exists() or not source.is_file() or is_reparse_point(source):
            raise RemediationConflict("vaulted startup file is missing")
        if _sha256_file(source) != str(snapshot["sha256"]):
            raise RemediationConflict("vaulted startup file hash mismatch")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if has_reparse_component(destination, include_leaf=False):
            raise RemediationConflict("restore destination contains a reparse component")
        os.replace(source, destination)
        return {"restored": True, "mutation": "startup_file_restored"}

    def _task_change(self, name: str, flag: str) -> None:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            ["schtasks.exe", "/Change", "/TN", name, flag],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=self.command_timeout, creationflags=flags, check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "scheduled task change failed").strip()[:500])

    def _apply_task(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        name = str(snapshot["task_name"])
        current = self._query_task_xml(name)
        if hashlib.sha256(current.encode("utf-8", errors="replace")).hexdigest() != str(snapshot["xml_sha256"]):
            raise RemediationConflict("scheduled task definition changed after plan creation")
        if bool(snapshot.get("was_enabled", True)):
            self._task_change(name, "/Disable")
        return {"disabled": True, "mutation": "scheduled_task_disabled"}

    def _restore_task(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        name = str(snapshot["task_name"])
        self._query_task_xml(name)
        if bool(snapshot.get("was_enabled", True)):
            self._task_change(name, "/Enable")
        return {"restored": True, "mutation": "scheduled_task_enabled"}

    def _set_service_start(self, name: str, value: int) -> None:
        import winreg
        subkey = rf"SYSTEM\CurrentControlSet\Services\{name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, int(value))

    def _read_service_start(self, name: str) -> int:
        import winreg
        subkey = rf"SYSTEM\CurrentControlSet\Services\{name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_QUERY_VALUE) as key:
            return int(winreg.QueryValueEx(key, "Start")[0])

    def _apply_service(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        name = str(snapshot["service_name"])
        if self._read_service_start(name) != int(snapshot["start"]):
            raise RemediationConflict("service start type changed after plan creation")
        # Disable persistence without terminating a currently running service.
        self._set_service_start(name, 3)
        return {"disabled": True, "mutation": "service_start_set_manual", "process_terminated": False}

    def _restore_service(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        name = str(snapshot["service_name"])
        current = self._read_service_start(name)
        if current == int(snapshot["start"]):
            return {"restored": True, "already_restored": True}
        if current != 3:
            raise RemediationConflict("service start type changed after remediation; refusing overwrite")
        self._set_service_start(name, int(snapshot["start"]))
        return {"restored": True, "mutation": "service_start_restored"}

    def apply(self, snapshot: dict[str, Any], *, vault_dir: Path, plan_id: str) -> dict[str, Any]:
        backend = str(snapshot.get("backend") or "")
        if backend == "registry_value":
            return self._apply_registry(snapshot)
        if backend == "startup_file":
            return self._apply_startup(snapshot, vault_dir=vault_dir, plan_id=plan_id)
        if backend == "scheduled_task":
            return self._apply_task(snapshot)
        if backend == "service_start":
            return self._apply_service(snapshot)
        raise UnsupportedRemediation("unsupported remediation backend")

    def restore(self, snapshot: dict[str, Any], *, vault_dir: Path, plan_id: str) -> dict[str, Any]:
        backend = str(snapshot.get("backend") or "")
        if backend == "registry_value":
            return self._restore_registry(snapshot)
        if backend == "startup_file":
            return self._restore_startup(snapshot, vault_dir=vault_dir, plan_id=plan_id)
        if backend == "scheduled_task":
            return self._restore_task(snapshot)
        if backend == "service_start":
            return self._restore_service(snapshot)
        raise UnsupportedRemediation("unsupported remediation backend")


@dataclass(slots=True)
class RemediationPlan:
    plan_id: str
    finding_id: str
    kind: str
    status: str
    created_at: float
    snapshot: dict[str, Any]
    integrity_hmac: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PLAN_SCHEMA,
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "kind": self.kind,
            "status": self.status,
            "created_at": self.created_at,
            "snapshot": dict(self.snapshot),
            "integrity_hmac": self.integrity_hmac,
            "automatic_action": False,
            "explicit_approval_required": True,
            "reversible": True,
        }


class AntispywareRemediationManager:
    """Creates HMAC-authenticated reversible plans and executes only approved plans."""

    def __init__(self, db, *, integrity_key: bytes, vault_dir: str | Path, backend: WindowsRemediationBackend | None = None):
        if not isinstance(integrity_key, (bytes, bytearray)) or len(integrity_key) < 16:
            raise ValueError("integrity_key must contain at least 16 bytes")
        self.db = db
        self.integrity_key = bytes(integrity_key)
        self.vault_dir = Path(vault_dir)
        self.backend = backend or WindowsRemediationBackend()

    def _mac_payload(self, *, plan_id: str, finding_id: str, kind: str, created_at: float, snapshot: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": PLAN_SCHEMA,
            "plan_id": plan_id,
            "finding_id": finding_id,
            "kind": kind,
            "created_at": float(created_at),
            "snapshot": snapshot,
        }

    def _sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(self.integrity_key, _canonical_json(payload), hashlib.sha256).hexdigest()

    def _verify_row(self, row: dict[str, Any]) -> dict[str, Any]:
        try:
            snapshot = json.loads(str(row.get("snapshot_json") or "{}"))
        except Exception as exc:
            raise RemediationConflict("remediation snapshot is malformed") from exc
        payload = self._mac_payload(
            plan_id=str(row.get("plan_id") or ""), finding_id=str(row.get("finding_id") or ""),
            kind=str(row.get("kind") or ""), created_at=float(row.get("created_at") or 0), snapshot=snapshot,
        )
        expected = self._sign(payload)
        if not hmac.compare_digest(expected, str(row.get("snapshot_hmac") or "")):
            raise RemediationConflict("remediation plan integrity verification failed")
        return snapshot

    def create_plan(self, finding_id: str) -> dict[str, Any]:
        finding_id = str(finding_id or "").strip().upper()
        if not finding_id.startswith("BCP-"):
            raise ValueError("invalid antispyware finding id")
        row = self.db.get_antispyware_finding(finding_id)
        if row is None:
            raise KeyError("antispyware finding not found")
        finding = dict(row)
        kind = str(finding.get("kind") or "").casefold()
        if kind not in SUPPORTED_REMEDIATION_KINDS:
            raise UnsupportedRemediation(f"{kind} is review-only in v0.9 Beta2")
        score = int(finding.get("score") or 0)
        evidence = {}
        try:
            evidence = json.loads(str(finding.get("evidence_json") or "{}"))
        except Exception:
            pass
        signals = evidence.get("signals") if isinstance(evidence, dict) else []
        pup_candidate = any(str((s or {}).get("source") or "") == "pup_adware" for s in (signals or []) if isinstance(s, dict))
        if score < 50 and not (pup_candidate and score >= 25):
            raise PermissionError("finding is below the reversible-remediation threshold")
        snapshot = self.backend.capture(finding)
        snapshot.update({
            "finding_digest": _finding_digest(finding),
            "score_at_plan": score,
            "pup_adware_candidate": bool(pup_candidate),
        })
        created = time.time()
        plan_id = PLAN_PREFIX + secrets.token_hex(10).upper()
        payload = self._mac_payload(plan_id=plan_id, finding_id=finding_id, kind=kind, created_at=created, snapshot=snapshot)
        signature = self._sign(payload)
        self.db.create_antispyware_remediation_plan(
            plan_id=plan_id, finding_id=finding_id, kind=kind, created_at=created,
            snapshot=snapshot, snapshot_hmac=signature,
        )
        return self.plan(plan_id)

    def plan(self, plan_id: str) -> dict[str, Any]:
        plan_id = str(plan_id or "").strip().upper()
        if not PLAN_ID_RE.fullmatch(plan_id):
            raise ValueError("invalid remediation plan id")
        row = self.db.get_antispyware_remediation_plan(plan_id)
        if row is None:
            raise KeyError("remediation plan not found")
        item = dict(row)
        snapshot = self._verify_row(item)
        item["snapshot"] = snapshot
        item.pop("snapshot_json", None)
        item["integrity_verified"] = True
        item["automatic_action"] = False
        item["explicit_approval_required"] = True
        item["reversible"] = True
        return item

    def plans(self, limit: int = 100) -> list[dict[str, Any]]:
        out = []
        for row in self.db.recent_antispyware_remediation_plans(limit):
            try:
                item = dict(row)
                item["snapshot"] = self._verify_row(item)
                item.pop("snapshot_json", None)
                item["integrity_verified"] = True
                out.append(item)
            except Exception:
                item = dict(row)
                item["integrity_verified"] = False
                item.pop("snapshot_json", None)
                out.append(item)
        return out

    def apply(self, plan_id: str, *, approved: bool) -> dict[str, Any]:
        if not approved:
            raise PermissionError("explicit operator approval is required")
        plan = self.plan(plan_id)
        if str(plan.get("status")) not in {"planned", "restored"}:
            raise RemediationConflict("remediation plan is not applicable in its current state")
        snapshot = dict(plan["snapshot"])
        result = self.backend.apply(snapshot, vault_dir=self.vault_dir, plan_id=str(plan["plan_id"]))
        self.db.update_antispyware_remediation_plan(
            str(plan["plan_id"]), status="applied", applied_at=time.time(), restored_at=0.0,
            last_error="", result=result,
        )
        self.db.update_antispyware_finding_status(str(plan["finding_id"]), "remediated_disabled")
        return {**self.plan(str(plan["plan_id"])), "result": result}

    def restore(self, plan_id: str, *, approved: bool) -> dict[str, Any]:
        if not approved:
            raise PermissionError("explicit operator approval is required")
        plan = self.plan(plan_id)
        if str(plan.get("status")) != "applied":
            raise RemediationConflict("only an applied remediation plan can be restored")
        snapshot = dict(plan["snapshot"])
        result = self.backend.restore(snapshot, vault_dir=self.vault_dir, plan_id=str(plan["plan_id"]))
        self.db.update_antispyware_remediation_plan(
            str(plan["plan_id"]), status="restored", restored_at=time.time(), last_error="", result=result,
        )
        self.db.update_antispyware_finding_status(str(plan["finding_id"]), "restored")
        return {**self.plan(str(plan["plan_id"])), "result": result}

    def status(self) -> dict[str, Any]:
        summary = self.db.antispyware_remediation_summary()
        return {
            "schema": PLAN_SCHEMA,
            "mode": "explicit_reversible",
            "supported": self.backend.supported(),
            "supported_kinds": sorted(SUPPORTED_REMEDIATION_KINDS),
            "review_only_kinds": sorted(REVIEW_ONLY_KINDS),
            "automatic_remediation": False,
            "automatic_destructive_action": False,
            "explicit_approval_required": True,
            "one_action_uac_compatible": True,
            "plan_integrity": "HMAC-SHA256",
            "anti_race_snapshot_verification": True,
            "service_process_termination": False,
            "summary": summary,
        }
