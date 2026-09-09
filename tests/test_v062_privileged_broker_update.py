from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.privileged_broker import PrivilegeTicketStore, canonical_action_digest
from sentinel.protection_protocol import ClientContext, ProtocolError, build_request, validate_request
from sentinel.protection_service_core import ProtectionServiceCore
from sentinel.service_hardening import IntegrityVerifier, write_integrity_manifest
import sentinel.service_update as service_update
from sentinel.service_update import (
    UpdateError,
    apply_update_transaction,
    manifest_version,
    rollback_transaction,
    validate_update_source,
    verify_signed_journal,
    version_key,
)

SECRET = "a" * 64


class FakeEvents:
    sequence = 0
    def since(self, seq, limit):
        return []


class FakeRuntime:
    def __init__(self):
        self.secret = SECRET
        self.events = FakeEvents()
        self.network = False
        self._hardening_status = {"ok": True, "mode": "sealed"}

    def status(self):
        return {"service": "BCSentinelProtection", "health": "HEALTHY", "network": self.network}

    def set_network_collection(self, enabled):
        self.network = bool(enabled)
        return True

    def set_protection_enabled(self, enabled):
        return True

    def update_config(self, changes):
        return dict(changes)

    def attribute(self, path): return {"path": path}
    def process_chain(self, pid): return [{"pid": pid}]
    def incidents(self, limit, min_score): return []
    def incident(self, incident_id): return None
    def quarantine_items(self): return []


class NullAudit:
    def __init__(self): self.rows = []
    def append(self, row): self.rows.append(dict(row)); return row


def ctx(*, admin=False, sid="S-1-5-21-1000", session=3, pid=111):
    return ClientContext(
        local=True, authenticated=True, is_admin=admin, sid=sid,
        session_id=session, transport="test", process_id=pid,
    )


def make_core():
    core = ProtectionServiceCore(FakeRuntime(), secret=SECRET)
    core._audit_writer = NullAudit()
    return core


def test_v062_protocol_seals_nested_privileged_payload_and_rejects_unknown_fields():
    req = build_request(
        "prepare_privileged_action", SECRET,
        action="set_network_collection", payload={"enabled": True},
    )
    validated = validate_request(req)
    assert validated.payload == {"action": "set_network_collection", "payload": {"enabled": True}}

    bad = build_request("prepare_privileged_action", SECRET, action="set_network_collection", payload={"enabled": True})
    bad["payload"]["payload"]["shell"] = "cmd.exe"
    with pytest.raises(ProtocolError):
        validate_request(bad)


def test_v062_prepare_does_not_require_admin_but_requires_authenticated_identity():
    core = make_core()
    request = build_request(
        "prepare_privileged_action", SECRET,
        action="set_network_collection", payload={"enabled": True},
    )
    result = core.dispatch(request, ctx(admin=False))
    assert result["ok"] is True
    assert result["action"] == "set_network_collection"
    assert len(result["ticket_id"]) >= 32

    anonymous = ClientContext(local=True, authenticated=False, is_admin=False)
    denied = core.dispatch(request, anonymous)
    assert denied["ok"] is False
    assert denied["error"]["code"] == "unauthorized"


def test_v062_ticket_executes_once_with_elevated_same_session_and_returns_to_original_process():
    core = make_core()
    requester = ctx(admin=False, session=7, pid=400)
    prepared = core.dispatch(
        build_request("prepare_privileged_action", SECRET, action="set_network_collection", payload={"enabled": True}),
        requester,
    )
    ticket_id = prepared["ticket_id"]

    elevated = ctx(admin=True, sid="S-1-5-21-admin", session=7, pid=401)
    executed = core.dispatch(build_request("execute_privileged_ticket", SECRET, ticket_id=ticket_id), elevated)
    assert executed["ok"] is True
    assert executed["action_ok"] is True
    assert core.runtime.network is True

    replay = core.dispatch(build_request("execute_privileged_ticket", SECRET, ticket_id=ticket_id), elevated)
    assert replay["ok"] is False
    assert replay["error"]["code"] == "ticket_rejected"

    result = core.dispatch(build_request("privileged_ticket_result", SECRET, ticket_id=ticket_id), requester)
    assert result["ok"] is True
    assert result["pending"] is False
    assert result["action_result"]["ok"] is True

    wrong_process = ctx(admin=False, session=7, pid=999)
    denied = core.dispatch(build_request("privileged_ticket_result", SECRET, ticket_id=ticket_id), wrong_process)
    assert denied["ok"] is False
    assert denied["error"]["code"] == "unauthorized"


def test_v062_ticket_rejects_cross_session_elevation():
    core = make_core()
    requester = ctx(admin=False, session=4, pid=100)
    prepared = core.dispatch(
        build_request("prepare_privileged_action", SECRET, action="set_network_collection", payload={"enabled": True}), requester
    )
    elevated = ctx(admin=True, sid="S-1-5-21-admin", session=9, pid=101)
    result = core.dispatch(build_request("execute_privileged_ticket", SECRET, ticket_id=prepared["ticket_id"]), elevated)
    assert result["ok"] is False
    assert result["error"]["code"] == "ticket_rejected"


def test_v062_ticket_store_expires_and_digest_is_deterministic():
    store = PrivilegeTicketStore(ttl_seconds=5)
    ticket = store.issue(ctx(), "set_network_collection", {"enabled": True})
    assert ticket.payload_digest == canonical_action_digest("set_network_collection", {"enabled": True})
    ticket.expires_at = 0
    with pytest.raises(KeyError):
        store.consume(ticket.ticket_id, ctx(admin=True, pid=222))


def test_v062_broker_client_does_not_import_heavy_service_runtime():
    client = Path("sentinel/protection_client.py").read_text(encoding="utf-8")
    assert "from .protection_constants import" in client
    assert "from .protection_service_core import" not in client


def test_v062_broker_binary_surface_accepts_ticket_only_and_build_precedes_manifest():
    broker = Path("sentinel/privileged_broker_windows.py").read_text(encoding="utf-8")
    assert 'add_argument("--ticket", required=True' in broker
    assert 'add_argument("--op"' not in broker
    assert 'add_argument("--path"' not in broker
    build = Path("BUILD-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert "BC-Sentinel-Broker" in build
    assert '"--onefile"' not in build
    assert build.index("BC-Sentinel-Broker") < build.index("tools.build_protection_manifest")
    install = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert "Privileged Broker compilato non trovato" in install


def _write_versioned_manifest(root: Path, version: str) -> None:
    write_integrity_manifest(root)
    path = root / "protection-integrity.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    obj["product_version"] = version
    path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def _make_install(root: Path, version: str, key: Path, sig: Path) -> None:
    root.mkdir(parents=True)
    (root / "BC-Sentinel-Protection.exe").write_bytes(("svc-" + version).encode())
    _write_versioned_manifest(root, version)
    verifier = IntegrityVerifier(root, key_path=key, signature_path=sig)
    assert verifier.seal().ok


def _make_source(root: Path, version: str) -> None:
    root.mkdir(parents=True)
    (root / "BC-Sentinel-Protection.exe").write_bytes(("svc-" + version).encode())
    (root / "BC-Sentinel-Broker.exe").write_bytes(("broker-" + version).encode())
    _write_versioned_manifest(root, version)


def test_v062_version_order_and_anti_downgrade(tmp_path):
    assert version_key("0.6.2-beta.1") > version_key("0.6.1-beta.5")
    assert version_key("0.6.2-rc.1") > version_key("0.6.2-beta.9")
    assert version_key("0.6.2") > version_key("0.6.2-rc.9")

    key, sig = tmp_path / "key", tmp_path / "protection-integrity.sig"
    target, source = tmp_path / "target", tmp_path / "source"
    _make_install(target, "0.6.2-beta.1", key, sig)
    _make_source(source, "0.6.1-beta.5")
    with pytest.raises(UpdateError, match="anti-downgrade"):
        validate_update_source(source, target, mode="upgrade", current_key_path=key, current_signature_path=sig)


def test_v062_transactional_upgrade_backup_journal_and_rollback(tmp_path, monkeypatch):
    key = tmp_path / "integrity.key"
    sig = tmp_path / "protection-integrity.sig"
    target, source, backups = tmp_path / "target", tmp_path / "source", tmp_path / "updates"
    _make_install(target, "0.6.1-beta.5", key, sig)
    _make_source(source, "0.6.2-beta.1")
    monkeypatch.setattr(service_update, "INTEGRITY_KEY_PATH", key)

    plan = validate_update_source(source, target, mode="upgrade", current_key_path=key, current_signature_path=sig)
    assert plan.current_version == "0.6.1-beta.5"
    assert plan.target_version == "0.6.2-beta.1"

    applied = apply_update_transaction(
        source, target, backups, mode="upgrade",
        current_key_path=key, current_signature_path=sig,
    )
    assert applied["status"] == "deployed_unsealed"
    assert manifest_version(target) == "0.6.2-beta.1"
    journal = Path(applied["journal"])
    assert verify_signed_journal(journal)["status"] == "deployed_unsealed"
    assert Path(applied["backup"]).is_dir()

    rolled = rollback_transaction(journal)
    assert rolled["status"] == "rolled_back"
    assert manifest_version(target) == "0.6.1-beta.5"


def test_v062_repair_requires_same_version(tmp_path):
    key, sig = tmp_path / "key", tmp_path / "protection-integrity.sig"
    target, source = tmp_path / "target", tmp_path / "source"
    _make_install(target, "0.6.2-beta.1", key, sig)
    _make_source(source, "0.6.2-beta.3")
    with pytest.raises(UpdateError, match="repair requires the same version"):
        validate_update_source(source, target, mode="repair", current_key_path=key, current_signature_path=sig)


def test_v062_same_version_upgrade_is_rejected_but_repair_is_accepted(tmp_path):
    key, sig = tmp_path / "key", tmp_path / "protection-integrity.sig"
    target, source = tmp_path / "target", tmp_path / "source"
    _make_install(target, "0.7.0-beta.3", key, sig)
    _make_source(source, "0.7.0-beta.3")

    with pytest.raises(UpdateError, match="anti-downgrade"):
        validate_update_source(source, target, mode="upgrade", current_key_path=key, current_signature_path=sig)

    plan = validate_update_source(
        source, target, mode="repair", current_key_path=key, current_signature_path=sig
    )
    assert plan.mode == "repair"
    assert plan.current_version == "0.7.0-beta.3"
    assert plan.target_version == "0.7.0-beta.3"


def test_v062_beta3_is_a_true_upgrade_from_beta2(tmp_path):
    key, sig = tmp_path / "key", tmp_path / "protection-integrity.sig"
    target, source = tmp_path / "target", tmp_path / "source"
    _make_install(target, "0.7.0-beta.2", key, sig)
    _make_source(source, "0.7.0-beta.3")

    plan = validate_update_source(
        source, target, mode="upgrade", current_key_path=key, current_signature_path=sig
    )
    assert plan.mode == "upgrade"
    assert plan.current_version == "0.7.0-beta.2"
    assert plan.target_version == "0.7.0-beta.3"


def test_v062_update_acceptance_classifies_same_version_and_downgrade_without_weakening_gate():
    from tools.update_acceptance import _classify_update_error

    same = _classify_update_error(
        UpdateError("anti-downgrade: upgrade target 0.7.0-beta.3 must be newer than 0.7.0-beta.3")
    )
    assert same["classification"] == "same_version_upgrade_rejected"
    assert same["recommended_mode"] == "repair"

    older = _classify_update_error(
        UpdateError("anti-downgrade: upgrade target 0.7.0-beta.2 must be newer than 0.7.0-beta.3")
    )
    assert older["classification"] == "downgrade_rejected"
    assert older["recommended_action"] == "use_a_build_newer_than_the_installed_version"


def test_v062_upgrade_script_has_stop_apply_seal_start_and_rollback():
    source = Path("AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8")
    assert "tools.service_update validate" in source
    assert "tools.service_update apply" in source
    assert "tools.service_update rollback" in source
    assert "seal-integrity" in source
    assert "pipe-selftest" in source
    assert "anti-downgrade" not in source  # enforced in the validated Python transaction manager, not string parsing in PowerShell



def test_v062_upgrade_script_power_shell_interpolation_is_parser_safe():
    source = Path("AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert '$Mode:' not in source
    assert '${Mode}:' in source


def test_v062_upgrade_script_parses_in_windows_powershell():
    import os
    import shutil
    import subprocess

    if os.name != "nt":
        pytest.skip("Windows PowerShell parser acceptance runs on native Windows")
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell not available")
    script = str(Path("AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1").resolve())
    command = "$null = [scriptblock]::Create([IO.File]::ReadAllText($env:BC_SENTINEL_PARSE_TARGET))"
    env = os.environ.copy()
    env["BC_SENTINEL_PARSE_TARGET"] = script
    proc = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=20, check=False, env=env,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout



def test_v062_native_parser_test_uses_environment_path_transport():
    import inspect
    source = inspect.getsource(test_v062_upgrade_script_parses_in_windows_powershell)
    assert "$env:BC_SENTINEL_PARSE_TARGET" in source
    assert "env=env" in source
    assert "command, script" not in source

def test_v062_version_consistent():
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert Path("sentinel/__init__.py").read_text().strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in Path("pyproject.toml").read_text(encoding="utf-8")
