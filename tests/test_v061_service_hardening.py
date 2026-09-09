from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.config import Settings
from sentinel.protection_protocol import build_request, validate_request
from sentinel.protection_service_core import ProtectionConfigStore
from sentinel.service_hardening import (
    AuditChainWriter,
    IntegrityVerifier,
    build_integrity_manifest,
    ensure_integrity_key,
    verify_audit_chain,
    write_integrity_manifest,
)


def test_v061_integrity_manifest_seal_and_detect_tamper(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    (root / "BC-Sentinel-Protection.exe").write_bytes(b"service-binary")
    (root / "rules").mkdir()
    (root / "rules" / "safe.yar").write_text("rule safe { condition: true }", encoding="utf-8")
    write_integrity_manifest(root)
    key = tmp_path / "integrity.key"
    sig = tmp_path / "integrity.sig"
    verifier = IntegrityVerifier(root, key_path=key, signature_path=sig)
    sealed = verifier.seal()
    assert sealed.ok is True
    assert sealed.manifest_authenticated is True

    (root / "BC-Sentinel-Protection.exe").write_bytes(b"tampered-binary")
    result = verifier.verify(full=False)
    assert result.ok is False
    assert any("mismatch" in issue for issue in result.issues)


def test_v061_manifest_rejects_missing_protected_file(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    f = root / "a.dll"
    f.write_bytes(b"a")
    write_integrity_manifest(root)
    verifier = IntegrityVerifier(root, key_path=tmp_path / "key", signature_path=tmp_path / "sig")
    assert verifier.seal().ok
    f.unlink()
    result = verifier.verify()
    assert not result.ok
    assert any("missing protected file" in issue for issue in result.issues)


def test_v061_integrity_key_is_distinct_from_ipc_config_secret(tmp_path):
    key_path = tmp_path / "integrity.key"
    key = ensure_integrity_key(key_path)
    assert len(key) == 32
    assert len(key_path.read_text(encoding="ascii").strip()) == 64
    store = ProtectionConfigStore(key)
    store.path = tmp_path / "config.json"
    store.sig_path = tmp_path / "config.sig"
    store.save(Settings.defaults())
    # A different user-readable IPC token cannot authenticate/forge config.
    attacker = ProtectionConfigStore("a" * 64)
    attacker.path = store.path
    attacker.sig_path = store.sig_path
    with pytest.raises(ValueError, match="integrity"):
        attacker.load()


def test_v061_audit_chain_detects_record_edit_and_truncation(tmp_path):
    audit = tmp_path / "audit.jsonl"
    key = tmp_path / "integrity.key"
    state = tmp_path / "audit.chain"
    writer = AuditChainWriter(audit, key_path=key, state_path=state)
    writer.append({"ts": 1, "action": "start"})
    writer.append({"ts": 2, "action": "config_change"})
    ok, _, count = verify_audit_chain(audit, key_path=key, state_path=state)
    assert ok and count == 2

    rows = audit.read_text(encoding="utf-8").splitlines()
    audit.write_text(rows[0] + "\n", encoding="utf-8")
    ok, detail, _ = verify_audit_chain(audit, key_path=key, state_path=state)
    assert not ok
    assert "state" in detail or "mismatch" in detail


def test_v061_hardening_status_is_read_only_protocol_operation():
    req = build_request("hardening_status", "a" * 64)
    validated = validate_request(req)
    assert validated.op == "hardening_status"
    assert validated.payload == {}


def test_v061_installer_deploys_to_program_files_and_splits_acl_keys():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert '$env:ProgramFiles' in source
    assert 'BC Sentinel\\Protection' in source
    assert 'protection-integrity.key' in source
    assert 'protection.secret' in source
    assert '& $deployed seal-integrity' in source
    assert '/inheritance:r' in source
    assert 'S-1-5-32-545:(OI)(CI)(RX)' in source
    assert source.index('& $deployed seal-integrity') < source.index('& $deployed --startup auto install')


def test_v061_build_embeds_rules_and_generates_manifest():
    source = Path("BUILD-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert '"--add-data", "rules;rules"' in source
    assert 'tools.build_protection_manifest' in source
    assert 'protection-integrity.json' in source


def test_v061_runtime_has_periodic_self_protection_and_scm_posture():
    core = Path("sentinel/protection_service_core.py").read_text(encoding="utf-8")
    hardening = Path("sentinel/service_hardening.py").read_text(encoding="utf-8")
    assert "BCS-SelfProtection" in core
    assert "SERVICE_HARDENING_INTERVAL_SECONDS" in core
    assert "windows_service_posture" in core
    assert "windows_acl_posture" in core
    assert "QueryServiceConfig" in hardening
    assert "GetFileSecurity" in hardening


def test_v061_windows_service_audits_scm_start_stop():
    source = Path("sentinel/protection_service_windows.py").read_text(encoding="utf-8")
    assert 'audit_lifecycle("scm_start")' in source
    assert 'audit_lifecycle("scm_stop_requested")' in source
    assert 'audit_lifecycle("scm_stopped")' in source


def test_v061_version_lineage_remains_compatible():
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.6.2-beta.1")
    assert Path("sentinel/__init__.py").read_text().strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in Path("pyproject.toml").read_text(encoding="utf-8")

def test_v061_ui_exposes_hardening_degraded_state():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'hardening_bad' in source
    assert 'Protection Service degradato' in source
    assert 'Protection Service attivo ma degradato' in source

def test_v061_acceptance_requires_live_hardening_and_reboot_tools_exist():
    acceptance = Path("tools/windows_acceptance.py").read_text(encoding="utf-8")
    assert "protection-hardening-foundation" in acceptance
    assert "protection-hardening-live" in acceptance
    assert Path("tools/reboot_acceptance.py").exists()
    assert Path("tools/service_hardening_benchmark.py").exists()

def test_v061_integrity_flags_unexpected_executable_file(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    (root / "svc.exe").write_bytes(b"svc")
    write_integrity_manifest(root)
    verifier = IntegrityVerifier(root, key_path=tmp_path / "key", signature_path=tmp_path / "sig")
    assert verifier.seal().ok
    (root / "rogue.dll").write_bytes(b"rogue")
    result = verifier.verify()
    assert not result.ok
    assert any("unexpected executable" in issue for issue in result.issues)


def test_v061_self_protection_monitor_survives_operator_protection_suspend():
    source = Path("sentinel/protection_service_core.py").read_text(encoding="utf-8")
    assert "stop_hardening=False" in source
    assert ('if name == "self_protection"' in source or 'if name in {"self_protection", "firewall"}' in source)

def test_v061_integrity_cache_rehashes_same_size_same_mtime_change(tmp_path):
    import os
    root = tmp_path / "install"
    root.mkdir()
    target = root / "service.dll"
    target.write_bytes(b"AAAA")
    write_integrity_manifest(root)
    verifier = IntegrityVerifier(root, key_path=tmp_path / "key", signature_path=tmp_path / "sig")
    assert verifier.seal().ok
    before = target.stat()
    assert verifier.verify().ok
    target.write_bytes(b"BBBB")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    result = verifier.verify(full=False)
    assert not result.ok
    assert any("hash mismatch" in issue for issue in result.issues)

def test_v061_integrity_key_acl_forbids_untrusted_read_in_runtime():
    source = Path("sentinel/protection_service_core.py").read_text(encoding="utf-8")
    assert "forbid_untrusted_read=True" in source
    hardening = Path("sentinel/service_hardening.py").read_text(encoding="utf-8")
    assert "TRUSTED_WRITE_SIDS" in hardening
    assert "_DANGEROUS_READ_MASK" in hardening


def test_v061_integrity_cache_fails_safe_when_change_cookie_unavailable(tmp_path, monkeypatch):
    import os
    import sentinel.service_hardening as hardening

    root = tmp_path / "install-failsafe"
    root.mkdir()
    target = root / "service.dll"
    target.write_bytes(b"AAAA")
    write_integrity_manifest(root)
    verifier = IntegrityVerifier(root, key_path=tmp_path / "key-failsafe", signature_path=tmp_path / "sig-failsafe")
    assert verifier.seal().ok
    before = target.stat()
    assert verifier.verify().ok

    # Simulate a Windows API failure: the verifier must re-hash rather than
    # trusting size/mtime when it lacks a reliable change cookie.
    monkeypatch.setattr(hardening, "_reliable_change_cookie", lambda path, st: None)
    target.write_bytes(b"BBBB")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    result = verifier.verify(full=False)
    assert not result.ok
    assert result.checked_files >= 1
    assert any("hash mismatch" in issue for issue in result.issues)


def test_v061_windows_integrity_cache_uses_native_change_time():
    source = Path("sentinel/service_hardening.py").read_text(encoding="utf-8")
    assert "GetFileInformationByHandleEx" in source
    assert "ChangeTime" in source
    assert "cache_trustworthy = change_cookie is not None" in source


def test_v061_beta2_installer_hardens_root_then_resets_children():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert 'Invoke-IcaclsChecked -Description "Program Files root"' in source
    assert '"/reset", "/T", "/C"' in source
    assert '& icacls.exe $installDir /verify /T /C' in source
    # Regression: never recursively apply directory inheritance grant flags to
    # every file in the frozen onedir tree after stripping inheritance.
    assert '$installUsers /T /C' not in source
    assert 'ProgramData child inheritance' in source

def test_v061_beta2_installer_surfaces_deployed_executable_acl_on_bootstrap_failure():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert 'ACL del binario distribuito:' in source
    assert '& icacls.exe $deployed | Out-Host' in source


def test_v061_beta2_installer_diagnoses_code_integrity_without_disabling_it():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert "Microsoft-Windows-CodeIntegrity/Operational" in source
    assert "Get-WinEvent" in source
    assert "Smart App Control" not in source


def test_v061_beta3_installer_repairs_failed_previous_program_files_tree_locale_neutral():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert "function Remove-InstallTreeSafely" in source
    assert "function Repair-TreeAclForAdministrators" in source
    assert '/setowner "*S-1-5-32-544" /T /C' in source
    assert '"*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /T /C' in source
    assert "/D Y" not in source
    assert "/D S" not in source
    assert "Remove-InstallTreeSafely -Path $installDir" in source


def test_v061_beta3_repairs_legacy_programdata_state_before_final_lockdown():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert 'Repair-TreeAclForAdministrators -Path $protectionDir -Description "ProgramData Protection legacy state"' in source
    assert 'ProgramData child inheritance' in source
    assert source.index('ProgramData Protection legacy state') < source.index('& $deployed init-config')


def test_v061_beta3_installer_requires_stable_running_service_and_diagnostics():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert "function Show-ServiceStartDiagnostics" in source
    assert '$svc.Status -eq "Running"' in source
    assert 'BC Sentinel Protection non e rimasto RUNNING dopo il bootstrap.' in source
    assert 'ProviderName = "Service Control Manager"' in source


def test_v061_beta3_windows_service_lazy_bootstrap_logs_constructor_failures():
    source = Path("sentinel/protection_service_windows.py").read_text(encoding="utf-8")
    assert "self.runtime = None" in source
    assert "self.runtime = ProtectionRuntime()" in source
    assert "bootstrap construction failed" in source
    assert source.index("self.runtime = None") < source.index("def SvcDoRun")


def test_v061_beta4_recovers_runtime_critical_programdata_files_without_localized_takeown_answer():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert "function Repair-KnownProgramDataStateFiles" in source
    assert '"quarantine.key"' in source
    assert '"sentinel-service.db"' in source
    assert '& takeown.exe /F $item /A' in source
    assert "/D Y" not in source and "/D S" not in source
    assert source.index("Repair-KnownProgramDataStateFiles") < source.index('& $deployed init-config')
    assert 'ACL recovery incompleta per $criticalPath' in source


def test_v061_beta4_named_pipe_transient_accept_errors_are_recycled():
    from sentinel.protection_transport_windows import is_transient_connect_error
    assert is_transient_connect_error(109)
    assert is_transient_connect_error(232)
    assert is_transient_connect_error(233)
    assert is_transient_connect_error(995)
    assert not is_transient_connect_error(5)
    source = Path("sentinel/protection_transport_windows.py").read_text(encoding="utf-8")
    assert "transient_streak >= 8" in source
    assert "named-pipe accept repeatedly failed" in source


def test_v061_beta4_windows_service_supervises_pipe_listener_before_stopping():
    source = Path("sentinel/protection_service_windows.py").read_text(encoding="utf-8")
    assert "IPC listener failure {failures}/5" in source
    assert "self.server = WindowsNamedPipeServer(self.core)" in source
    assert "IPC reprepare failed" in source
    assert "if failures >= 5" in source


def test_v061_beta5_trusted_write_sids_are_defined_and_narrow():
    import sentinel.service_hardening as hardening
    assert hardening.TRUSTED_WRITE_SIDS == {"S-1-5-18", "S-1-5-32-544"}
    assert "S-1-5-32-545" not in hardening.TRUSTED_WRITE_SIDS
    assert "S-1-5-11" not in hardening.TRUSTED_WRITE_SIDS
    assert "S-1-1-0" not in hardening.TRUSTED_WRITE_SIDS


def test_v061_beta5_acl_posture_keeps_service_sid_special_case():
    source = Path("sentinel/service_hardening.py").read_text(encoding="utf-8")
    assert 'sid in TRUSTED_WRITE_SIDS or sid.startswith("S-1-5-80-")' in source


def test_v061_beta5_acl_posture_executes_trusted_writer_branch(monkeypatch):
    import sys
    import types
    import sentinel.service_hardening as hardening

    class FakeDacl:
        def GetAceCount(self):
            return 2

        def GetAce(self, index):
            # ACCESS_ALLOWED ACE with GENERIC_WRITE. LocalSystem is trusted;
            # BUILTIN\\Users must still be reported as dangerous.
            sid = "S-1-5-18" if index == 0 else "S-1-5-32-545"
            return ((0, 0), 0x40000000, sid)

    class FakeSd:
        def GetSecurityDescriptorDacl(self):
            return FakeDacl()

    fake_win32security = types.SimpleNamespace(
        DACL_SECURITY_INFORMATION=4,
        ACCESS_ALLOWED_ACE_TYPE=0,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE=5,
        GetFileSecurity=lambda path, info: FakeSd(),
        ConvertSidToStringSid=lambda sid: sid,
    )
    monkeypatch.setitem(sys.modules, "win32security", fake_win32security)
    monkeypatch.setattr(hardening, "os", types.SimpleNamespace(name="nt"))

    result = hardening.windows_acl_posture(r"C:\\BC Sentinel")
    assert not result.ok
    assert result.dangerous_sids == ["S-1-5-32-545"]
    assert "S-1-5-18" not in result.dangerous_sids
