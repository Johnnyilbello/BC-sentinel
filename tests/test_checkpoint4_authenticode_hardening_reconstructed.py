from __future__ import annotations

import base64
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import sentinel.reputation as reputation


def _fake_native_powershell_tree(tmp_path: Path) -> Path:
    system = tmp_path / "Windows" / "System32"
    ps = system / "WindowsPowerShell" / "v1.0"
    security = ps / "Modules" / "Microsoft.PowerShell.Security" / "Microsoft.PowerShell.Security.psd1"
    security.parent.mkdir(parents=True)
    (ps / "powershell.exe").write_bytes(b"MZ-fixture")
    security.write_text("fixture", encoding="utf-8")
    return system


def _decoded_script(command: list[str]) -> str:
    encoded = command[command.index("-EncodedCommand") + 1]
    return base64.b64decode(encoded).decode("utf-16le")


def test_checkpoint4_authenticode_filename_is_data_not_powershell_syntax(tmp_path, monkeypatch):
    system = _fake_native_powershell_tree(tmp_path)
    monkeypatch.setattr(reputation, "_native_windows_system_directory", lambda: system)
    hostile = tmp_path / "signed’ ; New-Item marker-checkpoint4 ; #.exe"
    command, env = reputation._authenticode_command(hostile)
    script = _decoded_script(command)

    assert str(hostile) not in script
    assert "New-Item marker-checkpoint4" not in script
    assert "FromBase64String" in script
    assert "$PSModuleAutoLoadingPreference='None'" in script
    assert "Get-AuthenticodeSignature -LiteralPath $p" in script
    assert "Import-Module -LiteralPath $sm" in script
    assert "ConvertTo-Json" not in script
    assert "Microsoft.PowerShell.Utility" not in script
    assert "BCS-AUTH1" in script
    assert "-ExecutionPolicy" not in command
    assert "-Command" not in command
    assert "-EncodedCommand" in command
    assert Path(command[0]) == system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    assert env["SystemRoot"] == str(system.parent)
    assert env["WINDIR"] == str(system.parent)


def test_checkpoint4_poisoned_parent_environment_does_not_choose_powershell_or_modules(tmp_path, monkeypatch):
    system = _fake_native_powershell_tree(tmp_path)
    monkeypatch.setattr(reputation, "_native_windows_system_directory", lambda: system)
    monkeypatch.setenv("SystemRoot", str(tmp_path / "attacker-root"))
    monkeypatch.setenv("WINDIR", str(tmp_path / "attacker-windir"))
    monkeypatch.setenv("PSModulePath", str(tmp_path / "attacker-modules"))
    command, env = reputation._authenticode_command(tmp_path / "sample.exe")
    script = _decoded_script(command)
    assert str(tmp_path / "attacker-root") not in command[0]
    assert str(tmp_path / "attacker-modules") not in script
    assert env["SystemRoot"] == str(system.parent)
    assert env["PSModulePath"] == str(system / "WindowsPowerShell" / "v1.0" / "Modules")


def test_checkpoint4_authenticode_subprocess_failure_is_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(reputation.os, "name", "nt")
    monkeypatch.setattr(reputation, "_authenticode_command", lambda path: (["native-powershell", "-EncodedCommand", "AA=="], {}))
    monkeypatch.setattr(
        reputation.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr="Import-Module failed safely"),
    )
    result = reputation._inspect_authenticode_powershell_metadata(tmp_path / "sample.exe")
    assert result.status == "UnknownError"
    assert "Import-Module failed safely" in result.status_message


def test_checkpoint4_malformed_authenticode_protocol_is_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(reputation.os, "name", "nt")
    monkeypatch.setattr(reputation, "_authenticode_command", lambda path: (["native-powershell", "-EncodedCommand", "AA=="], {}))
    monkeypatch.setattr(
        reputation.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="not-json", stderr=""),
    )
    result = reputation._inspect_authenticode_powershell_metadata(tmp_path / "sample.exe")
    assert result.status == "UnknownError"
    assert "Invalid Authenticode protocol" in result.status_message


def test_checkpoint4_authenticode_protocol_round_trip():
    import base64

    values = [
        "Valid", "Signature verified", "CN=Microsoft Windows", "CN=Microsoft Root",
        "ABC123", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "CN=Timestamp CA",
    ]
    encoded = "|".join(base64.b64encode(v.encode("utf-8")).decode("ascii") for v in values)
    payload = reputation._decode_authenticode_protocol("noise\nBCS-AUTH1|" + encoded + "\n")
    assert payload["Status"] == "Valid"
    assert payload["Publisher"] == "CN=Microsoft Windows"
    assert payload["TimestampSigner"] == "CN=Timestamp CA"


def test_checkpoint4_winverifytrust_result_mapping_is_fail_closed():
    assert reputation._map_winverifytrust_result(0)[0] == "Valid"
    assert reputation._map_winverifytrust_result(0x800B0100)[0] == "NotSigned"
    assert reputation._map_winverifytrust_result(0x800B0003)[0] == "NotSigned"
    status, detail = reputation._map_winverifytrust_result(0x800B0101)
    assert status == "UnknownError"
    assert "0x800B0101" in detail


def test_checkpoint4_native_validity_is_authoritative_when_metadata_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(reputation.os, "name", "nt")
    monkeypatch.setattr(reputation, "_winverifytrust_status", lambda path: ("Valid", ""))
    monkeypatch.setattr(
        reputation,
        "_inspect_authenticode_powershell_metadata",
        lambda path: reputation.AuthenticodeDetails(status="UnknownError", status_message="metadata unavailable"),
    )
    result = reputation.inspect_authenticode_details(tmp_path / "sample.exe")
    assert result.status == "Valid"
    assert result.publisher == ""
    assert "metadata unavailable" in result.status_message


@pytest.mark.skipif(os.name != "nt", reason="native Windows Authenticode gate")
def test_checkpoint4_native_signed_system_binary_and_unsigned_text(tmp_path):
    system = reputation._native_windows_system_directory()
    signed = system / "kernel32.dll"
    signed_result = reputation.inspect_authenticode_details(signed)
    assert signed_result.status == "Valid", signed_result

    unsigned = tmp_path / "harmless-unsigned.ps1"
    unsigned.write_text("Write-Output 'BC Sentinel checkpoint4 harmless fixture'", encoding="utf-8")
    unsigned_result = reputation.inspect_authenticode_details(unsigned)
    assert unsigned_result.status == "NotSigned", unsigned_result
