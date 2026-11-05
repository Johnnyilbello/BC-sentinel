"""Explicit, fixed-command integration with the local Microsoft Defender engine."""
from __future__ import annotations

import os
from pathlib import Path
import sys

ACTIONS = {
    "status": "",
    "quick": "Start-MpScan -ScanType QuickScan -ErrorAction Stop;",
    "full": "Start-MpScan -ScanType FullScan -ErrorAction Stop;",
    "remove": "Remove-MpThreat -ErrorAction Stop;",
}


def command(action: str, *, removal_confirmed: bool = False) -> tuple[str, list[str]]:
    if action not in ACTIONS:
        raise ValueError("Azione Defender non supportata.")
    if action == "remove" and not removal_confirmed:
        raise PermissionError("La rimozione richiede conferma.")
    if sys.platform != "win32":
        raise OSError("Microsoft Defender richiede Windows.")
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not executable.is_absolute() or not executable.is_file():
        raise OSError("Windows PowerShell non disponibile.")
    readiness = "" if action == "status" else """
        $initial = Get-MpComputerStatus -ErrorAction Stop
        if (-not $initial.AMServiceEnabled -or -not $initial.AntivirusEnabled -or
            $initial.AMRunningMode -ne 'Normal') {
            throw 'Microsoft Defender non è disponibile in modalità antivirus attiva.'
        }
    """
    script = """
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $ErrorActionPreference = 'Stop'
        try {
    """ + readiness + ACTIONS[action] + """
            $status = Get-MpComputerStatus -ErrorAction Stop
            $threats = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.IsActive })
            [ordered]@{
                service_enabled = [bool]$status.AMServiceEnabled
                antivirus_enabled = [bool]$status.AntivirusEnabled
                mode = [string]$status.AMRunningMode
                signature_version = [string]$status.AntivirusSignatureVersion
                signature_updated = [string]$status.AntivirusSignatureLastUpdated
                active_threats = @($threats | ForEach-Object {
                    [ordered]@{ name = [string]$_.ThreatName; id = [string]$_.ThreatID }
                })
            } | ConvertTo-Json -Depth 5 -Compress
        } catch {
            [Console]::Error.WriteLine($_.Exception.Message)
            exit 1
        }
    """
    return str(executable), ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]
