from __future__ import annotations

from .config import PROGRAM_DATA_DIR

SERVICE_NAME = "BCSentinelProtection"
SERVICE_DISPLAY_NAME = "BC Sentinel Protection"
PIPE_NAME = r"\\.\pipe\BCSentinelProtection-v1"
SERVICE_DIR = PROGRAM_DATA_DIR / "Protection"
SERVICE_DB_PATH = SERVICE_DIR / "sentinel-service.db"
SERVICE_SECRET_PATH = SERVICE_DIR / "protection.secret"
SERVICE_CONFIG_PATH = SERVICE_DIR / "protection-config.json"
SERVICE_CONFIG_SIG_PATH = SERVICE_DIR / "protection-config.sig"
SERVICE_QUARANTINE_DIR = SERVICE_DIR / "quarantine"
SERVICE_QUARANTINE_KEY_PATH = SERVICE_DIR / "quarantine.key"
SERVICE_AUDIT_PATH = SERVICE_DIR / "service-audit.jsonl"
THREAT_INTELLIGENCE_DIR = SERVICE_DIR / "ThreatIntelligence"
ANTISPYWARE_REMEDIATION_DIR = SERVICE_DIR / "Antispyware" / "Remediation"
