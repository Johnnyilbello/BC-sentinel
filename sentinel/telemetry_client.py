"""Compatibility client name for UI code migrating to v0.6 protection IPC."""
from __future__ import annotations

from .path_security import is_reparse_point
from .protection_client import ProtectionServiceClient
from .protection_constants import SERVICE_NAME, SERVICE_SECRET_PATH


def secret_path():
    return SERVICE_SECRET_PATH


class TelemetryServiceClient(ProtectionServiceClient):
    def _secret(self) -> str:
        try:
            path = secret_path()
            if is_reparse_point(path):
                return ""
            value = path.read_text(encoding="ascii").strip()
            return value if len(value) >= 64 else ""
        except Exception:
            return ""
