"""v0.6 compatibility surface for the former Telemetry Service.

The v0.5 loopback TCP broker was retired in v0.6. Production IPC is now the
ACL-protected Windows named pipe implemented by protection_transport_windows.
This module retains small API names used by older UI/tests during migration;
it does not open a TCP listener.
"""
from __future__ import annotations

import uuid

from .protection_protocol import ClientContext, PROTOCOL_VERSION
from .protection_service_core import (
    EventBuffer,
    ProtectionRuntime,
    ProtectionServiceCore,
    SERVICE_NAME,
    SERVICE_SECRET_PATH,
    ensure_service_secret,
)


def secret_path():
    return SERVICE_SECRET_PATH


def ensure_secret() -> str:
    return ensure_service_secret()


class TelemetryBroker:
    """Compatibility adapter over the v0.6 ProtectionRuntime.

    New code must use ProtectionServiceCore + WindowsNamedPipeServer directly.
    """

    def __init__(self):
        self.runtime = ProtectionRuntime()
        self.core = ProtectionServiceCore(self.runtime)
        self.process_tree = self.runtime.process_tree
        self.correlator = self.runtime.correlator
        self.events = self.runtime.events
        self.secret = self.runtime.secret
        self.etw = self.runtime.etw
        self.persistence = self.runtime.persistence
        self.network = self.runtime.network

    def status(self):
        return self.runtime.status()

    def attribute(self, path: str):
        return self.runtime.attribute(path)

    def process_chain(self, pid: int):
        return self.runtime.process_chain(pid)

    def dispatch(self, request: dict):
        # Translate the legacy dictionary shape into the strict v0.6 envelope.
        op = str(request.get("op") or "")
        payload = {
            key: value
            for key, value in request.items()
            if key not in {"op", "token", "version", "request_id", "payload"}
        }
        if isinstance(request.get("payload"), dict):
            payload.update(request["payload"])
        envelope = {
            "version": PROTOCOL_VERSION,
            "request_id": str(request.get("request_id") or uuid.uuid4().hex),
            "op": op,
            "token": str(request.get("token") or ""),
            "payload": payload,
        }
        # Legacy direct dispatch is intentionally read-only unless a caller
        # explicitly supplies an authenticated admin ClientContext through the
        # new ProtectionServiceCore API.
        if op == "set_network_collection":
            pass
        return self.core.dispatch(envelope, ClientContext(local=True, authenticated=False))

    def start_backends(self):
        # Compatibility only. Network is no longer independently activated by
        # this legacy adapter; the ProtectionRuntime owns lifecycle/config.
        ok = self.runtime.start()
        status = self.runtime.status()
        return ok, bool(status.get("persistence")), bool(status.get("network"))

    def stop_backends(self):
        self.runtime.stop()

    def serve(self):
        raise RuntimeError(
            "Legacy TCP telemetry serving was removed in v0.6; use the Windows Protection Service named pipe."
        )

    def stop(self):
        self.runtime.stop()
