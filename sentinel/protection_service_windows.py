from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from .config import Settings
from .protection_service_core import (
    ProtectionConfigStore,
    ProtectionRuntime,
    ProtectionServiceCore,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    ensure_service_secret,
    SERVICE_AUDIT_PATH,
)
from .service_hardening import (
    AUDIT_CHAIN_STATE_PATH,
    INTEGRITY_KEY_PATH,
    IntegrityVerifier,
    ensure_integrity_key,
)
from .protection_transport_windows import WindowsNamedPipeServer


def initialize_service_config() -> None:
    # v0.6.1 splits the user-readable IPC token from the machine-private
    # integrity key. Migrate a valid v0.6.x configuration once without
    # accepting an invalid legacy HMAC as trustworthy.
    ipc_secret = ensure_service_secret()
    integrity_key = ensure_integrity_key(INTEGRITY_KEY_PATH)
    store = ProtectionConfigStore(integrity_key)
    settings = Settings.defaults()
    if store.path.exists() and store.sig_path.exists():
        try:
            store.load()
        except Exception:
            legacy = ProtectionConfigStore(ipc_secret)
            legacy.path = store.path
            legacy.sig_path = store.sig_path
            migrated = legacy.load()
            store.save(migrated)
    else:
        store.save(settings)

    # v0.6 audit records were not HMAC chained. Preserve them read-only rather
    # than mixing unsigned legacy records into the new chain.
    if SERVICE_AUDIT_PATH.exists() and not AUDIT_CHAIN_STATE_PATH.exists():
        try:
            first = SERVICE_AUDIT_PATH.read_text(encoding="utf-8").splitlines()[:1]
            if first and '"hmac"' not in first[0]:
                legacy_path = SERVICE_AUDIT_PATH.with_name("service-audit-v060-legacy.jsonl")
                if not legacy_path.exists():
                    SERVICE_AUDIT_PATH.replace(legacy_path)
        except Exception:
            pass



def seal_integrity_manifest() -> None:
    verifier = IntegrityVerifier(Path(sys.executable).resolve().parent, key_path=INTEGRITY_KEY_PATH)
    result = verifier.seal()
    if not result.ok:
        raise RuntimeError("; ".join(result.issues) or "integrity sealing failed")


def pipe_selftest() -> None:
    """Validate named-pipe creation without installing or starting the service."""
    class _NoopCore:
        pass
    server = WindowsNamedPipeServer(_NoopCore())
    try:
        server.prepare()
        if not server.ready:
            raise RuntimeError("named pipe did not reach ready state")
    finally:
        server.close_prepared()


if os.name == "nt":
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class BCSentinelProtectionService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = (
            "BC Sentinel privileged endpoint protection, telemetry and incident correlation service."
        )

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            # Build the heavy runtime lazily inside SvcDoRun.  This guarantees
            # constructor/bootstrap exceptions are logged to the Windows Event
            # Log instead of terminating the service host before diagnostics
            # become available.
            self.runtime = None
            self.core = None
            self.server = None
            self.thread = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.runtime is not None:
                self.runtime.audit_lifecycle("scm_stop_requested")
            try:
                if self.server is not None:
                    self.server.stop()
            finally:
                if self.runtime is not None:
                    self.runtime.stop()
                win32event.SetEvent(self.stop_event)

        def _run_pipe_server(self):
            # A single transient accept-loop failure must not collapse endpoint
            # protection. Rebuild the listener a bounded number of times; a
            # persistent control-plane failure still fails closed and stops the
            # service so SCM recovery can take over.
            failures = 0
            while True:
                try:
                    if self.server is None:
                        raise RuntimeError("named-pipe server not initialized")
                    self.server.serve_forever()
                    return
                except Exception as exc:
                    failures += 1
                    servicemanager.LogErrorMsg(
                        f"BC Sentinel Protection IPC listener failure {failures}/5: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    try:
                        self.runtime._last_error = f"ipc: {type(exc).__name__}: {exc}"
                    except Exception:
                        pass
                    # Stop requested by SCM: never resurrect IPC during shutdown.
                    if win32event.WaitForSingleObject(self.stop_event, 0) == win32event.WAIT_OBJECT_0:
                        return
                    if failures >= 5:
                        win32event.SetEvent(self.stop_event)
                        return
                    time.sleep(min(0.25 * failures, 1.0))
                    try:
                        self.server = WindowsNamedPipeServer(self.core)
                        self.server.prepare()
                    except Exception as prepare_exc:
                        servicemanager.LogErrorMsg(
                            f"BC Sentinel Protection IPC reprepare failed: "
                            f"{type(prepare_exc).__name__}: {prepare_exc}"
                        )

        def SvcDoRun(self):
            servicemanager.LogInfoMsg("BC Sentinel Protection starting")
            try:
                self.runtime = ProtectionRuntime()
                self.core = ProtectionServiceCore(self.runtime)
                self.server = WindowsNamedPipeServer(self.core)
            except Exception as exc:
                servicemanager.LogErrorMsg(
                    f"BC Sentinel Protection bootstrap construction failed: {type(exc).__name__}: {exc}"
                )
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)
                return
            self.runtime.audit_lifecycle("scm_start")
            if not self.runtime.start():
                servicemanager.LogErrorMsg(
                    f"BC Sentinel Protection failed to initialize: {self.runtime.status().get('last_error','')}"
                )
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)
                return
            try:
                # Create the first named-pipe instance synchronously. A service
                # must never remain RUNNING when its control plane failed before
                # becoming reachable.
                self.server.prepare()
            except Exception as exc:
                servicemanager.LogErrorMsg(
                    f"BC Sentinel Protection IPC bootstrap failed: {type(exc).__name__}: {exc}"
                )
                self.runtime.stop()
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)
                return
            self.thread = threading.Thread(
                target=self._run_pipe_server,
                name="BCS-ProtectionNamedPipe",
                daemon=True,
            )
            self.thread.start()
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            # A fatal pipe-thread error sets stop_event too. In either case stop
            # the engines so SCM never retains a hollow protection process.
            if self.server is not None:
                self.server.stop()
            if self.runtime is not None:
                self.runtime.stop()
                self.runtime.audit_lifecycle("scm_stopped")
            servicemanager.LogInfoMsg("BC Sentinel Protection stopped")

    def main():
        if len(sys.argv) >= 2 and sys.argv[1].lower() == "init-config":
            initialize_service_config()
            print("BC Sentinel Protection configuration initialized.")
            return
        if len(sys.argv) >= 2 and sys.argv[1].lower() == "seal-integrity":
            seal_integrity_manifest()
            print("BC Sentinel Protection integrity manifest sealed.")
            return
        if len(sys.argv) >= 2 and sys.argv[1].lower() == "pipe-selftest":
            pipe_selftest()
            print("BC Sentinel Protection named-pipe self-test passed.")
            return
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(BCSentinelProtectionService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(BCSentinelProtectionService)

else:
    class BCSentinelProtectionService:
        pass

    def main():
        if len(sys.argv) >= 2 and sys.argv[1].lower() == "init-config":
            initialize_service_config()
            return
        raise SystemExit("BC Sentinel Protection Service is Windows-only.")


if __name__ == "__main__":
    main()
