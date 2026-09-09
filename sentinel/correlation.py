from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from threading import RLock
from time import time
from .core.events import ProcessAttribution


def normalize_path(path):
    value = str(path or "").strip()
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return value.replace("/", "\\").casefold()


@dataclass(slots=True)
class FileTouch:
    path: str
    display_path: str
    pid: int | None
    ppid: int | None
    process_name: str
    process_path: str
    cmdline: str
    sha256: str
    signature_status: str
    signer: str
    create_time: float
    action: str
    ts: float


class FileProcessCorrelator:
    def __init__(self, max_events=8000, process_tree=None):
        self._events = deque(maxlen=max_events)
        self._lock = RLock()
        self.process_tree = process_tree

    def record(
        self,
        path,
        pid,
        process_name="",
        process_path="",
        action="",
        ts=None,
        *,
        ppid=None,
        cmdline="",
        sha256="",
        signature_status="",
        signer="",
        create_time=0.0,
    ):
        if not path:
            return
        pid_value = int(pid) if pid else None
        if self.process_tree is not None and pid_value:
            node = self.process_tree.get(pid_value)
            if node is not None:
                ppid = ppid or node.ppid
                process_name = process_name or node.name
                process_path = process_path or node.path
                cmdline = cmdline or node.cmdline
                sha256 = sha256 or node.sha256
                signature_status = signature_status or node.signature_status
                signer = signer or node.signer
                create_time = create_time or node.create_time
            self.process_tree.record_file_touch(pid_value, str(path))

        touch = FileTouch(
            normalize_path(path), str(path), pid_value, int(ppid) if ppid else None,
            process_name, process_path, cmdline, sha256, signature_status, signer,
            float(create_time or 0.0), action, ts or time(),
        )
        with self._lock:
            self._events.append(touch)

    def attribute(self, path, max_age=4.0):
        wanted = normalize_path(path)
        now = time()
        best = None
        exact = False
        with self._lock:
            for e in reversed(self._events):
                if now - e.ts > max_age:
                    break
                if e.path == wanted:
                    best = e
                    exact = True
                    break
            if best is None:
                base = wanted.rsplit("\\", 1)[-1]
                for e in reversed(self._events):
                    if now - e.ts > min(max_age, 1.5):
                        break
                    if base and e.path.endswith("\\" + base):
                        best = e
                        break

        if best is None:
            return ProcessAttribution()

        # Identity may have completed asynchronously after the file event was
        # recorded. Prefer the live ProcessTree metadata only if PID create-time
        # still matches, protecting against PID reuse.
        ppid = best.ppid
        name = best.process_name
        proc_path = best.process_path
        cmdline = best.cmdline
        sha256 = best.sha256
        signature_status = best.signature_status
        signer = best.signer
        create_time = best.create_time
        if self.process_tree is not None and best.pid:
            node = self.process_tree.get(best.pid)
            if node is not None and (
                not create_time or not node.create_time or abs(node.create_time - create_time) <= 0.001
            ):
                ppid = ppid or node.ppid
                name = name or node.name
                proc_path = proc_path or node.path
                cmdline = cmdline or node.cmdline
                sha256 = sha256 or node.sha256
                signature_status = signature_status or node.signature_status
                signer = signer or node.signer
                create_time = create_time or node.create_time

        return ProcessAttribution(
            pid=best.pid,
            ppid=ppid,
            name=name,
            path=proc_path,
            cmdline=cmdline,
            sha256=sha256,
            signature_status=signature_status,
            signer=signer,
            create_time=float(create_time or 0.0),
            source="etw",
            confidence=0.96 if exact else 0.62,
            observed_ts=best.ts,
        )
