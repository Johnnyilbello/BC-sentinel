from __future__ import annotations
from dataclasses import dataclass, field
from threading import RLock
from collections import deque
from time import time


@dataclass(slots=True)
class ProcessNode:
    pid: int
    ppid: int = 0
    name: str = ""
    path: str = ""
    cmdline: str = ""
    parent_name: str = ""
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    create_time: float = 0.0
    sha256: str = ""
    signature_status: str = ""
    signer: str = ""
    modified_files: list[str] = field(default_factory=list)
    started_ts: float = field(default_factory=time)
    exited_ts: float | None = None
    identity_updated_ts: float = 0.0


class ProcessTree:
    def __init__(self, max_nodes=5000):
        self.max_nodes = max_nodes
        self._nodes = {}
        self._order = deque()
        self._lock = RLock()

    def observe(
        self,
        pid,
        ppid=0,
        name="",
        path="",
        cmdline="",
        parent_name="",
        risk_score=0,
        reasons=None,
        create_time=0.0,
    ):
        pid = int(pid)
        created = float(create_time or 0.0)
        with self._lock:
            node = self._nodes.get(pid)
            # PID reuse is common on long-running systems. Never merge a new
            # process with stale metadata from an exited process with same PID.
            if node is not None and created and node.create_time and abs(node.create_time - created) > 0.001:
                # PID reuse: discard the stale generation from both lookup and
                # eviction order before installing the new process identity.
                self._nodes.pop(pid, None)
                try:
                    self._order.remove(pid)
                except ValueError:
                    pass
                node = None
            if node is None:
                node = ProcessNode(pid=pid, create_time=created)
                self._nodes[pid] = node
                self._order.append(pid)
            elif created and not node.create_time:
                node.create_time = created

            node.ppid = int(ppid or node.ppid or 0)
            node.name = name or node.name
            node.path = path or node.path
            node.cmdline = cmdline or node.cmdline
            node.parent_name = parent_name or node.parent_name
            node.risk_score = max(node.risk_score, int(risk_score))
            node.exited_ts = None
            for reason in reasons or []:
                if reason not in node.reasons:
                    node.reasons.append(reason)

            while len(self._nodes) > self.max_nodes and self._order:
                old = self._order.popleft()
                if old != pid:
                    self._nodes.pop(old, None)
            return node

    def enrich_identity(
        self,
        pid,
        *,
        create_time=0.0,
        sha256="",
        signature_status="",
        signer="",
        path="",
    ) -> bool:
        """Apply asynchronous executable identity iff PID identity still matches."""
        if not pid:
            return False
        with self._lock:
            node = self._nodes.get(int(pid))
            if node is None:
                return False
            expected = float(create_time or 0.0)
            if expected and node.create_time and abs(node.create_time - expected) > 0.001:
                return False
            node.path = path or node.path
            node.sha256 = sha256 or node.sha256
            node.signature_status = signature_status or node.signature_status
            node.signer = signer or node.signer
            node.identity_updated_ts = time()
            return True

    def record_file_touch(self, pid, path: str, max_files: int = 64) -> None:
        if not pid or not path:
            return
        with self._lock:
            node = self._nodes.get(int(pid))
            if node is None:
                return
            # Keep a compact unique recency list useful for correlation/UI.
            try:
                node.modified_files.remove(path)
            except ValueError:
                pass
            node.modified_files.append(path)
            if len(node.modified_files) > max(8, int(max_files)):
                del node.modified_files[: len(node.modified_files) - int(max_files)]

    def mark_exit(self, pid):
        with self._lock:
            n = self._nodes.get(int(pid))
            if n:
                n.exited_ts = time()

    def get(self, pid):
        if not pid:
            return None
        with self._lock:
            return self._nodes.get(int(pid))

    def ancestry(self, pid, max_depth=8):
        out = []
        seen = set()
        with self._lock:
            cur = self._nodes.get(int(pid))
            while cur and cur.pid not in seen and len(out) < max_depth:
                out.append(cur)
                seen.add(cur.pid)
                cur = self._nodes.get(cur.ppid)
        return out

    def describe_chain(self, pid):
        return " → ".join(n.name or str(n.pid) for n in reversed(self.ancestry(pid)))
