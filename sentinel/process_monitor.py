from __future__ import annotations
import json
import threading
import time

from .behavior import ProcessObservation, assess_process
from .core.events import SecurityEvent
from .database import Database
from .process_identity import ProcessIdentityResolver
from .process_tree import ProcessTree


class ProcessMonitor:
    def __init__(
        self,
        db=None,
        interval=0.8,
        callback=None,
        process_tree=None,
        event_callback=None,
        identity_resolver=None,
    ):
        self.db = db or Database()
        self.interval = interval
        self.callback = callback
        self.process_tree = process_tree or ProcessTree()
        self.event_callback = event_callback
        self._seen = {}
        self._stop = threading.Event()
        self._thread = None
        self._owns_identity = identity_resolver is None
        self.identity_resolver = identity_resolver or ProcessIdentityResolver(self.db)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="BCS-ProcessMonitor", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.5)
        self._thread = None

    def close(self):
        self.stop()
        if self._owns_identity:
            self.identity_resolver.shutdown(wait=False)

    def _schedule_identity(self, node):
        if not node or not node.path:
            return
        pid = node.pid
        created = node.create_time
        future = self.identity_resolver.submit(node.path)

        def done(fut):
            try:
                identity = fut.result()
            except Exception:
                return
            self.process_tree.enrich_identity(
                pid,
                create_time=created,
                sha256=identity.sha256,
                signature_status=identity.signature_status,
                signer=identity.signer,
                path=identity.path,
            )

        future.add_done_callback(done)

    def _run(self):
        try:
            import psutil
        except ImportError:
            return
        try:
            for p in psutil.process_iter(["pid", "create_time"]):
                self._seen[int(p.info["pid"])] = float(p.info.get("create_time") or 0)
        except Exception:
            pass

        while not self._stop.wait(self.interval):
            current = set()
            for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
                try:
                    info = proc.info
                    pid = int(info["pid"])
                    current.add(pid)
                    created = float(info.get("create_time") or 0)
                    if self._seen.get(pid) == created:
                        continue
                    self._seen[pid] = created
                    try:
                        parent = proc.parent()
                        parent_name = parent.name() if parent else ""
                    except Exception:
                        parent_name = ""
                    obs = ProcessObservation(
                        info.get("name") or "",
                        parent_name,
                        " ".join(info.get("cmdline") or []),
                        info.get("exe") or "",
                    )
                    result = assess_process(obs)
                    node = self.process_tree.observe(
                        pid,
                        int(info.get("ppid") or 0),
                        obs.name,
                        obs.path,
                        obs.cmdline,
                        parent_name,
                        result.score,
                        result.reasons,
                        create_time=created,
                    )
                    self._schedule_identity(node)
                    self.db.execute(
                        "INSERT INTO process_events(pid,ppid,name,path,cmdline,score,reasons_json) VALUES(?,?,?,?,?,?,?)",
                        (pid, node.ppid, obs.name, obs.path, obs.cmdline, result.score, json.dumps(result.reasons)),
                    )
                    if self.event_callback:
                        self.event_callback(SecurityEvent(
                            category="process", action="start", source="psutil",
                            score=result.score, path=obs.path, pid=pid, ppid=node.ppid,
                            process_name=obs.name, process_path=obs.path,
                            reasons=result.reasons,
                            data={
                                "chain": self.process_tree.describe_chain(pid),
                                "cmdline": obs.cmdline,
                                "create_time": created,
                                "sha256": node.sha256,
                                "signature_status": node.signature_status,
                                "signer": node.signer,
                            },
                        ))
                    if self.callback and result.score >= 25:
                        self.callback(obs, result)
                except Exception:
                    continue
            for pid in list(set(self._seen) - current)[:1000]:
                self.process_tree.mark_exit(pid)
                self._seen.pop(pid, None)
