from pathlib import Path
from sentinel.scanner import StaticScanner, ScanCancelled, hash_file

def test_hash_file_honors_cancellation(tmp_path):
    p=tmp_path/"large.bin"
    p.write_bytes(b"x"*(3*1024*1024))
    calls={"n":0}
    def cancelled():
        calls["n"]+=1
        return calls["n"]>=2
    try:
        hash_file(p,cancelled=cancelled)
    except ScanCancelled:
        pass
    else:
        raise AssertionError("hash_file did not cancel")

def test_scan_paths_cancels_during_enumeration(tmp_path):
    root=tmp_path/"many"
    root.mkdir()
    for i in range(200):
        (root/f"{i}.txt").write_text("safe",encoding="utf-8")
    checks={"n":0}
    def cancelled():
        checks["n"]+=1
        return checks["n"]>2
    reports=list(StaticScanner().scan_paths([root],cancelled=cancelled))
    assert reports == []
    assert checks["n"]>=3

def test_cancel_ui_sets_worker_flag_first():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    start=source.index("    def cancel_scan(self):")
    end=source.index("    # ---------- detection / realtime ----------",start)
    block=source[start:end]
    assert block.index("self.scan_thread.cancel()") < block.index("setText(\"Annullamento")
