from __future__ import annotations

import os
from pathlib import Path
import time

import pytest

from tools.v011_threat_trust_windows_compat import (
    HELPER_MARKER,
    apply_compat_patch,
)


FIXTURE = '''from __future__ import annotations
import os
from pathlib import Path

class ThreatTrustError(RuntimeError):
    pass

class ThreatTrustStore:
    def __init__(self, root: Path):
        self.keyset_path = root / "active-keyset.json"
        self.revocation_path = root / "revocations.json"

    def install_keyset(self):
        tmp = self.keyset_path.with_suffix(".json.tmp")
        os.replace(tmp, self.keyset_path)

    def install_revocations(self):
        tmp = self.revocation_path.with_suffix(".json.tmp")
        os.replace(tmp, self.revocation_path)
'''


def _load_patched(tmp_path: Path) -> tuple[Path, dict]:
    target = tmp_path / "threat_trust.py"
    target.write_text(FIXTURE, encoding="utf-8")
    result = apply_compat_patch(target)
    namespace: dict = {}
    exec(compile(target.read_text(encoding="utf-8"), str(target), "exec"), namespace)
    return target, namespace


def _winerror(code: int) -> OSError:
    exc = PermissionError(13, "simulated transient Windows lock")
    exc.winerror = code
    return exc


def test_threat_trust_patcher_hardens_all_store_publications_and_is_idempotent(tmp_path: Path):
    target, _namespace = _load_patched(tmp_path)
    text = target.read_text(encoding="utf-8")
    assert text.count(HELPER_MARKER) == 1
    assert "_bcsentinel_threat_trust_replace_with_retry(tmp, self.keyset_path)" in text
    assert "_bcsentinel_threat_trust_replace_with_retry(tmp, self.revocation_path)" in text
    assert "os.replace(tmp, self.keyset_path)" not in text
    assert "os.replace(tmp, self.revocation_path)" not in text

    second = apply_compat_patch(target)
    assert second["patched"] is False
    assert second["already_compatible"] is True
    assert set(second["hardened_targets"]) == {"keyset_path", "revocation_path"}


def test_threat_trust_retry_succeeds_after_transient_access_denied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _target, namespace = _load_patched(tmp_path)
    helper = namespace["_bcsentinel_threat_trust_replace_with_retry"]
    calls = []

    def fake_replace(source, target):
        calls.append((source, target))
        if len(calls) < 3:
            raise _winerror(5)

    monkeypatch.setattr(os, "replace", fake_replace)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    helper(Path("a.tmp"), Path("a.json"))
    assert len(calls) == 3


def test_threat_trust_retry_accepts_only_known_windows_lock_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _target, namespace = _load_patched(tmp_path)
    helper = namespace["_bcsentinel_threat_trust_replace_with_retry"]
    calls = 0

    def fake_replace(_source, _target):
        nonlocal calls
        calls += 1
        exc = OSError(22, "simulated unrelated failure")
        exc.winerror = 87
        raise exc

    monkeypatch.setattr(os, "replace", fake_replace)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    with pytest.raises(OSError, match="simulated unrelated failure"):
        helper(Path("a.tmp"), Path("a.json"))
    assert calls == 1


@pytest.mark.parametrize("code", [5, 32, 33])
def test_threat_trust_persistent_windows_lock_fails_closed_after_bounded_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
):
    _target, namespace = _load_patched(tmp_path)
    helper = namespace["_bcsentinel_threat_trust_replace_with_retry"]
    error_type = namespace["ThreatTrustError"]
    calls = 0

    def fake_replace(_source, _target):
        nonlocal calls
        calls += 1
        raise _winerror(code)

    monkeypatch.setattr(os, "replace", fake_replace)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    with pytest.raises(error_type, match="cannot atomically publish threat-trust state"):
        helper(Path("a.tmp"), Path("a.json"), attempts=4)
    assert calls == 4
