from __future__ import annotations

import errno
import inspect
from pathlib import Path

from sentinel import service_update


def test_v011_service_update_directory_promotions_use_bounded_retry():
    source = inspect.getsource(service_update)
    marker = source.index('def apply_update_transaction(')
    tail = source[marker:]
    assert 'os.replace(' not in tail
    assert tail.count('_replace_with_retry(') >= 9


def test_v011_replace_helper_retries_transient_access_denied(monkeypatch, tmp_path: Path):
    src = tmp_path / 'source'
    dst = tmp_path / 'target'
    src.mkdir()
    calls = {'count': 0}
    real_replace = service_update.os.replace

    def flaky_replace(a, b):
        calls['count'] += 1
        if calls['count'] < 3:
            raise PermissionError(errno.EACCES, 'transient access denied')
        return real_replace(a, b)

    monkeypatch.setattr(service_update.os, 'replace', flaky_replace)
    service_update._replace_with_retry(src, dst, attempts=4, delay=0)
    assert calls['count'] == 3
    assert dst.is_dir()
    assert not src.exists()


def test_v011_replace_helper_fails_closed_after_bound(monkeypatch, tmp_path: Path):
    src = tmp_path / 'source'
    dst = tmp_path / 'target'
    src.mkdir()
    calls = {'count': 0}

    def always_denied(a, b):
        calls['count'] += 1
        raise PermissionError(errno.EACCES, 'persistent access denied')

    monkeypatch.setattr(service_update.os, 'replace', always_denied)
    try:
        service_update._replace_with_retry(src, dst, attempts=3, delay=0)
    except PermissionError:
        pass
    else:
        raise AssertionError('persistent access denial must fail closed')
    assert calls['count'] == 3
    assert src.is_dir()
    assert not dst.exists()
