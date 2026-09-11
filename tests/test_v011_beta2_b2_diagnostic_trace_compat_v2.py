from tools.v011_beta2_b2_diagnostic_trace_compat_v2 import transform_realtime
from tools.v011_beta2_b2_diagnostic_trace_compat import MARKER


def _source(callback_block: str) -> str:
    return f'''from __future__ import annotations

class RealtimeMonitor:
    def __init__(self):
        self.event_callback = None

    def _scan_when_stable(self, path):
        if self.event_callback is not None:
{callback_block}
        self.scanner.scan(path)
'''


def test_ast_transform_accepts_canonical_callback_shape():
    source = _source('''            try:\n                self.event_callback(str(path))\n            except Exception:\n                pass''')
    patched = transform_realtime(source)
    assert patched.count(MARKER) == 1
    assert 'FILE_STABLE_CALLBACK_ENTER' in patched
    assert 'FILE_STABLE_CALLBACK_RETURN' in patched
    assert 'FILE_STABLE_CALLBACK_ERROR' in patched
    assert patched.count('self.event_callback(str(path))') == 1


def test_ast_transform_accepts_extra_comment_and_non_exact_spacing_shape():
    source = _source('''            # canonical observation bridge\n            try:\n                self.event_callback( str(path) )\n            except Exception:\n                pass''')
    patched = transform_realtime(source)
    assert patched.count(MARKER) == 1
    assert 'FILE_STABLE_CALLBACK_ENTER' in patched
    assert 'self.event_callback( str(path) )' in patched


def test_ast_transform_is_idempotent():
    source = _source('''            try:\n                self.event_callback(str(path))\n            except Exception:\n                pass''')
    once = transform_realtime(source)
    twice = transform_realtime(once)
    assert twice == once
