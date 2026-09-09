from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'sentinel' / 'service_update.py'
MARKER = 'def apply_update_transaction('
EXPECTED_DIRECT_REPLACES = 9


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f'service_update.py missing: {path}')
    text = path.read_text(encoding='utf-8')
    marker = text.find(MARKER)
    if marker < 0:
        raise RuntimeError('apply_update_transaction() not found; refusing compatibility patch')

    head = text[:marker]
    tail = text[marker:]
    direct_count = tail.count('os.replace(')
    hardened_count = tail.count('_replace_with_retry(')

    if direct_count == 0 and hardened_count >= EXPECTED_DIRECT_REPLACES:
        return {'patched': False, 'already_compatible': True, 'path': str(path), 'hardened_calls': hardened_count}
    if direct_count != EXPECTED_DIRECT_REPLACES:
        raise RuntimeError(
            'Unexpected service_update directory-promotion shape: '
            f'expected {EXPECTED_DIRECT_REPLACES} direct os.replace calls after apply_update_transaction, got {direct_count}'
        )
    if 'def _replace_with_retry(' not in head:
        raise RuntimeError('Existing bounded replace helper missing; refusing to inject alternate behavior')

    # All os.replace calls after apply_update_transaction operate on sibling deployment/backup directories.
    # Use the existing bounded retry helper with a slightly larger, still bounded Windows lock budget.
    # Rebuild the transaction tail with precise line-level substitution.
    original_tail = text[marker:]
    lines = original_tail.splitlines(keepends=True)
    converted = 0
    out: list[str] = []
    for line in lines:
        if 'os.replace(' in line:
            if line.count('os.replace(') != 1:
                raise RuntimeError('Unexpected multiple os.replace calls on one line')
            before, rest = line.split('os.replace(', 1)
            call, suffix = rest.rsplit(')', 1)
            line = before + '_replace_with_retry(' + call + ', attempts=12, delay=0.05)' + suffix
            converted += 1
        out.append(line)
    if converted != EXPECTED_DIRECT_REPLACES:
        raise RuntimeError(f'Converted {converted} directory replace calls; expected {EXPECTED_DIRECT_REPLACES}')

    updated = head + ''.join(out)
    path.write_text(updated, encoding='utf-8')

    verify = path.read_text(encoding='utf-8')
    verify_tail = verify[verify.find(MARKER):]
    if verify_tail.count('os.replace(') != 0:
        raise RuntimeError('Direct directory os.replace calls remain after compatibility patch')
    if verify_tail.count('_replace_with_retry(') < EXPECTED_DIRECT_REPLACES:
        raise RuntimeError('Not all directory promotions were hardened')
    return {'patched': True, 'already_compatible': False, 'path': str(path), 'hardened_calls': verify_tail.count('_replace_with_retry(')}


def main() -> int:
    result = apply_compat_patch()
    if result['patched']:
        print('v0.11 service-update Windows compatibility: bounded directory replace retry installed')
    else:
        print('v0.11 service-update Windows compatibility: already canonical')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
