"""Exercise a frozen Windows artifact with disposable application profiles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def verify(executable: Path) -> dict:
    results = []
    cases = {
        'fresh_profile': None,
        'invalid_utf8_trial': b'\xff\xfePRIVATE_TEST_VALUE',
        'truncated_json_trial': b'{"schema":',
        'nonfinite_trial': b'{"schema":"bc-sentinel-trial-state-v1","started_at":NaN,"trial_days":14}',
        'wrong_shape_trial': b'[]',
        'invalid_license': None,
    }
    for name, trial in cases.items():
        with tempfile.TemporaryDirectory(prefix='BCSentinel-runtime-verify-') as folder:
            root = Path(folder)
            env = dict(os.environ)
            env['LOCALAPPDATA'] = str(root)
            env['PATH'] = os.pathsep.join([str(Path(os.environ['SystemRoot']) / 'System32'), os.environ['SystemRoot']])
            env['QT_QPA_PLATFORM'] = 'offscreen'
            for key in ('PYTHONPATH', 'PYTHONHOME', 'BC_SENTINEL_LICENSE_TOKEN_JSON', 'BC_SENTINEL_LICENSE_PUBLIC_KEY'):
                env.pop(key, None)
            if name == 'invalid_license':
                env['BC_SENTINEL_LICENSE_TOKEN_JSON'] = 'PRIVATE_TEST_VALUE'
            trial_path = root / 'BCSentinel' / 'commercial' / 'trial.json'
            if trial is not None:
                trial_path.parent.mkdir(parents=True)
                trial_path.write_bytes(trial)
            started = time.monotonic()
            exits = {}
            for option in ('--self-check', '--health-json', '--smoke'):
                proc = subprocess.run([str(executable), option], env=env, cwd=root, timeout=60, capture_output=True)
                exits[option] = proc.returncode
            report_path = root / 'support.json'
            proc = subprocess.run([str(executable), '--diagnostics-json', str(report_path)], env=env, cwd=root, timeout=60, capture_output=True)
            exits['diagnostics'] = proc.returncode
            raw = report_path.read_text(encoding='utf-8') if report_path.exists() else ''
            report = json.loads(raw) if raw else {}
            preserved = trial is None or trial_path.read_bytes() == trial
            status_ok = trial is None or report.get('commercial_status') == 'UNAVAILABLE'
            passed = all(code == 0 for code in exits.values()) and bool(report) and preserved and status_ok and 'PRIVATE_TEST_VALUE' not in raw
            results.append({'case': name, 'passed': passed, 'exit_codes': exits, 'trial_preserved': preserved, 'commercial_status': report.get('commercial_status'), 'seconds': round(time.monotonic()-started, 2)})
    return {'passed': all(row['passed'] for row in results), 'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'cases': results, 'clean_vm_tested': False, 'protection_runtime_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.executable.resolve(strict=True))
    args.report.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
