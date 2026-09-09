# BC Sentinel v0.8.0-beta.2 — Acceptance Harness Fix1

## Native Windows failure

The Windows test run reached the native `yara-python` branch and exposed a test-only API mismatch in `tests/test_v080_beta1_signed_threat_intelligence.py`.

The production `Signal` dataclass exposes `key`, while the test asserted against a nonexistent `code` attribute. `YaraEngine` already emits the expected rule identity through `Signal.key`.

## Fix

- replaced the three YARA assertions from `signal.code` to `signal.key`;
- added a contract regression proving the YARA signal identifier is `Signal.key`;
- no production source, YARA engine, scanner, threat-package manager, Protection Service, firewall, updater, key lifecycle, reputation, recovery or retrieval logic was changed.

## Security impact

None. This is an acceptance-harness compatibility fix. Native YARA execution remains required on Windows and the test continues to require the expected `BCS080_ALPHA` / `BCS080_BRAVO` rule matches.
