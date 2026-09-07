# Test Status — BC Sentinel v0.9.0-beta.2

Package verification was performed on the extracted final release tree.

```text
pytest: 469 passed, 1 skipped
compileall: PASS
local acceptance suites: 10/10 PASS
```

The single local skip is Windows-only. Expected native Windows pytest target: **470 passed**.

New Beta2 acceptance gates:

- `antispyware-v090-beta2-foundation`
- `antispyware-v090-beta2-live`

Required freeze condition:

```text
passed = true
critical_failures = []
```

Beta2 native remediation acceptance additionally requires the harmless temporary registry apply/restore probe to complete successfully.
