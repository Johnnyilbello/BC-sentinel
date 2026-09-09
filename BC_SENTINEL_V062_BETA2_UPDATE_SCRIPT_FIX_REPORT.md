# BC Sentinel v0.6.2-beta.2 — Update Script Parser Fix Report

## Native Windows finding
`tools.update_acceptance --mode upgrade` passed and authenticated 160 source files for the planned upgrade from v0.6.1-beta.5 to v0.6.2-beta.1. The subsequent PowerShell wrapper failed at parse time on `"BC Sentinel $Mode: ..."`.

## Root cause
In a double-quoted PowerShell string, a colon directly following a variable name can be parsed as part of a scoped/qualified variable reference. `$Mode:` was therefore rejected before the script body executed.

## Fix
The interpolation is now `"BC Sentinel ${Mode}: ..."`. The braces delimit the variable name explicitly.

## Regression prevention
- Static test forbids `$Mode:` and requires `${Mode}:`.
- Native Windows pytest executes the Windows PowerShell parser via `[scriptblock]::Create(...)` against the full update script.

## Transaction safety
The reported failure was a parser error, so no service stop, backup, deploy, replacement, ACL mutation, sealing, or rollback step from the update transaction executed. The installed v0.6.1-beta.5 baseline therefore remained untouched.
