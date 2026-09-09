# BC Sentinel v0.6.2-beta.3 — Native Parser Harness Fix Report

## Windows finding
The beta.2 native test failed with `UnexpectedToken` on `C:\Users\LNV ...` even though the update script itself had already been corrected.

## Root cause
Windows PowerShell `-Command` consumed the trailing script path as command text rather than as `$args[0]`. Because the absolute path contains a space in the Windows profile name, it was tokenized at `C:\Users\LNV ...`. This was a defect in the acceptance harness, not a parser error in `AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1`.

## Fix
The parser target path is now passed in `BC_SENTINEL_PARSE_TARGET`, and the PowerShell command reads it through `$env:BC_SENTINEL_PARSE_TARGET` before calling `[scriptblock]::Create(...)`. Environment-variable transport preserves the exact path without shell re-tokenization.

## Regression prevention
- Native Windows parser acceptance continues to parse the complete `.ps1` without executing it.
- A regression test requires `BC_SENTINEL_PARSE_TARGET` and forbids the old `$args[0]` path transport.

## Transaction safety
The user's failure occurred during pytest only. No update transaction was invoked, so the frozen v0.6.1-beta.5 installation remained unchanged.
