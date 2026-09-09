# BC Sentinel v0.2.1-beta FIX4

Fixes the PowerShell build interruption that occurred after all pytest tests
had already passed.

Observed:
- pytest reached 100%;
- `Add-Content` then failed because `$script:LogPath` was null;
- PowerShell's `ErrorActionPreference = Stop` turned that logging failure into
  a fatal build error.

FIX4:
- initializes `BC-Sentinel-install.log` at bootstrap startup;
- adds `Write-BCLog`, a non-critical safe logger;
- stdout/stderr capture for pytest and the application uses `Write-BCLog`;
- logging failures are intentionally ignored and can no longer abort setup or
  EXE generation;
- regression tests verify LogPath exists before the build/test path.

Security-engine behavior is unchanged.
