# BC Sentinel v0.6.1-beta.2 — Windows ACL Bootstrap Fix Report

## Trigger
Native Windows install of v0.6.1-beta.1 reached the Program Files deployment but PowerShell failed to execute `BC-Sentinel-Protection.exe init-config` with `Accesso negato`.

## Root cause addressed
The installer removed inheritance and then recursively applied directory inheritance flags `(OI)(CI)` to the complete frozen onedir tree with `/T /C`. This mixed directory inheritance semantics with file ACL mutation and ignored per-item failures, creating a risk that child files become non-executable after inheritance removal.

## Fix
- Harden only the Program Files root with inheritable SYSTEM/Admin full control and Users read/execute.
- Reset descendants to inherited ACLs using `icacls <children> /reset /T /C`.
- Run `icacls /verify` before executing the deployed service.
- Check icacls exit codes instead of silently continuing.
- Apply the same root+inheritance strategy to ProgramData children.
- Self-repair a stranded prior `Program Files\BC Sentinel\Protection` tree before replacement, scoped only to BC Sentinel-owned files.
- On bootstrap execution failure, print the deployed EXE ACL and recent Windows Code Integrity events.
- No automatic disabling or bypass of Smart App Control/Application Control.

## Preserved hardening
The v0.6.1-beta.1 NTFS ChangeTime integrity-cache fix remains unchanged. Service/Named Pipe/authentication/detection architecture is unchanged.

## Development validation
- pytest: 232 passed
- compileall: PASS
