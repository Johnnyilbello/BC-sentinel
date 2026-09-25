# Windows test installer

Use the compiled `BC-Sentinel-Setup-v0.13.0-b133.exe`, not the source ZIP,
for installation on a Windows x64 test machine or Windows Sandbox. Python,
Git and winget are not required. Install for the current user and launch
BC Sentinel from the Start menu. The engineering build is unsigned.

Uninstall previous test builds first, or use a fresh Sandbox session. Old
DLLs not listed in a new payload manifest may survive an in-place install.
Closing Sandbox discards its data. Do not disable Windows security controls
to install a test build.

## QtWidgets startup repair, 2026-09-23

The initial package failed with `DLL load failed while importing QtWidgets`.
Dependency analysis selected Poppler's `icuuc.dll` from the builder's PATH;
Qt6Core imports unsuffixed ICU exports (including `ucnv_open`) which this
foreign DLL does not export. Source Python succeeded while the frozen UI failed.

`tools/windows_packaging.py` now isolates PyInstaller's environment from
unrelated applications and Qt/Python path overrides. The installer build runs
the actual frozen `--smoke` UI before producing a distributable installer;
the contract-only `--self-check` was insufficient to catch this defect.

Accepted repair source: `a3ca97da1e561434272bd623887917a8a1e990d2`.
Local regression: 1498 passed, 41 existing warnings.
Windows CI: https://github.com/Johnnyilbello/BC-sentinel/actions/runs/35794872653

Local packaged checks passed: install, self-check, health, UI smoke, diagnostic
export, uninstall. Runtime checks used a PATH with only Windows directories.
This is not an independent clean-VM or the friend's-machine acceptance.

Installer SHA256:
`06a0d31155ff82979413234828b3407bfbdaa77ee4cf46b613a3dfbfcf27ed82`.
The existing installer filename/version remains 0.13.0-b133; source identity
is bound by the build evidence, not inferred from this historical filename.
