# BC Sentinel v0.11.0-beta.6 — B6-7 Local Windows Portable GUI Acceptance

Date: **2026-09-15**

Milestone: **B6-7 — Portable Technician GUI Release**

Accepted branch:

```text
feature/v011-beta6-b67-portable-gui
```

Accepted code commit:

```text
eb08758a304eb838d08af890ef9c4786264afbc0
```

Frozen checkpoint created from the exact accepted commit:

```text
checkpoint/v011-beta6-b67-pass
```

## Acceptance command

```powershell
git pull --ff-only origin feature/v011-beta6-b67-portable-gui
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA6-B67.ps1" -ConfirmPortableGuiAcceptance -OpenArtifactUI
```

## Local Windows result

```text
BC SENTINEL v0.11.0-beta.6 B6-7 PORTABLE TECHNICIAN GUI RELEASE - PASS
```

### Deterministic predecessor + B6-7 gate

```text
Beta5 test files: 9
Beta6 test files: 27
344 passed, 36 warnings in 11.55s
Deterministic predecessor + B6-7 gate: PASS
```

The warnings were existing PySide6 signal-disconnect runtime warnings and did not fail the deterministic gate.

### PyInstaller built artifact

```text
Python: 3.12.10
PyInstaller: 6.22.2
Build mode: onedir
Windowed: true
Installer: false
Service: false
Driver: false
Build attempt: 1/3 PASS
File count: 214
Total bytes: 124067173
```

Built executable:

```text
BC-Sentinel-Beta6-Portable.exe
SHA-256: 7a4e678c18e980adc77b1380923a041c9a8d71b242fd2837a74c85670f51686b
```

### Copied-artifact acceptance

The artifact was copied outside the build directory and accepted from the copied location.

Verified checks:

```text
build_commit_matches = true
contract_process_exit_zero = true
gui_offscreen_smoke_exit_zero = true
portable_copy_exe_hash_identical = true
portable_copy_integrity = true
repo_independent_working_directory = true
runtime_contract_passed = true
runtime_contract_written = true
runtime_explicit_operator_action = true
runtime_no_automatic_quarantine = true
runtime_no_automatic_repair = true
runtime_no_automatic_restore = true
runtime_no_general_execution = true
runtime_no_installer_service_driver = true
runtime_no_network_cloud_requirement = true
runtime_profile_exact = true
source_artifact_integrity = true
target_byte_identical = true
target_file_count_identical = true
windowed_onedir_manifest = true
```

### Safety contract preserved

The accepted artifact reports:

```text
general_home_execution_authorized = false
automatic_quarantine = false
automatic_restore = false
automatic_repair = false
delete_authorized = false
repair_authorized = false
terminate_process_authorized = false
trust_allowlist_mutation_authorized = false
privileged_system_file_mutation_authorized = false
installer_required = false
service_install = false
driver_install = false
network_required = false
cloud_required = false
startup_command_dispatch = false
explicit_operator_action_required = true
persistent_restore_after_restart = true
```

### Protected B2 freeze

The launcher compared protected B2 state against the accepted B6-5.9 source checkpoint:

```text
checkpoint/v011-beta6-b659-pass
72c18bbdf1c50c633343750ead0f2467d8705e12
```

Frozen protected state remained unchanged:

```text
sentinel/protection_service_core.py = ABSENT (frozen)
sentinel/realtime.py = ABSENT (frozen)
sentinel/edr.py = unchanged
sentinel/edr_service_bridge.py = unchanged
```

No BC Sentinel portable Windows service was registered.

### Real GUI artifact acceptance

For visual acceptance, the previously accepted pinned historical Smart Scan runtime was attached. The **compiled PyInstaller executable itself** was opened, inspected, and closed normally:

```text
Pinned historical Smart Scan runtime attached for visual acceptance.
Built GUI opened and closed normally: PASS
```

## Conclusion

B6-7 is **LOCAL WINDOWS ACCEPTED / CLOSED**.

The exact accepted source state is frozen at:

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

This closes the Beta6 final built-artifact acceptance milestone without adding broader remediation authority.
