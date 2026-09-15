# B6-6 — Accessibility, low-spec and responsive hardening

Branch: `feature/v011-beta6-b66-accessibility-hardening`
Base: `checkpoint/v011-beta6-b659-pass` at
`72c18bbdf1c50c633343750ead0f2467d8705e12`, through the separately accepted
post-B6-5.9 product-polish commit.

## Scope

B6-6 hardens the read-only Rescue Technician shell. It does not make an engine
command available and does not alter the frozen Beta5 engine, source target,
quarantine controller, repair handoff, data-rescue operation, or any checkpoint.

| Requirement | Delivered evidence |
|---|---|
| Background work | `ReadOnlyFixtureWorker` runs an injected diagnostic fixture in a `QThread`; it has no engine lookup or dispatch path. |
| No UI freeze | The Qt test observes timer ticks while a fixture worker runs, then verifies the state returns to `REVIEW`. |
| Bounded diagnostics | `BoundedActivityLog` retains 160 entries and truncates a single message at 480 characters. |
| 100% / 125% / 150% | Offscreen checks at 10, 12 and 15 points retain the contract action, activity log and semantic labels. |
| Keyboard | Enter on the safety-contract button and `Alt+C` invoke the same inspected-contract path. |
| Responsive layout | Header and information cards switch from horizontal to vertical below 1100 pixels. Values wrap and remain selectable. |
| Long messages | Long paths are truncated only in the diagnostic tail; target/session/engine cards wrap and permit text selection. |

The activity log is an in-memory presentation tail. It is not an evidence store,
does not write to the target and does not change any engine state.

## Authority invariants

`validate_b66_accessibility_contract()` asserts all of the following remain
false: automatic command dispatch, repair, quarantine, restore, repair-execute
exposure and target execution. Existing workflow command buttons remain disabled.
The worker accepts a callable only from local UI instrumentation/tests; no button
or startup path creates one.

## Test and acceptance

`tests/test_v011_beta6_b66_accessibility_hardening.py` covers bounded logging,
wide/compact layout, 100%/125%/150% text scales, keyboard activation, controls'
semantic labels, disabled engine controls, worker responsiveness, and proof that
the worker dispatches no frozen-engine command.

Run the deterministic local gate from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST-V011-BETA6-B66.ps1
```

`-OpenUI` opens the Technician console only after the gate passes. The script
requires its temporary-root argument, when supplied, to be outside the repository
because B6-5 correctly forbids treating project-owned paths as user-file targets.

Windows CI is defined in `.github/workflows/b66-accessibility-hardening.yml`.
It runs the whole collectible Beta5/Beta6 regression set, including B6-5.9 and
the product-polish interaction tests, in Qt offscreen mode and uploads JUnit XML.
