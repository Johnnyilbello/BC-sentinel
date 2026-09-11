# BC Sentinel — Roadmap v0.11.0-beta.6 Rescue Technician UX / Field Operations

## Frozen predecessor
Beta6 starts only from the accepted Beta5 final checkpoint:

```text
checkpoint/v011-beta5-b57-pass
16676519e3e43d9916e5e4281813bd75c9eebd7e
```

The accepted Beta3/Beta4/Beta5 rescue engines and checkpoints are immutable predecessors. Beta6 is a technician UX/orchestration layer and must not weaken trust precedence, refusal semantics, rollback requirements, certification outcomes, protected B2 sources or accepted performance/safety thresholds.

## Accepted Beta6 checkpoints

### B6-0 — Technician UX Foundation — ACCEPTED / FROZEN

```text
checkpoint/v011-beta6-b60-pass
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

Authoritative Windows acceptance on 2026-09-11:
- accepted B5-7 predecessor gate PASS;
- 16 B6-0 tests PASS;
- Qt offscreen shell PASS;
- exact frozen Beta5 command surface preserved;
- startup dispatch disabled;
- workflow actions disabled at foundation startup;
- no destructive authority, service or B2 source change.

B6-0 is immutable. B6-1 and later milestones extend it through new layers rather than rewriting the accepted foundation.

## Current milestone
**B6-1 — Target Discovery & Selection UX**

## Goal
Turn the accepted Beta5 Portable Technician Release into a field-usable graphical technician workflow without changing the rescue trust model.

The UI must make safe behavior easier and unsafe assumptions harder. It must explain current state, provenance, refusals, incomplete evidence and next operator action in plain language while preserving the exact underlying engine outcome.

## Non-negotiable safety contract
- no new automatic repair authority;
- no automatic quarantine;
- no automatic restore;
- no unlock/mount mutation;
- no format/reimage execution;
- no registry/boot write authority;
- no target execution;
- `repair-execute` remains absent from the technician UI;
- RR-6 outcomes remain authoritative;
- `INDETERMINATE_REFUSED` is never displayed or transformed as success;
- B5-4 advisory states remain advisory only;
- interrupted mutation-capable stages still require fresh confirmation;
- all generated evidence remains outside the target;
- symlink/reparse/path safety remains fail-closed;
- no network/cloud dependency is required for rescue operation;
- existing B2 protected sources remain unchanged.

## UI principles
1. **Status before action** — always show what is known, unknown, refused or incomplete before offering the next step.
2. **One primary action** — each screen exposes one safe primary action and secondary diagnostics separately.
3. **Evidence visibility** — hashes, provenance, target fingerprint and refusal reasons are inspectable, never hidden.
4. **No fake success** — partial, degraded, refused and advisory states use distinct language and cannot render as recovered.
5. **Technician-readable** — plain-language summary first, technical detail expandable.
6. **Low-spec friendly** — UI remains responsive on damaged/slow hosts; long operations never block the event loop.
7. **Keyboard/accessibility** — predictable focus order, scalable text and semantic status labels.
8. **Portable-first** — no installer/service/driver required for the technician UI.

## Milestones

### B6-0 — Technician UX Foundation ✅ FROZEN
Create the read-only UI contract and application shell.

Acceptance:
- PySide6 shell starts without touching target or rescue state;
- exact Beta5 command inventory is represented as capability metadata;
- destructive/forbidden commands remain absent;
- state model distinguishes `IDLE`, `READY`, `RUNNING`, `REVIEW`, `REFUSED`, `ERROR`;
- target/evidence/session fields are explicit and initially empty;
- no automatic command dispatch at startup;
- no service/driver/install/network/cloud dependency;
- deterministic UI-model tests;
- protected B2 sources unchanged.

### B6-1 — Target Discovery & Selection UX 🟡 CURRENT
Wrap accepted B5-0 discovery in a guided target picker.

Acceptance:
- live SystemDrive clearly marked unsupported as offline target;
- READY/LOCKED/ACCESS_DENIED/INCOMPLETE/UNSUPPORTED/ERROR represented distinctly;
- no unlock or mount action offered;
- fingerprint and source visible for READY targets;
- only a READY target with valid RR-6 fingerprint can become selected;
- discovery and target selection require explicit operator action;
- startup performs no target discovery or selection;
- controlled target fixtures remain byte-identical;
- protected B2 sources unchanged.

### B6-2 — Guided Session Workflow
Guide plan → scan → health/stress → resume/decision while preserving exact engine outcomes.

Acceptance:
- no hidden stage execution;
- progress/cancellation for read-only stages;
- mutation-capable handoff never auto-resumes;
- session/correlation IDs visible;
- crash/resume state surfaced from B5-3.

### B6-3 — Evidence / Report Workspace
Technician viewer for trusted/untrusted evidence, hashes, decision and B5-5 reports.

Acceptance:
- trust state visually distinct;
- report verification can be run independently;
- unresolved risks remain visible;
- export/package does not imply recovery.

### B6-4 — Portable / USB Field Mode
Package the GUI for removable-media technician use.

Acceptance:
- onedir portable build;
- no installer/service/driver;
- workspace/evidence location chosen outside target;
- removable-media path changes handled safely;
- integrity manifest and executable SHA-256.

### B6-5 — Safety Guardrails & Operator Confirmations
Harden dangerous-transition UX without adding new authority.

Acceptance:
- repair handoff shows exact plan hash + confirmation token;
- fresh confirmation after interrupted mutation-capable stage;
- no destructive action mapped to a single accidental click;
- refused/incomplete states cannot expose optimistic next actions.

### B6-6 — Accessibility / Low-Spec / Responsive Hardening
Make field UX robust on slow or constrained PCs.

Acceptance:
- background workers for long operations;
- bounded log rendering;
- no UI freeze during accepted stress fixture;
- 100%/125%/150% scale checks;
- keyboard-only workflow;
- long paths/messages do not overflow or truncate critical information.

### B6-7 — Portable Technician GUI Release
Final built-artifact acceptance.

Acceptance:
- complete Beta5 predecessor regression remains green;
- all Beta6 deterministic/UI-model tests green;
- PyInstaller GUI artifact builds on Windows;
- built GUI starts and shows exact safety/capability contract;
- real accepted engine commands dispatch only after explicit operator action;
- target byte-identical in read-only workflow acceptance;
- no service/driver/install/network/cloud requirement;
- protected B2 sources unchanged;
- final checkpoint freeze.

## Logging / observability
Critical UI/worker failures must show enough information to diagnose immediately:
- exact UI stage and underlying engine command;
- normalized target/workspace/evidence path;
- session/correlation ID where available;
- subprocess PID/exit code;
- start/end/elapsed timing;
- engine state/outcome;
- output/evidence hash where relevant;
- refusal/error class and reason;
- bounded stdout/stderr tail.

Production UI logs must remain structured and bounded. Acceptance logs may be verbose.

## Codex reasoning policy
- **Extra High**: trust boundaries, operator-confirmation semantics, worker/subprocess cancellation, resume behavior and final built-artifact acceptance.
- **High**: PySide6 implementation, state model, tests, packaging, accessibility and observability after the safety contract is fixed.
- milestone-by-milestone only; no broad rewrite of frozen rescue engines.
