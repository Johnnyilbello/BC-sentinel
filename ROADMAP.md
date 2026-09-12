# BC Sentinel — Product, Detection & Innovation Roadmap

BC Sentinel is evolving into a unified Windows security and recovery platform designed to be understandable by a normal user while remaining fully inspectable by an expert.

## Current source of truth

Latest Windows-accepted stable checkpoint:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

`B6-0` remains frozen. Development beyond it stays on feature branches until the corresponding Windows acceptance gate passes.

The detailed historical milestone documents and git history remain the source of record for previously accepted v0.3–v0.11, Rescue RR, Beta4 and Beta5 work. This roadmap now defines the forward product direction from the accepted Beta6 baseline.

---

# Product principle — one Home, complete Advanced details

BC Sentinel will **not** split into separate Home and Technician products.

There is one primary experience:

```text
HOME
```

The default layer explains:

- what is happening;
- how serious it is;
- what BC Sentinel recommends;
- what the user can safely do now.

Every important area also exposes:

```text
Advanced details
```

Advanced details must retain the complete technical evidence available, including where applicable:

- full paths;
- SHA-256 and other identifiers;
- signer / Authenticode state;
- PID / PPID and process tree;
- command/script context;
- YARA / PE / static evidence;
- behavioral evidence;
- persistence evidence;
- registry/service/task context;
- network/DNS/domain context;
- incident timeline;
- confidence and severity;
- evidence IDs;
- action and rollback journal;
- disk/partition/filesystem state in Rescue.

The product therefore has **two levels of information, not two operating modes**.

---

# Stable safety contract

The accepted B6-0 trust model remains authoritative until a future milestone explicitly proves and gates a safer capability.

```text
automatic rescue dispatch      = false
automatic repair               = false
automatic quarantine           = false
repair-execute exposed         = false
unlock exposed                 = false
mount-write exposed            = false
format execution               = false
reimage execution              = false
registry/boot write authority  = false
target execution               = false
```

RR-6 recovery outcomes remain authoritative:

```text
RECOVERED
NOT_RECOVERED
INDETERMINATE_REFUSED
```

Refusal or uncertainty must never be converted into success.

Increased autonomy must be earned through measurable detection quality, confidence gates, reversibility, acceptance testing and explicit authority boundaries.

---

# Accepted foundation — summary

The accepted codebase already contains or has validated foundations for:

- realtime and on-demand scanning;
- SHA-256, YARA and PE inspection;
- ransomware and behavior shields;
- local reputation and signed threat intelligence;
- Windows Protection Service and privileged action broker;
- ETW process/file/network attribution;
- firewall controls and reversible containment foundations;
- Web Protection, anti-phishing and scam detection;
- antispyware and persistence analysis;
- EDR telemetry, process ancestry and incident correlation;
- reversible remediation foundations;
- encrypted quarantine workflows;
- portable/offline Rescue & Recovery;
- target discovery and hostile-system assessment;
- crash-safe session journal/resume;
- safe data rescue;
- integrity verification and recovery certification;
- portable Technician Release;
- Beta6 PySide6 UX foundation.

Historical milestone documents remain authoritative for their individual acceptance criteria and safety invariants.

---

# Beta6 — Unified Home UX

## B6-0 — Technician UX Foundation ✅ STABLE

Accepted PySide6 foundation over the frozen Beta5 Portable Technician backend.

Acceptance status: Windows gate passed.

## B6-1 — Target Discovery & Selection UX — NEXT

**Goal:** make target discovery understandable to any user without losing expert evidence.

Required outcomes:

- automatic discovery of disks, volumes, Windows installations and supported Rescue targets;
- clear human-readable target cards;
- recommendation of the most likely Windows system target;
- visible warnings for ambiguity, encryption, unsupported state or unsafe selection;
- read-only-first target validation;
- no target code execution;
- no new destructive authority;
- `Advanced details` for physical disk ID, partition table, volume/filesystem, mount state, encryption/BitLocker state, discovery confidence and evidence metadata;
- deterministic tests for ambiguous and damaged targets;
- Windows acceptance gate before stabilization.

## B6-2 — Home / Security Overview

Create the main everyday BC Sentinel surface:

- overall protection state;
- realtime protection state;
- web protection;
- ransomware protection;
- firewall/network protection;
- privacy status;
- Rescue readiness;
- recent incidents;
- unresolved risks;
- primary `Scan PC` action;
- one clear recommended action when intervention is required;
- Advanced details available without changing modes.

## B6-3 — One-Click Smart Scan

Unify existing scanners behind a simple action while retaining technical visibility.

BC Sentinel should choose appropriate scan depth using system state, scope, telemetry and risk instead of requiring the user to understand scanner internals.

The user sees the result and recommendation; Advanced details exposes what was scanned, why, which engines/signals participated and what evidence was produced.

## B6-4 — Threat Cards + Advanced Details

Every relevant detection follows a two-level contract.

### Default card

```text
What happened?
How serious is it?
What does BC Sentinel recommend?
Is the recommended action reversible?
```

### Advanced details

Expose the full evidence chain and reasoning available.

No important technical evidence may be removed merely to simplify the default UI.

## B6-5 — Guided Resolution

Create a unified safe response flow:

```text
Detect
-> Explain
-> Contain
-> Repair
-> Verify
-> Report
```

High-impact or irreversible actions remain gated. Unsupported or ambiguous remediation remains report-only.

## B6-6 — Rescue for Everyone

Expose the accepted Rescue stack as a guided recovery experience understandable to a non-technical user.

The user should not need to understand partitions, hives, boot state or evidence chains to start a safe analysis. Those details remain fully available under Advanced details.

## B6-7 — Advanced Details Everywhere

Apply the same technical drill-down model across:

- scans;
- detections;
- EDR incidents;
- ransomware;
- Web Protection;
- firewall/network;
- persistence;
- remediation;
- Rescue;
- reports;
- future innovation features.

## B6-8 — History, Evidence & Reports

Unify:

- incidents;
- evidence;
- actions;
- containment state;
- remediation state;
- rollback state;
- Rescue sessions;
- verification results;
- final reports.

The history must be understandable at user level and auditable at technical level.

## B6-9 — Tray, Notifications, Onboarding & Settings

Finish the daily-use desktop experience:

- tray integration;
- low-noise native notifications;
- onboarding;
- accessibility;
- safe defaults;
- clear protection controls;
- startup behavior;
- understandable privacy/security settings.

## B6-10 — Consumer + Expert Acceptance Gate

Validate that the same product can be used safely by a non-technical user while remaining trustworthy and inspectable for an expert.

Acceptance must include usability, false-positive handling, accessibility, performance, regression and safety testing.

---

# Continuous Program A — Detection & Attack Coverage

**Status: PERMANENT — applies to every future milestone and release.**

BC Sentinel must never treat the existence of a feature as proof that an attack is covered.

The engineering target is to maximize measurable ability to:

```text
Detect
Correlate
Interrupt
Explain
Recover
Verify
```

across known, unknown, behavioral, fileless, multi-stage and offline attack paths.

BC Sentinel must not claim impossible 100% malware or attack detection. Gaps must be measured and turned into engineering work.

## Coverage domains

The program must progressively validate at least:

- malicious files and payloads;
- unknown / low-prevalence binaries;
- process abuse;
- memory/injection indicators where safely observable;
- PowerShell, CMD, WMI, JavaScript/VBS and script abuse;
- living-off-the-land behavior;
- persistence mechanisms;
- ransomware behavior;
- credential-access / credential-theft indicators;
- privilege-escalation indicators;
- defense evasion;
- security-control tampering;
- malicious/suspicious network behavior;
- command-and-control indicators;
- DNS/domain/web threats;
- phishing/scam chains;
- download -> execution chains;
- lateral-movement indicators where endpoint-visible;
- fileless and multi-stage attacks;
- boot/offline persistence detectable through Rescue;
- damaged or hostile Windows environments.

## Mandatory metrics

Each relevant campaign should measure, where applicable:

```text
Coverage
Precision
Detection speed
Correlation rate
Blocking / interruption rate
False-positive rate
Recovery success
Verification success
Explainability completeness
Evidence completeness
Resource cost
```

## MITRE ATT&CK mapping

Scenarios should be mapped to MITRE ATT&CK techniques/sub-techniques when useful.

ATT&CK coverage is an engineering map, not proof of overall product quality. A technique only counts as meaningfully covered when the detection/response behavior is reproducible and passes its acceptance criteria.

## Attack-chain testing

Testing must increasingly validate full chains, not only isolated events.

Example:

```text
browser
-> download
-> script interpreter
-> child process
-> persistence
-> outbound connection
-> destructive/encryption behavior
```

For a chain, BC Sentinel should record whether it:

1. observed the relevant signals;
2. detected suspicious/malicious behavior;
3. correlated the events into one incident;
4. identified likely root cause;
5. interrupted the harmful objective when safely possible;
6. preserved evidence;
7. recovered or rolled back supported damage;
8. verified the result.

## Coverage ledger

A machine-readable coverage ledger must be introduced and maintained.

Minimum fields:

```text
scenario_id
technique
subtechnique
scenario
detected
correlated
blocked
recovered
verified
false_positive_status
time_to_detection
time_to_interruption
evidence_quality
last_verified_build
platform/profile
notes
```

A failed or missing scenario becomes an explicit engineering gap.

## Release rule

No release may claim a protection capability unless the advertised behavior has current acceptance evidence on the target platform.

Regression coverage must preserve previously accepted detection behavior unless an intentional security decision explicitly changes it.

## Testing safety

Use harmless fixtures, simulations, controlled emulation, disposable VMs and controlled offline targets.

Do not deliberately expose an everyday workstation to uncontrolled live malware merely to increase a coverage number.

---

# Continuous Program B — BC Sentinel Innovation Program

**Status: PERMANENT — cross-cuts future protection, EDR, Rescue and UX work.**

BC Sentinel should not become only a conventional antivirus with additional modules. Innovation must improve how an attack is understood, predicted, interrupted, explained and recovered from.

## I1 — Sentinel Security Graph

Build a causal graph that links, when available:

```text
processes
files
scripts
registry
services
scheduled tasks
persistence
network/DNS/domains
identity/context
detections
containment actions
remediation actions
Rescue evidence
```

Goal: treat an attack as a connected incident rather than unrelated alerts.

The graph must preserve provenance, timestamps, confidence and evidence IDs.

## I2 — Confidence Gate

Every autonomous or recommended security action should be evaluated against:

```text
Confidence
Severity
Reversibility
Potential damage
Evidence strength
```

Temporary observation/containment may use a lower authority threshold than destructive or system-critical mutation.

High-impact irreversible actions require explicit stronger evidence and acceptance gates.

The Confidence Gate must be inspectable in Advanced details.

## I3 — Attack Prediction Engine

Use the evolving Security Graph and temporal evidence to estimate whether behavior is converging toward objectives such as:

- ransomware;
- persistence;
- credential theft;
- command-and-control;
- defense evasion;
- security-control tampering;
- destructive behavior.

Prediction must be evidence-driven, confidence-scored and measurable.

It must never be presented as certainty when the evidence is incomplete.

Primary objective: interrupt an attack **before** its damaging objective when confidence and safety permit.

## I4 — Reversible Self-Healing

Extend the existing reversible-remediation foundations.

Supported repair lifecycle:

```text
Detect
-> Understand
-> Contain
-> Snapshot / Journal
-> Repair
-> Verify
-> Roll back if verification fails
```

Where technically possible, preserve enough pre-action state to restore affected configuration or artifacts safely.

No broad destructive cleanup to manufacture a successful result.

## I5 — Rescue Continuity

Make a live incident portable into the Rescue environment.

If the running Windows instance can no longer be trusted, Rescue should continue the same incident instead of starting from zero.

Carry forward relevant evidence such as:

- incident ID;
- process tree;
- suspicious files and hashes;
- script/command context;
- persistence findings;
- registry/configuration changes;
- network/DNS/domain indicators;
- attack-chain hypothesis;
- containment/remediation actions already performed;
- evidence IDs;
- journal/rollback state.

Target flow:

```text
Live Protection
-> Detection / EDR
-> Rescue
-> Recovery
-> Verification
```

as one continuous incident lifecycle.

## I6 — Deception Mesh

Research and implement safe local deception signals such as canary resources and controlled decoys that legitimate software should not normally access or mutate.

A deception event is a signal, not an automatic malware verdict.

It must feed the Security Graph and Confidence Gate together with independent evidence.

## I7 — Adaptive Local Intelligence

Develop local intelligence capable of combining:

- static evidence;
- behavior;
- temporal sequence;
- graph relationships;
- local reputation/prevalence;
- signer/provenance;
- system context;
- historical incident context.

AI/ML output must remain:

- inspectable;
- confidence-scored;
- explainable enough to support a security decision;
- optional for core deterministic protection where feasible;
- subordinate to hard safety policy for privileged/destructive operations.

## I8 — Explainable Security

Every significant security decision should be answerable in two forms.

### User explanation

Example structure:

```text
BC Sentinel blocked this activity because a program launched a script interpreter,
created a persistence entry and contacted a previously unseen remote endpoint.
These events together strongly resemble a malicious persistence chain.
```

### Advanced explanation

Expose the underlying evidence, timeline, graph edges, confidence inputs, deterministic rules and actions.

The explanation must describe evidence, not invent certainty.

---

# Forward protection roadmap

The previously planned macro-areas remain valid, but all future work now inherits the Unified Home, Detection Coverage and Innovation requirements above.

## Dynamic Analysis / Sandbox

- isolated suspicious-file execution;
- pre/post filesystem, registry, process and network diff;
- behavioral evidence into the Security Graph;
- strict resource/time/network controls;
- no unknown-sample execution on the host OS.

## IDS/IPS & Credential Attack Protection

- network intrusion research and detection;
- brute-force/password-spray/credential-stuffing indicators;
- RDP/remote-service protection;
- adaptive containment only behind explicit safety gates;
- correlation with endpoint identity/process/network context.

## Privacy Protection & Safe Banking

- webcam/microphone monitoring where platform support is trustworthy;
- per-application privacy context;
- keylogger/injection indicators;
- protected-session research;
- privacy events integrated with the Security Graph.

## Identity Protection

- secure local credential/vault research;
- password health and reuse checks;
- TOTP/2FA support where appropriate;
- credential-access hardening;
- identity-risk evidence correlated with endpoint incidents.

## VPN & Untrusted-Network Protection

- tightly controlled VPN/secure-DNS integration or companion architecture;
- kill-switch research;
- untrusted-network policy;
- integration with firewall and incident context.

## Production Packaging

- signed Windows binaries;
- service/broker/UI packaging;
- secure installer upgrade/repair/uninstall;
- secure updater bootstrap;
- release provenance;
- reproducible release checks;
- compatibility and rollback runbooks.

---

# Rescue & Recovery — permanent cross-product track

The accepted Rescue & Recovery line remains a core BC Sentinel differentiator.

Goal: recover severely compromised Windows systems even when installed Windows is too slow, unstable or untrustworthy to install or normally execute BC Sentinel.

Formatting/reimaging remains the **last resort**, but BC Sentinel must never claim a trustworthy recovery when integrity cannot be demonstrated.

Future Rescue work inherits:

- read-only-first acquisition;
- evidence preservation;
- explicit repair plans;
- rollback/backup strategy;
- safe data rescue;
- integrity verification;
- fail-closed handling of ambiguous/locked/encrypted targets;
- Detection & Attack Coverage;
- Security Graph integration;
- Confidence Gate;
- Rescue Continuity.

---

# v1.0 release principle

BC Sentinel reaches production status only when every advertised capability has current native acceptance evidence and the product demonstrates:

- protected service lifecycle;
- secure updates;
- bounded false-positive rate;
- compatibility validation;
- measurable detection/attack coverage;
- deterministic safety boundaries;
- reversible remediation where advertised;
- trustworthy Rescue outcomes;
- usable Home experience;
- complete Advanced details for expert inspection;
- release provenance and rollback/runbooks.

---

# Long-term product objective

BC Sentinel should evolve toward a security system that can:

> understand an attack while it develops, correlate its evidence, estimate where it is heading, interrupt dangerous behavior when confidence and safety permit, repair reversible damage, verify the result, and continue the same incident through offline Rescue when the running operating system can no longer be trusted.

The default user experience may simply say:

```text
Your PC is protected.
```

The evidence behind that statement must remain measurable, explainable and available under **Advanced details**.
