# BC Sentinel v0.11.0-beta.3 — RR-6 Integrity Verification & Recovery Certification

## Purpose
RR-6 is the final Rescue & Recovery Beta3 milestone. It decides whether the available evidence is strong enough to call an offline/recovered Windows installation `RECOVERED`.

RR-6 is deliberately fail-closed. A clean-looking scan alone is insufficient.

## Outcomes
- `RECOVERED`: every mandatory independent trust gate passes.
- `NOT_RECOVERED`: positive evidence proves an unresolved high-confidence security/integrity problem.
- `INDETERMINATE_REFUSED`: required proof is missing, stale, tampered, incomplete or unverifiable.

`INDETERMINATE_REFUSED` is not a success and must never be presented as recovered.

## Mandatory trust families
1. **RR-3 post-recovery scan evidence**
   - expected RR-3 profile;
   - zero scan errors;
   - scan not truncated;
   - no unresolved deterministic IOC;
   - no unresolved YARA match;
   - required offline registry-hive metadata present and consistent with the current target.
2. **Critical-system-file integrity baseline**
   - target fingerprint matches;
   - mandatory critical paths are present;
   - current SHA-256 equals the trusted baseline SHA-256.
3. **Registry-hive integrity evidence**
   - SYSTEM and SOFTWARE evidence required;
   - evidence hashes must still match the current offline target.
4. **RR-4 transaction evidence when repairs occurred**
   - transaction evidence is mandatory when provenance says repairs occurred;
   - only trusted terminal states are accepted;
   - current file hashes must match the state recorded by the transaction.
5. **Evidence provenance**
   - explicitly approved provenance schema;
   - target fingerprint binding;
   - evidence path binding;
   - SHA-256 binding for scan/baseline/repair evidence.

## Target fingerprint
The first checkpoint uses a content-derived fingerprint based on mandatory offline Windows identity/integrity markers:
- `Windows/System32/ntoskrnl.exe`
- `Windows/System32/config/SYSTEM`
- `Windows/System32/config/SOFTWARE`

The fingerprint does not depend on the drive letter or mount path.

## Safety boundary
RR-6 is read-only against the offline target:
- no target execution;
- no DLL loading from target;
- no shell execution;
- no registry write;
- no boot/BCD/firmware write;
- no file delete;
- no quarantine execution;
- no repair execution;
- no process kill or host isolation;
- no automatic destructive action;
- no mandatory network/cloud dependency.

The certification report explicitly keeps formatting/reimaging available when trust cannot be demonstrated.

## Certification report
`rr6-certification-report.json` contains:
- profile/schema;
- session/correlation IDs;
- target fingerprint;
- outcome and certification boolean;
- exact refusal / not-recovered reasons;
- per-family checks;
- SHA-256 of all supplied evidence;
- safety state;
- report SHA-256;
- evidence-based recovery statement.

`rr6-audit.jsonl` records certification start/completion with exact reason and report hash.

## Acceptance matrix
The milestone does not pass by testing only the happy path.

Required built-binary Windows cases:
1. complete coherent evidence → `RECOVERED`;
2. unresolved deterministic IOC → `NOT_RECOVERED`;
3. truncated/incomplete evidence → `INDETERMINATE_REFUSED`;
4. target remains byte-identical in every case;
5. no Windows service is installed;
6. B2 protected service/realtime/EDR sources remain byte-identical.

Deterministic tests additionally cover YARA findings, provenance tampering, target-fingerprint mismatch, critical-file mismatch, registry-hive mismatch and repair-transaction state validation.

## Important limitation
RR-6 certification is an evidence decision, not a guarantee that unknown malware can never exist. `RECOVERED` means all mandatory evidence available to this Rescue checkpoint is complete, internally consistent and free of unresolved high-confidence findings. When that proof is unavailable, the engine refuses certification.

## Beta3 closure
Beta3 may close only after the deterministic regressions, the built portable executable and all three outcome paths pass on the FULL Windows tree. Only then may `checkpoint/v011-beta3-rr6-pass` be created.
