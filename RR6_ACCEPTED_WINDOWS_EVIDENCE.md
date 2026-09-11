# BC Sentinel v0.11.0-beta.3 — RR-6 Accepted Windows Evidence

## Status
**ACCEPTED / PASS**

Frozen tested checkpoint:

```text
checkpoint/v011-beta3-rr6-pass
e03482f4216c4cd20ede1e16d9a4c4b5b07668bc
```

This checkpoint is immutable. It is the exact commit invoked by the successful Windows bootstrap run.

## Test environment
- Windows 11 (`10.0.26200`)
- Python `3.12.10`
- PyInstaller `6.22.2`
- non-elevated PowerShell
- FULL local BC Sentinel tree
- certification target remains read-only

## Regression gate
RR-0 through RR-6 regression suite:

```text
134 passed in 2.50s
```

RR-0, RR-1, RR-2, RR-3, RR-4A, RR-4B, RR-5 and RR-6 deterministic acceptance gates all returned PASS.

## RR-6 deterministic outcomes
The deterministic RR-6 acceptance proved all required outcome classes:

```text
clean_outcome        = RECOVERED
not_recovered_outcome = NOT_RECOVERED
refused_outcome      = INDETERMINATE_REFUSED
tamper_outcome       = INDETERMINATE_REFUSED
```

Safety properties remained enforced:
- no target execution;
- no registry write;
- no boot write;
- no file delete;
- no repair execution in RR-6;
- no automatic destructive action;
- reimage/format is not suppressed when integrity cannot be demonstrated.

## Portable build gate
PyInstaller onedir build completed successfully on the first isolated build attempt.

Portable binary:

```text
BC-Sentinel-Rescue-Certification-Portable.exe
SHA256=21b6532b6cc7b92515c6c1340897978351346efa547c3017f4484f68e1f8ca2f
```

Build result:

```text
RR6 BUILD ATTEMPT=1 RESULT=PASS exit_code=0
BC SENTINEL RR6 CERTIFICATION BUILD - PASS
```

## Built-binary live Windows gate
Synthetic offline Windows target fingerprint:

```text
058f3ecc78d9a6ab4034a4ceba739fbac105ce576ed2629ead1b6813568f29be
```

### Clean evidence
Result:

```text
outcome=RECOVERED
certified_recovered=true
report_sha256=1fdee7f95d4591ca0e2e35ef6c8f823efbf5e0e99859df0a41ba39f94f1212d3
```

### Unresolved deterministic IOC
Result:

```text
outcome=NOT_RECOVERED
certified_recovered=false
not_recovered_reasons=[unresolved_deterministic_ioc]
```

### Incomplete / truncated evidence
Result:

```text
outcome=INDETERMINATE_REFUSED
certified_recovered=false
refusal_reasons=[rr3_scan_truncated]
```

## Integrity and safety confirmation
The successful live gate additionally proved:
- offline target unchanged;
- no Windows service registered by the certification binary;
- B2 Protection Service / realtime / EDR protected sources unchanged;
- certification remained evidence-based and read-only.

Final Windows gates:

```text
RR6 LIVE: clean RECOVERED PASS | unresolved IOC NOT_RECOVERED PASS | incomplete evidence REFUSED PASS | target unchanged | no service | B2 sources unchanged
BC SENTINEL v0.11.0-beta.3 RR-6 INTEGRITY CERTIFICATION - PASS
BC SENTINEL v0.11.0-beta.3 RR-6 BOOTSTRAP - PASS
```

## Acceptance conclusion
RR-6 satisfies the Beta3 closure condition. A machine may be declared `RECOVERED` only when all mandatory independent trust gates succeed. Positive unresolved high-confidence evidence produces `NOT_RECOVERED`. Missing, stale, incomplete or untrustworthy evidence produces `INDETERMINATE_REFUSED` rather than a false recovery claim.
