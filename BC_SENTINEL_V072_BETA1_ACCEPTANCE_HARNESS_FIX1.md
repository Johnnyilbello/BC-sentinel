# BC Sentinel v0.7.2-beta.1 — Native Acceptance Harness Fix1

## Scope

This harness-only fix removes host-antivirus dependence from two legacy v0.7.1-beta.3 scanner/IOC unit tests inherited by v0.7.2-beta.1.

## Native Windows failure diagnosed

Two tests wrote the canonical EICAR antivirus test payload to temporary `.com` files and then immediately reopened them through `StaticScanner`. On a protected Windows host, the file could be intercepted by the host security stack between creation and reopening, producing `OSError: [Errno 22] Invalid argument` before BC Sentinel scanner logic executed.

Affected tests:

- `test_beta3_signed_ioc_hash_overrides_old_local_hash_allowlist`
- `test_beta3_scanner_refreshes_ioc_map_immediately_on_database_revision`

## Fix

- Replaced on-disk EICAR content in those unit tests with a harmless synthetic byte fixture.
- Constructed an in-memory unit-level IOC SHA-256 entry matching that harmless fixture, preserving the exact scanner semantics under test: signed-IOC precedence over an old local hash allowlist and immediate IOC-map refresh on database revision.
- Kept the shipped Ed25519-signed IOC bundle, pinned public key, signature verification, tamper rejection and `tools.ioc_acceptance` unchanged.
- Added a regression guard so the legacy Beta3 scanner/IOC test file cannot reintroduce `write_bytes(EICAR_TEST_STRING)`.

## Security impact

Production scanner code is unchanged. Web Protection code is unchanged. IOC trust anchors and signed feed contents are unchanged. This is an acceptance-harness correction only.

## Regression

Local complete suite after Fix1:

```text
361 passed, 1 skipped
```

The single skip is the Windows-only PowerShell parser acceptance. Expected native Windows total remains:

```text
362 passed
```
