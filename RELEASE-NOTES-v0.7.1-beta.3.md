# BC Sentinel v0.7.1-beta.3 — Signed IOC, Reversible Containment & Security Center Inbox

## Scope

This release layers signed local threat intelligence, bounded network containment and a persistent threat-decision inbox on top of the native-Windows-accepted v0.7.1-beta.2 foundation. The accepted BLOCK-only Windows Firewall boundary, explicit UAC/service authorization model and manual-only permanent deletion policy remain unchanged.

## Signed IOC foundation

- IOC bundles use canonical JSON plus Ed25519 signatures.
- BC Sentinel ships only the pinned public verification key; no private signing key is packaged.
- Bundle sequence numbers are anti-rollback protected and same-sequence/different-payload reuse is rejected.
- Bundles have issued/expiry validation and a maximum of 1,000 entries.
- Supported indicators: SHA-256, bounded IPv4/IPv6 networks and domains.
- The shipped acceptance bundle is harmless: canonical EICAR test SHA-256 plus TEST-NET `192.0.2.240`.
- Installing a signed IOC bundle alone does not create firewall rules.

## Scanner / Network Intelligence

- Active signed SHA-256 evidence is added as an explicit deterministic scoring signal.
- An old local hash allowlist cannot silently suppress a newly active signed known-bad IOC; the user must make a fresh decision.
- Signed endpoint/network IOC matches are exposed by Network Intelligence as `source=signed_ioc` and malicious/high-confidence evidence.

## Reversible containment leases

- Lease creates only a BC Sentinel-managed outbound BLOCK rule.
- Explicit privileged approval is required.
- TTL is bounded to 60 seconds–24 hours.
- Qualification requires an active signed IOC for the target or a verified incident score >=70.
- Expiry automatically releases the exact approved lease; explicit operator release is also supported.
- Release never mutates unrelated Windows/third-party firewall rules.
- Create/release/import remain behind the Protection Service rate-limited privileged boundary.

## Security Center Inbox

- HIGH/CRITICAL detections are persisted by the Protection Service when it owns realtime protection.
- Unresolved detections remain visible after the transient popup is closed.
- `Cronologia → Security Center Inbox → Gestisci minaccia` reviews the pending item.
- Before applying a decision, BC Sentinel rescans/revalidates the exact SHA-256. Missing or replaced files are marked accordingly rather than applying a stale decision to different content.
- `Mantieni questa volta` and `Consenti hash` also synchronize the decision state with the Protection Service.
- Existing quarantine and permanent-delete identity protections remain in force.

## Performance / COM hardening

- Scanner profiling now reports phase costs for hash identity, content read, YARA, PE parsing, reputation and total time.
- Small files already read fully into memory are scanned by YARA from the same bytes, removing an avoidable second filesystem read without skipping deterministic reinspection.
- Windows Firewall COM rule enumeration is materialized inside the COM apartment and proxies are cleared before apartment teardown.
- The native Windows drift acceptance is the release gate for proving whether the previous pywin32 `IUnknown` release warning is fully eliminated; this release does not claim that outcome before native evidence.

## Acceptance targets

New beta.3 tools:

- `python -m tools.ioc_acceptance`
- `python -m tools.containment_lease_acceptance`
- existing `tools.firewall_drift_acceptance`, `tools.threat_decision_acceptance` and aggregate `tools.windows_acceptance --service-live` remain release gates.

The safe IOC acceptance verifies signature/tamper rejection, installs sequence 1, confirms both harmless indicators and proves IOC import leaves the firewall baseline unchanged. The containment acceptance creates a temporary TEST-NET lease from the signed IOC, observes the exact BC-owned rule, releases it and requires baseline restoration.

## Development gate before packaging

- 349 tests passed; 1 Windows-only test skipped in the development environment.
- `compileall` PASS.
- Signed IOC local acceptance PASS.
- Threat Decision harmless regression PASS.
- Local 2,000-file diagnostic run: warm/cold speedup 1.231x with 1,980/2,000 hash-cache hits after removing per-file IOC SQLite lookups and merging duplicate bounded content reads. Native Windows benchmark remains the authoritative performance result.
