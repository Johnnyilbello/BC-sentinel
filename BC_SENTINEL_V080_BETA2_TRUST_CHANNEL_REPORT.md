# BC Sentinel v0.8.0-beta.2 — Trust Channel Security Report

## Goal

Harden the v0.8 threat-content supply chain so signing keys can rotate/revoke safely, reputation can be distributed as signed advisory data, interrupted activation can recover consistently, and future remote retrieval can be added without giving the network channel authority to activate content.

## Trust hierarchy

```text
Pinned Threat Root Key
        ↓ verifies
Root-signed Threat Keyset
        ↓ authorizes/revokes
Threat Content Keys
        ↓ verify
IOC / YARA / Reputation / Advisory Behavior Packages
```

The root key never signs ordinary threat content directly. Content-key changes require a monotonically increasing root-signed keyset.

## Revocation model

A revoked key is rejected for new validation, staging and activation. Existing already-committed content is not destructively deleted simply because its signer was later revoked; status can expose signer conflict until replacement content is installed. A last-known-good package signed by a revoked key is not treated as a generally valid downgrade path.

## Signed reputation

The new reputation component supports bounded domain/network indicators with:

- malicious/suspicious status;
- confidence 1–100;
- label/provenance;
- expiry bounded by the parent signed package.

It affects explainable risk scoring only. It is intentionally not equivalent to a signed IOC denylist and cannot independently create a firewall rule or file quarantine.

## Activation crash recovery

Before content publication, the manager writes an HMAC-authenticated activation journal containing the previous committed reference and target reference. On restart:

- if state already references the target, the commit is confirmed and the journal is cleared;
- otherwise the previously committed package content is republished and the partial activation is rolled back.

The package high-water state is only committed together with the authenticated state update.

## Secure retrieval foundation

Remote retrieval is deliberately separate from verification/staging/activation. The retriever requires:

- HTTPS;
- TCP/443;
- exact host allowlist;
- configured SHA-256 certificate pin;
- no redirects;
- no URL credentials;
- bounded body size (256 KiB);
- optional expected SHA-256 content digest.

The retriever has no activation API and reports `auto_stage=false`, `auto_activate=false`, `cloud_required=false`.

## Remaining work

- native Windows acceptance for v0.8.0-beta.2;
- production key-rotation operational runbook and offline signing process;
- remote manifest/index format and controlled retrieval scheduling;
- publisher key revocation/rotation for application releases;
- broader fault injection around filesystem/power-loss boundaries;
- large signed-reputation performance benchmarks.
