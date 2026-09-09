# BC Sentinel v0.8.0-beta.3 — Engineering Report

## Scope

Beta 3 converts the Beta 2 HTTPS retrieval foundation into a controlled remote threat-content discovery channel without adding automatic activation or a cloud dependency.

## Trust chain

`Pinned Index Key -> Signed Threat Index -> HTTPS pinned retrieval -> envelope SHA-256/size -> content signing key lifecycle -> signed threat package -> cache -> explicit protected stage/activation`

The index and package signatures are independent. Compromise of a content signing key cannot authorize a forged remote index, while a valid index cannot bypass a revoked content key.

## Revocation operations

When the currently active package signer is later revoked, BC Sentinel reports `critical_replacement_required`. Existing verified content remains active so endpoint protection does not disappear abruptly. New content from the revoked key is rejected, a replacement is required, automatic destructive action remains disabled and the policy is explicitly fail-closed.

## Crash consistency

Activation now exposes fault-injection checkpoints across all publication phases. Acceptance recreates the manager after each injected crash and requires exactly one complete state: previous package or target package. A mixed IOC/YARA/reputation/state combination is a release failure.

## Remote channel safety

- HTTPS/TCP 443 only;
- exact host allowlist;
- peer certificate SHA-256 pin required;
- redirects and URL credentials forbidden;
- signed index required;
- package envelope SHA-256 and size required;
- content-addressed bounded cache;
- no auto-stage;
- no auto-activate;
- no arbitrary code execution;
- core protection remains offline-capable.
