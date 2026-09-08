# BC Sentinel v0.9.0-rc.1 — Native Windows Acceptance

## Superseding status — 8 September 2026

The older 7 September acceptance narrative for a 482-test RC artifact is retained only as historical context and **does not certify the current checkpoint-4 build**.

Current checkpoint-4 evidence:

- 578 tests passed, zero skipped;
- local RC acceptance passed;
- fresh Protection Service/Broker builds passed;
- native Authenticode foundation sub-gate passed;
- compileall and artifact integrity passed.

The following current-build native gates remain **OPEN / DEFERRED**:

1. elevated Windows foundation / ETW;
2. live Protection Service acceptance;
3. standard-user → UAC broker path;
4. transactional upgrade acceptance on the checkpoint-4 build;
5. same-version repair acceptance on the checkpoint-4 build;
6. reboot-persistence acceptance;
7. aggregate native benchmarking/freeze evidence.

Development is allowed to proceed to v0.10 by explicit decision, but these gates must remain visible and must not be rewritten as PASS. A historical installed-service result cannot substitute for acceptance of the current artifact.
