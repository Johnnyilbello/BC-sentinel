# BC Sentinel v0.11.0-beta.7 — B7-7 Windows Acceptance & Freeze

Status: **CLOSED / ACCEPTED**

Accepted code checkpoint:

```text
checkpoint/v011-beta7-b77-pass
4d57f749276c588782147d47078ef4c52d1adc51
```

Frozen predecessor:

```text
checkpoint/v011-beta7-b76-pass
1bd66f4f9e55313388e871e26c6a35d55a3dbb20
```

## Final acceptance evidence

- exact-head Windows CI run `34984650411`: PASS;
- local Windows acceptance: PASS;
- complete Beta5 + Beta6 + Beta7 deterministic regression: **422 passed, 36 warnings**;
- protected B2 state unchanged from Beta6: PASS;
- accepted Beta6 portable contract unchanged: PASS;
- accepted B7-0 through B7-6 foundations unchanged: PASS;
- B7-0 ledger remains conservative (`PLANNED=6`, `VERIFIED=0`);
- B7-6 campaign remains exactly `PARTIAL=3`, `GAP=3`, `VERIFIED=0`;
- B7-1/B7-2/B7-3/B7-5 deterministic/intelligence outputs preserved;
- B7-4 attack-chain remains synthetic, harmless and non-executing;
- B7-5 explanations remain evidence-bound and do not amplify confidence;
- final deterministic core digest: `dcd6a7ff975c2fbdce9549d4af630ab6c252acf26ca7b0c31e0c70e72db8ea4e`.

## Resource measurement

Observed local synthetic final pipeline:

- elapsed: `0.17224099999293685 s`;
- peak traced memory: `82653 bytes`;
- acceptance ceiling: `60 s` and `512 MiB`.

Resource values are excluded from the deterministic core digest.

## Safety contract at freeze

```text
automatic quarantine          = false
automatic repair              = false
automatic restore             = false
general Home execution        = false
DELETE                        = false
REPAIR                        = false
TERMINATE_PROCESS             = false
TRUST/ALLOWLIST mutation      = false
privileged/system mutation    = false
authority granted             = false
```

## Freeze rule

`checkpoint/v011-beta7-b77-pass` points to the exact code SHA accepted by both CI and local Windows acceptance. It must never be moved. Any documentation-only commits after this freeze are not part of the accepted executable checkpoint.

Beta7 is complete.
