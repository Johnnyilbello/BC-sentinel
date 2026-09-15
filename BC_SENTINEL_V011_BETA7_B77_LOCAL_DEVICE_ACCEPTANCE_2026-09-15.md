# BC Sentinel v0.11.0-beta.7 — B7-7 Local Windows Acceptance

Date: 2026-09-15

Accepted branch: `feature/v011-beta7-b77-final-acceptance`

Accepted code commit: `4d57f749276c588782147d47078ef4c52d1adc51`

Frozen predecessor: `checkpoint/v011-beta7-b76-pass` / `1bd66f4f9e55313388e871e26c6a35d55a3dbb20`

Final checkpoint created only after exact-head CI and local acceptance passed: `checkpoint/v011-beta7-b77-pass`.

## Local Windows acceptance results

- protected B2 state unchanged from Beta6: PASS;
- accepted Beta6 portable contract unchanged: PASS;
- accepted B7-0 through B7-6 foundations unchanged: PASS;
- compile gate: PASS;
- complete Beta5 + Beta6 + Beta7 deterministic regression: **422 passed, 36 warnings**;
- B7-0 Coverage Ledger self-check: PASS;
- B7-1 Security Graph self-check: PASS;
- B7-2 Incident Correlation self-check: PASS;
- B7-3 Confidence Gate self-check: PASS;
- B7-4 Attack-Chain Harness self-check: PASS;
- B7-5 Explainable Security self-check: PASS;
- B7-6 Coverage Expansion Campaign self-check: PASS;
- B7-7 final deterministic/resource/safety contract: PASS.

## Final accepted invariants

- base ledger: `PLANNED=6`, `VERIFIED=0`, unsupported positive claims disabled;
- campaign: `PARTIAL=3`, `GAP=3`, `VERIFIED=0`;
- attack-chain fixture remains synthetic and non-executing;
- explainability remains evidence-bound and does not amplify confidence;
- Beta6 portable boundary remains accepted;
- automatic quarantine/repair/restore: false;
- general Home execution: false;
- DELETE/REPAIR/process termination/trust mutation: false;
- authority granted: false.

Final deterministic core digest:
`dcd6a7ff975c2fbdce9549d4af630ab6c252acf26ca7b0c31e0c70e72db8ea4e`

Observed local synthetic pipeline resource measurement:
- elapsed: `0.17224099999293685 s`;
- peak traced memory: `82653 bytes`;
- acceptance ceilings: `60 s`, `536870912 bytes`.

Exact-head Windows CI run `34984650411` completed successfully on the accepted code SHA before checkpoint freeze.

Final local gate:
`BC SENTINEL v0.11.0-beta.7 B7-7 WINDOWS ACCEPTANCE & FREEZE - PASS`
