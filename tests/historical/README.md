# Historical regression tests

These twelve tests remain in Git. They describe v0.9/v0.10 and early v0.11
runtime surfaces or Beta2 root scripts removed from the current product tree.
The current branch cannot collect nine modules and has twelve assertions against
missing root scripts. They are excluded from the current-source test discovery;
the Beta5â€“Beta14 acceptance gate remains unchanged.

Use the matching historical checkpoint to investigate them:

- v0.9/v0.10 and legacy runtime modules: `7d90b682` (full v0.10 RC1 source).
- Beta2 checkpoint scripts: `origin/checkpoint/v011-beta2-b2-pass-v6`.

Run these on disposable checkouts and record the checkout SHA and result. Some
Beta1 tests were added after the full legacy runtime was removed; if no commit
contains both a test and its required runtime, preserve it as archival contract
evidence rather than recreating unsafe historical components in this branch.
Do not describe this directory as passing without an actual run at its matching
checkpoint. The current branch's supported suite and this archive have separate
results.

## Verified on Windows, 2026-09-28

Read-only Git archives were extracted outside the current checkout. No real
malware or live acceptance scripts were executed.

- `7d90b682955b49c03b677f6b318b0c7fb80306fb`: the six v0.9/v0.10 files above,
  **53 passed** (33.87 s).
- `b943f1ee550ad5c2bee3d8753962d5971c212381`: the three Beta2 files above,
  **33 passed** (0.90 s).
- The three Beta1 files were also checked for collection at the Beta2 checkpoint:
  **3 collection errors**, missing legacy runtime modules. They remain unresolved
  archival contracts, not passing tests. The v0.10 archive does not contain these
  later Beta1 tests. Their absence is not evidence of product stability.

The current candidate CI additionally runs `python -m pytest` across every
applicable current test, not only the Beta5–Beta14 filename selection.
