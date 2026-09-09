# Local security checkpoint 3 — 8 September 2026

Continues checkpoint 2. The full roadmap remains active. **v0.9 is not frozen; v0.10 has not been accepted.**

## Reproduced updater defects and corrections

Five pre-fix adversarial failures are preserved in `audit-20260907-checkpoint3/update-before.txt`: root redirection, overlapping backup/deployment roots, source replacement after approval, failed promotion without restoration, and acceptance of a modified/rehashed rollback backup. All experiments used harmless, disposable local releases.

The updater now binds approval to exact source and authenticated installed manifest digests. It copies only bounded, unambiguous manifest entries using pinned Windows read handles, validates the staged tree, and preserves the previous deployment through sibling renames. A process-held lock serializes transactions. Staging inherits a protected DACL from the installed tree, not the untrusted source.

Schema-2 authenticated journals bind immutable transaction paths and both manifest digests. Recovery validates the original backup before touching a deployment, rejects stale rollback over an unrelated release, and supports idempotent recovery after interruption. The PowerShell wrapper captures a failed apply's journal and verifies the original installation before restarting after an early failure without a journal.

The first full regression run exposed a transient Windows lock during journal replacement: 567 passed, one failed. The updater now writes a unique temporary journal and retries only sharing/access lock errors, with a bounded delay. Persistent failure retains the prior authenticated journal. The original failing run remains in `regression-first.txt`.

## Verification of this checkpoint

| Check | Result |
|---|---|
| Complete regression | **570 passed, zero skipped**, 102.96 seconds (`regression.txt`, `regression.xml`) |
| Updater adversarial coverage | 46 tests, included above: fault phases, process death, concurrent transactions, reparse/overlap, manifest aliases, DACL inheritance, rollback identity and journal locks |
| Local RC acceptance | Passed (`acceptance-rc.json`), including updater and quarantine runtime checks |
| Python compileall | Passed for app, sentinel, tools and tests |
| Fresh service and broker builds | Passed |
| Frozen service isolated pipe self-test | Passed, exit 0 |
| Full artifact manifest | Passed, 169 files |

Artifact: `audit-20260907-checkpoint3/BC-Sentinel-Protection-audit.zip`.

SHA-256: `b8a08da216a92ba5c7270884456d5c623c4912c6540a2882fcf993e0a1f3e457`.

`build-evidence.json` records the archive and changed source/test hashes. The artifact is **not production signed and has not been installed**. Earlier checkpoints remain available as historical evidence.

## Remaining gates and limits

Current-build elevated foundation, live service, upgrade/repair, reboot persistence and native benchmarking remain open. Historical installed-service acceptance is not acceptance of this artifact. The prior foundation failure identified non-elevated ETW access denial and inherited PowerShell module selection breaking Authenticode inspection; neither is represented as resolved here.

Legacy schema-1 journals lack an authenticated backup digest and are refused for automatic rollback. Recovery trees and unique temporary journals may be retained after failures; no automated retention cleanup is claimed. The privileged updater bootstrap is still the development workflow, not a production-signed distribution chain. Native Windows handle guarantees do not certify privileged behavior on other operating systems.

The user authorized creating an isolated persistent Windows VM on 8 September. VM preparation and subsequent guest evidence are tracked separately; the host service, firewall and execution policies were not modified by this checkpoint.
