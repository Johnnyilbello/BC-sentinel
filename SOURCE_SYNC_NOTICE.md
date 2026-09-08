# SOURCE SYNC NOTICE — v0.10.0-beta.1

The connected `Johnnyilbello/BC-sentinel` repository is being used as a **security-relevant development delta**, not as proof that it contains the complete latest Windows source tree.

## Current source-of-record boundary

The latest documented complete baseline is v0.9.0-rc.1 checkpoint 4 (8 September 2026): 578 tests passed, zero skipped, plus the updater/AuthentiCode hardening described by the checkpoint-3/checkpoint-4 audits.

The older generated `BC_Sentinel_v0_10_0_Beta1_Web_Deception_Anti_Scam_Foundation.zip` predates checkpoint 4. It must not be used as a replacement base because doing so could discard later security corrections.

## Required rebase

Apply the v0.10.0-beta.1 files and `V010_BETA1_CORE_INTEGRATION.patch` to the **exact complete checkpoint-4 source tree**, resolve conflicts without removing checkpoint-3/4 fixes, then rerun targeted + complete regressions before producing a new archive.

The historical repository claims that v0.9 RC1 was frozen/native accepted with 482/491-test-era evidence are superseded. Current v0.9 native elevated/live/UAC/upgrade/repair/reboot gates remain deferred/open.

No new v0.10 release archive SHA-256 is valid until the rebased complete tree has passed its required gates and a fresh immutable artifact is built.