# Source synchronization — v0.10.0-beta.3

The downloadable v0.10.0-beta.3 package is the full reconstructed working tree used for local regression. The GitHub v0.10 development history began as a security-delta repository rather than the byte-identical checkpoint-4 source-of-record, so this branch records the Beta2/Beta3 delta, acceptance tooling, one-command launchers, version metadata and integration patches required to reproduce the v0.10 changes on the full tree.

From Beta3 onward package launchers always include upgrade/repair and standard-user -> UAC acceptance. Reboot is intentionally deferred to final roadmap acceptance.

Do not infer historical native acceptance solely from the old GitHub delta history; use the packaged Windows acceptance outputs for release evidence.
