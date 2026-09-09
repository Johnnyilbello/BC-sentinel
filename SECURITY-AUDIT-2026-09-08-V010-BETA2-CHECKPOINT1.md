# BC Sentinel v0.10.0-beta.2 — Security checkpoint 1

Beta2 hardens the pre-existing reversible firewall containment foundation into a v0.10-specific fail-closed Web Response policy. The phishing/deception score remains advisory and capped below HIGH; it cannot create an address block. Signed evidence is revalidated at action time. Domain containment additionally requires a fresh same-PID DNS-to-network observation and rejects shared/CDN addresses. Duplicate actions reuse an active lease rather than creating redundant rules. Startup recovery preserves observed active rules, expires overdue leases, and releases stale protected state rather than silently recreating missing blocks.

Native Windows service, firewall, UAC and build gates remain acceptance evidence and are run by the supplied elevated all-in-one script.
