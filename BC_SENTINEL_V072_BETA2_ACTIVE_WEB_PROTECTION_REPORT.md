# BC Sentinel v0.7.2-beta.2 — Active Web Protection Security Report

## Security objective
Allow BC Sentinel to react to high-confidence Web Protection evidence without introducing browser TLS interception or unsafe IP-wide blocking on CDN/shared-hosting infrastructure.

## Detection → response architecture
The pipeline is deliberately split:

`DNS ETW -> PID-scoped DNS cache -> process network connection -> Web assessment -> persistent BCW finding -> explicit operator decision -> Protection Service revalidation -> temporary firewall lease`

`NetworkMonitor` remains read-only. Firewall mutation is performed only by the existing privileged service after the one-action UAC path succeeds.

## Shared-IP model
Beta 1 stored only the latest `(PID, IP)` attribution. Beta 2 keeps an additional bounded history keyed by `(PID, IP, domain)` for the same TTL. This history is not used to attribute a domain to another PID. It exists only to answer the safer question: "Has this IP recently served more than one exact domain?"

If yes, `shared_ip=true`. A signed-domain verdict remains malicious and visible, but its decision becomes `review_shared_infrastructure` and address containment is disabled. This is intentionally conservative: false shared classification is preferable to blocking unrelated CDN tenants.

A signed network IOC is different: the signed indicator explicitly targets the address/network, so shared-domain observations do not suppress that evidence class.

## Time-of-action revalidation
A persisted finding is evidence, not authority. `web_containment_create` does not trust the old UI payload. The service reloads the finding and independently revalidates:
- status `pending`;
- score >=70 and `block_recommended=true`;
- current signed IOC validity;
- live PID-scoped DNS mapping for domain-derived containment;
- exact domain/address agreement;
- current shared-IP posture;
- bounded TTL and explicit approval.

Expired/changed DNS state and newly shared infrastructure fail closed.

DNS resolution alone is not sufficient to qualify a domain-derived IP block. The persisted finding must originate from an observed network connection by the same PID; DNS-only evidence is retained for review but cannot create a containment lease.

## IPC boundary
New read/authenticated decision operation:
- `web_finding_decide` — `ignore_once` or `reviewed`; authenticated local identity required; no durable trust.

New privileged operation:
- `web_containment_create` — one finding id, bounded TTL, reason and explicit approval; UAC/admin required.

There is no generic domain-to-firewall privileged operation.

## Persistence
The `web_findings` table separates actionable state from raw `security_events`. It records evidence JSON, source, score, process identity, shared-IP posture, decision, lifecycle status and linked lease id. Pending duplicates are coalesced within a bounded window.

## UI
Security Center Web Protection now supports:
- persistent finding rows;
- shared/CDN review state;
- `Ignora una volta`;
- `Blocca 15 min` only when eligible;
- explicit explanation before containment;
- UAC-backed execution and lease confirmation.

## Performance acceptance
A new 3-run median benchmark clears only BC Sentinel's application hash cache between cold runs. OS page cache and endpoint-security effects remain part of the real Windows environment. Reported ranges make host-side variability visible rather than hiding it.

## Security properties that remain unchanged
- deterministic protection works without AI/cloud;
- heuristic-only anti-phishing cannot cross into automatic enforcement;
- no HTTPS MITM or certificate injection;
- no third-party firewall mutation;
- no permanent web block from the active-response path;
- containment remains BC-owned, outbound BLOCK, time-bounded and reversible.
