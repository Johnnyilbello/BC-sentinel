# BC Sentinel v0.7.2-beta.3 — Domain Trust Security Report

## Security objective
Add durable operator trust for legitimate domains without creating a bypass around signed threat intelligence or weakening the active Web Protection containment gates accepted in Beta 2.

## Trust precedence
The decision order is deliberately asymmetric:

`active signed IOC -> exact local domain trust -> structural/local heuristics`

This means local policy can suppress advisory heuristics for a known legitimate exact domain, but cannot suppress an active signed malicious IOC. Existing trust is retained for audit/history and surfaced as overridden rather than silently deleted.

## Exact-domain only
Persistent trust accepts one canonical IDNA-normalized domain. Wildcards are rejected. Parent-domain trust does not automatically apply to child subdomains. This prevents a broad trust action from unintentionally covering attacker-controlled descendants or unrelated delegated subdomains.

## Privileged boundary
Persistent trust changes use narrow operations:
- `web_domain_trust_add`;
- `web_domain_trust_remove`.

Both require authenticated administrator context and are compatible with the existing one-action UAC broker. The GUI passes the exact domain and optional source finding id; the service normalizes and revalidates the policy itself.

An add operation is refused while the exact/subdomain match is covered by an active signed domain IOC. Finding/domain mismatch also fails closed.

## Provenance model
Current Web Protection assessments expose structured provenance rather than only a final score. Signed IOC metadata includes bundle id, severity, expiry and label. Local trust includes exact scope, reason and source finding. Heuristic decisions expose their bounded local signals.

This makes the decision explainable without relying on AI-generated interpretation.

## Reputation storage
The local reputation ledger is observation-based and does not claim internet-wide reputation. It records bounded aggregate evidence from local Web Protection observations and is capped to 20,000 domains. Process/address samples are capped at 16 each. Signed feed state and trusted-domain policy live in separate protected tables and are not deleted by reputation pruning.

## Browser context
Browser classification is exact executable-name based. A lookalike such as `chrome-helper-malware.exe` remains unclassified even if its signer field claims Google. Signer, signature and process hash stay evidence rather than trust authority.

## Security Center behavior
Persistent trust can resolve pending findings only for the exact trusted domain. Revocation returns future observations to normal signed-IOC/heuristic evaluation. Historical findings remain auditable.

## Retained containment safety
Beta 3 does not alter the Beta 2 containment prerequisites. Domain-derived IP containment still requires signed domain IOC evidence, live same-PID DNS correlation, a real same-PID connection, non-shared IP posture and explicit UAC approval. Shared/CDN infrastructure still fails closed.
