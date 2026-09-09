from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from .web_deception import HEURISTIC_SCORE_CAP, assess_local_url

CLONE_SCAM_PROFILE = "v0.10.0-beta.3"


@dataclass(slots=True, frozen=True)
class CloneScamSignal:
    family: str
    code: str
    weight: int
    reason: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CloneScamAssessment:
    url: str
    observed_host: str
    declared_identity: str = ""
    score: int = 0
    status: str = "unknown"
    decision: str = "observe"
    assessment_class: str = "observe"
    block_recommended: bool = False
    risk_families: list[str] = field(default_factory=list)
    signal_codes: list[str] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    identity_context: dict[str, Any] = field(default_factory=dict)
    url_score: int = 0
    page_score: int = 0
    independent_evidence_families: int = 0
    fingerprint: str = ""
    profile: str = CLONE_SCAM_PROFILE

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_IDENTITIES: dict[str, dict[str, tuple[str, ...]]] = {
    "microsoft": {"tokens": ("microsoft", "outlook", "office", "onedrive"), "domains": ("microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com")},
    "google": {"tokens": ("google", "gmail"), "domains": ("google.com", "gmail.com", "googleusercontent.com", "gstatic.com", "googleapis.com")},
    "github": {"tokens": ("github",), "domains": ("github.com", "githubusercontent.com", "githubassets.com")},
    "paypal": {"tokens": ("paypal",), "domains": ("paypal.com", "paypalobjects.com")},
    "apple": {"tokens": ("apple", "icloud"), "domains": ("apple.com", "icloud.com")},
    "amazon": {"tokens": ("amazon",), "domains": ("amazon.com", "amazon.it", "amazonaws.com")},
    "cloudflare": {"tokens": ("cloudflare",), "domains": ("cloudflare.com", "cloudflare.net", "cloudflareinsights.com")},
    "salesforce": {"tokens": ("salesforce",), "domains": ("salesforce.com", "force.com")},
    "atlassian": {"tokens": ("atlassian", "jira", "trello"), "domains": ("atlassian.com", "jira.com", "trello.com")},
}

_WORD_RE = re.compile(r"[a-z0-9]+", re.I)
_URGENCY = ("urgent", "urgente", "immediately", "immediato", "suspended", "sospeso", "last chance", "ultimo avviso", "within 24 hours", "entro 24 ore")
_REMOTE_SUPPORT = ("remote access", "accesso remoto", "anydesk", "teamviewer", "support agent", "tecnico", "assistenza tecnica")
_INVESTMENT = ("guaranteed return", "rendimento garantito", "double your", "raddoppia", "investment", "investimento", "profit guaranteed", "profitto garantito")
_DELIVERY = ("customs fee", "spese doganali", "redelivery", "riconsegna", "parcel", "pacco", "courier", "corriere")
_PAYMENT = ("payment", "pagamento", "refund", "rimborso", "invoice", "fattura", "card", "carta", "bank", "banca")
_IRREVERSIBLE = {"gift_card", "giftcard", "crypto", "cryptocurrency", "bitcoin", "wire", "wire_transfer", "bank_transfer", "bonifico", "voucher"}
_CREDENTIAL_FIELDS = {"password", "passwd", "passcode", "otp", "pin", "2fa", "recovery_code", "seed", "seed_phrase"}
_PAYMENT_FIELDS = {"card", "card_number", "cvv", "cvc", "iban", "bank_account", "wallet", "crypto_wallet"}


def _host(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        return str(urlsplit(candidate).hostname or "").casefold().rstrip(".")
    except Exception:
        return ""


def _same_or_subdomain(host: str, domain: str) -> bool:
    host = str(host or "").casefold().rstrip(".")
    domain = str(domain or "").casefold().rstrip(".")
    return bool(domain and (host == domain or host.endswith("." + domain)))


def _identity_key(value: str) -> str:
    raw = str(value or "").strip().casefold()
    if not raw:
        return ""
    for key, profile in _IDENTITIES.items():
        if raw == key or raw in profile["tokens"]:
            return key
    return ""


def _canonical_for(identity: str, host: str) -> bool:
    profile = _IDENTITIES.get(identity)
    return bool(profile and any(_same_or_subdomain(host, domain) for domain in profile["domains"]))


def _text_has(text: str, phrases: Iterable[str]) -> bool:
    folded = str(text or "").casefold()
    return any(str(phrase).casefold() in folded for phrase in phrases)


def _brand_claims(text: str) -> list[str]:
    folded = str(text or "").casefold()
    tokens = set(_WORD_RE.findall(folded))
    found: list[str] = []
    for key, profile in _IDENTITIES.items():
        if any(token in tokens for token in profile["tokens"]):
            found.append(key)
    return found


def _stable_fingerprint(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "WCS-" + hashlib.sha256(canonical.encode("utf-8", "strict")).hexdigest()[:20]


def _dedupe(signals: list[CloneScamSignal]) -> list[CloneScamSignal]:
    unique: dict[tuple[str, str, str], CloneScamSignal] = {}
    for signal in signals:
        unique.setdefault((signal.family, signal.code, signal.evidence), signal)
    return list(unique.values())


def assess_page_context(
    *,
    url: str,
    declared_identity: str = "",
    page_title: str = "",
    visible_text: str = "",
    form_action: str = "",
    form_fields: Iterable[str] | None = None,
    payment_methods: Iterable[str] | None = None,
    link_hosts: Iterable[str] | None = None,
    redirect_chain: Iterable[str] | None = None,
) -> CloneScamAssessment:
    """Local, explainable clone-site/scam assessment with a hard heuristic cap.

    Page-content vocabulary never qualifies a block by itself. Textual scam cues
    are scored only when an independent structural/identity anchor exists. This
    is advisory input to Web Protection; it never performs network access,
    injects into browsers, decrypts HTTPS, or creates firewall rules.
    """
    observed_host = _host(url)
    declared_key = _identity_key(declared_identity)
    fields = {str(item or "").strip().casefold() for item in (form_fields or ()) if str(item or "").strip()}
    payments = {str(item or "").strip().casefold().replace(" ", "_") for item in (payment_methods or ()) if str(item or "").strip()}
    links = sorted({_host(item) for item in (link_hosts or ()) if _host(item)})
    chain = tuple(str(item or "").strip() for item in (redirect_chain or ()) if str(item or "").strip())

    local = assess_local_url(url, declared_identity=declared_identity, redirect_chain=chain)
    identity_context = dict(local.identity_context or {})
    signals: list[CloneScamSignal] = []

    title_claims = _brand_claims(page_title)
    body_claims = _brand_claims(visible_text[:16000])
    claimed = sorted(set(title_claims + body_claims + ([declared_key] if declared_key else [])))
    canonical_claims = [key for key in claimed if _canonical_for(key, observed_host)]
    noncanonical_claims = [key for key in claimed if not _canonical_for(key, observed_host)]

    credential_fields = sorted(fields & _CREDENTIAL_FIELDS)
    payment_fields = sorted(fields & _PAYMENT_FIELDS)
    action_host = _host(form_action)
    cross_origin_action = bool(action_host and observed_host and action_host != observed_host and not _same_or_subdomain(action_host, observed_host) and not _same_or_subdomain(observed_host, action_host))

    if declared_key and not _canonical_for(declared_key, observed_host):
        signals.append(CloneScamSignal("clone_site", "declared_brand_noncanonical", 12, "Identità dichiarata su dominio non canonico", declared_key))
    for key in noncanonical_claims[:2]:
        signals.append(CloneScamSignal("clone_site", "page_brand_noncanonical", 10, "Pagina dichiara un brand protetto fuori dai domini canonici", key))
    if credential_fields and noncanonical_claims:
        signals.append(CloneScamSignal("credential_capture", "credential_form_on_noncanonical_brand", 12, "Form credenziali su pagina che imita un brand non canonico", ",".join(credential_fields[:4])))
    if cross_origin_action and (credential_fields or payment_fields):
        signals.append(CloneScamSignal("form_destination", "sensitive_form_cross_origin", 12, "Form sensibile invia dati a un host differente", action_host))
    if len(links) >= 8 and observed_host and sum(1 for item in links if item != observed_host and not _same_or_subdomain(item, observed_host)) >= 6 and noncanonical_claims:
        signals.append(CloneScamSignal("clone_site", "brand_page_external_link_fanout", 5, "Pagina brandizzata non canonica con molti host esterni", str(len(links))))

    # Scam/fraud vocabulary only contributes when structural/identity risk is
    # already independently present. This avoids scoring normal commerce/support
    # pages merely because they contain payment, urgency, or support language.
    structural_anchor = bool(int(local.score or 0) > 0 or noncanonical_claims or cross_origin_action)
    combined_text = f"{page_title}\n{visible_text}"[:20000]
    if structural_anchor:
        irreversible = sorted(payments & _IRREVERSIBLE)
        has_payment = bool(payment_fields or payments or _text_has(combined_text, _PAYMENT))
        if irreversible and has_payment:
            signals.append(CloneScamSignal("scam_fraud", "irreversible_payment_request", 12, "Richiesta di pagamento difficilmente reversibile associata a rischio strutturale", ",".join(irreversible[:4])))
        if has_payment and _text_has(combined_text, _URGENCY):
            signals.append(CloneScamSignal("scam_fraud", "urgent_payment_pressure", 8, "Pressione/urgenza combinata con richiesta di pagamento e rischio strutturale", "urgency+payment"))
        if _text_has(combined_text, _REMOTE_SUPPORT) and (credential_fields or has_payment):
            signals.append(CloneScamSignal("scam_fraud", "remote_support_sensitive_request", 10, "Contesto di assistenza remota combinato con richiesta sensibile", "remote_support"))
        if _text_has(combined_text, _INVESTMENT) and ("crypto" in payments or "bitcoin" in payments or "cryptocurrency" in payments):
            signals.append(CloneScamSignal("scam_fraud", "investment_crypto_claim", 12, "Promessa/pressione d'investimento combinata con pagamento crypto", "investment+crypto"))
        if _text_has(combined_text, _DELIVERY) and has_payment:
            signals.append(CloneScamSignal("scam_fraud", "delivery_fee_pressure", 8, "Richiesta di pagamento legata a consegna/dogana su contesto strutturalmente rischioso", "delivery+payment"))

    signals = _dedupe(signals)
    page_score = sum(max(0, int(signal.weight)) for signal in signals)
    score = min(HEURISTIC_SCORE_CAP, max(int(local.score or 0), 0) + page_score)
    families = sorted({signal.family for signal in signals} | set(local.risk_families or ()))
    codes = sorted({signal.code for signal in signals} | set(local.signal_codes or ()))
    evidence_families = len(set(families))

    clone_evidence = any(signal.family in {"clone_site", "credential_capture", "form_destination"} for signal in signals)
    scam_evidence = any(signal.family == "scam_fraud" for signal in signals)
    if clone_evidence and scam_evidence:
        assessment_class = "clone_and_scam_candidate"
    elif clone_evidence:
        assessment_class = "clone_site_candidate"
    elif scam_evidence:
        assessment_class = "scam_fraud_candidate"
    else:
        assessment_class = "observe"

    # Require more than one independent family before page context itself moves
    # to review. URL-only Beta1 risk retains its own local suspicious status.
    review = bool((score >= 20 and evidence_families >= 2) or str(local.status) == "suspicious")
    fingerprint_payload = {
        "profile": CLONE_SCAM_PROFILE,
        "host": observed_host,
        "declared": declared_key,
        "url_fingerprint": str(local.heuristic_fingerprint or ""),
        "signals": sorted((signal.family, signal.code, signal.evidence) for signal in signals),
    }
    return CloneScamAssessment(
        url=str(url or ""), observed_host=observed_host, declared_identity=declared_key,
        score=score, status="suspicious" if review else "unknown",
        decision="review" if review else "observe", assessment_class=assessment_class,
        block_recommended=False, risk_families=families, signal_codes=codes,
        signals=[signal.to_dict() for signal in signals], identity_context=identity_context,
        url_score=int(local.score or 0), page_score=page_score,
        independent_evidence_families=evidence_families,
        fingerprint=_stable_fingerprint(fingerprint_payload),
    )
