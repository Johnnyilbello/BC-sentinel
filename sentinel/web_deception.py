from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit


HEURISTIC_PROFILE = "v0.10.0-beta.1"


@dataclass(slots=True, frozen=True)
class WebHeuristicSignal:
    family: str
    code: str
    weight: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_LURE_GROUPS: dict[str, tuple[str, ...]] = {
    "credential_lure": (
        "login", "signin", "sign-in", "verify", "verification", "password",
        "account", "secure", "security", "otp", "2fa", "authentication",
    ),
    "payment_refund_lure": (
        "payment", "refund", "invoice", "billing", "card", "bank", "iban",
        "charge", "receipt", "payout",
    ),
    "prize_investment_lure": (
        "prize", "winner", "giveaway", "bonus", "airdrop", "investment",
        "crypto", "wallet", "seed", "recovery-phrase", "recoveryphrase", "claim",
    ),
}

_PERCENT_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
_URL_TOKEN_RE = re.compile(r"[a-z0-9]+", re.I)


def _script_family(ch: str) -> str:
    if not ch.isalpha():
        return ""
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return ""
    for family in ("LATIN", "CYRILLIC", "GREEK"):
        if family in name:
            return family.casefold()
    return "other"


def domain_deception_signals(original_host: str, normalized_host: str) -> list[WebHeuristicSignal]:
    """Return bounded structural/identity-deception evidence for one hostname.

    These signals are advisory. Callers must retain the global heuristic cap and
    must never translate them directly into destructive response.
    """
    normalized = str(normalized_host or "").casefold().rstrip(".")
    original = str(original_host or "").strip().rstrip(".")
    if not normalized:
        return []

    signals: list[WebHeuristicSignal] = []
    labels = normalized.split(".")

    if any(label.startswith("xn--") for label in labels):
        signals.append(WebHeuristicSignal(
            "identity_deception", "idn_punycode", 18,
            "Dominio IDN/Punycode: richiede verifica visiva",
        ))

    scripts = {_script_family(ch) for ch in original if _script_family(ch)}
    scripts.discard("other")
    if len(scripts) >= 2:
        signals.append(WebHeuristicSignal(
            "identity_deception", "mixed_script_hostname", 12,
            "Hostname Unicode con alfabeti misti: possibile imitazione visiva",
        ))

    if len(labels) >= 6:
        signals.append(WebHeuristicSignal(
            "host_structure", "deep_subdomain_chain", 8,
            "Numero elevato di sottodomini",
        ))
    if len(normalized) >= 90:
        signals.append(WebHeuristicSignal(
            "host_structure", "long_hostname", 6,
            "Nome dominio insolitamente lungo",
        ))
    if sum(label.count("-") for label in labels) >= 5:
        signals.append(WebHeuristicSignal(
            "host_structure", "hyphen_dense_hostname", 5,
            "Hostname con molte separazioni tramite trattini",
        ))
    return signals


def _lure_families(text: str) -> list[str]:
    tokens = {token.casefold() for token in _URL_TOKEN_RE.findall(unquote(str(text or "")))}
    matched: list[str] = []
    for family, words in _LURE_GROUPS.items():
        if any(word.casefold() in tokens for word in words):
            matched.append(family)
    return matched


def url_deception_signals(value: str, *, structural_score: int = 0) -> list[WebHeuristicSignal]:
    """Return URL-context signals with false-positive-resistant lure handling.

    Lure wording such as `login` or `invoice` is not suspicious by itself. It is
    scored only when independent structural risk already exists.
    """
    raw = str(value or "").strip()
    if not raw:
        return []
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parsed = urlsplit(candidate)
    except Exception:
        return []

    signals: list[WebHeuristicSignal] = []
    host = str(parsed.hostname or "")
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        signals.append(WebHeuristicSignal(
            "host_structure", "raw_ip_url", 24,
            "URL usa un indirizzo IP al posto di un dominio",
        ))
    except ValueError:
        pass

    if parsed.username is not None or parsed.password is not None:
        signals.append(WebHeuristicSignal(
            "url_deception", "userinfo_before_host", 15,
            "URL contiene credenziali/userinfo prima dell'host",
        ))

    encoded_count = len(_PERCENT_ESCAPE_RE.findall(raw))
    if encoded_count >= 5:
        signals.append(WebHeuristicSignal(
            "url_obfuscation", "dense_percent_encoding", 5,
            "URL contiene una quantità elevata di sequenze percent-encoded",
        ))

    decoded_query = unquote(parsed.query or "")
    if "http://" in decoded_query.casefold() or "https://" in decoded_query.casefold():
        signals.append(WebHeuristicSignal(
            "redirect_context", "nested_url_parameter", 6,
            "Parametro URL contiene una destinazione HTTP/HTTPS annidata",
        ))

    independent_score = max(0, int(structural_score)) + sum(s.weight for s in signals)
    lure_families = _lure_families(" ".join((parsed.path or "", parsed.query or "", parsed.fragment or "")))
    if lure_families and independent_score >= 8:
        signals.append(WebHeuristicSignal(
            "scam_lure", "lure_with_structural_risk", 8,
            "Contesto tipico di phishing/truffa combinato con rischio strutturale indipendente",
        ))
        if len(set(lure_families)) >= 2:
            signals.append(WebHeuristicSignal(
                "scam_lure", "multiple_lure_families", 4,
                "Più famiglie di esche (account/pagamento/premio) nello stesso URL rischioso",
            ))
    return signals


def serialize_signals(signals: list[WebHeuristicSignal]) -> list[dict[str, object]]:
    return [signal.to_dict() for signal in signals]
