from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit


HEURISTIC_PROFILE = "v0.10.0-beta.1"
HEURISTIC_SCORE_CAP = 49


@dataclass(slots=True, frozen=True)
class WebHeuristicSignal:
    family: str
    code: str
    weight: int
    reason: str
    subject: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class ProtectedIdentity:
    key: str
    display_name: str
    tokens: tuple[str, ...]
    domains: tuple[str, ...]


@dataclass(slots=True)
class LocalWebReputation:
    value: str
    observed_host: str
    unicode_host: str
    declared_identity: str = ""
    score: int = 0
    status: str = "unknown"
    decision: str = "observe"
    block_recommended: bool = False
    risk_families: list[str] = field(default_factory=list)
    signal_codes: list[str] = field(default_factory=list)
    signals: list[dict[str, object]] = field(default_factory=list)
    identity_context: dict[str, object] = field(default_factory=dict)
    heuristic_fingerprint: str = ""
    heuristic_profile: str = HEURISTIC_PROFILE

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


# This bounded built-in catalogue is only local context for impersonation heuristics.
# It is not a cloud reputation service and it never creates a malicious verdict alone.
_PROTECTED_IDENTITIES: tuple[ProtectedIdentity, ...] = (
    ProtectedIdentity(
        "microsoft", "Microsoft", ("microsoft", "outlook"),
        ("microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com"),
    ),
    ProtectedIdentity(
        "google", "Google", ("google", "gmail"),
        ("google.com", "gmail.com", "googleusercontent.com", "gstatic.com", "googleapis.com"),
    ),
    ProtectedIdentity(
        "github", "GitHub", ("github",),
        ("github.com", "githubusercontent.com", "githubassets.com"),
    ),
    ProtectedIdentity(
        "paypal", "PayPal", ("paypal",),
        ("paypal.com", "paypalobjects.com"),
    ),
    ProtectedIdentity(
        "apple", "Apple", ("apple", "icloud"),
        ("apple.com", "icloud.com"),
    ),
    ProtectedIdentity(
        "amazon", "Amazon", ("amazon",),
        ("amazon.com", "amazon.it", "amazonaws.com"),
    ),
    ProtectedIdentity(
        "cloudflare", "Cloudflare", ("cloudflare",),
        ("cloudflare.com", "cloudflare.net", "cloudflareinsights.com"),
    ),
    ProtectedIdentity(
        "salesforce", "Salesforce", ("salesforce",),
        ("salesforce.com", "force.com"),
    ),
    ProtectedIdentity(
        "atlassian", "Atlassian", ("atlassian", "jira", "trello"),
        ("atlassian.com", "jira.com", "trello.com"),
    ),
)


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
        "crypto", "wallet", "seed", "recovery phrase", "claim",
    ),
    "support_remote_access_lure": (
        "support", "helpdesk", "remote access", "remote-access", "technician",
        "unlock", "suspended", "disabled",
    ),
    "delivery_customs_lure": (
        "delivery", "parcel", "package", "customs", "shipping", "courier",
        "redelivery", "postage",
    ),
}

_PERCENT_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
_URL_TOKEN_RE = re.compile(r"[a-z0-9]+", re.I)
# Unicode-aware hostname tokenizer: preserve Cyrillic/Greek/Latin alphanumerics
# before deriving the bounded confusable skeleton.
_HOST_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)

# Common cross-script glyphs used only to derive a bounded comparison skeleton.
_CONFUSABLES = {
    "а": "a", "А": "a", "е": "e", "Е": "e", "о": "o", "О": "o",
    "р": "p", "Р": "p", "с": "c", "С": "c", "у": "y", "У": "y",
    "х": "x", "Х": "x", "і": "i", "І": "i", "ј": "j", "Ј": "j",
    "κ": "k", "Κ": "k", "ο": "o", "Ο": "o", "ρ": "p", "Ρ": "p",
    "ν": "v", "Ν": "v", "χ": "x", "Χ": "x", "ι": "i", "Ι": "i",
}


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


def _safe_idna_decode(host: str) -> str:
    labels: list[str] = []
    for label in str(host or "").strip().rstrip(".").split("."):
        if not label:
            continue
        try:
            labels.append(label.encode("ascii").decode("idna") if label.casefold().startswith("xn--") else label)
        except (UnicodeError, ValueError):
            labels.append(label)
    return ".".join(labels).casefold()


def _safe_idna_encode(host: str) -> str:
    labels: list[str] = []
    for label in str(host or "").strip().rstrip(".").split("."):
        if not label:
            continue
        try:
            labels.append(label.encode("idna").decode("ascii").casefold())
        except (UnicodeError, ValueError):
            labels.append(label.casefold())
    return ".".join(labels)


def _confusable_skeleton(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", str(text or ""))
    out: list[str] = []
    for ch in normalized:
        if unicodedata.combining(ch):
            continue
        out.append(_CONFUSABLES.get(ch, ch.casefold()))
    return "".join(out)


def _is_same_or_subdomain(host: str, domain: str) -> bool:
    normalized_host = str(host or "").casefold().rstrip(".")
    normalized_domain = str(domain or "").casefold().rstrip(".")
    return bool(normalized_domain and (normalized_host == normalized_domain or normalized_host.endswith("." + normalized_domain)))


def _canonical_identity_for_host(host: str) -> ProtectedIdentity | None:
    for profile in _PROTECTED_IDENTITIES:
        if any(_is_same_or_subdomain(host, domain) for domain in profile.domains):
            return profile
    return None


def _profile_for_declared(value: str) -> ProtectedIdentity | None:
    candidate = str(value or "").strip().casefold()
    if not candidate:
        return None
    for profile in _PROTECTED_IDENTITIES:
        names = {profile.key, profile.display_name.casefold()}
        names.update(token.casefold() for token in profile.tokens)
        if candidate in names:
            return profile
    return None


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    a = str(left or "").casefold()
    b = str(right or "").casefold()
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = differences = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        differences += 1
        if differences > 1:
            return False
        if len(a) == len(b):
            i += 1
        j += 1
    differences += int(i < len(a) or j < len(b))
    return differences == 1


def _host_tokens(host: str) -> tuple[str, ...]:
    return tuple(token.casefold() for token in _HOST_TOKEN_RE.findall(str(host or "")))


def identity_deception_signals(
    original_host: str,
    normalized_host: str,
    *,
    declared_identity: str = "",
) -> list[WebHeuristicSignal]:
    """Return bounded impersonation/look-alike evidence without asserting malware."""
    normalized = _safe_idna_encode(normalized_host or original_host)
    unicode_host = _safe_idna_decode(normalized or original_host)
    if not normalized:
        return []

    canonical = _canonical_identity_for_host(normalized)
    declared = _profile_for_declared(declared_identity)
    signals: list[WebHeuristicSignal] = []

    if declared and not any(_is_same_or_subdomain(normalized, domain) for domain in declared.domains):
        signals.append(WebHeuristicSignal(
            "identity_deception", "declared_identity_mismatch", 12,
            "L'identità dichiarata non corrisponde al dominio osservato",
            subject=declared.key, evidence=normalized,
        ))

    # A canonical domain owned by the profile is not treated as a look-alike merely
    # because its subdomain/path contains brand vocabulary.
    if canonical is not None:
        return signals

    raw_tokens = _host_tokens(unicode_host)
    skeleton_tokens = tuple(_confusable_skeleton(token) for token in raw_tokens)
    for profile in _PROTECTED_IDENTITIES:
        for brand in profile.tokens:
            target = brand.casefold()
            if any(raw == target for raw in raw_tokens):
                signals.append(WebHeuristicSignal(
                    "identity_deception", "brand_token_untrusted_host", 12,
                    "Nome di un'identità protetta presente fuori dai relativi domini canonici",
                    subject=profile.key, evidence=normalized,
                ))
                break
            if any(skeleton == target and raw != target for raw, skeleton in zip(raw_tokens, skeleton_tokens)):
                signals.append(WebHeuristicSignal(
                    "identity_deception", "unicode_confusable_identity", 22,
                    "Hostname Unicode visivamente confondibile con un'identità protetta",
                    subject=profile.key, evidence=unicode_host,
                ))
                break
            if any(_edit_distance_at_most_one(token, target) for token in skeleton_tokens):
                signals.append(WebHeuristicSignal(
                    "identity_deception", "typosquat_distance_one", 14,
                    "Token del dominio a distanza di modifica uno da un'identità protetta",
                    subject=profile.key, evidence=normalized,
                ))
                break

    # Deduplicate per family/code/subject so several tokens from one brand do not inflate score.
    unique: dict[tuple[str, str, str], WebHeuristicSignal] = {}
    for signal in signals:
        unique.setdefault((signal.family, signal.code, signal.subject), signal)
    return list(unique.values())


def domain_deception_signals(
    original_host: str,
    normalized_host: str,
    *,
    declared_identity: str = "",
) -> list[WebHeuristicSignal]:
    """Return bounded structural/identity-deception evidence for one hostname."""
    normalized = _safe_idna_encode(normalized_host or original_host)
    original = str(original_host or "").strip().rstrip(".")
    if not normalized:
        return []

    signals: list[WebHeuristicSignal] = []
    labels = normalized.split(".")
    unicode_host = _safe_idna_decode(normalized)

    if any(label.startswith("xn--") for label in labels):
        signals.append(WebHeuristicSignal(
            "identity_deception", "idn_punycode", 18,
            "Dominio IDN/Punycode: richiede verifica visiva", evidence=normalized,
        ))

    scripts = {_script_family(ch) for ch in unicode_host if _script_family(ch)}
    scripts.discard("other")
    if len(scripts) >= 2:
        signals.append(WebHeuristicSignal(
            "identity_deception", "mixed_script_hostname", 12,
            "Hostname Unicode con alfabeti misti: possibile imitazione visiva", evidence=unicode_host,
        ))

    if len(labels) >= 6:
        signals.append(WebHeuristicSignal(
            "host_structure", "deep_subdomain_chain", 8,
            "Numero elevato di sottodomini", evidence=normalized,
        ))
    if len(normalized) >= 90:
        signals.append(WebHeuristicSignal(
            "host_structure", "long_hostname", 6,
            "Nome dominio insolitamente lungo", evidence=normalized,
        ))
    if sum(label.count("-") for label in labels) >= 5:
        signals.append(WebHeuristicSignal(
            "host_structure", "hyphen_dense_hostname", 5,
            "Hostname con molte separazioni tramite trattini", evidence=normalized,
        ))

    signals.extend(identity_deception_signals(original, normalized, declared_identity=declared_identity))
    unique: dict[tuple[str, str, str], WebHeuristicSignal] = {}
    for signal in signals:
        unique.setdefault((signal.family, signal.code, signal.subject), signal)
    return list(unique.values())


def _lure_families(text: str) -> list[str]:
    decoded = unquote(str(text or "")).casefold()
    tokens = {token.casefold() for token in _URL_TOKEN_RE.findall(decoded)}
    matched: list[str] = []
    for family, phrases in _LURE_GROUPS.items():
        for phrase in phrases:
            phrase_cf = phrase.casefold()
            phrase_tokens = _URL_TOKEN_RE.findall(phrase_cf)
            if (len(phrase_tokens) == 1 and phrase_tokens[0] in tokens) or (len(phrase_tokens) > 1 and phrase_cf in decoded):
                matched.append(family)
                break
    return matched


def _parse_host(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    candidate = candidate if "://" in candidate else "https://" + candidate
    try:
        return _safe_idna_encode(str(urlsplit(candidate).hostname or ""))
    except Exception:
        return ""


def redirect_chain_signals(chain: list[str] | tuple[str, ...] | None) -> list[WebHeuristicSignal]:
    """Return advisory redirect-chain evidence. No network request is made here."""
    values = [str(item or "").strip() for item in (chain or ()) if str(item or "").strip()]
    if len(values) < 2:
        return []
    hosts = [_parse_host(value) for value in values]
    hosts = [host for host in hosts if host]
    if len(hosts) < 2:
        return []

    signals: list[WebHeuristicSignal] = []
    if len(values) >= 6:
        signals.append(WebHeuristicSignal(
            "redirect_context", "long_redirect_chain", 6,
            "Catena di redirect insolitamente lunga", evidence=str(len(values)),
        ))
    if len(set(hosts)) >= 4:
        signals.append(WebHeuristicSignal(
            "redirect_context", "many_redirect_hosts", 5,
            "La catena attraversa molti host distinti", evidence=str(len(set(hosts))),
        ))

    start_identity = _canonical_identity_for_host(hosts[0])
    if start_identity:
        for destination in hosts[1:]:
            destination_signals = identity_deception_signals(destination, destination)
            if any(signal.subject == start_identity.key for signal in destination_signals):
                signals.append(WebHeuristicSignal(
                    "redirect_context", "brand_redirect_to_lookalike", 10,
                    "Redirect da dominio canonico verso un host simile ma non canonico",
                    subject=start_identity.key, evidence=destination,
                ))
                break

    for host in hosts[1:]:
        try:
            ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            continue
        signals.append(WebHeuristicSignal(
            "redirect_context", "redirect_to_raw_ip", 8,
            "La catena di redirect termina o transita su un indirizzo IP", evidence=host,
        ))
        break
    return signals


def url_deception_signals(
    value: str,
    *,
    structural_score: int = 0,
    redirect_chain: list[str] | tuple[str, ...] | None = None,
) -> list[WebHeuristicSignal]:
    """Return URL-context signals with false-positive-resistant lure handling."""
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
            "URL usa un indirizzo IP al posto di un dominio", evidence=host,
        ))
    except ValueError:
        pass

    if parsed.username is not None or parsed.password is not None:
        signals.append(WebHeuristicSignal(
            "url_deception", "userinfo_before_host", 15,
            "URL contiene credenziali/userinfo prima dell'host", evidence=host,
        ))

    encoded_count = len(_PERCENT_ESCAPE_RE.findall(raw))
    if encoded_count >= 5:
        signals.append(WebHeuristicSignal(
            "url_obfuscation", "dense_percent_encoding", 5,
            "URL contiene una quantità elevata di sequenze percent-encoded", evidence=str(encoded_count),
        ))

    decoded_query = unquote(parsed.query or "")
    if "http://" in decoded_query.casefold() or "https://" in decoded_query.casefold():
        signals.append(WebHeuristicSignal(
            "redirect_context", "nested_url_parameter", 6,
            "Parametro URL contiene una destinazione HTTP/HTTPS annidata",
        ))

    signals.extend(redirect_chain_signals(redirect_chain))
    independent_score = max(0, int(structural_score)) + sum(max(0, int(signal.weight)) for signal in signals)
    lure_families = _lure_families(" ".join((parsed.path or "", parsed.query or "", parsed.fragment or "")))
    if lure_families and independent_score >= 8:
        signals.append(WebHeuristicSignal(
            "scam_lure", "lure_with_structural_risk", 8,
            "Contesto tipico di phishing/truffa combinato con rischio strutturale indipendente",
            evidence=",".join(sorted(set(lure_families))),
        ))
        if len(set(lure_families)) >= 2:
            signals.append(WebHeuristicSignal(
                "scam_lure", "multiple_lure_families", 4,
                "Più famiglie di esche nello stesso URL rischioso",
                evidence=",".join(sorted(set(lure_families))),
            ))
    return signals


def bounded_heuristic_score(signals: list[WebHeuristicSignal] | tuple[WebHeuristicSignal, ...]) -> int:
    return min(HEURISTIC_SCORE_CAP, sum(max(0, int(signal.weight)) for signal in signals))


def build_identity_context(observed_host: str, *, declared_identity: str = "") -> dict[str, object]:
    normalized = _safe_idna_encode(observed_host)
    canonical = _canonical_identity_for_host(normalized)
    declared = _profile_for_declared(declared_identity)
    candidates = sorted({
        signal.subject
        for signal in identity_deception_signals(normalized, normalized, declared_identity=declared_identity)
        if signal.subject
    })
    return {
        "declared_identity": declared.key if declared else str(declared_identity or "").strip().casefold(),
        "observed_host": normalized,
        "unicode_host": _safe_idna_decode(normalized),
        "canonical_identity": canonical.key if canonical else "",
        "declared_matches_observed": bool(declared and any(_is_same_or_subdomain(normalized, domain) for domain in declared.domains)),
        "impersonation_candidates": candidates,
    }


def stable_deception_fingerprint(
    observed_host: str,
    signal_codes: list[str] | tuple[str, ...],
    *,
    declared_identity: str = "",
) -> str:
    material = "\n".join((
        HEURISTIC_PROFILE,
        _safe_idna_encode(observed_host),
        str(declared_identity or "").strip().casefold(),
        ",".join(sorted(set(str(code or "").strip() for code in signal_codes if str(code or "").strip()))),
    )).encode("utf-8", "strict")
    return "WDR-" + hashlib.sha256(material).hexdigest()[:20]


def assess_local_url(
    value: str,
    *,
    declared_identity: str = "",
    redirect_chain: list[str] | tuple[str, ...] | None = None,
) -> LocalWebReputation:
    """Pure local URL/domain heuristic layer used below deterministic IOC/trust precedence.

    It performs no DNS/network request, never recommends blocking and never exceeds
    the heuristic score cap. The full WebProtectionEngine remains authoritative for
    signed IOC, exact-domain trust and network/download correlation.
    """
    raw = str(value or "").strip()
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parsed = urlsplit(candidate)
    except Exception:
        parsed = urlsplit("https://")
    original_host = str(parsed.hostname or "")
    normalized_host = _safe_idna_encode(original_host)

    domain_signals = domain_deception_signals(
        original_host,
        normalized_host,
        declared_identity=declared_identity,
    )
    domain_score = bounded_heuristic_score(domain_signals)
    url_signals = url_deception_signals(
        candidate,
        structural_score=domain_score,
        redirect_chain=redirect_chain,
    )
    signals = domain_signals + url_signals
    score = bounded_heuristic_score(signals)
    families = list(dict.fromkeys(signal.family for signal in signals))
    codes = list(dict.fromkeys(signal.code for signal in signals))
    context = build_identity_context(normalized_host, declared_identity=declared_identity)

    return LocalWebReputation(
        value=raw,
        observed_host=normalized_host,
        unicode_host=_safe_idna_decode(normalized_host),
        declared_identity=str(declared_identity or "").strip(),
        score=score,
        status="suspicious" if score >= 20 else "unknown",
        decision="review" if score >= 20 else "observe",
        block_recommended=False,
        risk_families=families,
        signal_codes=codes,
        signals=serialize_signals(signals),
        identity_context=context,
        heuristic_fingerprint=stable_deception_fingerprint(
            normalized_host,
            codes,
            declared_identity=declared_identity,
        ),
    )


def serialize_signals(signals: list[WebHeuristicSignal] | tuple[WebHeuristicSignal, ...]) -> list[dict[str, object]]:
    return [signal.to_dict() for signal in signals]