from __future__ import annotations
from dataclasses import dataclass, field

LEVELS = (
    (85, "CRITICAL"),
    (70, "HIGH"),
    (50, "SUSPICIOUS"),
    (25, "LOW"),
    (0, "SAFE"),
)


@dataclass(slots=True)
class Signal:
    key: str
    weight: int
    reason: str
    source: str = "heuristic"


@dataclass(slots=True)
class ThreatAssessment:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    confidence: float = 0.0
    evidence_count: int = 0


def level_for(score: int) -> str:
    score = max(0, min(100, int(score)))
    for minimum, name in LEVELS:
        if score >= minimum:
            return name
    return "SAFE"


def assess(signals: list[Signal]) -> ThreatAssessment:
    """Score independent evidence with conservative multi-signal correlation.

    v0.3.1 goals:
    - repeated variants of one heuristic cannot linearly inflate a verdict;
    - collections of only weak heuristics are capped below SUSPICIOUS;
    - several independent medium/strong signals receive a small correlation
      bonus, rewarding convergence rather than any single noisy feature;
    - negative trust context can dampen weak evidence but cannot negate a
      deterministic high-confidence signature such as EICAR/YARA.
    """
    seen: dict[str, int] = {}
    positive_total = 0
    negative_total = 0
    reasons: list[str] = []
    unique_positive: list[Signal] = []
    sources: set[str] = set()

    for sig in signals:
        count = seen.get(sig.key, 0)
        multiplier = 1.0 if count == 0 else 0.35
        contribution = round(int(sig.weight) * multiplier)
        if contribution >= 0:
            positive_total += contribution
            if count == 0 and sig.weight > 0:
                unique_positive.append(sig)
                sources.add(str(sig.source or "heuristic"))
        else:
            negative_total += contribution
        seen[sig.key] = count + 1
        if sig.reason and sig.reason not in reasons:
            reasons.append(sig.reason)

    max_weight = max((int(s.weight) for s in unique_positive), default=0)
    deterministic = max_weight >= 80 or any(
        (s.source or "").casefold() in {"yara", "signature", "test-signature"}
        and s.weight >= 50
        for s in unique_positive
    )

    # Weak-only static heuristics (entropy, location, common imports) are useful
    # context but not enough on their own to create a user-facing detection.
    if unique_positive and not deterministic and max_weight <= 12:
        positive_total = min(positive_total, 35)

    synergy = 0
    if not deterministic and len(unique_positive) >= 3 and max_weight >= 15:
        synergy += min(8, (len(unique_positive) - 2) * 3)
        if len(sources) >= 2:
            synergy += 2

    # Trust is supporting evidence only. Never lower deterministic verdicts.
    trust_adjustment = 0 if deterministic else negative_total
    total = positive_total + synergy + trust_adjustment
    score = max(0, min(100, total))

    if deterministic:
        confidence = 1.0
    elif unique_positive:
        confidence = min(
            0.95,
            0.22 + min(0.45, max_weight / 100.0 * 0.9)
            + min(0.20, len(unique_positive) * 0.04)
            + min(0.08, max(0, len(sources) - 1) * 0.04),
        )
    else:
        confidence = 0.0

    return ThreatAssessment(
        score,
        level_for(score),
        reasons,
        signals,
        round(confidence, 3),
        len(unique_positive),
    )
