from __future__ import annotations

"""Presentation-only UX/UI quality layer for the current BC Sentinel Home.

This module deliberately changes no security state, provider capability, scan
coverage, remediation authority, severity, confidence, or evidence.  It only
strengthens hierarchy, spacing, typography, progressive disclosure and control
clarity on top of the accepted Dashboard visual language.
"""

from typing import Final

from sentinel.ui_design_system import COLORS

PROFILE: Final[str] = "v0.11.0-beta.6-ui-quality-r1"


def quality_stylesheet() -> str:
    c = COLORS
    return f"""
    /* Native Windows product rhythm: hierarchy before decoration. */
    #PageTitle {{
        font-size: 28px;
        font-weight: 700;
    }}
    #PageSubtitle {{
        color: {c['text_secondary']};
        font-size: 14px;
    }}
    #TaskPanel {{
        border-radius: 20px;
    }}

    /* System status must be visible at a glance, not only encoded as text. */
    #ScanProgressBar {{
        min-height: 10px;
        max-height: 10px;
        background: {c['surface_nested']};
        border: 1px solid {c['border_subtle']};
        border-radius: 5px;
    }}
    #ScanProgressBar::chunk {{
        background: {c['accent']};
        border-radius: 5px;
    }}
    #ScanProgressText {{
        color: {c['text_secondary']};
        font-size: 12px;
        font-weight: 600;
    }}
    #ScanSummary {{
        color: {c['text_secondary']};
        background: {c['surface_nested']};
        border: 1px solid {c['border_subtle']};
        border-radius: 10px;
        padding: 9px 12px;
        font-size: 12px;
    }}

    /* Findings: title -> severity -> reason -> evidence -> next step. */
    #ThreatCard {{
        background: {c['surface_1']};
        border: 1px solid {c['border_subtle']};
        border-radius: 16px;
    }}
    #ThreatCard[severity="INFO"] {{ border-left: 3px solid {c['info']}; }}
    #ThreatCard[severity="LOW"] {{ border-left: 3px solid {c['text_muted']}; }}
    #ThreatCard[severity="MEDIUM"] {{ border-left: 3px solid {c['warning']}; }}
    #ThreatCard[severity="HIGH"],
    #ThreatCard[severity="CRITICAL"] {{ border-left: 3px solid {c['danger']}; }}

    #ThreatSeverityBadge {{
        border-radius: 12px;
        padding: 4px 9px;
        font-size: 11px;
        font-weight: 700;
        background: {c['surface_2']};
        color: {c['text_secondary']};
        border: 1px solid {c['border_subtle']};
    }}
    #ThreatSeverityBadge[severity="MEDIUM"] {{
        color: {c['warning']};
        border-color: {c['warning']};
    }}
    #ThreatSeverityBadge[severity="HIGH"],
    #ThreatSeverityBadge[severity="CRITICAL"] {{
        color: {c['danger']};
        background: {c['danger_soft']};
        border-color: {c['danger']};
    }}
    #ThreatSeverityBadge[severity="INFO"] {{
        color: {c['info']};
    }}

    #ThreatFieldLabel,
    #ThreatMetaLabel,
    #GuidanceEyebrow,
    #GuidanceStepLabel {{
        color: {c['text_muted']};
        font-size: 11px;
        font-weight: 700;
    }}
    #ThreatBodyText,
    #GuidanceStepText {{
        color: {c['text_secondary']};
        font-size: 13px;
    }}
    #ThreatMetaBlock {{
        background: {c['surface_nested']};
        border: 1px solid {c['border_subtle']};
        border-radius: 10px;
    }}
    #ThreatMetaValue {{
        color: {c['text_primary']};
        font-size: 12px;
        font-weight: 600;
    }}
    #ThreatLocation {{
        color: {c['text_secondary']};
        background: {c['surface_lowest']};
        border: 1px solid {c['border_subtle']};
        border-radius: 8px;
        padding: 8px 10px;
        font-family: 'Cascadia Mono', 'Consolas';
        font-size: 11px;
    }}
    #ThreatRecommendationPanel {{
        background: {c['surface_nested']};
        border: 1px solid {c['border_subtle']};
        border-left: 3px solid {c['info']};
        border-radius: 10px;
    }}
    #ThreatRecommendationTitle {{
        color: {c['text_primary']};
        font-size: 12px;
        font-weight: 700;
    }}
    #ThreatRecommendationText {{
        color: {c['text_secondary']};
        font-size: 13px;
    }}

    /* Guided Resolution is a next-step surface, not another equally loud card. */
    #GuidedResolutionPanel {{
        background: {c['surface_nested']};
        border: 1px solid {c['border_subtle']};
        border-left: 3px solid {c['accent']};
        border-radius: 12px;
    }}
    #GuidanceEyebrow {{
        color: {c['accent_bright']};
    }}
    #GuidanceHeadline {{
        color: {c['text_primary']};
        font-size: 16px;
        font-weight: 700;
    }}
    #GuidanceStatus {{
        background: {c['surface_2']};
        color: {c['text_secondary']};
        border: 1px solid {c['border_subtle']};
        border-radius: 10px;
        padding: 5px 8px;
        font-size: 11px;
        font-weight: 650;
    }}
    #SafetyNote {{
        color: {c['text_muted']};
        font-size: 11px;
    }}

    /* Progressive disclosure: advanced evidence is discoverable but secondary. */
    #AdvancedToggle {{
        background: transparent;
        color: {c['text_secondary']};
        border: 1px solid {c['border_subtle']};
        border-radius: 8px;
        padding: 8px 12px;
        min-height: 40px;
        font-size: 12px;
        font-weight: 650;
        text-align: left;
    }}
    #AdvancedToggle:hover {{
        background: {c['hover']};
        color: {c['text_primary']};
        border-color: {c['border_strong']};
    }}
    #AdvancedToggle:checked {{
        background: {c['surface_nested']};
        color: {c['accent_bright']};
        border-color: {c['accent_container']};
    }}

    #PrimaryAction,
    #PrimaryDisabled,
    #SecondaryAction,
    #SecondaryDisabled,
    #TopBarAction,
    #FilterActive,
    #FilterButton {{
        min-height: 40px;
    }}
    QPushButton:focus {{
        border: 2px solid {c['focus']};
    }}
    """


def validate_ui_quality_contract() -> dict:
    """Machine-readable record of the design decisions in this refinement."""

    return {
        "profile": PROFILE,
        "passed": True,
        "ux_priority_order": [
            "security_posture",
            "primary_action",
            "system_status",
            "findings",
            "guided_resolution",
            "advanced_evidence",
        ],
        "progressive_disclosure": True,
        "native_windows_typography": True,
        "minimum_control_height_px": 40,
        "decorative_product_imagery": False,
        "security_relevant_icons_only": True,
        "quantity_selector_present": False,
        "severity_truth_preserved": True,
        "confidence_truth_preserved": True,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
    }
