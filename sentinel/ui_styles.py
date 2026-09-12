from __future__ import annotations

"""Central QSS for the Dashboard-derived BC Sentinel visual system."""

from sentinel.ui_design_system import COLORS, TYPOGRAPHY, stylesheet as base_stylesheet


def home_stylesheet() -> str:
    c = COLORS
    t = TYPOGRAPHY
    return base_stylesheet() + f"""
    /* AppShell: every reachable page owns its dark surface explicitly. */
    #SecurityOverviewWindow,
    #AppShell,
    #MainColumn,
    #PageScroll,
    #PageViewport,
    #PageHost,
    #SecurityRoot,
    #PageStack,
    #DashboardPage,
    #SecondaryPageScroll,
    #SecondaryPageViewport,
    #SecondaryPageHost,
    #ScanPage,
    #QuarantinePage,
    #HistoryPage,
    #ProtectionPage,
    #SettingsPage {{
        background: {c['bg_app']};
        border: none;
    }}

    /* Sidebar - preserve the accepted Dashboard structure and active state. */
    #Sidebar {{
        background: {c['bg_sidebar']};
        border-right: 1px solid {c['border_subtle']};
    }}
    #BrandName {{
        color: {c['accent']};
        font-size: 20px;
        font-weight: 700;
    }}
    #BrandEdition {{
        color: {c['text_muted']};
        font-size: 10px;
        font-weight: 650;
        letter-spacing: 1px;
    }}
    #NavActive,
    #NavItem,
    #SidebarFooterItem {{
        text-align: left;
        padding: 10px 12px;
        border-radius: 8px;
        border: none;
        font-size: 14px;
        font-weight: 600;
        min-height: 38px;
    }}
    #NavActive {{
        background: {c['selected']};
        color: {c['text_primary']};
        border-left: 3px solid {c['accent']};
    }}
    #NavItem,
    #SidebarFooterItem {{
        background: transparent;
        color: {c['text_secondary']};
    }}
    #NavItem:hover,
    #SidebarFooterItem:hover {{
        background: {c['hover']};
        color: {c['text_primary']};
    }}
    #NavItem:pressed,
    #SidebarFooterItem:pressed {{
        background: {c['pressed']};
    }}
    #SidebarScan {{
        background: {c['accent_soft']};
        color: {c['text_muted']};
        border: 1px solid {c['border_strong']};
        border-radius: 8px;
        padding: 10px 12px;
        font-weight: 700;
    }}
    #SidebarDivider {{
        background: {c['border_subtle']};
        border: none;
        margin: 8px 0 6px 0;
    }}

    /* Topbar remains intentionally secondary to primary security actions. */
    #TopBar {{
        background: {c['bg_header']};
        border-bottom: 1px solid {c['border_subtle']};
    }}
    #TopBarTitle {{
        color: {c['text_primary']};
        font-size: 15px;
        font-weight: 650;
    }}
    #TopBarAction,
    #MenuButton {{
        background: transparent;
        color: {c['text_secondary']};
        border: 1px solid {c['border_subtle']};
        border-radius: 8px;
        padding: 7px 11px;
        font-weight: 600;
    }}
    #TopBarAction:hover,
    #MenuButton:hover {{
        background: {c['hover']};
        color: {c['text_primary']};
        border-color: {c['border_strong']};
    }}
    #TopBarAction:pressed,
    #MenuButton:pressed {{
        background: {c['pressed']};
    }}

    /* Accepted Dashboard. Structure is intentionally preserved. */
    #PostureHero {{
        background: {c['surface_1']};
        border: 1px solid {c['border_strong']};
        border-radius: 24px;
    }}
    #HeroTitle {{
        color: {c['text_primary']};
        font-size: 28px;
        font-weight: 700;
    }}
    #HeroSummary {{
        color: {c['text_secondary']};
        font-size: {t['subtitle']}px;
    }}
    #PosturePill,
    #NeutralPill,
    #StatusBadge {{
        border-radius: 12px;
        padding: 4px 9px;
        font-size: {t['caption']}px;
        font-weight: 700;
    }}
    #PosturePill[posture="PROTECTED"] {{
        color: {c['success']};
        background: {c['accent_soft']};
        border: 1px solid {c['accent_container']};
    }}
    #PosturePill[posture="ATTENTION"] {{
        color: {c['danger']};
        background: {c['danger_soft']};
        border: 1px solid {c['danger']};
    }}
    #PosturePill[posture="UNVERIFIED"] {{
        color: {c['warning']};
        background: {c['surface_nested']};
        border: 1px solid {c['border_strong']};
    }}
    #NeutralPill {{
        color: {c['text_secondary']};
        background: {c['surface_3']};
        border: 1px solid {c['border_strong']};
    }}

    #PrimaryDisabled,
    #SecondaryDisabled {{
        border-radius: 8px;
        padding: 10px 16px;
        font-size: 14px;
        font-weight: 700;
        min-height: 40px;
    }}
    #PrimaryDisabled {{
        background: {c['disabled_surface']};
        color: {c['disabled_text']};
        border: 1px solid {c['border_subtle']};
    }}
    #SecondaryDisabled {{
        background: transparent;
        color: {c['disabled_text']};
        border: 1px solid {c['border_subtle']};
    }}

    #MetricCard {{
        background: {c['surface_1']};
        border: 1px solid {c['border_strong']};
        border-radius: 16px;
    }}
    #MetricCard[accentMetric="true"] {{
        border-left: 4px solid {c['accent']};
    }}
    #MetricLabel {{
        color: {c['text_secondary']};
        font-size: 12px;
        font-weight: 650;
        letter-spacing: 1px;
    }}
    #MetricValue,
    #MetricValueAccent {{
        font-size: {t['metric']}px;
        font-weight: 700;
    }}
    #MetricValue {{
        color: {c['text_primary']};
    }}
    #MetricValueAccent {{
        color: {c['accent']};
    }}

    #ModulesPanel {{
        background: {c['surface_1']};
        border: 1px solid {c['border_strong']};
        border-radius: 24px;
    }}
    #SectionTitle {{
        color: {c['text_primary']};
        font-size: {t['title']}px;
        font-weight: 700;
    }}
    #SectionHint {{
        color: {c['text_muted']};
        font-size: {t['caption']}px;
    }}
    #SectionDivider {{
        background: {c['border_subtle']};
        border: none;
    }}
    #ProtectionCard {{
        background: {c['bg_app']};
        border: 1px solid {c['border_subtle']};
        border-radius: 16px;
    }}
    #ProtectionCard:hover {{
        background: {c['surface_nested']};
        border-color: {c['border_strong']};
    }}
    #ModuleIcon,
    #SettingIcon,
    #SettingIconSmall {{
        background: {c['surface_2']};
        border: 1px solid {c['border_subtle']};
        border-radius: 18px;
    }}
    #CardTitle,
    #SettingTitle {{
        color: {c['text_primary']};
        font-size: 15px;
        font-weight: 700;
    }}
    #CardDescription,
    #SettingDescription {{
        color: {c['text_secondary']};
        font-size: {t['body']}px;
    }}
    #CardSummary,
    #CardState,
    #SettingMeta {{
        color: {c['text_muted']};
        font-size: 12px;
    }}
    #CardState[statusRole="positive"] {{
        color: {c['success']};
    }}
    #CardState[statusRole="attention"] {{
        color: {c['danger']};
    }}
    #InlineButton {{
        background: transparent;
        color: {c['text_secondary']};
        border: none;
        padding: 5px 0;
        font-size: 11px;
        font-weight: 650;
        text-align: left;
    }}
    #InlineButton:hover {{
        color: {c['accent_bright']};
    }}
    #RecoveryButton,
    #PrimaryAction,
    #PrimaryCompact {{
        background: {c['accent']};
        color: #062016;
        border: 1px solid {c['accent_bright']};
        border-radius: 8px;
        padding: 8px 12px;
        font-weight: 750;
    }}
    #RecoveryButton:hover,
    #PrimaryAction:hover,
    #PrimaryCompact:hover {{
        background: {c['accent_bright']};
    }}

    /* Secondary pages now inherit the same Dashboard surface hierarchy. */
    #PageHeader {{
        background: transparent;
        border: none;
    }}
    #PageTitle {{
        color: {c['text_primary']};
        font-size: {t['pageTitle']}px;
        font-weight: 700;
    }}
    #PageSubtitle {{
        color: {c['text_secondary']};
        font-size: {t['subtitle']}px;
    }}
    #SectionHeader {{
        background: transparent;
        border: none;
    }}
    #PanelTitle {{
        color: {c['text_primary']};
        font-size: {t['title']}px;
        font-weight: 700;
    }}
    #PanelDescription {{
        color: {c['text_secondary']};
        font-size: {t['body']}px;
    }}

    #ActivityCard,
    #TaskPanel,
    #TablePanel,
    #CommandPanel,
    #SettingsPanel {{
        background: {c['surface_1']};
        border: 1px solid {c['border_subtle']};
        border-radius: 16px;
    }}
    #EmptyState {{
        background: {c['surface_nested']};
        border: 1px solid {c['border_subtle']};
        border-radius: 12px;
        margin: 16px;
    }}
    #TaskTitle,
    #EmptyTitle {{
        color: {c['text_primary']};
        font-size: 20px;
        font-weight: 700;
    }}
    #TaskSubtitle,
    #EmptyBody {{
        color: {c['text_secondary']};
        font-size: {t['body']}px;
    }}
    #Microcopy {{
        color: {c['text_muted']};
        font-size: 12px;
    }}

    /* Tabs, filters and secondary actions. */
    #FilterActive,
    #FilterButton,
    #SecondaryAction,
    #IconButton {{
        border-radius: 8px;
        padding: 8px 12px;
        font-size: 12px;
        font-weight: 650;
        min-height: 34px;
    }}
    #FilterActive {{
        background: {c['accent_soft']};
        color: {c['accent_bright']};
        border: 1px solid {c['accent_container']};
    }}
    #FilterButton,
    #SecondaryAction,
    #IconButton {{
        background: transparent;
        color: {c['text_secondary']};
        border: 1px solid {c['border_subtle']};
    }}
    #FilterButton:hover,
    #SecondaryAction:hover,
    #IconButton:hover {{
        background: {c['hover']};
        color: {c['text_primary']};
        border-color: {c['border_strong']};
    }}
    #FilterButton:disabled,
    #SecondaryAction:disabled,
    #IconButton:disabled {{
        color: {c['disabled_text']};
        background: transparent;
        border-color: {c['border_subtle']};
    }}

    /* Dense data surfaces still belong to the same product. */
    #DataTable {{
        background: {c['surface_1']};
        alternate-background-color: {c['surface_nested']};
        color: {c['text_primary']};
        border: none;
        gridline-color: {c['border_subtle']};
        selection-background-color: {c['accent_soft']};
        selection-color: {c['text_primary']};
        font-size: 12px;
    }}
    #DataTable QHeaderView::section {{
        background: {c['surface_2']};
        color: {c['text_secondary']};
        border: none;
        border-bottom: 1px solid {c['border_subtle']};
        padding: 10px;
        font-size: 11px;
        font-weight: 700;
    }}
    #HistoryTable {{
        font-family: 'Cascadia Mono', 'Consolas';
    }}

    /* Protection + Settings hierarchy. */
    #ProtectionRow,
    #SettingRow {{
        background: {c['surface_nested']};
        border: 1px solid {c['border_subtle']};
        border-radius: 12px;
    }}
    #ProtectionRow:hover,
    #SettingRow:hover {{
        background: {c['hover']};
        border-color: {c['border_strong']};
    }}
    #StatusBadge[statusRole="positive"] {{
        color: {c['success']};
        background: {c['accent_soft']};
        border: 1px solid {c['accent_container']};
    }}
    #StatusBadge[statusRole="attention"] {{
        color: {c['danger']};
        background: {c['danger_soft']};
        border: 1px solid {c['danger']};
    }}
    #StatusBadge[statusRole="neutral"] {{
        color: {c['text_secondary']};
        background: {c['surface_2']};
        border: 1px solid {c['border_subtle']};
    }}

    #AdvancedPanel {{
        background: {c['surface_lowest']};
        border: 1px solid {c['border_subtle']};
        border-radius: 10px;
    }}
    #AdvancedTitle {{
        color: {c['text_secondary']};
        font-size: 11px;
        font-weight: 700;
    }}
    #AdvancedText {{
        background: {c['surface_lowest']};
        color: {c['text_secondary']};
        border: 1px solid {c['border_subtle']};
        border-radius: 8px;
        font-family: 'Cascadia Mono', 'Consolas';
        font-size: 10px;
    }}

    /* Threat alert keeps danger semantic and never uses it decoratively. */
    #ThreatDialog,
    #ThreatBody,
    #ThreatFooter {{
        background: {c['surface_1']};
    }}
    #ThreatHeader {{
        background: {c['danger_soft']};
        border-bottom: 1px solid {c['danger']};
    }}
    #ThreatHeaderTitle {{
        color: {c['danger']};
        font-weight: 700;
    }}
    #ThreatName {{
        color: {c['text_primary']};
        font-size: 18px;
        font-weight: 700;
    }}
    #ThreatText,
    #ThreatMetaValue {{
        color: {c['text_secondary']};
        font-size: 12px;
    }}
    #ThreatMetaLabel {{
        color: {c['text_muted']};
        font-size: 11px;
        font-weight: 700;
    }}
    #DangerAction {{
        background: {c['danger']};
        color: #2b0907;
        border: none;
        border-radius: 8px;
        padding: 8px 12px;
        font-weight: 700;
    }}

    QStatusBar {{
        color: {c['text_muted']};
        background: {c['bg_app']};
        border-top: 1px solid {c['border_subtle']};
    }}
    """


def rescue_stylesheet() -> str:
    c = COLORS
    return base_stylesheet() + f"""
    #HomeWindow,
    #HomeRoot,
    #TargetScroll,
    #TargetViewport,
    #TargetRoot {{
        background: {c['bg_app']};
        border: none;
    }}
    #BrandName {{
        color: {c['accent']};
        font-size: 18px;
        font-weight: 700;
    }}
    #Eyebrow {{
        color: {c['text_muted']};
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1px;
    }}
    #Title {{
        color: {c['text_primary']};
        font-size: 30px;
        font-weight: 700;
    }}
    #Subtitle,
    #SafetyText,
    #TargetLocation,
    #TargetExplanation,
    #FooterText,
    #SummaryLabel {{
        color: {c['text_secondary']};
        font-size: 13px;
    }}
    #SafetyBanner {{
        background: {c['surface_nested']};
        border: 1px solid {c['border_strong']};
        border-radius: 12px;
    }}
    #SafetyTitle {{
        color: {c['warning']};
        font-weight: 700;
    }}
    #TargetCard,
    #AdvancedPanel {{
        background: {c['surface_1']};
        border: 1px solid {c['border_strong']};
        border-radius: 16px;
    }}
    #TargetCard[selected="true"] {{
        border: 1px solid {c['accent']};
        background: {c['surface_nested']};
    }}
    #TargetIcon {{
        background: {c['surface_2']};
        border: 1px solid {c['border_subtle']};
        border-radius: 20px;
    }}
    #TargetTitle,
    #AdvancedTitle {{
        color: {c['text_primary']};
        font-weight: 700;
    }}
    #TargetTitle {{
        font-size: 16px;
    }}
    #TargetStatus {{
        background: {c['surface_3']};
        color: {c['text_secondary']};
        border: 1px solid {c['border_strong']};
        border-radius: 14px;
        padding: 3px 10px;
        font-weight: 700;
    }}
    #TargetStatus[status="CURRENT_SYSTEM"] {{
        background: {c['accent_soft']};
        color: {c['accent_bright']};
        border-color: {c['accent_container']};
    }}
    #StateLabel {{
        color: {c['text_secondary']};
        font-weight: 650;
    }}
    #PrimaryButton {{
        background: {c['accent']};
        color: #062016;
        border: 1px solid {c['accent_bright']};
        border-radius: 8px;
        padding: 9px 14px;
        font-weight: 750;
    }}
    #PrimaryButton:hover {{
        background: {c['accent_bright']};
    }}
    #DetailsButton {{
        background: transparent;
        color: {c['text_secondary']};
        border: 1px solid {c['border_subtle']};
        border-radius: 8px;
        padding: 8px 12px;
    }}
    #DetailsButton:hover {{
        background: {c['hover']};
        color: {c['text_primary']};
    }}
    #InactiveAction {{
        background: {c['disabled_surface']};
        color: {c['disabled_text']};
        border: 1px solid {c['border_subtle']};
        border-radius: 8px;
        padding: 8px 12px;
    }}
    #AdvancedText {{
        background: {c['surface_lowest']};
        color: {c['text_secondary']};
        border: 1px solid {c['border_subtle']};
        border-radius: 8px;
        font-family: 'Cascadia Mono', 'Consolas';
        font-size: 10px;
    }}
    QStatusBar {{
        color: {c['text_muted']};
        background: {c['bg_app']};
        border-top: 1px solid {c['border_subtle']};
    }}
    """
