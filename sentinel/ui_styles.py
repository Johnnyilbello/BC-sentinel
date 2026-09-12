from __future__ import annotations

"""Central QSS for the Stitch-derived BC Sentinel visual system."""

from sentinel.ui_design_system import COLORS, stylesheet as base_stylesheet


def home_stylesheet() -> str:
    c = COLORS
    return base_stylesheet() + f"""
    #SecurityOverviewWindow,#AppShell,#MainColumn,#PageScroll,#PageViewport,#PageHost,#SecurityRoot,#PageStack,#DashboardPage,#ScanPage,#QuarantinePage,#HistoryPage,#ProtectionPage,#SettingsPage {{ background:{c['canvas']}; border:none; }}
    #Sidebar {{ background:{c['sidebar']}; border-right:1px solid {c['border']}; }}
    #BrandName {{ color:{c['accent']}; font-size:20px; font-weight:700; }}
    #BrandEdition {{ color:{c['text_secondary']}; font-size:10px; font-weight:600; letter-spacing:1px; }}
    #NavActive,#NavItem,#SidebarFooterItem {{ text-align:left; padding:10px 12px; border-radius:8px; border:none; font-size:14px; font-weight:600; min-height:38px; }}
    #NavActive {{ background:#14382c; color:{c['text']}; border-left:3px solid {c['accent']}; }}
    #NavItem,#SidebarFooterItem {{ background:transparent; color:{c['text_secondary']}; }}
    #NavItem:hover {{ background:{c['surface_high']}; color:{c['text']}; }}
    #SidebarScan {{ background:#153a2d; color:#7ea592; border:1px solid #2b654c; border-radius:8px; padding:10px 12px; font-weight:700; }}
    #SidebarDivider {{ background:{c['border_soft']}; border:none; margin:6px 0; }}
    #TopBar {{ background:{c['canvas']}; border-bottom:1px solid {c['border']}; }}
    #TopBarTitle {{ color:{c['text']}; font-size:15px; font-weight:650; }}
    #TopBarAction,#MenuButton {{ background:transparent; color:{c['text_secondary']}; border:1px solid {c['border']}; border-radius:8px; padding:7px 11px; font-weight:600; }}
    #TopBarAction:hover,#MenuButton:hover {{ background:{c['surface_high']}; color:{c['text']}; }}
    #PostureHero {{ background:{c['surface']}; border:1px solid {c['border']}; border-radius:24px; }}
    #HeroTitle {{ color:#f2f6f3; font-size:28px; font-weight:700; }}
    #HeroSummary {{ color:{c['text_secondary']}; font-size:14px; }}
    #PosturePill,#NeutralPill {{ border-radius:12px; padding:4px 9px; font-size:11px; font-weight:700; }}
    #PosturePill[posture="PROTECTED"] {{ color:{c['accent_bright']}; background:#10271c; border:1px solid #2a6045; }}
    #PosturePill[posture="ATTENTION"] {{ color:{c['danger']}; background:#301817; border:1px solid #6c302e; }}
    #PosturePill[posture="UNVERIFIED"] {{ color:{c['warning']}; background:#2d2414; border:1px solid #665027; }}
    #NeutralPill {{ color:{c['text_secondary']}; background:{c['surface_highest']}; border:1px solid {c['border']}; }}
    #PrimaryDisabled,#SecondaryDisabled {{ border-radius:8px; padding:10px 16px; font-size:14px; font-weight:700; min-height:40px; }}
    #PrimaryDisabled {{ background:#174532; color:#79a892; border:1px solid #286148; }}
    #SecondaryDisabled {{ background:transparent; color:#7d8c84; border:1px solid #405047; }}
    #MetricCard {{ background:{c['surface']}; border:1px solid {c['border']}; border-radius:16px; }}
    #MetricCard[accentMetric="true"] {{ border-left:4px solid {c['accent']}; }}
    #MetricLabel {{ color:{c['text_secondary']}; font-size:12px; font-weight:650; letter-spacing:1px; }}
    #MetricValue,#MetricValueAccent {{ font-size:24px; font-weight:700; }} #MetricValue {{ color:#f0f5f1; }} #MetricValueAccent {{ color:{c['accent']}; }}
    #ModulesPanel {{ background:{c['surface']}; border:1px solid {c['border']}; border-radius:24px; }}
    #SectionTitle {{ color:#f0f5f1; font-size:18px; font-weight:700; }} #SectionHint {{ color:{c['text_muted']}; font-size:11px; }} #SectionDivider {{ background:{c['border']}; border:none; }}
    #ProtectionCard {{ background:{c['canvas']}; border:1px solid #344139; border-radius:16px; }} #ProtectionCard:hover {{ background:#111813; border:1px solid {c['border']}; }}
    #ModuleIcon,#SettingIcon {{ background:{c['surface_high']}; border:1px solid {c['border_soft']}; border-radius:21px; }}
    #CardTitle,#SettingTitle {{ color:#f1f5f2; font-size:15px; font-weight:700; }} #CardDescription,#SettingDescription {{ color:{c['text_secondary']}; font-size:13px; }} #CardSummary,#CardState {{ color:{c['text_muted']}; font-size:12px; }}
    #CardState[statusRole="positive"] {{ color:{c['accent_bright']}; }} #CardState[statusRole="attention"] {{ color:{c['danger']}; }}
    #InlineButton {{ background:transparent; color:{c['text_secondary']}; border:none; padding:5px 0; font-size:11px; font-weight:650; text-align:left; }} #InlineButton:hover {{ color:{c['accent']}; }}
    #RecoveryButton,#PrimaryAction {{ background:{c['accent']}; color:#062016; border:1px solid #34c996; border-radius:8px; padding:8px 12px; font-weight:750; }}
    #ActivityCard,#EmptyState,#TaskPanel,#TablePanel,#SettingsPanel {{ background:{c['surface']}; border:1px solid {c['border_soft']}; border-radius:16px; }} #CommandPanel {{ background:{c['surface']}; border:1px solid {c['border']}; border-radius:0; }}
    #PageTitle {{ color:#f2f6f3; font-size:30px; font-weight:700; }} #PageSubtitle {{ color:{c['text_secondary']}; font-size:14px; }} #PanelTitle {{ color:#f1f5f2; font-size:18px; font-weight:700; }}
    #TaskTitle,#EmptyTitle {{ color:#f1f5f2; font-size:20px; font-weight:700; }} #TaskSubtitle,#EmptyBody,#Microcopy {{ color:{c['text_muted']}; font-size:13px; }}
    #FilterActive,#FilterButton,#SecondaryAction,#IconButton {{ border-radius:8px; padding:8px 12px; font-size:12px; font-weight:650; }} #FilterActive {{ background:{c['accent_soft']}; color:{c['accent_bright']}; border:1px solid #2a6045; }} #FilterButton,#SecondaryAction,#IconButton {{ background:{c['surface_high']}; color:{c['text_secondary']}; border:1px solid {c['border']}; }}
    #DataTable {{ background:{c['surface']}; color:{c['text']}; border:none; gridline-color:{c['border_soft']}; selection-background-color:{c['accent_soft']}; selection-color:{c['text']}; font-size:12px; }}
    #DataTable QHeaderView::section {{ background:{c['surface_high']}; color:{c['text_secondary']}; border:none; border-bottom:1px solid {c['border']}; padding:10px; font-size:11px; font-weight:700; }} #HistoryTable {{ font-family:'Cascadia Mono','Consolas'; }}
    #SettingRow {{ background:{c['canvas']}; border:1px solid {c['border_soft']}; border-radius:12px; }}
    #AdvancedPanel {{ background:{c['surface_lowest']}; border:1px solid {c['border_soft']}; border-radius:10px; }} #AdvancedTitle {{ color:{c['text_secondary']}; font-size:11px; font-weight:700; }} #AdvancedText {{ background:#09100c; color:#bec9c1; border:1px solid #27332c; border-radius:8px; font-family:'Cascadia Mono','Consolas'; font-size:10px; }}
    #ThreatDialog,#ThreatBody,#ThreatFooter {{ background:{c['surface']}; }} #ThreatHeader {{ background:#3b1d1b; border-bottom:1px solid #6c302e; }} #ThreatHeaderTitle {{ color:{c['danger']}; font-weight:700; }} #ThreatName {{ color:#f4f6f5; font-size:18px; font-weight:700; }} #ThreatText,#ThreatMetaValue {{ color:{c['text_secondary']}; font-size:12px; }} #ThreatMetaLabel {{ color:{c['text_muted']}; font-size:11px; font-weight:700; }} #DangerAction {{ background:{c['danger']}; color:#2b0907; border:none; border-radius:8px; padding:8px 12px; font-weight:700; }}
    QStatusBar {{ color:{c['text_muted']}; background:{c['canvas']}; border-top:1px solid {c['border_soft']}; }}
    """


def rescue_stylesheet() -> str:
    c=COLORS
    return base_stylesheet()+f"""
    #HomeWindow,#HomeRoot,#TargetScroll,#TargetViewport,#TargetRoot {{ background:{c['canvas']}; border:none; }}
    #BrandName {{ color:{c['accent']}; font-size:18px; font-weight:700; }} #Eyebrow {{ color:{c['text_muted']}; font-size:10px; font-weight:700; letter-spacing:1px; }} #Title {{ color:#f2f6f3; font-size:30px; font-weight:700; }}
    #Subtitle,#SafetyText,#TargetLocation,#TargetExplanation,#FooterText,#SummaryLabel {{ color:{c['text_secondary']}; font-size:13px; }}
    #SafetyBanner {{ background:#2d2414; border:1px solid #665027; border-radius:12px; }} #SafetyTitle {{ color:{c['warning']}; font-weight:700; }}
    #TargetCard,#AdvancedPanel {{ background:{c['surface']}; border:1px solid {c['border']}; border-radius:16px; }} #TargetCard[selected="true"] {{ border:1px solid {c['accent']}; background:#111a15; }}
    #TargetIcon {{ background:{c['surface_high']}; border:1px solid {c['border_soft']}; border-radius:20px; }} #TargetTitle,#AdvancedTitle {{ color:#eef3ef; font-weight:700; }} #TargetTitle {{ font-size:16px; }}
    #TargetStatus {{ background:{c['surface_highest']}; color:{c['text_secondary']}; border:1px solid {c['border']}; border-radius:14px; padding:3px 10px; font-weight:700; }} #TargetStatus[status="CURRENT_SYSTEM"] {{ background:#123428; color:{c['accent_bright']}; border-color:#2a6045; }}
    #StateLabel {{ color:{c['text_secondary']}; font-weight:650; }} #PrimaryButton {{ background:{c['accent']}; color:#062016; border:1px solid #34c996; border-radius:8px; padding:9px 14px; font-weight:750; }} #PrimaryButton:hover {{ background:#22c990; }}
    #DetailsButton {{ background:transparent; color:{c['text_secondary']}; border:1px solid {c['border']}; border-radius:8px; padding:8px 12px; }} #DetailsButton:hover {{ background:{c['surface_high']}; color:{c['text']}; }}
    #InactiveAction {{ background:{c['surface_low']}; color:#718078; border:1px solid {c['border_soft']}; border-radius:8px; padding:8px 12px; }} #AdvancedText {{ background:#09100c; color:#bec9c1; border:1px solid #27332c; border-radius:8px; font-family:'Cascadia Mono','Consolas'; font-size:10px; }}
    QStatusBar {{ color:{c['text_muted']}; background:{c['canvas']}; border-top:1px solid {c['border_soft']}; }}
    """
