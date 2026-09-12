# BC Sentinel v0.11.0-beta.6 — B6-2 Complete Stitch UI Migration

Status: **IMPLEMENTED ON FEATURE BRANCH / STATIC AUDIT COMPLETE / WINDOWS LOCAL + VISUAL GATE PENDING**

Branch:

```text
feature/v011-beta6-b62-home-security-overview
```

Stable release remains unchanged:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

## Sources of truth

Functional truth remains the existing BC Sentinel code, engine contracts and accepted safety gates.

Visual truth is the complete product-owner bundle:

```text
stitch_bc_sentinel_antivirus_ui.zip
```

All 15 files in the bundle were reviewed. Detailed evidence is recorded in `BC_SENTINEL_STITCH_UI_AUDIT.md` and the persistent visual rules in `BC_SENTINEL_UI_SOURCE_OF_TRUTH.md`.

## Migration completed

B6-2 now uses one shared Sentinel Elite design system across the Home shell and secondary consumer-security surfaces:

- persistent BC Sentinel shell;
- Dashboard;
- Scansione;
- Quarantena;
- Cronologia;
- Protezione;
- Impostazioni;
- System & Recovery entry surface;
- reusable threat-alert dialog for real detection events;
- shared vector Sentinel mark;
- shared Material-like line icon renderer;
- shared color, spacing, radius, motion and breakpoint tokens;
- shared table, empty-state, panel, toggle and action language.

`sentinel/home_security_ui.py` is the single public application-shell entry. The internal `home_security_ui_impl.py` is retained only as the Dashboard presentation component; navigation, responsive behavior, shared styling and secondary surfaces are owned by the public shell and shared design-system modules. It is not a second user-facing UI.

## Stitch mapping

| ZIP reference | Runtime surface |
| --- | --- |
| `dashboard_*` | Dashboard/Home shell, status hero, KPI row, protection modules |
| `scansione_*` | Scan task surface and scan action hierarchy |
| `quarantena_*` | Quarantine management/table surface |
| `cronologia_*` | Dense event-history/command-center table |
| `impostazioni_*` | Protection/general/folders/allowlist settings composition |
| `minaccia_rilevata_*` | Critical threat modal component |
| `bc_sentinel_app_icon/*` | Vector Sentinel shield/S mark direction |
| `sentinel_elite/DESIGN.md` | Canonical app shell, typography, palette, spacing and rounded surfaces |
| `brutalist_luxe_command/DESIGN.md` | Scoped data-density language for History/evidence only |

## Runtime truth preserved

The visual migration does not promote capability presence to active protection.

```text
module exists                -> ENGINE_AVAILABLE
accepted runtime proof       -> may become ACTIVE
missing runtime proof        -> UNVERIFIED
verified OFF/ATTENTION       -> ATTENTION
all required verified ACTIVE -> PROTECTED
```

No green `Protected` state is allowed without current accepted runtime evidence.

## No fabricated operational data

The Stitch screenshots contain example security data, but the real application does not copy those fixtures into runtime screens.

Until real providers are connected:

- Dashboard KPI values use unavailable/neutral values;
- Quarantine shows an explicit empty state;
- History shows an explicit empty state;
- Settings do not invent stored configuration;
- Scan does not simulate progress;
- threat modal appears only when instantiated with a real detection payload.

## Safety boundary unchanged

B6-2 adds no security mutation authority.

```text
startup scan dispatch       = false
startup Rescue dispatch     = false
Smart Scan execution        = false in B6-2
automatic repair            = false
automatic quarantine        = false
unlock                      = false
mount-write                  = false
format                       = false
reimage                      = false
registry/boot write          = false
target execution            = false
```

System & Recovery still opens the accepted B6-1 flow in `IDLE`; discovery remains explicit.

## Responsive contract

The new shell is intentionally responsive rather than a compressed desktop screenshot:

- large desktop: 260 px sidebar, horizontal hero, 3 KPI columns, 2 × 2 module grid;
- standard laptop: 220 px sidebar, stacked hero/actions, single-column KPI/module layout when required;
- tablet/narrow window: 76 px icon rail, single-column content;
- minimum supported narrow window: outer page remains free of horizontal scrolling;
- secondary screens have explicit compact reflow;
- tables remain contained inside their own surface rather than widening the application shell.

The page host is synchronized to the actual `QScrollArea` viewport width. The previous one-third-width and 229 px overflow regressions are now explicit gate failures.

## Typography and tokens

Canonical core values:

```text
canvas             #0f1412
surface            #1c211f
surface high       #262b29
border             #3c4a42
text               #dde4dd
text secondary     #bbcabf
accent             #10b981
verified accent    #4edea3
warning            amber
critical           coral/red
spacing            4 / 8 / 16 / 24 / 32 / 48
motion             140 / 200 / 250 / 300 ms
```

Preferred typography follows Stitch (`Hanken Grotesk` display, `Plus Jakarta Sans` body) with Windows-safe fallback to `Segoe UI Variable Text` / `Segoe UI`. Dense evidence/history may use Cascadia Mono / Consolas.

## Validation gate

Run from normal, non-elevated PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST-V011-BETA6-B62.ps1
```

The gate now verifies:

1. complete B6-1 predecessor gate;
2. compileall of shared design system, all migrated UI modules, tests and acceptance tooling;
3. B6-0/B6-1/B6-2 pytest regression suite;
4. conservative runtime truth;
5. six-page Stitch shell;
6. shared iconography/tokens;
7. disabled Smart Scan and Full Scan execution in B6-2;
8. no fabricated Quarantine/History rows;
9. large-desktop geometry;
10. laptop responsive reflow;
11. tablet icon-rail reflow;
12. zero outer horizontal overflow;
13. Qt offscreen application construction;
14. unchanged hashes for security/predecessor sources during the gate;
15. presence/compilation of the internal Dashboard presentation component while the public shell remains `sentinel.home_security_ui`.

## Acceptance boundary

The migration must not be called stable until the updated branch passes the Windows local gate and a real visual review confirms:

- no clipping or overflow;
- faithful Stitch proportions;
- typography and spacing quality;
- correct desktop/laptop/narrow reflow;
- no native-white Qt leaks;
- correct focus/disabled/hover states;
- passive System & Recovery behavior;
- no false `Protected` claim.

B6-1 real offline multi-disk / locked-BitLocker hardware acceptance remains separately pending.

## Next milestone

Only after the B6-2 Windows gate and visual acceptance:

```text
B6-3 — One-Click Smart Scan
```

No B6-3 scan execution authority is introduced by this migration.
