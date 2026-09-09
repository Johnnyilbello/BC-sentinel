---
name: Sentinel Elite
colors:
  surface: '#0e1511'
  surface-dim: '#0e1511'
  surface-bright: '#343b36'
  surface-container-lowest: '#09100c'
  surface-container-low: '#161d19'
  surface-container: '#1a211d'
  surface-container-high: '#242c27'
  surface-container-highest: '#2f3632'
  on-surface: '#dde4dd'
  on-surface-variant: '#bbcabf'
  inverse-surface: '#dde4dd'
  inverse-on-surface: '#2b322d'
  outline: '#86948a'
  outline-variant: '#3c4a42'
  surface-tint: '#4edea3'
  primary: '#4edea3'
  on-primary: '#003824'
  primary-container: '#10b981'
  on-primary-container: '#00422b'
  inverse-primary: '#006c49'
  secondary: '#adc6ff'
  on-secondary: '#002e6a'
  secondary-container: '#0566d9'
  on-secondary-container: '#e6ecff'
  tertiary: '#b7c8e1'
  on-tertiary: '#213145'
  tertiary-container: '#94a4bd'
  on-tertiary-container: '#2a3a4f'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#6ffbbe'
  primary-fixed-dim: '#4edea3'
  on-primary-fixed: '#002113'
  on-primary-fixed-variant: '#005236'
  secondary-fixed: '#d8e2ff'
  secondary-fixed-dim: '#adc6ff'
  on-secondary-fixed: '#001a42'
  on-secondary-fixed-variant: '#004395'
  tertiary-fixed: '#d3e4fe'
  tertiary-fixed-dim: '#b7c8e1'
  on-tertiary-fixed: '#0b1c30'
  on-tertiary-fixed-variant: '#38485d'
  background: '#0e1511'
  on-background: '#dde4dd'
  surface-variant: '#2f3632'
typography:
  display-lg:
    fontFamily: Hanken Grotesk
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Hanken Grotesk
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Hanken Grotesk
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  body-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Plus Jakarta Sans
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 12px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.5rem
  DEFAULT: 1rem
  md: 1.5rem
  lg: 2rem
  xl: 3rem
  full: 9999px
spacing:
  unit: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
  sidebar_width: 240px
  sidebar_collapsed: 64px
  container_gap: 20px
---

## Brand & Style

This design system is engineered for a high-end enterprise cybersecurity environment. It prioritizes clarity, authority, and calm during high-pressure security events. The visual identity leans into **Premium Minimalism** with a **Glassmorphic** foundation—specifically leveraging the "Mica" and "Acrylic" materials native to high-end desktop environments.

The brand personality is "The Silent Guardian": unobtrusive when everything is secure, but authoritative and precise when action is required. We avoid "hacker" tropes in favor of a sophisticated financial-grade aesthetic. The interface uses deep charcoal surfaces and refined geometric typography to establish a sense of impenetrable stability.

## Colors

The palette is anchored by a deep slate and charcoal foundation to reduce eye strain for security analysts. 

- **Primary Emerald (#10b981):** Represents the "Secure" state. Used for primary CTAs like "Quick Scan" and status indicators when the system is protected.
- **Surface Tiers:** We use a multi-layered dark grey scale. `#0f1115` serves as the application canvas, while `#1a1d23` is used for cards and elevated containers.
- **Functional Semantics:** Amber (#f59e0b) is reserved for non-critical warnings (e.g., outdated definitions), while Crimson (#ef4444) is strictly for active threats and critical failures.
- **Accent Slate (#3b82f6):** Provides a professional neutral-cool tone for interactive elements that are not related to security status, such as settings icons or navigation links.

## Typography

This design system utilizes a dual-font strategy to balance technical precision with approachability.

**Hanken Grotesk** is used for all headlines and display data. Its sharp, contemporary geometry provides a sense of modern engineering. **Plus Jakarta Sans** is used for body text and labels; its slightly softer terminals ensure high legibility in data-heavy lists and logs, preventing the interface from feeling overly sterile.

Critical status messages should use `headline-md` in the appropriate semantic color. All technical logs and data tables should utilize `body-sm` to maximize information density while maintaining readability.

## Layout & Spacing

The layout follows a **Fixed-Fluid Hybrid** model optimized for 1080p desktop displays. 

- **Sidebar:** A left-aligned vertical navigation bar. It utilizes a semi-transparent "Acrylic" effect (backdrop-blur: 20px) to provide depth.
- **Grid:** A standard 12-column grid is used within the main content area.
- **Rhythm:** An 8px linear scale (using the 4px base unit) governs all padding and margins. 
- **Margins:** Main application windows maintain a 24px inner margin from the sidebar and window edges to ensure the content feels "breathes" despite high data density.

## Elevation & Depth

Hierarchy is established through **Tonal Layering** and **Acrylic Materials** rather than heavy shadows.

1.  **Level 0 (Canvas):** `#0f1115`. The base application background.
2.  **Level 1 (Surface):** `#1a1d23`. Used for cards, panels, and the main sidebar.
3.  **Level 2 (Interaction/Popovers):** Semi-transparent layers with a subtle 1px border (`#ffffff10`) and a very soft, diffused shadow (0px 8px 24px rgba(0,0,0,0.4)).

To mimic the Windows 11 "Mica" effect, the background of the sidebar should allow a hint of the desktop wallpaper to bleed through, tinted by the primary slate tones.

## Shapes

In accordance with the premium visual identity, we use **Pill-shaped (Level 3)** roundedness for primary interactive elements and **Large Rounded (Level 2/3)** corners for structural containers.

- **Primary Buttons:** Use a full pill shape to stand out against the geometric grid.
- **Cards & Modules:** Utilize a `32px` (2rem) radius to create a soft, sophisticated enclosure for technical data.
- **Inputs & Small UI:** Revert to a more standard `8px` (0.5rem) radius to maintain a professional, functional appearance for data entry.

## Components

### Buttons
- **Primary (Quick Scan):** Solid `#10b981` with white or deep charcoal text. Pill-shaped. Subtle inner glow on hover.
- **Secondary:** Outlined with `#3b82f6` or `#2d3139`. Semi-transparent fill on hover.
- **Danger:** Solid `#ef4444`. Reserved exclusively for "Quarantine All" or "Delete" actions.

### Sidebar
- **Active State:** A vertical pill-shaped indicator on the left edge in Emerald Green, with the menu icon and text shifting to a higher white opacity.
- **Blur:** Backdrop blur (30px) combined with a `#1a1d23` tint at 80% opacity.

### Cards
- **Border:** Constant 1px solid border of `#2d3139`. 
- **Header:** Labels in `label-md` with 50% opacity text.
- **State Indicators:** Use small (8px) glowing dots in the top right corner to indicate live monitoring status.

### Toggles & Inputs
- **Toggles:** Follow the Windows 11 style—pill-shaped track with a sliding thumb. The track turns Emerald Green when "On".
- **Input Fields:** Darker than the card surface (`#0f1115`) with a 1px border that highlights in Slate Blue on focus.

### Status Banners
- Full-width bars at the top of the content area. Use a low-opacity tint of the semantic color (e.g., 10% Red) with a solid 2px left border for urgent notifications.