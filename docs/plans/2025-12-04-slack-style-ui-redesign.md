# Slack-Style UI Redesign

**Date**: 2025-12-04
**Status**: Approved for implementation
**Scope**: Full visual overhaul — tabs, filters, buttons, chips, colors

---

## 1. Color Palette

### Background Colors (warm grays)
```
Level 0 (deepest):    #1A1D21   — Window background
Level 1 (surfaces):   #222529   — Panel backgrounds
Level 2 (cards):      #2C2F33   — Card backgrounds
Level 3 (elevated):   #36393F   — Hover states, elevated cards
Level 4 (highest):    #3F4248   — Active states
```

### Text Colors
```
Primary:    #DCDDDE   — Main text (not pure white)
Secondary:  #96989D   — Labels, secondary info
Muted:      #72767D   — Hints, disabled
Inverse:    #1A1D21   — Text on light backgrounds
```

### Accent Colors (Slack palette)
```
Primary:    #1264A3   — Primary actions, selected states
Highlight:  #1D9BD1   — Hover on primary
Success:    #2BAC76   — Include filters, success states
Danger:     #E01E5A   — Exclude filters, errors, delete
Warning:    #ECB22E   — Warnings
```

### Border Colors
```
Subtle:     #3F4248   — Minimal separation
Default:    #4D5156   — Standard borders (use sparingly)
Focus:      #1264A3   — Input focus rings
```

---

## 2. Tab Bar

### Container
- Background: `#1A1D21` (same as window)
- Bottom border: 1px `#3F4248`
- No top/side borders

### Tab Item States

**Unselected:**
- Background: transparent
- Text: `#96989D`
- Border: none

**Hover:**
- Background: `#36393F`
- Text: `#DCDDDE`
- Transition: 150ms ease

**Selected:**
- Background: transparent
- Text: `#FFFFFF`
- Bottom accent: 3px `#1264A3`
- Font weight: Medium (500)

### Tab Item Dimensions
- Padding: 16px horizontal, 10px vertical
- Gap between tabs: 4px
- Corner radius: 8px (for hover bg)
- Font size: 13px
- Icon (emoji): 16px

---

## 3. Filter Panel

### Collapsible Behavior

**Collapsed state:**
- Single row showing: toggle button, active filter chips inline, Apply/Clear
- Height: ~48px
- Click "Filters" label or chevron to expand

**Expanded state:**
- Full panel with inputs and category tabs
- Smooth height animation: 200ms ease

### Panel Container
- Background: `#222529`
- Border: 1px `#3F4248` (or none with shadow)
- Corner radius: 12px
- Padding: 20px horizontal, 16px vertical
- Shadow: `0 2px 8px rgba(0,0,0,0.15)`

### Include/Exclude Toggle
- Style: Segmented control (connected pills)
- Height: 28px
- Corner radius: 20px (pill)
- Gap: 0 (connected)

**Include active:**
- Background: `#2BAC76`
- Text: white

**Exclude active:**
- Background: `#E01E5A`
- Text: white

**Inactive:**
- Background: transparent
- Text: `#96989D`
- Border: 1px `#4D5156`

### Category Selector (replaces nested TabControl)
- Style: Segmented horizontal pills
- Background (container): `#2C2F33`
- Corner radius (container): 8px
- Padding (container): 4px

**Segment unselected:**
- Background: transparent
- Text: `#96989D`

**Segment selected:**
- Background: `#36393F`
- Text: white
- Corner radius: 6px

### Filter Chips
- Corner radius: 12px (pill)
- Padding: 8px horizontal, 6px vertical
- Font: System 12px (not monospace)
- Gap: 6px
- Border: none (use background contrast)

**Neutral:**
- Background: `#36393F`
- Text: `#DCDDDE`

**Included:**
- Background: `#2BAC76`
- Text: white

**Excluded:**
- Background: `#E01E5A`
- Text: white

### Input Fields
- Background: `#1A1D21`
- Border: 1px `#3F4248`
- Border (focus): 2px `#1264A3`
- Corner radius: 6px
- Height: 36px
- Font size: 14px
- Text: `#DCDDDE`
- Placeholder: `#72767D`

---

## 4. Buttons

### Primary (Apply, Analyze, Submit)
- Background: `#1264A3`
- Background (hover): `#0B4F8A`
- Text: white
- Border: none
- Corner radius: 6px
- Height: 32px
- Padding: 16px horizontal
- Font weight: 500

### Secondary (Clear, Cancel)
- Background: transparent
- Background (hover): `#36393F`
- Border: 1px `#4D5156`
- Border (hover): 1px `#5D6167`
- Text: `#DCDDDE`
- Corner radius: 6px
- Height: 32px

### Danger (Delete, Remove)
- Background: transparent
- Background (hover): `#E01E5A`
- Border: 1px `#E01E5A`
- Text: `#E01E5A`
- Text (hover): white
- Corner radius: 6px

### Ghost (Icon buttons, close)
- Background: transparent
- Background (hover): `#36393F`
- Border: none
- Corner radius: 6px

### Behavioral Changes
- NO scale transforms on hover/press
- Transitions: 150ms color/background only
- Disabled: 40% opacity, cursor not-allowed

---

## 5. Typography

### Font Stack
```
-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif
```

### Type Scale
| Use | Size | Weight | Color |
|-----|------|--------|-------|
| Tab labels | 13px | 400/500 | `#96989D` / `#FFFFFF` |
| Section headers | 12px | 600 | `#72767D` uppercase |
| Body text | 13px | 400 | `#DCDDDE` |
| Input text | 14px | 400 | `#DCDDDE` |
| Chip labels | 12px | 500 | varies |
| Muted/hints | 11px | 400 | `#72767D` |

---

## 6. Spacing

Base unit: 4px

| Token | Value | Use |
|-------|-------|-----|
| xs | 4px | Tight gaps |
| sm | 8px | Chip margins, inline |
| md | 12px | Section gaps |
| lg | 16px | Card padding |
| xl | 24px | Major sections |
| 2xl | 32px | Page margins |

---

## 7. Implementation Files

1. `Styles/UnifiedDarkTheme.axaml` — Color palette, tokens
2. `Views/MainWindow.axaml` — Tab bar styles
3. `Views/Controls/UnifiedFilterPanelControl.axaml` — Filter panel
4. `ViewModels/Components/UnifiedFilterPanelViewModel.cs` — Collapse state

---

## 8. Implementation Order

1. **Phase 1**: Color palette in UnifiedDarkTheme.axaml
2. **Phase 2**: Tab bar restyling in MainWindow.axaml
3. **Phase 3**: Filter panel visual update + collapse logic
4. **Phase 4**: Button/chip styles globally
