# Filter Panel Visual Redesign

**Date:** 2025-12-02
**Status:** Approved

## Overview

Redesign the unified filter panel to improve visual clarity and user experience when switching between Include/Exclude modes.

## Layout Structure

```
┌─────────────────────────────────────────────────────────────┐
│ [+ Include] [− Exclude]                    [Apply] [Clear]  │  ← Row 1: Mode + Actions
├─────────────────────────────────────────────────────────────┤
│ [Including: TCP, 192.168.1.0/24 ×]                         │  ← Row 2: Active filters summary
│ [Excluding: UDP ×]                                          │
├─────────────────────────────────────────────────────────────┤
│ Source IP: [___________]  Dest IP: [___________]            │  ← Row 3: Global IP/Port
│ Port Range: [___________]                                   │     (moved from General tab)
├─────────────────────────────────────────────────────────────┤
│ [General•] [Threats] [VoiceQoS] [Country]                   │  ← Row 4: Tabs (• = has filters)
├─────────────────────────────────────────────────────────────┤
│ Tab content (protocols, severities, codecs, etc.)           │  ← Row 5: Tab-specific options
└─────────────────────────────────────────────────────────────┘
```

## Changes

### 1. Move IP/Port Inputs Above Tabs

- Source IP, Destination IP, and Port Range inputs moved from General tab to Row 3
- These inputs now apply globally across all tabs
- General tab retains only Protocols and Security filter chips

### 2. Panel Background Tinting by Mode

**Include Mode (Green):**
- Panel background: `#0A1A14` (dark green tint)
- Panel border: `#2EA043` (green)
- Input fields background: `#0D1F17` (subtle green)
- Input fields border: `#2EA04380` (green, 50% opacity)

**Exclude Mode (Red):**
- Panel background: `#1A0A0A` (dark red tint)
- Panel border: `#F85149` (red)
- Input fields background: `#1F0D0D` (subtle red)
- Input fields border: `#F8514980` (red, 50% opacity)

### 3. Mode Button Persistence

- Active Include: Solid green `#238636` background, stays visible permanently
- Active Exclude: Solid red `#DA3633` background, stays visible permanently
- Inactive mode: Grey `#21262D` background

### 4. Input Field Tinting

- Source IP, Destination IP, Port Range text boxes get subtle background tint
- Tint color matches current mode (green/red)
- Reinforces which mode user is building filters in

### 5. Tab Header Highlighting

- Small colored dot (6px) appears after tab name when tab has active filters
- Dot color matches filter type:
  - Green dot: tab has Include filters
  - Red dot: tab has Exclude filters
  - Both dots: tab has both Include and Exclude filters
- Implementation: `HasIncludeFilters` and `HasExcludeFilters` booleans per tab ViewModel

### 6. Animated Mode Transitions

- 200ms ease-out CSS transition on:
  - Panel background color
  - Panel border color
  - Input field background/border colors
- Provides polished feel when switching between Include/Exclude

## Color Reference

| Element | Include Mode | Exclude Mode | Neutral |
|---------|-------------|--------------|---------|
| Panel BG | `#0A1A14` | `#1A0A0A` | `#0A1628` |
| Panel Border | `#2EA043` | `#F85149` | `#3B82F6` |
| Input BG | `#0D1F17` | `#1F0D0D` | `#0D1117` |
| Input Border | `#2EA04380` | `#F8514980` | `#30363D` |
| Active Button | `#238636` | `#DA3633` | - |
| Tab Dot | `#3FB950` | `#F85149` | - |

## Files to Modify

1. `src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml` - Layout restructure, styles
2. `src/PCAPAnalyzer.UI/ViewModels/Components/UnifiedFilterPanelViewModel.cs` - Mode state properties
3. `src/PCAPAnalyzer.UI/ViewModels/Components/GeneralFilterTabViewModel.cs` - Remove IP/Port inputs
4. Tab ViewModels - Add `HasIncludeFilters`/`HasExcludeFilters` properties
