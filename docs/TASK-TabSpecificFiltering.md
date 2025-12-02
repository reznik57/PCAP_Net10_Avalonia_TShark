# Implementation Guide: Tab-Specific Filtering for Threats, VoiceQoS, and Country Tabs

**Created:** 2025-12-01
**Status:** Ready for Implementation
**Priority:** High
**Estimated Complexity:** Medium (3-4 hours focused work)

---

## Executive Summary

The UnifiedFilterPanel collects filter criteria from all tabs (General, Threats, VoiceQoS, Country), but only **General tab filters work** because they operate on `PacketInfo` fields. The other tabs' filters require data from `AnalysisResult`, which is computed *after* packet parsing.

**Current State:**
- General tab filters (IP, Port, Protocol, Direction): ✅ Working
- Threats filters (Severity, Category): ❌ Not implemented
- VoiceQoS filters (Codec, Quality, Issues): ❌ Not implemented
- Country filters (Country, Region): ❌ Not implemented

---

## The Problem: Data Availability Matrix

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA FLOW ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PCAP File → TSharkService → PacketInfo[] → AnalysisOrchestrator    │
│                                  │                    │              │
│                                  │                    ▼              │
│                                  │         ┌─────────────────────┐   │
│                                  │         │   AnalysisResult    │   │
│                                  │         ├─────────────────────┤   │
│                                  │         │ - Threats[]         │◄──┤ Severity, Category
│                                  │         │ - VoiceQoSData      │◄──┤ Codec, Quality
│                                  │         │ - CountryTraffic{}  │◄──┤ Country, Region
│                                  │         │ - NetworkStatistics │   │
│                                  │         └─────────────────────┘   │
│                                  │                                   │
│                                  ▼                                   │
│                         ┌───────────────┐                            │
│                         │  PacketInfo   │                            │
│                         ├───────────────┤                            │
│                         │ - SourceIP    │◄── IP filters work here   │
│                         │ - DestIP      │                            │
│                         │ - Port        │◄── Port filters work here │
│                         │ - L7Protocol  │◄── "RTP", not "G.729"     │
│                         │ - NO Codec    │                            │
│                         │ - NO Severity │                            │
│                         │ - NO Country  │                            │
│                         └───────────────┘                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Insight:** `PacketInfo.L7Protocol` contains `"RTP"`, NOT `"G.729"`. Codec names are derived from RTP payload analysis stored in `VoiceQoSData`.

---

## Architectural Decision: Two-Stage Filtering

### The Ultrathink Debate

**Perspective A (The Architect):**
> "We should NOT try to backfill PacketInfo with analysis data. That violates separation of concerns and would require re-architecture. Instead, implement a two-stage filter: Stage 1 filters packets (General tab), Stage 2 filters analysis results (tab-specific). This is clean, maintainable, and matches existing patterns."

**Perspective B (The Security Analyst/User):**
> "I want to filter by 'Critical severity threats from China using G.729 codec'. The UI shows these filters as chips, so they MUST work. I don't care about architecture - show me my data."

**Perspective C (The Devil's Advocate):**
> "If we filter Threats separately from Packets, the counts might not match. User sees '5,225 threats' but after filtering, packet count doesn't change. This is confusing. We need to either: (a) clearly communicate what each filter affects, or (b) implement cross-linking so threat filters affect packet display too."

### The Decision

**Implement Tab-Specific Filtering with Clear UX Boundaries:**

1. General tab filters → Affect ALL views (packets, charts, statistics)
2. Tab-specific filters → Affect ONLY that tab's data view
3. Filter chips show the full filter, but effect is scoped

---

## Implementation Plan

### Phase 1: Infrastructure (30 min)

#### Task 1.1: Add FilterGroup Reference to Tab ViewModels

Each tab needs access to `GlobalFilterState` to read its relevant filter groups.

**Files to modify:**
- `src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs`
- `src/PCAPAnalyzer.UI/ViewModels/VoiceQoSViewModel.cs`
- `src/PCAPAnalyzer.UI/ViewModels/CountryTrafficViewModel.cs`

**Pattern:**
```csharp
public partial class ThreatsViewModel : SmartFilterableTab
{
    private readonly GlobalFilterState _globalFilterState;

    // Existing constructor - add parameter
    public ThreatsViewModel(
        GlobalFilterState globalFilterState,  // ADD THIS
        IAnalysisCacheService cacheService,
        // ... other deps
    )
    {
        _globalFilterState = globalFilterState;
        _globalFilterState.OnFilterChanged += OnGlobalFilterChanged;
    }

    private void OnGlobalFilterChanged()
    {
        // Re-apply tab-specific filters when global state changes
        ApplyTabSpecificFilters();
    }
}
```

#### Task 1.2: Create Tab Filter Extraction Helper

Add a method to extract tab-relevant criteria from FilterGroup.

**File:** `src/PCAPAnalyzer.UI/Models/FilterGroup.cs`

```csharp
/// <summary>
/// Extracts threat-specific filter criteria from this group.
/// Returns null if no threat criteria are set.
/// </summary>
public (List<string>? Severities, List<string>? Categories)? GetThreatCriteria()
{
    if ((Severities?.Count ?? 0) == 0 && (ThreatCategories?.Count ?? 0) == 0)
        return null;
    return (Severities, ThreatCategories);
}

/// <summary>
/// Extracts VoiceQoS-specific filter criteria from this group.
/// </summary>
public (List<string>? Codecs, List<string>? Qualities, List<string>? Issues)? GetVoiceQoSCriteria()
{
    if ((Codecs?.Count ?? 0) == 0 && (QualityLevels?.Count ?? 0) == 0 && (VoipIssues?.Count ?? 0) == 0)
        return null;
    return (Codecs, QualityLevels, VoipIssues);
}

/// <summary>
/// Extracts country-specific filter criteria from this group.
/// </summary>
public (List<string>? Countries, List<string>? Regions)? GetCountryCriteria()
{
    if ((Countries?.Count ?? 0) == 0 && (Regions?.Count ?? 0) == 0)
        return null;
    return (Countries, Regions);
}
```

---

### Phase 2: Threats Tab Filtering (45 min)

#### Task 2.1: Implement Threat Filtering Logic

**File:** `src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs`

Find the property that holds the threats list (likely `Threats` or `FilteredThreats`).

```csharp
// Add filtered collection
[ObservableProperty]
private ObservableCollection<SecurityThreat> _filteredThreats = new();

// Original unfiltered data (from cache)
private IReadOnlyList<SecurityThreat> _allThreats = Array.Empty<SecurityThreat>();

private void ApplyTabSpecificFilters()
{
    // Start with all threats
    IEnumerable<SecurityThreat> result = _allThreats;

    // Collect all threat criteria from include groups
    var includeSeverities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var includeCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    foreach (var group in _globalFilterState.IncludeGroups)
    {
        var criteria = group.GetThreatCriteria();
        if (criteria.HasValue)
        {
            if (criteria.Value.Severities != null)
                foreach (var s in criteria.Value.Severities)
                    includeSeverities.Add(s);
            if (criteria.Value.Categories != null)
                foreach (var c in criteria.Value.Categories)
                    includeCategories.Add(c);
        }
    }

    // Apply include filters (OR within category)
    if (includeSeverities.Count > 0)
    {
        result = result.Where(t => includeSeverities.Contains(t.Severity));
    }
    if (includeCategories.Count > 0)
    {
        result = result.Where(t => includeCategories.Contains(t.Type));
    }

    // Collect exclude criteria
    var excludeSeverities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var excludeCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    foreach (var group in _globalFilterState.ExcludeGroups)
    {
        var criteria = group.GetThreatCriteria();
        if (criteria.HasValue)
        {
            if (criteria.Value.Severities != null)
                foreach (var s in criteria.Value.Severities)
                    excludeSeverities.Add(s);
            if (criteria.Value.Categories != null)
                foreach (var c in criteria.Value.Categories)
                    excludeCategories.Add(c);
        }
    }

    // Apply exclude filters
    if (excludeSeverities.Count > 0)
    {
        result = result.Where(t => !excludeSeverities.Contains(t.Severity));
    }
    if (excludeCategories.Count > 0)
    {
        result = result.Where(t => !excludeCategories.Contains(t.Type));
    }

    // Update UI
    FilteredThreats.Clear();
    foreach (var threat in result)
    {
        FilteredThreats.Add(threat);
    }

    // Update count display
    OnPropertyChanged(nameof(ThreatCount));
}
```

#### Task 2.2: Update UI Binding

Ensure the Threats tab UI binds to `FilteredThreats` instead of the raw collection.

**File:** `src/PCAPAnalyzer.UI/Views/ThreatsView.axaml`

```xml
<!-- Change ItemsSource from Threats to FilteredThreats -->
<DataGrid ItemsSource="{Binding FilteredThreats}" ...>
```

---

### Phase 3: VoiceQoS Tab Filtering (45 min)

#### Task 3.1: Implement VoiceQoS Filtering Logic

**File:** `src/PCAPAnalyzer.UI/ViewModels/VoiceQoSViewModel.cs`

The VoiceQoS data is stored in `QoSTraffic` or similar. Filter by codec/quality.

```csharp
private void ApplyTabSpecificFilters()
{
    IEnumerable<QoSConnection> result = _allQoSConnections;

    // Collect codec filters
    var includeCodecs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var includeQualities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    foreach (var group in _globalFilterState.IncludeGroups)
    {
        var criteria = group.GetVoiceQoSCriteria();
        if (criteria.HasValue)
        {
            if (criteria.Value.Codecs != null)
                foreach (var c in criteria.Value.Codecs)
                    includeCodecs.Add(c);
            if (criteria.Value.Qualities != null)
                foreach (var q in criteria.Value.Qualities)
                    includeQualities.Add(q);
        }
    }

    // Apply codec filter
    if (includeCodecs.Count > 0)
    {
        result = result.Where(q =>
            includeCodecs.Any(c => q.QoSType?.Contains(c, StringComparison.OrdinalIgnoreCase) ?? false) ||
            includeCodecs.Any(c => q.Codec?.Equals(c, StringComparison.OrdinalIgnoreCase) ?? false)
        );
    }

    // Apply quality filter (Good, Fair, Poor, etc.)
    if (includeQualities.Count > 0)
    {
        result = result.Where(q => includeQualities.Contains(GetQualityLevel(q)));
    }

    // Update filtered collection
    FilteredQoSConnections.Clear();
    foreach (var conn in result)
    {
        FilteredQoSConnections.Add(conn);
    }
}

private string GetQualityLevel(QoSConnection conn)
{
    // Derive quality from jitter/latency thresholds
    if (conn.AverageJitter > 50 || conn.AverageLatency > 200)
        return "Poor";
    if (conn.AverageJitter > 30 || conn.AverageLatency > 150)
        return "Fair";
    return "Good";
}
```

---

### Phase 4: Country Tab Filtering (30 min)

#### Task 4.1: Implement Country Filtering Logic

**File:** `src/PCAPAnalyzer.UI/ViewModels/CountryTrafficViewModel.cs`

```csharp
private void ApplyTabSpecificFilters()
{
    IEnumerable<CountryStatistic> result = _allCountryStats;

    var includeCountries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var includeRegions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    foreach (var group in _globalFilterState.IncludeGroups)
    {
        var criteria = group.GetCountryCriteria();
        if (criteria.HasValue)
        {
            if (criteria.Value.Countries != null)
                foreach (var c in criteria.Value.Countries)
                    includeCountries.Add(c);
            if (criteria.Value.Regions != null)
                foreach (var r in criteria.Value.Regions)
                    includeRegions.Add(r);
        }
    }

    // Apply country filter
    if (includeCountries.Count > 0)
    {
        result = result.Where(c => includeCountries.Contains(c.CountryCode));
    }

    // Apply region filter (map country to region)
    if (includeRegions.Count > 0)
    {
        result = result.Where(c => includeRegions.Contains(GetRegion(c.CountryCode)));
    }

    // Exclude logic...

    FilteredCountries.Clear();
    foreach (var country in result)
    {
        FilteredCountries.Add(country);
    }
}
```

---

### Phase 5: DI Registration (15 min)

#### Task 5.1: Update ServiceConfiguration

**File:** `src/PCAPAnalyzer.UI/ServiceConfiguration.cs`

Ensure `GlobalFilterState` is injected into tab ViewModels:

```csharp
// GlobalFilterState should already be singleton
services.AddSingleton<GlobalFilterState>();

// Tab ViewModels - verify they receive GlobalFilterState
services.AddTransient<ThreatsViewModel>();
services.AddTransient<VoiceQoSViewModel>();
services.AddTransient<CountryTrafficViewModel>();
```

---

### Phase 6: Testing (30 min)

#### Test Cases

1. **Threats Tab - Severity Filter**
   - Apply "Critical" severity filter
   - Verify only Critical threats shown in ThreatsTab
   - Verify Dashboard still shows all packets

2. **VoiceQoS Tab - Codec Filter**
   - Apply "G.729" codec filter
   - Verify only G.729 connections shown
   - Verify RTP packet count unchanged on Dashboard

3. **Country Tab - Country Filter**
   - Apply "CN" (China) country filter
   - Verify only China traffic shown
   - Verify map highlights China

4. **Clear Button**
   - Apply filters, click Clear
   - Verify immediate reset to unfiltered state

5. **Combined Filters**
   - Apply IP filter (General) + Severity filter (Threats)
   - Verify Dashboard shows filtered packets
   - Verify ThreatsTab shows both IP-filtered AND severity-filtered threats

---

## Files Modified Summary

| File | Change |
|------|--------|
| `UnifiedFilterPanelViewModel.cs` | ✅ DONE - Clear auto-applies |
| `DashboardViewModel.Filters.cs` | ✅ DONE - Documented limitations |
| `FilterGroup.cs` | Add `GetThreatCriteria()`, `GetVoiceQoSCriteria()`, `GetCountryCriteria()` |
| `ThreatsViewModel.cs` | Add `ApplyTabSpecificFilters()`, subscribe to `OnFilterChanged` |
| `VoiceQoSViewModel.cs` | Add `ApplyTabSpecificFilters()`, subscribe to `OnFilterChanged` |
| `CountryTrafficViewModel.cs` | Add `ApplyTabSpecificFilters()`, subscribe to `OnFilterChanged` |
| `ThreatsView.axaml` | Bind to `FilteredThreats` |
| `VoiceQoSView.axaml` | Bind to filtered collection |
| `CountryTrafficView.axaml` | Bind to filtered collection |

---

## Post-Implementation Checklist

- [ ] Build succeeds with 0 errors, 0 warnings
- [ ] All existing tests pass
- [ ] Clear button immediately shows unfiltered data
- [ ] Threats severity filter works
- [ ] VoiceQoS codec filter works
- [ ] Country filter works
- [ ] Combined filters (General + Tab-specific) work
- [ ] Filter chips display correctly in summary bar
- [ ] Memory usage acceptable (no leaks from event subscriptions)

---

## Known Limitations

1. **Cross-tab filtering is one-way:** A severity filter on Threats doesn't affect Dashboard packet count. This is by design - severity is a property of threats, not packets.

2. **Codec matching is fuzzy:** "G.729" in QoSType field may be "G.729a" or "G729" - use Contains() not Equals().

3. **Region mapping required:** Need a country-to-region mapping for region filters to work.

---

## Quick Start for Next Session

```bash
# 1. Open the project
cd "/mnt/d/PCAP_Net10_Avalonia_TShark - Cursor"

# 2. Start with Phase 1, Task 1.1 - add GlobalFilterState to ThreatsViewModel

# 3. Test incrementally after each phase
dotnet build && dotnet run --project src/PCAPAnalyzer.UI

# 4. Run tests
dotnet test tests/PCAPAnalyzer.Tests
```

**Start with:** `src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs`

---

*This guide was generated by Claude Code on 2025-12-01*
