# Anomalies Tab Design

**Date:** 2025-12-02
**Status:** Approved
**Author:** Claude (Principal Engineer review)

## Overview

A NEW dedicated Anomalies tab alongside the existing Threats tab, following Dashboard's visual patterns and interaction models. Separates behavioral/traffic anomalies from security vulnerabilities for cleaner investigation workflows.

**Separation of Concerns:**
- **Anomalies Tab:** Behavioral/traffic deviations (SYN floods, retransmissions, beaconing, exfiltration patterns)
- **Threats Tab:** Security vulnerabilities (CVEs, insecure protocols, cleartext credentials)

## Architecture

### ViewModel Composition

```
AnomaliesViewModel : SmartFilterableTab
├── AnomaliesChartsViewModel      // Timeline, ports bar, category donut
├── AnomaliesStatisticsViewModel  // KPIs, ranked tables (sources/targets)
├── AnomaliesPopupViewModel       // Row detail popup state
├── AnomaliesDrillDownViewModel   // Time-slice drill-down analysis
└── AnomaliesFilterViewModel      // Severity/category/detector chip state
```

### Data Flow

```
AnalysisResult.Anomalies (from SessionAnalysisCache)
    ↓
AnomaliesViewModel.LoadFromAnalysisResultAsync()
    ├→ Store _allAnomalies: List<NetworkAnomaly>
    ├→ Build _frameToAnomalyMap (for global filter support)
    ├→ Calculate KPIs (counts, unique IPs, time span)
    ├→ Group by time buckets for timeline
    ├→ Rank sources/targets by anomaly count
    └→ UpdateAllComponentsAsync()
         ├→ Charts.UpdateTimeline(timeSeriesData)
         ├→ Charts.UpdateCategoryDonut(categoryGroups)
         ├→ Charts.UpdatePortsBar(portGroups)
         ├→ Statistics.UpdateKPIs(kpis)
         └→ Statistics.UpdateRankedTables(sources, targets)
```

## Visual Layout

### Master Structure

```
AnomaliesView.axaml
├── Filter Progress Bar (conditional)
└── ScrollViewer
    └── StackPanel (Margin: 24, Spacing: 24)
        │
        ├── UnifiedFilterPanelControl
        │   └── Extended with: [Severity chips] [Category chips] [Detector toggles]
        │
        ├── KPI Row (6-column Grid)
        │   ┌─────────────┬──────────┬──────────┬───────────────┬───────────────┬────────────┐
        │   │ Total       │ Critical │ High     │ Unique        │ Unique        │ Time       │
        │   │ Anomalies   │ (red)    │ (orange) │ Sources       │ Targets       │ Span       │
        │   │ (blue)      │          │          │ (cyan)        │ (pink)        │ (purple)   │
        │   └─────────────┴──────────┴──────────┴───────────────┴───────────────┴────────────┘
        │
        ├── Anomaly Timeline (Hero Chart, 320px height)
        │   Header: "Anomalies Over Time" + [Zoom In/Out/Reset]
        │   4 series: Critical (red), High (orange), Medium (yellow), Low (blue)
        │   X-axis: Time | Y-axis: Anomalies/minute
        │   Tooltip: Multi-colored severity breakdown
        │   Click: Opens time-slice drill-down popup
        │
        ├── Secondary Charts Row (2-column Grid)
        │   ┌─────────────────────────┬─────────────────────────┐
        │   │ Anomalous Ports         │ Category Distribution   │
        │   │ (Horizontal Bar, 250px) │ (Donut Chart, 250px)    │
        │   └─────────────────────────┴─────────────────────────┘
        │
        ├── Ranked Tables Row (2-column Grid)
        │   ┌─────────────────────────┬─────────────────────────┐
        │   │ Top Anomalous Sources   │ Top Anomalous Targets   │
        │   │ (IP, Count, Severity,   │ (IP, Count, Severity,   │
        │   │  Categories, Details)   │  Categories, Details)   │
        │   │ 440px scroll height     │ 440px scroll height     │
        │   └─────────────────────────┴─────────────────────────┘
        │
        └── Drill-Down Popup Overlay (conditional, semi-transparent)
```

### Color Scheme

| Severity | Color | Hex |
|----------|-------|-----|
| Critical | Red | `#F85149` |
| High | Orange | `#F59E0B` |
| Medium | Yellow | `#FCD34D` |
| Low | Blue | `#3B82F6` |

### Visual Styling (Dashboard-consistent)

- **Card Background:** `#0D1117`
- **Card Border:** `1px #30363D`
- **Corner Radius:** `8px`
- **Card Padding:** `20px`
- **Page Margin:** `24px`
- **Section Spacing:** `24px`
- **Accent Bar:** `3px` colored stripe above card headers

## Data Models

### AnomalySourceViewModel (Table Rows)

```csharp
public class AnomalySourceViewModel : ObservableObject
{
    public string IPAddress { get; set; }
    public int AnomalyCount { get; set; }
    public AnomalySeverity HighestSeverity { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public List<AnomalyCategory> Categories { get; set; }
    public double Percentage { get; set; }
    public int Rank { get; set; }
    public string Country { get; set; }
    public List<long> AffectedFrames { get; set; }
}
```

### AnomalyKPIs

```csharp
public class AnomalyKPIs
{
    public int TotalAnomalies { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int UniqueSourceIPs { get; set; }
    public int UniqueTargetIPs { get; set; }
    public TimeSpan TimeSpan { get; set; }
}
```

### Table Row Template

```
┌──────┬─────────────────┬─────────┬───────────────┬────────────────┬─────────┐
│ Rank │ IP Address      │ Country │ Severity Bar  │ Categories     │ Details │
│ #1   │ 192.168.1.100   │ US      │ ████████ 45%  │ [TCP][Network] │   →     │
└──────┴─────────────────┴─────────┴───────────────┴────────────────┴─────────┘
```

- **Severity Bar:** Width proportional to percentage, color by highest severity
- **Category Badges:** Small colored pills, max 3 visible with "+N more" overflow

## Drill-Down Interactions

### Time-Slice Drill-Down (Click Timeline)

```
┌─────────────────────────────────────────────────────────────────┐
│ Anomalies: 14:30 - 14:35                              [X Close] │
├─────────────────────────────────────────────────────────────────┤
│ Summary: 23 anomalies (5 Critical, 8 High, 6 Medium, 4 Low)     │
├─────────────────────────────────────────────────────────────────┤
│ Breakdown by Category:                                          │
│   [████████] TCP (12)  [████] Network (6)  [███] Security (5)   │
├─────────────────────────────────────────────────────────────────┤
│ Top Anomalies in Window:                                        │
│   🔴 SYN Flood Attack → 192.168.1.100 (Critical)               │
│   🟠 TCP Retransmission 8.2% on stream 47 (High)               │
│   🟠 Beaconing detected from 10.0.0.55 (High)                  │
├─────────────────────────────────────────────────────────────────┤
│ [View All Packets in Window]  [Export Window Data]              │
└─────────────────────────────────────────────────────────────────┘
```

### Row Detail Popup (Click Details Button)

```
┌─────────────────────────────────────────────────────────────────┐
│ Source Analysis: 192.168.1.100                        [X Close] │
├─────────────────────────────────────────────────────────────────┤
│ US  |  45 anomalies  |  First: 14:02, Last: 14:47              │
├─────────────────────────────────────────────────────────────────┤
│ Severity Breakdown:        │ Category Breakdown:                │
│   Critical: 5              │   TCP: 28                          │
│   High: 18                 │   Network: 12                      │
│   Medium: 15               │   Security: 5                      │
│   Low: 7                   │                                    │
├─────────────────────────────────────────────────────────────────┤
│ Anomaly List (paginated, 10/page):                    Page 1/5  │
│   14:02:33  🔴 SYN Flood Attack         → 10.0.0.1:443         │
│   14:05:17  🟠 TCP Retransmission 12%   → 10.0.0.1:443         │
├─────────────────────────────────────────────────────────────────┤
│ Evidence Packets:                                     [20/page] │
│   Frame 1234, 1238, 1245, 1267, ...                             │
├─────────────────────────────────────────────────────────────────┤
│ Recommendations:                                                │
│   • Block IP at firewall if external                            │
│   • Investigate host if internal (possible compromise)          │
└─────────────────────────────────────────────────────────────────┘
```

### Chart Segment Click

- Click category donut segment → Filter table to that category
- Click ports bar → Filter to anomalies involving that port
- Visual feedback: clicked segment highlights, others fade to 50% opacity

## Filter Architecture

### GlobalFilterState Extension

```csharp
public class GlobalFilterState
{
    // Existing common filters
    public List<string> SourceIPs { get; set; }
    public List<string> DestinationIPs { get; set; }
    public PortRange? PortRange { get; set; }
    public DateTimeRange? TimeRange { get; set; }
    public List<string> Protocols { get; set; }

    // NEW: Anomaly filters (global scope)
    public List<AnomalySeverity> AnomalySeverityFilter { get; set; }
    public List<AnomalyCategory> AnomalyCategoryFilter { get; set; }
    public List<string> AnomalyDetectorFilter { get; set; }
}
```

### Filter Panel Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ COMMON FILTERS (synced across tabs)                             │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │ Source IP   │ │ Dest IP     │ │ Port Range  │ │ Time Range  │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│ ANOMALY FILTERS (global - affects all tabs)                     │
│                                                                 │
│ Severity:  [Critical] [High] [Medium] [Low]    ← toggle chips   │
│            (red)      (orange)(yellow)(blue)      OR logic      │
│                                                                 │
│ Category:  [Network] [TCP] [Application] [VoIP] [IoT] [Security]│
│                                                                 │
│ Detector:  [▾ Select detectors...]  ← dropdown multi-select     │
├─────────────────────────────────────────────────────────────────┤
│ Active Filters: [192.168.1.x ✕] [Critical ✕] [TCP ✕]  [Clear All]│
└─────────────────────────────────────────────────────────────────┘
```

### Filter Logic

- **AND** between filter categories
- **OR** within each category
- Example: `[Critical OR High] AND [TCP OR Network] AND [Source: 192.168.1.x]`

### Cross-Tab Impact

| Tab | When anomaly filter active |
|-----|---------------------------|
| **Dashboard** | Shows only packets in matching anomalies' `AffectedFrames` |
| **Threats** | Filters to threats sharing IPs/ports with matching anomalies |
| **Anomalies** | Direct filter on anomaly list |
| **VoiceQoS** | Shows only streams with matching VoIP anomalies |
| **Country Traffic** | Shows traffic from countries with matching anomalies |

## File Structure

### New Files

```
src/PCAPAnalyzer.UI/
├── ViewModels/
│   ├── AnomaliesViewModel.cs
│   ├── AnomaliesViewModel.Filters.cs
│   └── Components/
│       ├── AnomaliesChartsViewModel.cs
│       ├── AnomaliesStatisticsViewModel.cs
│       ├── AnomaliesPopupViewModel.cs
│       ├── AnomaliesDrillDownViewModel.cs
│       └── AnomaliesFilterViewModel.cs
│
├── Views/
│   ├── AnomaliesView.axaml
│   ├── AnomaliesView.axaml.cs
│   ├── AnomaliesView.ChartHandlers.cs
│   ├── AnomaliesView.TooltipManager.cs
│   └── AnomaliesView.ZoomControls.cs
│
├── Models/
│   └── AnomalyDisplayModels.cs
│
└── Services/
    ├── IAnomalyFrameIndexService.cs
    └── AnomalyFrameIndexService.cs
```

### Modified Files

- `GlobalFilterState.cs` - Add anomaly filter properties
- `MainWindowViewModel.cs` - Add AnomaliesViewModel property
- `MainWindow.axaml` - Add Anomalies tab
- `ServiceConfiguration.cs` - Register new services
- `DashboardViewModel.cs` - Honor anomaly filters via frame lookup
- `ThreatsViewModel.cs` - Honor anomaly filters
- `VoiceQoSViewModel.cs` - Honor anomaly filters
- `CountryTrafficViewModel.cs` - Honor anomaly filters

## Integration

### AnomalyFrameIndexService

```csharp
public interface IAnomalyFrameIndexService
{
    void BuildIndex(List<NetworkAnomaly> anomalies);

    HashSet<long> GetFramesMatchingFilters(
        List<AnomalySeverity>? severities,
        List<AnomalyCategory>? categories,
        List<string>? detectors);

    List<NetworkAnomaly> GetAnomaliesForFrame(long frameNumber);
}

public class AnomalyFrameIndexService : IAnomalyFrameIndexService
{
    private List<NetworkAnomaly> _allAnomalies;
    private Dictionary<long, List<NetworkAnomaly>> _frameToAnomalies;

    public void BuildIndex(List<NetworkAnomaly> anomalies)
    {
        _allAnomalies = anomalies;
        _frameToAnomalies = anomalies
            .SelectMany(a => a.AffectedFrames.Select(f => (Frame: f, Anomaly: a)))
            .GroupBy(x => x.Frame)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Anomaly).ToList());
    }

    public HashSet<long> GetFramesMatchingFilters(
        List<AnomalySeverity>? severities,
        List<AnomalyCategory>? categories,
        List<string>? detectors)
    {
        var matching = _allAnomalies.AsEnumerable();

        if (severities?.Any() == true)
            matching = matching.Where(a => severities.Contains(a.Severity));
        if (categories?.Any() == true)
            matching = matching.Where(a => categories.Contains(a.Category));
        if (detectors?.Any() == true)
            matching = matching.Where(a => detectors.Contains(a.DetectorName));

        return matching.SelectMany(a => a.AffectedFrames).ToHashSet();
    }
}
```

### ServiceConfiguration Addition

```csharp
// In ConfigureServices()
services.AddSingleton<IAnomalyFrameIndexService, AnomalyFrameIndexService>();
services.AddTransient<AnomaliesViewModel>();
services.AddTransient<AnomaliesChartsViewModel>();
services.AddTransient<AnomaliesStatisticsViewModel>();
services.AddTransient<AnomaliesPopupViewModel>();
services.AddTransient<AnomaliesDrillDownViewModel>();
services.AddTransient<AnomaliesFilterViewModel>();
```

### Tab Order

```
[Dashboard] [Anomalies] [Threats] [VoiceQoS] [Country Traffic] [Packet Analysis]
```

Anomalies positioned after Dashboard, before Threats - logical investigation flow from overview → behavioral anomalies → security threats.

## Summary

| Aspect | Decision |
|--------|----------|
| **Type** | NEW tab alongside Threats |
| **Position** | After Dashboard, before Threats |
| **Architecture** | Composition pattern (5 component ViewModels) |
| **Hero Chart** | Anomaly Timeline (4 severity lines, zoom, click drill-down) |
| **KPIs** | Total, Critical, High, Unique Sources, Unique Targets, Time Span |
| **Secondary Viz** | Ports bar chart, Category donut |
| **Tables** | Top Anomalous Sources, Top Anomalous Targets (ranked) |
| **Drill-Down** | Time-slice popup, Row detail popup, Chart segment filtering |
| **Filters** | Global anomaly filters affecting all tabs |
| **Styling** | Dashboard-consistent dark theme |
