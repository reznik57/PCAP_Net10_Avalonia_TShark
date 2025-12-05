# Anomalies Packet Table Design

**Date:** 2025-12-03
**Status:** Approved

## Overview

Add a Packet Analysis table to the Anomalies tab showing packets that triggered anomalies, with context-sensitive filtering.

## Requirements

1. **Global table** at bottom showing all anomalous packets (union of all `NetworkAnomaly.AffectedFrames`)
2. **Context-sensitive filtering** when clicking Details on sources/targets/categories/ports
3. **In-memory packets** from `MainWindowPacketViewModel` (no re-query)
4. **Anomaly column** showing which anomaly triggered each packet (most severe if multiple)

## Data Model

```csharp
public class AnomalyPacketViewModel
{
    public PacketInfo Packet { get; set; }

    // Primary anomaly (highest severity)
    public string AnomalyType { get; set; }
    public AnomalySeverity Severity { get; set; }
    public AnomalyCategory Category { get; set; }

    // Multi-anomaly support
    public int AnomalyCount { get; set; }
    public List<NetworkAnomaly> AllAnomalies { get; set; }
}
```

## Component Architecture

```
AnomaliesViewModel (existing)
    │
    ├── AnomaliesPacketTableViewModel (NEW)
    │       ├── AllAnomalousPackets: List<AnomalyPacketViewModel>
    │       ├── FilteredPackets: ObservableCollection<AnomalyPacketViewModel>
    │       ├── CurrentFilter: source/target/category/port/time
    │       ├── Pagination (CurrentPage, TotalPages, PageSize=30)
    │       └── SelectedPacket → PacketDetailsPanel
    │
    └── DrillDown (existing)
            └── FilterByAnomalyContext() calls
```

## UI Layout

Table appears at bottom of AnomaliesView, below Top Sources/Top Targets:

**Columns:**
- Frame # (with bookmark indicator)
- Time (HH:mm:ss.fff)
- Source IP
- Src Port
- Destination IP
- Dst Port
- Protocol (color-coded)
- Size
- **Anomaly Type** (e.g., "TCP Retransmission", "+2 more" if multiple)
- **Severity Badge** (colored dot: Critical/High/Medium/Low)

**Header:** "Anomaly Packet Analysis" with packet count badge and filter status

## Filter Interactions

| Trigger | Filter |
|---------|--------|
| Details on Source row | `FilterBySource(ip)` |
| Details on Target row | `FilterByTarget(ip)` |
| Details on Category row | `FilterByCategory(category)` |
| Details on Port row | `FilterByPort(port)` |
| Chart click | `FilterByTimeWindow(timestamp, ±30s)` |
| "Show All" button | `ClearFilter()` |

Filter badge shows active filter with X to clear.

## Implementation Files

**New:**
- `src/PCAPAnalyzer.UI/Models/AnomalyPacketViewModel.cs`
- `src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesPacketTableViewModel.cs`

**Modify:**
- `src/PCAPAnalyzer.UI/Views/AnomaliesView.axaml` - add table section
- `src/PCAPAnalyzer.UI/ViewModels/AnomaliesViewModel.cs` - wire up PacketTable VM

**Reuse:**
- `PacketDetailsPanel` control
- Pagination pattern from `PacketTableControl`
- Severity/Protocol color converters

## Data Flow

1. Analysis complete → `AnomaliesViewModel` receives anomalies
2. Build `Dictionary<long, List<NetworkAnomaly>>` frame index
3. Get packets from `MainWindowPacketViewModel.CachedDashboardPackets`
4. Filter packets by frame numbers in index
5. Create `AnomalyPacketViewModel` list joining packet + anomaly data
6. Pagination displays 30 per page
