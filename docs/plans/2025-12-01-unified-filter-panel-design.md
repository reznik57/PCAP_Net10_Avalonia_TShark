# Unified Filter Panel Design

**Date:** 2025-12-01
**Status:** Approved
**Problem:** Current filter UI has 3 stacked sections consuming ~350px, confusing INCLUDE/EXCLUDE separation, and poor discoverability.

## Design Overview

Replace the current 3-section filter layout with a unified panel featuring:
- Global mode toggle (Include/Exclude)
- Summary rows showing all active filters
- Tabbed organization for filter categories
- All filters apply globally with lazy per-tab computation

### Visual Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ [Include ●] [Exclude ○]                      [Apply] [Clear]   │
│                                                                 │
│ ✓ Including: [TCP ×] [192.168.1.0/24 ×] [Port:443 ×]           │
│ ✗ Excluding: [HTTP ×] [10.0.0.1 ×]                             │
├─────────────────────────────────────────────────────────────────┤
│ [General] [Threats] [VoiceQoS] [Country]                        │
├─────────────────────────────────────────────────────────────────┤
│ (Tab content - filter chips and inputs for selected category)  │
└─────────────────────────────────────────────────────────────────┘
```

**Space improvement:** ~350px → ~180px

## Mode Toggle & Summary

### Mode Toggle Behavior

| State | Include Button | Exclude Button | Chip Click Effect |
|-------|---------------|----------------|-------------------|
| Include mode (default) | Filled green | Hollow/dimmed | Adds to Including row |
| Exclude mode | Hollow/dimmed | Filled red | Adds to Excluding row |

### Summary Row Behavior

- **Empty state:** Rows hidden entirely
- **With filters:** Rows appear showing chips with `×` for removal
- **Chip format:**
  - Protocol: `[TCP ×]`
  - IP: `[192.168.1.0/24 ×]`
  - Port: `[Port:443 ×]` or `[Port:80-443 ×]`

### Buttons

- **Apply:** Triggers filter computation, shows loading if >100ms
- **Clear:** Removes all filters, resets to default state

## Filter Category Tabs

### General Tab (default)
```
Protocols:   [TCP] [UDP] [ICMP] [DNS] [HTTP] [HTTPS] [TLS] [QUIC]...
Security:    [Insecure] [Anomalies] [Suspicious] [Cleartext]
TLS:         [TLS 1.0] [TLS 1.1] [TLS 1.2] [TLS 1.3]
TCP Flags:   [SYN] [FIN] [RST] [PSH] [ACK]

Source IP:      [__________________]
Destination IP: [__________________]
Port Range:     [__________________]
```

### Threats Tab
```
Severity:    [Critical] [High] [Medium] [Low]
Category:    [Network] [Application] [Crypto] [Exfiltration] [IoT] [VoIP]
Threat Type: [Retransmission] [Port Scan] [Cleartext Auth]...

Search:      [__________________]
```

### VoiceQoS Tab
```
Codecs:      [G.711] [G.729] [Opus] [H.264]...
Quality:     [Poor] [Fair] [Good] [Excellent]
Issues:      [High Jitter] [High Latency] [Packet Loss]

Jitter Threshold:  [____ ms]
Latency Threshold: [____ ms]
```

### Country Tab
```
Direction:   [Inbound] [Outbound] [Internal]
Regions:     [North America] [Europe] [Asia] [Middle East]...
Countries:   [US] [CN] [RU] [DE]...

Country Search: [__________________]
```

### Chip Visual States

- **Inactive:** Gray background, subtle border
- **Included:** Green background
- **Excluded:** Red background

## Data Architecture

### GlobalFilterState (Singleton)

```csharp
public class GlobalFilterState : INotifyPropertyChanged
{
    public FilterMode CurrentMode { get; set; } = FilterMode.Include;

    public FilterCriteria IncludeFilters { get; } = new();
    public FilterCriteria ExcludeFilters { get; } = new();

    public int Version { get; private set; }
    public event Action? OnFilterChanged;

    public void IncrementVersion() => Version++;
}

public class FilterCriteria
{
    public HashSet<string> Protocols { get; } = new();
    public HashSet<string> SourceIPs { get; } = new();
    public HashSet<string> DestIPs { get; } = new();
    public HashSet<PortRange> Ports { get; } = new();
    public HashSet<string> Severities { get; } = new();
    public HashSet<string> Categories { get; } = new();
    public HashSet<string> TlsVersions { get; } = new();
    public HashSet<string> TcpFlags { get; } = new();
    // ... etc
}
```

### Per-Tab Lazy Evaluation

```csharp
public abstract class FilterableTabViewModel : ViewModelBase
{
    private int _lastAppliedFilterVersion = -1;

    protected override void OnActivated()
    {
        var globalVersion = _globalFilterState.Version;
        if (globalVersion != _lastAppliedFilterVersion)
        {
            _ = ApplyFiltersAsync();
            _lastAppliedFilterVersion = globalVersion;
        }
    }
}
```

### Filter Logic

```
INCLUDE first, EXCLUDE second:

IF IncludeFilters empty:
    candidates = AllPackets
ELSE:
    candidates = AllPackets.Where(IncludeMatch)

Result = candidates.Where(!ExcludeMatch)
```

**Rationale:** Matches search engine conventions, more intuitive ("show X except Y").

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Click included chip while in Exclude mode | Move from Include → Exclude |
| Click excluded chip while in Exclude mode | Remove from Exclude (toggle off) |
| Same value in both Include and Exclude | Prevent with toast "Already in Include list" |
| Invalid IP format | Red border, tooltip "Invalid IP format" |
| Invalid port range | Red border, tooltip "Port must be 1-65535" |
| 20+ active filters | Horizontal scroll or wrap summary row |

## Keyboard Shortcuts (Optional)

- `I` - Switch to Include mode
- `E` - Switch to Exclude mode
- `Enter` in text field - Add filter
- `Ctrl+Enter` - Apply filters

## Migration Notes

### Files to Modify

- `IGlobalFilterService.cs` - Replace deprecated interface
- `GlobalFilterState.cs` - New singleton state class
- `FilterPanelControl.axaml` - Complete UI redesign
- `DashboardFilterService.cs` - Update to use new state model
- `*ViewModel.cs` - Add lazy filter version checking

### Files to Remove

- Current `EXCLUDE FILTERS` section
- Current `INCLUDE MODE` toggle in Quick Filters
- Redundant `THREAT FILTERS` section (merged into Threats tab)

## Success Criteria

1. **Space reduction:** ~350px → ~180px (48% reduction)
2. **Discoverability:** New users understand Include/Exclude without instructions
3. **Performance:** Tab switching with filter changes <300ms for 1M packets
4. **Consistency:** All filters apply globally, all tabs respect filter state
