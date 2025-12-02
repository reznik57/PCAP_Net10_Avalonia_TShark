# Port Chart Duplicate Fix - 2025-12-02

## Issue Summary

**Problem 1:** Yellow line (Port 443) disappeared when clearing filters in the Port Activity Timeline chart.

**Problem 2:** NuGet package restore errors in IDE.

## Root Cause Analysis

### Issue 1: Port Chart Line Disappearing

**Symptoms:**
- Port 443 (yellow, index 2) generated with correct data (sample log values: 2.11, 2.29, 2.12)
- 5 series created after filter clear, but Port 443 line invisible
- Logs showed Port 2598 appearing TWICE at indices [0] and [1]

**Root Cause:**
The `CalculateTopPortsWithCount` method in `StatisticsCalculator.cs` was tracking port statistics using `(Port, Protocol)` tuples to distinguish TCP vs UDP traffic. This caused duplicate port numbers in the final TopPorts list:

```
[0] Port 2598/TCP: 459.730 packets
[1] Port 2598/UDP: 145.805 packets
[2] Port 443/TCP: ...
```

When the chart code re-sorted and took the top 5 ports:
```csharp
var topPorts = _currentStatistics.TopPorts
    .OrderByDescending(p => ShowPortActivityAsThroughput ? p.ByteCount : p.PacketCount)
    .Take(displayCount)  // displayCount = 5
```

Port 443 was pushed out of the top 5 because two slots were consumed by duplicate Port 2598 entries.

### Issue 2: NuGet Restore

Standard package cache corruption - resolved with `dotnet restore --force`.

## Solution Implemented

### Fix 1: Port Consolidation in StatisticsCalculator

Modified `CalculateTopPortsWithCount` in `/src/PCAPAnalyzer.Core/Services/Statistics/StatisticsCalculator.cs` (lines 173-197):

```csharp
// FIX: Consolidate duplicate ports (same port number, different protocols)
// This prevents the chart from showing Port 2598 twice and pushing Port 443 out of view
var consolidatedPorts = topPorts
    .Where(p => p.Port > 0) // Exclude protocol-only entries (Port=0)
    .GroupBy(p => p.Port)
    .Select(g => {
        // If multiple protocols for same port, aggregate them
        var first = g.First();
        return new PortStatistics
        {
            Port = first.Port,
            Protocol = g.Count() > 1 ? string.Join("/", g.Select(x => x.Protocol).Distinct()) : first.Protocol,
            Service = first.Service,
            PacketCount = g.Sum(x => x.PacketCount),
            ByteCount = g.Sum(x => x.ByteCount),
            Percentage = packets.Count > 0 ? (double)g.Sum(x => x.PacketCount) / packets.Count * 100 : 0,
            IsWellKnown = first.IsWellKnown
        };
    })
    .ToList();

// Re-add protocol-only entries (ICMP, etc.)
consolidatedPorts.AddRange(topPorts.Where(p => p.Port == 0));

return (consolidatedPorts.OrderByDescending(p => p.PacketCount).Take(30).ToList(), uniquePortCount);
```

**Key Changes:**
1. **Group by port number**: Consolidates entries with same port but different protocols
2. **Aggregate statistics**: Sums PacketCount and ByteCount across protocols
3. **Protocol display**: Shows "TCP/UDP" for multi-protocol ports
4. **Preserve protocol-only**: ICMP and other non-port protocols remain separate

### Fix 2: NuGet Restore

```bash
dotnet restore --force
dotnet build
```

## Verification

### Test Coverage

Created new test `CalculateTopPortsWithCount_WithDuplicatePortDifferentProtocols_ConsolidatesIntoSingleEntry` in `/tests/PCAPAnalyzer.Tests/Services/Statistics/StatisticsCalculatorTests.cs`:

```csharp
[Fact]
public void CalculateTopPortsWithCount_WithDuplicatePortDifferentProtocols_ConsolidatesIntoSingleEntry()
{
    // Arrange - Same port 2598 used with both TCP and UDP
    var packets = new List<PacketInfo>
    {
        CreatePortPacket(2598, Protocol.TCP, 100),
        CreatePortPacket(2598, Protocol.TCP, 100),
        CreatePortPacket(2598, Protocol.UDP, 100),
        CreatePortPacket(2598, Protocol.UDP, 100),
        CreatePortPacket(443, Protocol.TCP, 100)
    };

    // Act
    var (topPorts, uniqueCount) = _calculator.CalculateTopPortsWithCount(packets, _wellKnownPorts);

    // Assert - Should consolidate Port 2598 TCP+UDP into single entry
    var port2598Entries = topPorts.Where(p => p.Port == 2598).ToList();
    port2598Entries.Should().HaveCount(1, "duplicate ports should be consolidated");

    var consolidatedPort = port2598Entries.First();
    consolidatedPort.Protocol.Should().Contain("TCP");
    consolidatedPort.Protocol.Should().Contain("UDP");
    consolidatedPort.PacketCount.Should().Be(4, "should sum packets from both TCP and UDP");

    // Port 443 should still be present
    topPorts.Should().Contain(p => p.Port == 443);
}
```

### Test Results

```
✅ All 38 StatisticsCalculatorTests passed
✅ Duplicate port consolidation test passed
✅ No regressions in existing functionality
✅ Build succeeded with 0 warnings, 0 errors
```

## Impact Analysis

### User Experience Improvements

**Before Fix:**
- Port 443 (HTTPS) invisible in chart after filter clear
- Confusing display showing same port number multiple times
- Chart limited to fewer actual ports due to duplicate entries

**After Fix:**
- All expected ports visible consistently
- Clean port labels: "Port 443 (HTTPS)", "Port 2598 (TCP/UDP)"
- Full utilization of chart display slots (5 or 10 unique ports)

### Performance Impact

- **Minimal overhead**: Single GroupBy operation on already-sorted top 30 ports
- **Memory**: Reduces duplicate entries, slightly lower memory footprint
- **No impact** on packet processing or initial statistics calculation

### Breaking Changes

**None.** The consolidation is transparent to consumers:
- `TopPorts` still returns `List<PortStatistics>`
- All fields (PacketCount, ByteCount, Percentage) remain accurate
- Protocol field enhanced to show "TCP/UDP" for multi-protocol ports

## Files Modified

1. `/src/PCAPAnalyzer.Core/Services/Statistics/StatisticsCalculator.cs`
   - Added port consolidation logic (lines 173-197)
   - Added XML documentation explaining consolidation behavior

2. `/tests/PCAPAnalyzer.Tests/Services/Statistics/StatisticsCalculatorTests.cs`
   - Added comprehensive test for duplicate port consolidation

## Design Rationale

### Why Consolidate at Calculation Time?

**Considered Alternatives:**

1. **Consolidate in UI layer** (DashboardViewModelExtensions.cs)
   - ❌ Violates separation of concerns
   - ❌ Would need to be repeated for every chart/view
   - ❌ Business logic leaking into presentation layer

2. **Keep protocol separation everywhere**
   - ❌ Confusing UX (seeing "Port 443/TCP" and "Port 443/UDP" separately)
   - ❌ Wastes chart display slots
   - ❌ Misaligns with user mental model (ports, not port-protocol pairs)

3. **✅ Consolidate in StatisticsCalculator** (chosen)
   - ✅ Single source of truth
   - ✅ All consumers benefit automatically
   - ✅ Aligns data model with user expectations
   - ✅ Protocol information preserved in Protocol field

### UniqueCount Preservation

The `uniquePortCount` return value is calculated BEFORE consolidation:
```csharp
int uniquePortCount = portStats.Count + protocolOnlyStats.Count;
```

This preserves the accurate count of unique (port, protocol) combinations for statistical accuracy while the TopPorts list shows consolidated user-friendly entries.

## Future Considerations

### Potential Enhancements

1. **Protocol breakdown in tooltips**: Show "TCP: 300 pkts, UDP: 150 pkts" on hover
2. **Configurable consolidation**: Allow users to toggle between consolidated/separated views
3. **Visual protocol indicators**: Color-code or icon to show multi-protocol ports

### Monitoring

Track in production:
- Are there ports with >2 protocols? (TCP/UDP/SCTP combinations)
- Do users expect protocol separation in certain contexts?
- Performance impact with very high port counts

## Conclusion

**Status: ✅ RESOLVED**

The duplicate port issue was caused by internal tracking granularity (port+protocol) leaking into the user-facing data structure. The fix consolidates duplicate ports at the calculation layer, ensuring consistent chart behavior and optimal display slot utilization.

**Testing:** Comprehensive test coverage confirms the fix works correctly without breaking existing functionality.

**Build:** Clean build with zero warnings or errors.

---
**Author:** Claude Code
**Date:** 2025-12-02
**Version:** PCAPAnalyzer v1.0
**Status:** Production-Ready
