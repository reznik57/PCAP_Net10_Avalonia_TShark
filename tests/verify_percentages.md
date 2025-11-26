# Percentage Calculation Verification

## Test Scenarios

### Scenario 1: Top Connections by Bytes
- Total Traffic: 100 MB
- Top Connection: 5 MB
- **Expected Percentage**: 5% (5/100)
- **Previous (Wrong)**: Would show 25% if top 10 total was 20 MB

### Scenario 2: Top Connections by Packets  
- Total Packets: 10,000
- Top Connection: 500 packets
- **Expected Percentage**: 5% (500/10,000)
- **Previous (Wrong)**: Would show 50% if top 10 total was 1,000 packets

### Scenario 3: Source IPs by Bytes
- Total Traffic: 1 GB
- Top Source IP: 100 MB
- **Expected Percentage**: 10% (100/1000)
- **Previous (Wrong)**: Would show 50% if top sources total was 200 MB

### Scenario 4: Destination IPs by Bytes
- Total Traffic: 500 MB  
- Top Destination IP: 25 MB
- **Expected Percentage**: 5% (25/500)
- **Previous (Wrong)**: Would show 25% if top destinations total was 100 MB

## Code Verification

### DashboardViewModelExtensions.cs (Lines 308-320)
```csharp
// CORRECT - Uses total statistics
var totalBytes = _currentStatistics?.TotalBytes ?? 0;
var totalPackets = _currentStatistics?.TotalPackets ?? 0;

foreach (var conn in connectionsByBytes)
{
    conn.Percentage = totalBytes > 0 ? (conn.ByteCount * 100.0) / totalBytes : 0;
}

foreach (var conn in connectionsByPackets)
{
    conn.Percentage = totalPackets > 0 ? (conn.PacketCount * 100.0) / totalPackets : 0;
}
```

### DashboardViewModel.cs (UpdateSourcesByBytes)
```csharp
// CORRECT - Uses total traffic bytes
var totalTrafficBytes = _currentStatistics.TotalBytes;
Percentage = totalTrafficBytes > 0 ? (source.ByteCount * 100.0) / totalTrafficBytes : 0;
```

### DashboardViewModel.cs (UpdateDestinationsByBytes)
```csharp
// CORRECT - Uses total traffic bytes
var totalTrafficBytes = _currentStatistics.TotalBytes;
Percentage = totalTrafficBytes > 0 ? (dest.ByteCount * 100.0) / totalTrafficBytes : 0;
```

## Expected Behavior After Fix

1. **Percentages are absolute**: Each item shows its percentage of TOTAL traffic
2. **Sum can be < 100%**: Top 10 items might only represent 60% of total traffic
3. **Consistent across views**: Toggling between Top 10/25 doesn't change individual percentages
4. **More realistic values**: Top items typically show single-digit percentages unless traffic is highly concentrated

## Manual Testing Steps

1. Load a PCAP file with diverse traffic
2. Check Dashboard tab
3. Verify for each table:
   - Top Connections by Bytes: % values relative to Quick Stats "Total Bytes"
   - Top Connections by Packets: % values relative to Quick Stats "Total Packets"  
   - Source IPs by Bytes: % values relative to Quick Stats "Total Bytes"
   - Destination IPs by Bytes: % values relative to Quick Stats "Total Bytes"
4. Toggle between Top 10/25 views
5. Confirm individual percentages don't change (only more/fewer items shown)

## Validation Formula

For any item:
```
Percentage = (Item Value / Total Statistics Value) × 100
```

Where:
- For Bytes tables: Total Statistics Value = _currentStatistics.TotalBytes
- For Packets tables: Total Statistics Value = _currentStatistics.TotalPackets

## Success Criteria

✅ Percentages reflect portion of TOTAL traffic, not just displayed items
✅ Individual percentages remain constant when toggling display count
✅ Sum of all traffic (not just displayed) should equal ~100%
✅ More realistic percentage values (typically < 10% for individual items)