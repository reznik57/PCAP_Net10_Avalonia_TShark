---
name: pcap:add-anomaly-detector
description: Use when adding a new anomaly detection rule or detector type - ensures proper interface implementation, threshold documentation, testing, and DI registration
---

# Add Anomaly Detector Skill

This skill guides you through adding a new anomaly detector to the PCAP analyzer.

## Prerequisites

Before starting, ensure you understand:
- The detection pattern you want to implement
- What packets/protocols are relevant
- Threshold values and their justification

## Mandatory Checklist

Create TodoWrite todos for EACH of these items:

### Phase 1: Design
- [ ] Define the anomaly type (add to `AnomalyType` enum if new)
- [ ] Document detection logic in plain English
- [ ] Define threshold constants with justification comments
- [ ] Identify required PacketInfo fields

### Phase 2: Implementation
- [ ] Create detector class in `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/`
- [ ] Implement `IAnomalyDetector` interface
- [ ] Add threshold constants at top of file with documentation
- [ ] Implement `DetectAsync` method following the standard pattern
- [ ] Limit `SampleFrameNumbers` to 100 max
- [ ] Use `ConfigureAwait(false)` on all async calls
- [ ] Support `CancellationToken` throughout

### Phase 3: Integration
- [ ] Register detector in `UnifiedAnomalyDetectionService`
- [ ] Add detector to DI in `ServiceConfiguration.cs`
- [ ] Verify detector is called by orchestrator

### Phase 4: Testing
- [ ] Create test class in `tests/PCAPAnalyzer.Tests/Services/AnomalyDetectors/`
- [ ] Write positive test (pattern present → anomaly detected)
- [ ] Write negative test (no pattern → no anomaly)
- [ ] Write threshold boundary test
- [ ] Test with small packet counts (<100 packets)
- [ ] Test with large packet counts (>10000 packets)

### Phase 5: Validation
- [ ] Run `dotnet build` — zero warnings
- [ ] Run `dotnet test` — all tests pass
- [ ] Test with real PCAP file containing the pattern

## Standard Detector Pattern

```csharp
public class MyNewDetector : IAnomalyDetector
{
    // ALWAYS document threshold justification
    private const int MY_THRESHOLD = 100;  // Based on: [reasoning]
    private const int MAX_SAMPLE_FRAMES = 100;

    private readonly ILogger<MyNewDetector> _logger;

    public MyNewDetector(ILogger<MyNewDetector> logger)
    {
        _logger = logger;
    }

    public async Task<IEnumerable<NetworkAnomaly>> DetectAsync(
        IReadOnlyList<PacketInfo> packets,
        CancellationToken cancellationToken = default)
    {
        var anomalies = new List<NetworkAnomaly>();

        // 1. Filter relevant packets
        var relevant = packets
            .Where(p => IsRelevant(p))
            .ToList();

        if (relevant.Count == 0)
            return anomalies;

        // 2. Group by analysis dimension
        var groups = relevant.GroupBy(p => GetGroupKey(p));

        // 3. Analyze each group
        foreach (var group in groups)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (MeetsThreshold(group))
            {
                anomalies.Add(CreateAnomaly(group));
            }
        }

        return anomalies;
    }

    private NetworkAnomaly CreateAnomaly(IGrouping<string, PacketInfo> group)
    {
        return new NetworkAnomaly
        {
            Id = Guid.NewGuid().ToString(),
            Type = AnomalyType.MyNewType,
            Severity = CalculateSeverity(group),
            Description = $"Detected pattern: {group.Key}",
            DetailedAnalysis = BuildDetailedAnalysis(group),
            FirstSeen = group.Min(p => p.Timestamp),
            LastSeen = group.Max(p => p.Timestamp),
            OccurrenceCount = group.Count(),
            SampleFrameNumbers = group
                .Take(MAX_SAMPLE_FRAMES)
                .Select(p => p.FrameNumber)
                .ToList()
        };
    }
}
```

## Severity Scoring Guide

| Score Range | Severity | Criteria |
|-------------|----------|----------|
| 0.0 - 0.3 | Low | Informational, likely benign |
| 0.3 - 0.6 | Medium | Suspicious, warrants investigation |
| 0.6 - 0.8 | High | Likely malicious |
| 0.8 - 1.0 | Critical | Active attack |

## Common Mistakes to Avoid

1. **Hardcoded thresholds without documentation** — Always explain why
2. **Missing cancellation support** — Check token in loops
3. **Unbounded SampleFrameNumbers** — Limit to 100
4. **No small capture handling** — Test with <100 packets
5. **Sync-over-async** — Never use `.Result` or `.Wait()`

## When Done

Run the verification skill:
```
/superpowers:verification-before-completion
```
