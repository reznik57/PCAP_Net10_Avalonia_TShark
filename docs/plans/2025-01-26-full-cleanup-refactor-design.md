# Full Cleanup & Refactor Design

**Date:** 2025-01-26
**Status:** Approved
**Scope:** Interface conversion, ViewModel decomposition, TShark optimization, deprecated removal, configuration extraction

---

## Executive Summary

Comprehensive refactoring of PCAP Analyzer to achieve:
- Testable architecture via DI interfaces
- 300-500 line ViewModel targets (down from 2000+)
- 50,000+ packets/second TShark performance
- Zero deprecated code
- Externalized configuration

---

## 1. Interface Definitions

### IStatisticsCalculator
Pure calculation service, no side effects.

```csharp
public interface IStatisticsCalculator
{
    List<ProtocolStatistic> CalculateProtocolStatistics(
        IEnumerable<PacketInfo> packets,
        IReadOnlyDictionary<string, string> protocolColors);

    (List<EndpointStatistic> Sources, List<EndpointStatistic> Destinations)
        CalculateTopEndpoints(IEnumerable<PacketInfo> packets, int topN = 30);

    List<ConversationStatistic> CalculateTopConversations(
        IEnumerable<PacketInfo> packets, int topN = 30);

    List<PortStatistic> CalculateTopPorts(
        IEnumerable<PacketInfo> packets, int topN = 20);

    ServiceStatistics CalculateServiceStatistics(IEnumerable<PacketInfo> packets);
}
```

### IGeoIPEnricher
Async enrichment with geographic data.

```csharp
public interface IGeoIPEnricher
{
    Task EnrichEndpointsAsync(
        IEnumerable<EndpointStatistic> endpoints,
        IProgress<int>? progress = null,
        CancellationToken ct = default);

    Task EnrichConversationsAsync(
        IEnumerable<ConversationStatistic> conversations,
        CancellationToken ct = default);

    IEnumerable<PacketInfo> SamplePackets(
        IEnumerable<PacketInfo> packets, int maxSamples = 10000);
}
```

### IThreatDetector
Heuristic-based threat detection.

```csharp
public interface IThreatDetector
{
    IEnumerable<SecurityThreat> DetectPortScanning(IEnumerable<PacketInfo> packets);
    IEnumerable<SecurityThreat> DetectSuspiciousProtocols(IEnumerable<PacketInfo> packets);
    IEnumerable<SecurityThreat> DetectAnomalousTraffic(IEnumerable<PacketInfo> packets);
    IEnumerable<SecurityThreat> DetectPotentialDDoS(IEnumerable<PacketInfo> packets);
}
```

### ITimeSeriesGenerator
Time-bucketed aggregation.

```csharp
public interface ITimeSeriesGenerator
{
    TimeSeriesResult GenerateTimeSeries(
        IEnumerable<PacketInfo> packets,
        TimeSpan bucketSize,
        IEnumerable<SecurityThreat>? threats = null);

    int CalculateMaxPacketsPerWindow(
        IEnumerable<PacketInfo> packets,
        TimeSpan window);
}
```

---

## 2. ViewModel Decomposition

### MainWindowViewModel (2,369 → ~400 lines)

**Extract to Core services:**
| Responsibility | New Service |
|----------------|-------------|
| Tab switching/population | `ITabOrchestrationService` |
| Filter coordination | `IFilterCoordinator` |

**Keep as component ViewModels:**
- `MainWindowFileViewModel` (existing)
- `MainWindowAnalysisViewModel` (existing)
- `MainWindowUIStateViewModel` (existing)
- `MainWindowChartsViewModel` (existing)

### ThreatsViewModel (1,712 → ~450 lines)

**Extract to Core services:**
| Responsibility | New Service |
|----------------|-------------|
| Threat analysis logic | `IThreatAnalysisService` |
| Export logic | `IExportService` (existing) |

**Keep:**
- Pagination via `PaginatedViewModel<T>` base
- `ThreatsChartsViewModel` component

---

## 3. OptimizedTSharkService Architecture

### Pipeline for Static Files

```
                    ┌─────────────┐
                    │ editcap     │
                    │ (split file)│
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ TShark Process 1│ │ TShark Process 2│ │ TShark Process N│
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Parser Block    │ │ Parser Block    │ │ Parser Block    │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             ▼
                    ┌─────────────────┐
                    │ MergeBlock      │
                    │ (timestamp sort)│
                    └─────────────────┘
```

### Chunk Calculation

```csharp
private int CalculateOptimalChunks(long fileSize)
{
    return fileSize switch
    {
        < 50_000_000 => 1,      // <50MB: single process
        < 200_000_000 => 2,     // 50-200MB: 2 processes
        < 500_000_000 => 4,     // 200-500MB: 4 processes
        _ => Math.Min(Environment.ProcessorCount, 8)  // >500MB: CPU cores
    };
}
```

### Performance Targets

| File Size | Target Time | Throughput |
|-----------|-------------|------------|
| 100MB | ~3 seconds | ~50,000 pkt/s |
| 1GB | ~20 seconds | ~50,000 pkt/s |

---

## 4. Configuration System

### File Structure

```
config/
├── ports.json
├── countries.json
├── timeouts.json
└── protocols.json
```

### Options Classes

```csharp
public class PortConfiguration
{
    public Dictionary<int, string> WellKnownPorts { get; set; } = new();
    public List<InsecurePortDefinition> InsecurePorts { get; set; } = new();
    public List<int> EncryptedPorts { get; set; } = new() { 443, 22, 8443 };
}

public class CountryConfiguration
{
    public HashSet<string> HighRiskCountries { get; set; } = new();
    public Dictionary<string, string> ContinentMappings { get; set; } = new();
}

public class TimeoutConfiguration
{
    public int TSharkProcessMs { get; set; } = 120_000;
    public int GeoIPLookupMs { get; set; } = 5_000;
    public int RenderDelayMs { get; set; } = 100;
    public int AnalysisCacheExpirationDays { get; set; } = 30;
}

public class ProtocolConfiguration
{
    public Dictionary<string, string> ProtocolColors { get; set; } = new();
    public Dictionary<string, int> SecurityRatings { get; set; } = new();
}
```

---

## 5. Deprecated Code Removal

| Component | Action |
|-----------|--------|
| `IGlobalFilterService` | DELETE - replaced by `ITabFilterService` |
| `GlobalFilterService` | DELETE |
| `GetLocationSync()` | DELETE - use `GetLocationAsync()` |
| `LiveCaptureService` | DELETE - replaced by `LiveCaptureManagerAdapter` |
| `PortDatabase` legacy section | DELETE - moved to JSON config |

---

## 6. Implementation Phases

### Phase 1: Stabilize (Low Risk)
1. Commit current working refactoring
2. Fix async void methods
3. Fix swallowed exception

### Phase 2: Interface Conversion (Medium Risk)
4. Create 4 interfaces
5. Convert static classes to DI services
6. Update StatisticsService injections
7. Register in ServiceConfiguration

### Phase 3: Configuration Extraction (Medium Risk)
8. Create config JSON files
9. Create Options classes
10. Update services to use IOptions<T>

### Phase 4: Deprecated Removal (Medium Risk)
11. Remove IGlobalFilterService
12. Remove sync GeoIP methods
13. Remove LiveCaptureService

### Phase 5: ViewModel Decomposition (High Risk)
14. Extract ITabOrchestrationService
15. Extract IFilterCoordinator
16. Extract IThreatAnalysisService
17. Slim ViewModels to 300-500 lines

### Phase 6: OptimizedTSharkService (High Risk)
18. Implement editcap splitting
19. Implement parallel TShark processes
20. Implement TPL Dataflow merge
21. Benchmark and tune

---

## 7. Verification Checkpoints

- After each phase: `dotnet build && dotnet test`
- After Phase 2, 4, 5: Manual smoke test
- After Phase 6: Performance benchmarks

---

## 8. Success Criteria

- [ ] All 604+ tests pass
- [ ] 0 build warnings
- [ ] No files >500 lines in ViewModels
- [ ] No static helper classes
- [ ] No deprecated code
- [ ] All config externalized to JSON
- [ ] TShark throughput >50,000 pkt/s for large files
