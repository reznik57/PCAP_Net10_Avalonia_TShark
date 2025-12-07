# Updated Refactor Plan

**Date:** 2025-12-07
**Status:** Active
**Baseline:** 1094 tests passing, 0 warnings

---

## Current State Assessment

### Completed (from original plan)

| Item | Status |
|------|--------|
| Phase 1: Async void fixes | ✅ Done (commit `982eff9`) |
| Phase 1: Exception handling | ✅ Done (App.axaml.cs global handlers) |
| Phase 2: Interface definitions | ✅ Done (4 interfaces exist) |
| Phase 2: Config extraction | ✅ Done (ports, protocols, timeouts, countries JSON) |
| Security: Command injection fix | ✅ Done (commit `2955c76`) |

### Interfaces Already Created

```
src/PCAPAnalyzer.Core/Interfaces/Statistics/
├── IStatisticsCalculator.cs  ✅
├── IGeoIPEnricher.cs         ✅
├── IThreatDetector.cs        ✅
└── ITimeSeriesGenerator.cs   ✅
```

### Still Pending

| Item | Original Plan | Current State |
|------|---------------|---------------|
| MainWindowViewModel | Target: 400 lines | Actual: 1,340 lines |
| ThreatsViewModel | Target: 450 lines | Actual: 1,117 lines |
| DashboardViewModel | Target: 500 lines | Actual: 997 lines |
| Config externalization | `config/*.json` | ✅ All 5 configs exist (monitoring, ports, protocols, timeouts, countries) |
| Deprecated code removal | IGlobalFilterService | Still referenced in ServiceConfiguration |
| OptimizedTSharkService | Parallel TShark | Not started |

---

## Revised Phases

### Phase 2: Configuration Extraction ✅ COMPLETE
**Risk: Low | Effort: Medium**

All configuration files and IOptions<T> classes exist:

```
config/
├── monitoring.json     ✅ EXISTS
├── ports.json          ✅ EXISTS (WellKnownPorts, EncryptedPorts, InsecurePorts)
├── protocols.json      ✅ EXISTS (ProtocolColors, SecurityRatings, SuspiciousProtocols)
├── timeouts.json       ✅ EXISTS (TShark, GeoIP, cache timeouts)
└── countries.json      ✅ EXISTS (HighRiskCountries, ContinentMappings)
```

- UnifiedGeoIPService now uses IOptions<CountryConfiguration> for high-risk countries
- ThreatDetector uses IOptions<ProtocolConfiguration> for suspicious protocols

### Phase 3: Deprecated Code Removal ✅ COMPLETE
**Risk: Medium | Effort: Low**

| Target | Status |
|--------|--------|
| `IGlobalFilterService` | ✅ Already removed (only comment reference remains) |
| Obsolete TShark methods | ✅ Removed (BuildStreamingArguments, etc.) |
| `CreateProcessStartInfoLegacy` | ✅ Removed |
| `PortDatabase` static class | ✅ Kept - serves different purpose than IOptions config |

**Remaining tech debt (acceptable for now):**
- `CachedStatisticsService.CalculateStatistics` sync wrapper still has callers
  - All callers use `Task.Run()` pattern which is acceptable
  - Full async migration would require significant ViewModel changes

### Phase 4: ViewModel Decomposition (NEXT)
**Risk: High | Effort: High**

#### MainWindowViewModel (1,340 → 400 lines)

Already has component pattern:
- `MainWindowFileViewModel` ✅
- `MainWindowAnalysisViewModel` ✅
- `MainWindowUIStateViewModel` ✅
- `MainWindowChartsViewModel` ✅
- `MainWindowPacketViewModel` ✅
- `MainWindowDashboardViewModel` ✅

**Remaining extraction:**
1. Move tab orchestration to `ITabOrchestrationService`
2. Move filter coordination to `IFilterCoordinator`
3. Remove duplicate logic between components

#### ThreatsViewModel (1,117 → 450 lines)

Extract:
1. Threat analysis logic → `IThreatAnalysisService`
2. Chart building → `ThreatsChartsViewModel` component
3. Export logic → Use existing `IExportService`

#### DashboardViewModel (997 → 500 lines)

Extract:
1. Statistics calculation → Use `IStatisticsCalculator`
2. Chart data preparation → `DashboardChartsViewModel` component
3. Filtering logic → `IFilterCoordinator`

### Phase 5: OptimizedTSharkService
**Risk: High | Effort: High**

Already exists: `ParallelTSharkService.cs`

Verify/enhance:
1. Confirm editcap splitting works
2. Confirm parallel TShark processes
3. Benchmark throughput (target: 50,000 pkt/s)
4. Tune chunk sizes based on file size

---

## Success Criteria

- [ ] All 1094+ tests pass
- [ ] 0 build warnings
- [ ] No ViewModels >500 lines
- [ ] All config in JSON files
- [ ] No deprecated code
- [ ] TShark throughput >50,000 pkt/s

---

## Recommended Execution Order

1. **Phase 2: Config extraction** ✅ COMPLETE
2. **Phase 3: Deprecated removal** ✅ COMPLETE
3. **Phase 4: ViewModel decomposition** - Highest value, highest risk ← NEXT
4. **Phase 5: TShark optimization** - Performance tuning last

---

## Verification After Each Phase

```bash
dotnet build && dotnet test
```

Manual smoke test after Phases 3, 4, 5.
