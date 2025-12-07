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

### Status Summary

| Item | Original Target | Final State |
|------|-----------------|-------------|
| MainWindowViewModel | 400 lines | 1,340 lines (8 components extracted, MVVM inherent) |
| ThreatsViewModel | 450 lines | 1,117 lines (4 components extracted, MVVM inherent) |
| DashboardViewModel | 500 lines | 997 lines (9 partials + 3 components, MVVM inherent) |
| Config externalization | `config/*.json` | ✅ All 5 configs exist |
| Deprecated code removal | IGlobalFilterService | ✅ Removed (only comment remains) |
| OptimizedTSharkService | Parallel TShark | ✅ Verified working (3-4× speedup) |

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

### Phase 4: ViewModel Decomposition - ANALYSIS COMPLETE
**Risk: High | Effort: High**
**Assessment: Decomposition already largely complete. Remaining size is inherent to MVVM pattern.**

#### MainWindowViewModel (1,340 lines)

**Already has 8 component ViewModels:**
- `MainWindowFileViewModel` ✅
- `MainWindowAnalysisViewModel` ✅
- `MainWindowUIStateViewModel` ✅
- `MainWindowChartsViewModel` ✅
- `MainWindowPacketViewModel` ✅
- `MainWindowDashboardViewModel` ✅
- `MainWindowStatsViewModel` ✅
- `MainWindowNavigationViewModel` ✅

**Tech debt identified (260 lines):**
- Filter-building logic in `BuildPacketFilterFromGlobalState()` duplicates `SmartFilterBuilderService`
- Should be refactored to use `FilterBuilder` from base class
- Risk: Medium (touches GlobalFilterState integration)

#### ThreatsViewModel (1,117 lines)

**Already has 4 component ViewModels:**
- `ThreatsChartsViewModel` ✅
- `ThreatsDrillDownViewModel` ✅
- `ThreatsReportExportViewModel` ✅
- `ThreatsFilterTabViewModel` ✅

**Remaining size is:**
- MVVM property declarations (~200 lines)
- Event handlers/orchestration (~300 lines)
- Filter logic `ApplyThreatFilters()` (~80 lines)

#### DashboardViewModel (4,036 total lines across partial classes)

**Already heavily decomposed:**
- `DashboardViewModel.cs` (997 lines) - main orchestration
- `DashboardViewModel.Filters.cs` (580 lines) - filter building
- `DashboardViewModel.Filtering.cs` (384 lines) - filter application
- `DashboardViewModelExtensions.cs` (819 lines) - helper methods
- `DashboardViewModel.Export.cs` (380 lines) - export logic
- Plus 3 component ViewModels (Charts, Popup, Statistics)

**Tech debt identified:**
- `DashboardViewModel.Filters.cs` duplicates `SmartFilterBuilderService` logic
- Should consolidate to use shared service

#### Recommended Next Steps (Lower Risk)

1. **Consolidate filter logic** → Extend `ISmartFilterBuilder` to handle all `FilterGroup` properties
2. **Remove duplicate filter code** from MainWindowViewModel and DashboardViewModel
3. **Target: ~500 line reduction** (not full "400 line" target which is unrealistic for orchestrators)

### Phase 5: OptimizedTSharkService ✅ VERIFIED
**Risk: High | Effort: High**

**Implementation: `ParallelTSharkService.cs` (775 lines)**

#### Verification Results:

| Feature | Status |
|---------|--------|
| Editcap splitting | ✅ Uses `editcap -c 100000`, WSL path conversion, command injection safe |
| Parallel TShark | ✅ `SemaphoreSlim` limits to CPU cores, frame offset fix, temp cleanup |
| Fast packet counting | ✅ `capinfos -Mc` header-only (~1-2s), TShark fallback |
| Chunk size | ⚠️ Fixed 100,000 packets (works for most files) |

#### Benchmark Tool:
```bash
dotnet run --project tests/PCAPAnalyzer.Benchmark -- <pcap-file>
```

**Documented performance:** 115s → 35-50s (3-4× speedup on 12-core system)

#### Optional Future Enhancements:
- Dynamic chunk sizing for >1GB files
- Memory pressure integration with `MemoryPressureMonitor`

---

## Success Criteria

- [x] All 1094+ tests pass ✅
- [x] 0 build warnings ✅
- [x] All config in JSON files ✅ (ports, protocols, timeouts, countries, monitoring)
- [x] No deprecated code ✅ (obsolete TShark methods removed)
- [x] TShark parallel processing ✅ (ParallelTSharkService verified, benchmark tool available)
- [ ] No ViewModels >500 lines (REVISED: Main orchestrator VMs inherently large due to MVVM)

---

## Recommended Execution Order

1. **Phase 2: Config extraction** ✅ COMPLETE
2. **Phase 3: Deprecated removal** ✅ COMPLETE
3. **Phase 4: ViewModel decomposition** ✅ ANALYZED - Already decomposed, documented tech debt
4. **Phase 5: TShark optimization** ✅ VERIFIED - ParallelTSharkService working, benchmark available

---

## Verification After Each Phase

```bash
dotnet build && dotnet test
```

Manual smoke test after Phases 3, 4, 5.
