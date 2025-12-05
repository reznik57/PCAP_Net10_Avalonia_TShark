# Complete Technical Debt Refactoring Plan

**Date:** 2025-12-05
**Status:** In Progress
**Scope:** Full architectural cleanup across all layers

---

## Executive Summary

Comprehensive refactoring of PCAP Analyzer codebase (533 files, 121K LOC) to address:
- Security vulnerabilities (BinaryFormatter)
- Dead code and unused services
- Inconsistent architectural patterns
- Large monolithic files (12 files >1000 lines)
- Service Locator anti-patterns
- Duplicate code across ViewModels
- Pending design implementations

---

## Phase 0: Security & Dead Code (P0 - Critical)

### 0.1 Security: Replace BinaryFormatter
**File:** `src/PCAPAnalyzer.Core/Services/ML/Models/OneClassSvmModel.cs`
**Issue:** BinaryFormatter is obsolete and insecure
**Action:** Replace with System.Text.Json serialization

### 0.2 Dead Code: Remove unused interfaces
**Files to DELETE:**
- `src/PCAPAnalyzer.Core/Interfaces/IFilterLogic.cs` - zero usages
- `src/PCAPAnalyzer.Core/Services/FilterLogic.cs` - contains unused IFilterServiceCore

### 0.3 Dead Code: Remove unused services
**Files to DELETE or integrate:**
- `src/PCAPAnalyzer.UI/Services/SuricataService.cs` - instantiated but never called
- `src/PCAPAnalyzer.UI/Services/YaraService.cs` - instantiated but never called

**File to MODIFY:**
- `src/PCAPAnalyzer.UI/ViewModels/MainWindowViewModel.cs` - remove SuricataService/YaraService instantiation (lines 279-284)

### 0.4 Dead Code: Remove wrapper service
**File to DELETE:**
- `src/PCAPAnalyzer.Core/Services/NetworkFilterHelperService.cs` - thin wrapper delegating to static NetworkFilterHelper

**File to MODIFY:**
- `src/PCAPAnalyzer.UI/ServiceConfiguration.cs` - register NetworkFilterHelper directly or remove registration

### 0.5 Dead Code: Remove deprecated global filter
**Files to DELETE:**
- `src/PCAPAnalyzer.UI/Models/GlobalFilterState.cs` - deprecated, replaced by ITabFilterService
- `src/PCAPAnalyzer.UI/Helpers/GlobalFilterStateHelper.cs` - helper for deprecated system

---

## Phase 1: Map Control Consolidation (P1 - High)

### Current State: 8 map controls
1. `UnifiedMapControl.cs` (base)
2. `ContinentMapControlV2.cs` (1074 lines)
3. `EnhancedWorldMapControl.cs` (857 lines)
4. `GeographicMapControlV2.cs`
5. `DetailedWorldMapControl.cs`
6. `ShapefileWorldMapControl.cs` (1074 lines)
7. `SimpleWorldMapControl.cs`
8. `StaticWorldMapControl.axaml.cs`

### Target Architecture
```
IMapControl (interface)
    │
    └── MapControl (unified implementation)
            │
            ├── IMapRenderingStrategy
            │       ├── ContinentRenderingStrategy
            │       ├── CountryRenderingStrategy
            │       └── SimpleRenderingStrategy
            │
            └── IMapDataProvider
                    ├── ShapefileDataProvider
                    └── EmbeddedPathDataProvider
```

### Action Plan
1. Create `IMapRenderingStrategy` interface
2. Extract rendering logic from each control into strategies
3. Create unified `MapControl` that accepts strategy
4. Migrate all views to use unified control
5. Delete redundant control files

---

## Phase 2: Filter Unification (P1 - High)

### Current State: 3 different filtering paradigms
1. **Dashboard:** SmartFilterableTab with chip-based INCLUDE/EXCLUDE
2. **CountryTraffic:** RxJS Subject with debouncing
3. **Threats:** Direct property-based filtering

### Target Architecture
All tabs use `SmartFilterableTab` base class with:
- Chip-based filter UI
- INCLUDE/EXCLUDE groups
- Consistent debouncing
- Unified filter service integration

### Action Plan
1. Audit `SmartFilterableTab` for completeness
2. Migrate `CountryTrafficViewModel` to inherit SmartFilterableTab
3. Migrate `ThreatsViewModel` to inherit SmartFilterableTab
4. Migrate `AnomaliesViewModel` to inherit SmartFilterableTab
5. Remove duplicate filtering code from each ViewModel

---

## Phase 3: Large File Decomposition (P2 - Medium)

### Files >1000 lines requiring decomposition

| File | Lines | Target | Strategy |
|------|-------|--------|----------|
| VoiceQoSViewModel.cs | 1295 | <400 | Extract Charts, Statistics, DrillDown components |
| MainWindowChartsViewModel.cs | 1198 | <400 | Move chart data logic to ChartDataService |
| EnhancedFilterViewModel.cs | 1186 | <400 | Extract filter categories into sub-VMs |
| TSharkService.cs | 1151 | <500 | Extract TSharkParser, TSharkExecutor |
| PacketDetailsViewModel.cs | 1141 | <400 | Extract Hex, Security, Stream sub-VMs |
| MainWindowAnalysisViewModel.cs | 1118 | <400 | Already component-based, reduce orchestration |
| ShapefileWorldMapControl.cs | 1074 | DELETE | Replace with unified MapControl |
| ThreatsViewModel.cs | 1062 | <400 | Has components, reduce main to orchestrator |
| UnifiedGeoIPService.cs | 1056 | <400 | Split: Provider, Locator, Analyzer, Profiler |
| CountryTrafficViewModel.cs | 1033 | <400 | Extract Export, Statistics components |
| MainWindowViewModel.cs | 1008 | <400 | Already component-based, reduce further |
| DashboardViewModel.cs | 991 | OK | Acceptable for composed orchestrator |

---

## Phase 4: Service Locator Elimination (P2 - Medium)

### Current Anti-Pattern
```csharp
// MainWindowViewModel.cs lines 286-324
var cacheService = App.Services?.GetService<IAnalysisCacheService>();
var credentialService = App.Services?.GetService<ICredentialDetectionService>();
// ... 8 more service resolutions
```

### Target Pattern
```csharp
public MainWindowViewModel(
    IAnalysisCacheService cacheService,
    ICredentialDetectionService credentialService,
    // ... explicit constructor injection
)
```

### Files to Modify
1. `MainWindowViewModel.cs` - inject all 10+ services
2. `DashboardViewModel.cs` - inject IGeoIPService
3. `CountryTrafficViewModel.Export.cs` - inject IGeoIPService
4. `FileAnalysisViewModel.cs` - audit service resolution

---

## Phase 5: Extract Shared Abstractions (P2 - Medium)

### 5.1 BaseSecurityMetricsViewModel
**Duplicated in:** DashboardStatisticsViewModel, CountryStatisticsViewModel, ThreatsStatisticsViewModel, LiveStatisticsViewModel

```csharp
public abstract class BaseSecurityMetricsViewModel : ObservableObject
{
    [ObservableProperty] private int _totalThreats;
    [ObservableProperty] private int _criticalThreats;
    [ObservableProperty] private int _highThreats;
    [ObservableProperty] private int _mediumThreats;
    [ObservableProperty] private int _lowThreats;
    [ObservableProperty] private double _overallRiskScore;
    [ObservableProperty] private string _riskLevel = "Unknown";
    [ObservableProperty] private string _riskLevelColor = "#6B7280";

    protected void UpdateFromThreats(IEnumerable<SecurityThreat> threats) { ... }
}
```

### 5.2 IChartDataService
**Duplicated in:** DashboardChartsViewModel, ThreatsChartsViewModel, AnomaliesChartsViewModel, VoiceQoSChartsViewModel

```csharp
public interface IChartDataService
{
    ISeries[] CreateProtocolDistributionChart(NetworkStatistics stats);
    ISeries[] CreateTimeSeriesChart(IEnumerable<TimeSeriesDataPoint> data);
    ISeries[] CreateTopTalkersChart(IEnumerable<EndpointStatistics> endpoints);
}
```

### 5.3 IAnomalyDetector Base Interface
**Issue:** Some detectors implement IAnomalyDetector, others are standalone
**Action:** All 8 detectors implement common interface with shared severity logic

### 5.4 IFileDialogService Abstraction
**Issue:** ViewModels directly access Avalonia platform APIs
**Action:** Extract file dialog operations to injected service

---

## Phase 6: Implement Pending Designs (P3 - Low)

### 6.1 TShark Memory Optimization
**Design:** `docs/plans/2025-12-03-tshark-memory-optimization-design.md`
**Summary:** StringPool for IP/protocol interning, 60% memory reduction

### 6.2 Slack-Style UI Redesign
**Design:** `docs/plans/2025-12-04-slack-style-ui-redesign.md`
**Summary:** Color palette, tab bar, filter panel, button styles

### 6.3 Anomalies Packet Table
**Design:** `docs/plans/2025-12-03-anomalies-packet-table-design.md`
**Summary:** Packet table showing anomaly-triggering packets

---

## Phase 7: Complete TODO Stubs (P3 - Low)

### 7.1 PDF Report Generation
**File:** `src/PCAPAnalyzer.Core/Services/Reporting/PdfReportGenerator.cs`
**TODO:** "Implement PDF generation using QuestPDF"

### 7.2 CSV Export - Anomalies
**File:** `src/PCAPAnalyzer.UI/ViewModels/AnomalyViewModel.cs`
**TODO:** "Implement CSV export"

### 7.3 CSV Export - Host Inventory
**File:** `src/PCAPAnalyzer.UI/ViewModels/HostInventoryViewModel.cs`
**TODO:** "Implement CSV export"

### 7.4 Async Refactor - Anomalies
**File:** `src/PCAPAnalyzer.UI/ViewModels/AnomaliesViewModel.cs`
**TODO:** "Refactor to async if needed for GeoIP enrichment"

---

## Phase 8: Interface Cleanup (P3 - Low)

### Split ITabFilterService (21 methods → 3 interfaces)
```csharp
// Core filtering
public interface ITabFilterService { ... } // 8 methods

// Predefined filters
public interface IPredefinedFilterProvider { ... } // 10 methods

// Quick filter builder
public interface IQuickFilterBuilder { ... } // 3 methods
```

### Remove Single-Implementation Interfaces (evaluate)
- IProtocolSecurityEvaluator → direct service
- IPortDatabase → direct service
- IPacketStatisticsCalculator → static utility

---

## Verification Checklist

After each phase:
- [ ] `dotnet build` - zero warnings
- [ ] `dotnet test` - all 1093 tests pass
- [ ] Manual smoke test - app launches, can analyze PCAP
- [ ] Git commit with phase summary

---

## Risk Mitigation

1. **Incremental commits** - each sub-task is a separate commit
2. **Feature branches** - major phases in separate branches
3. **Test coverage** - run full test suite after each change
4. **Rollback points** - tag before each phase starts

---

## Estimated Scope

| Phase | Files Modified | Files Deleted | New Files |
|-------|---------------|---------------|-----------|
| P0 | 5 | 5 | 0 |
| P1 | 15 | 7 | 4 |
| P2 | 8 | 0 | 1 |
| P3 | 12 | 0 | 0 |
| P4 | 4 | 0 | 0 |
| P5 | 8 | 0 | 3 |
| P6 | 10 | 0 | 4 |
| P7 | 4 | 0 | 0 |
| **Total** | ~66 | 12 | 12 |

