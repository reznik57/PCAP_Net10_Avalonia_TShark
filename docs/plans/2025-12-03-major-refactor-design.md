# Major Refactor: File Size Reduction & Code Organization

**Date:** 2025-12-03
**Goal:** All files under 25k tokens (~75KB), improved maintainability
**Scope:** 20 files >35KB

---

## Summary

Refactor large files using three strategies:
1. **Component extraction** for ViewModels/Controls
2. **External JSON** for data-heavy files
3. **Service decomposition** for Core services

---

## Target Files

### Strategy A: Component Extraction

| File | Current Size | Target Size | Components |
|------|-------------|-------------|------------|
| MainWindowViewModel.cs | 113KB | ~30KB | Consolidate existing pattern |
| ThreatsViewModel.cs | 81KB | ~25KB | Charts, DrillDown, Filters |
| DashboardViewModel.cs | 76KB | ~25KB | Charts, Statistics, Filters |
| ContinentMapControlV2.cs | 73KB | ~25KB | Rendering, Interaction, Data |
| VoiceQoSChartsViewModel.cs | 54KB | ~25KB | Per-chart components |
| PacketDetailsViewModel.cs | 50KB | ~25KB | Tabs, Hex, Protocol |
| VoiceQoSViewModel.cs | 49KB | ~25KB | Charts, Streams, Metrics |
| MainWindowAnalysisViewModel.cs | 47KB | Review | May be acceptable |
| SmartFilterableTab.cs | 46KB | ~20KB | Base, FilterLogic, UIBindings |
| MainWindowChartsViewModel.cs | 45KB | Review | May be acceptable |
| EnhancedWorldMapControl.cs | 38KB | ~20KB | Rendering, Interaction |
| DashboardChartsViewModel.cs | 38KB | ~20KB | Per-chart components |
| EnhancedFilterViewModel.cs | 38KB | ~20KB | Groups, Presets, Logic |
| EnhancedMapViewModel.cs | 34KB | Review | May be acceptable |
| CountryTrafficViewModel.cs | 33KB | Review | May be acceptable |
| ContinentSubmapControl.cs | 33KB | Review | May be acceptable |

### Strategy B: External JSON Data

| File | Current Size | Extract To |
|------|-------------|------------|
| PortDatabase.cs | 74KB → ~15KB | `Resources/Data/ports.json` |
| InsecurePortDetector.cs | 57KB → ~15KB | `Resources/Data/insecure-ports.json` |

### Strategy C: Service Decomposition

| File | Current Size | Split Into |
|------|-------------|------------|
| ProtocolDeepDiveService.cs | 63KB | Per-protocol analyzers |
| ProtocolSecurityEvaluator.cs | 50KB | Per-protocol evaluators |
| TSharkService.cs | 48KB | Core, Parsing, Process, Platform |

---

## Architecture Patterns

### Component Extraction Pattern (ViewModels)

```
ViewModels/
├── Base/
│   ├── SmartFilterableTab.cs
│   ├── SmartFilterableTab.Filtering.cs
│   └── SmartFilterableTab.UIState.cs
├── Components/
│   ├── Shared/
│   │   ├── FilterPanelViewModel.cs
│   │   └── DrillDownPanelViewModel.cs
│   ├── Dashboard/
│   │   ├── DashboardChartsViewModel.cs
│   │   ├── DashboardStatisticsViewModel.cs
│   │   └── DashboardFiltersViewModel.cs
│   ├── Threats/
│   │   ├── ThreatsChartsViewModel.cs
│   │   ├── ThreatsDrillDownViewModel.cs
│   │   └── ThreatsFiltersViewModel.cs
│   └── VoiceQoS/
│       ├── VoiceQoSStreamsViewModel.cs
│       ├── VoiceQoSMetricsViewModel.cs
│       └── VoiceQoSChartsViewModel.cs
├── DashboardViewModel.cs      # Thin coordinator
├── ThreatsViewModel.cs        # Thin coordinator
└── VoiceQoSViewModel.cs       # Thin coordinator
```

**Composition Pattern:**
```csharp
public partial class ThreatsViewModel : SmartFilterableTab
{
    public ThreatsChartsViewModel Charts { get; }
    public ThreatsDrillDownViewModel DrillDown { get; }
    public ThreatsFiltersViewModel Filters { get; }

    public ThreatsViewModel(
        ThreatsChartsViewModel charts,
        ThreatsDrillDownViewModel drillDown,
        ThreatsFiltersViewModel filters)
    {
        Charts = charts;
        DrillDown = drillDown;
        Filters = filters;
    }

    protected override async Task LoadDataCoreAsync()
    {
        await Charts.RefreshAsync(_analysisResult);
        await DrillDown.InitializeAsync(_analysisResult);
    }
}
```

**Principles:**
- Parent owns data, children render
- Components are DI-registered
- No circular dependencies
- Events for upward communication

### External JSON Data Pattern

```
src/PCAPAnalyzer.Core/
├── Resources/Data/
│   ├── ports.json
│   ├── registered-ports.json
│   ├── insecure-ports.json
│   └── malware-ports.json
├── Security/
│   ├── PortDatabase.cs      # Loader + lookup
│   ├── PortDefinition.cs    # Model
│   └── IPortDatabase.cs     # Interface
```

**JSON Schema:**
```json
{
  "version": "1.0",
  "lastUpdated": "2025-01-15",
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "service": "SSH",
      "description": "Secure Shell",
      "category": "remote-access",
      "securityRating": "secure",
      "commonUsage": ["administration", "file-transfer"]
    }
  ]
}
```

**Loader:**
```csharp
public sealed class PortDatabase : IPortDatabase
{
    private readonly FrozenDictionary<(int Port, string Protocol), PortDefinition> _ports;

    public PortDatabase()
    {
        using var stream = typeof(PortDatabase).Assembly
            .GetManifestResourceStream("PCAPAnalyzer.Core.Resources.Data.ports.json");
        var data = JsonSerializer.Deserialize<PortDataFile>(stream);
        _ports = data.Ports.ToFrozenDictionary(p => (p.Port, p.Protocol));
    }
}
```

### Service Decomposition Pattern

**ProtocolDeepDiveService → Registry + Analyzers:**
```
Services/ProtocolAnalysis/
├── IProtocolAnalyzer.cs
├── ProtocolAnalyzerRegistry.cs
├── Analyzers/
│   ├── DnsAnalyzer.cs
│   ├── HttpAnalyzer.cs
│   ├── TlsAnalyzer.cs
│   └── GenericTcpAnalyzer.cs
```

**TSharkService → Focused Classes:**
```
TShark/
├── TSharkService.cs              # Coordinator
├── Processing/
│   ├── TSharkProcessManager.cs
│   ├── TSharkOutputParser.cs
│   └── TSharkFieldMapper.cs
├── Configuration/
│   ├── TSharkCommandBuilder.cs
│   └── TSharkFieldDefinitions.cs
└── Platform/
    ├── ITSharkPlatformAdapter.cs
    ├── WindowsTSharkAdapter.cs
    ├── WslTSharkAdapter.cs
    └── LinuxTSharkAdapter.cs
```

### Controls Decomposition Pattern

**Rendering Pipeline:**
```
Controls/Maps/
├── ContinentMapControl.cs
├── Rendering/
│   ├── IMapRenderer.cs
│   ├── ContinentPathRenderer.cs
│   ├── TrafficHeatmapRenderer.cs
│   └── ConnectionLineRenderer.cs
├── Interaction/
│   ├── MapInteractionHandler.cs
│   └── ContinentSelectionManager.cs
└── Data/
    ├── ContinentGeometry.cs
    └── MapProjection.cs
```

```csharp
public class ContinentMapControl : Control
{
    private readonly IMapRenderer[] _renderers;

    public override void Render(DrawingContext context)
    {
        var mapContext = new MapRenderContext(context, Bounds, _projection);
        foreach (var renderer in _renderers)
            renderer.Render(mapContext, DataContext as MapViewModel);
    }
}
```

---

## Implementation Plan

### Phase 1: Foundation (Low Risk)
1. Extract PortDatabase to JSON
2. Extract InsecurePortDetector to JSON
3. Decompose TSharkService
4. Decompose ProtocolDeepDiveService
5. Decompose ProtocolSecurityEvaluator

### Phase 2: ViewModel Components (Medium Risk)
6. Split SmartFilterableTab (base for all tabs)
7. Extract ThreatsViewModel components
8. Extract DashboardViewModel components
9. Extract VoiceQoSViewModel components
10. Extract PacketDetailsViewModel components

### Phase 3: Controls (Higher Risk)
11. Decompose ContinentMapControlV2
12. Decompose EnhancedWorldMapControl

### Phase 4: Cleanup
13. Review remaining 35-45KB files
14. Remove deprecated code paths
15. Update documentation

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Breaking changes | Keep originals until verified, use `[Obsolete]` |
| DI registration | Add incrementally, verify startup |
| XAML bindings | Search `.axaml` before renaming |
| Test coverage | Run `dotnet test` after each extraction |

---

## Definition of Done (per file)

- [ ] New component files created
- [ ] Original file delegates to components
- [ ] DI registrations updated in ServiceConfiguration.cs
- [ ] `dotnet build` succeeds with 0 warnings
- [ ] `dotnet test` passes
- [ ] Manual smoke test of affected UI
- [ ] File size under 75KB (~25k tokens)

---

## Success Metrics

- All 20 target files under 75KB
- Zero test regressions
- Build succeeds with no new warnings
- UI functionality unchanged
