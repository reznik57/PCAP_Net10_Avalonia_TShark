---
name: pcap:decompose-viewmodel
description: Use when splitting a large ViewModel (>800 lines) into smaller component ViewModels - ensures proper composition, DI registration, and maintains existing functionality
---

# Decompose ViewModel Skill

This skill guides you through decomposing a large ViewModel into smaller, focused component ViewModels.

## When to Use

- ViewModel exceeds 800-1000 lines
- ViewModel has multiple distinct responsibilities
- Testing is difficult due to size
- Multiple developers need to work on different parts

## Target: ThreatsViewModel (1,556 lines)

The primary decomposition target is `ThreatsViewModel`. This skill uses it as the reference example.

## Mandatory Checklist

Create TodoWrite todos for EACH of these items:

### Phase 1: Analysis
- [ ] Read the entire ViewModel to understand all responsibilities
- [ ] Identify distinct functional areas (table, filters, drill-down, export, charts)
- [ ] Map dependencies between areas
- [ ] Identify shared state that must remain in parent

### Phase 2: Design Component Structure
- [ ] Define component ViewModels and their responsibilities
- [ ] Determine what stays in parent (shared state, coordination)
- [ ] Design communication pattern (events, callbacks, shared services)
- [ ] Plan file naming: `{Parent}ViewModel` → `{Parent}{Component}ViewModel`

### Phase 3: Extract Components (One at a Time)
For EACH component:
- [ ] Create new ViewModel class file
- [ ] Move relevant properties and methods
- [ ] Update parent to hold component reference
- [ ] Wire up DI registration
- [ ] Update AXAML bindings
- [ ] Run build to verify no breaks
- [ ] Run tests to verify functionality

### Phase 4: Update Parent ViewModel
- [ ] Keep only coordination logic in parent
- [ ] Expose component ViewModels as properties
- [ ] Wire up inter-component communication
- [ ] Remove dead code

### Phase 5: Testing
- [ ] Verify all existing functionality works
- [ ] Add unit tests for each component
- [ ] Test component interactions

### Phase 6: Validation
- [ ] Run `dotnet build` — zero warnings
- [ ] Run `dotnet test` — all tests pass
- [ ] Manual UI testing of all features

## ThreatsViewModel Decomposition Plan

### Current (1,556 lines)
```
ThreatsViewModel
├── Threat table logic
├── Severity grouping
├── Filtering
├── Drill-down popups
├── Pagination
├── Export functionality
└── Chart coordination
```

### Target Structure
```
ThreatsViewModel (~400 lines) - Coordinator
├── ThreatsTableViewModel (~300 lines)
│   ├── Table data binding
│   ├── Sorting
│   └── Pagination
├── ThreatsFilterViewModel (~200 lines)
│   ├── Filter state
│   └── Quick filter
├── ThreatsDrillDownViewModel (~250 lines)
│   ├── Popup state
│   └── Detail loading
├── ThreatsExportViewModel (~150 lines)
│   └── Export formats
└── ThreatsChartsViewModel (already exists, 748 lines)
    └── Chart rendering
```

## Component Extraction Pattern

### Step 1: Create Component ViewModel
```csharp
// ThreatsTableViewModel.cs
public class ThreatsTableViewModel : ViewModelBase
{
    private readonly ILogger<ThreatsTableViewModel> _logger;

    // Properties moved from parent
    [Reactive] public ObservableCollection<ThreatDisplayItem> DisplayedThreats { get; set; }
    [Reactive] public ThreatDisplayItem? SelectedThreat { get; set; }
    [Reactive] public string SortColumn { get; set; }
    [Reactive] public bool SortDescending { get; set; }

    // Pagination
    [Reactive] public int CurrentPage { get; set; }
    [Reactive] public int PageSize { get; set; }
    [Reactive] public int TotalPages { get; set; }

    public ThreatsTableViewModel(ILogger<ThreatsTableViewModel> logger)
    {
        _logger = logger;
        // Initialize...
    }

    // Methods moved from parent
    public void ApplySort(string column) { }
    public void GoToPage(int page) { }
}
```

### Step 2: Update Parent to Use Component
```csharp
// ThreatsViewModel.cs (after decomposition)
public class ThreatsViewModel : SmartFilterableTab
{
    // Component ViewModels
    public ThreatsTableViewModel Table { get; }
    public ThreatsFilterViewModel Filters { get; }
    public ThreatsDrillDownViewModel DrillDown { get; }
    public ThreatsExportViewModel Export { get; }
    public ThreatsChartsViewModel Charts { get; }

    public ThreatsViewModel(
        ThreatsTableViewModel table,
        ThreatsFilterViewModel filters,
        ThreatsDrillDownViewModel drillDown,
        ThreatsExportViewModel export,
        ThreatsChartsViewModel charts,
        ITabFilterService filterService,
        ILogger<ThreatsViewModel> logger)
        : base(filterService)
    {
        Table = table;
        Filters = filters;
        DrillDown = drillDown;
        Export = export;
        Charts = charts;

        // Wire up inter-component communication
        WireUpComponents();
    }

    private void WireUpComponents()
    {
        // When table selection changes, update drill-down
        Table.WhenAnyValue(x => x.SelectedThreat)
            .Subscribe(threat => DrillDown.SetThreat(threat));

        // When filters change, refresh table
        Filters.WhenAnyValue(x => x.ActiveFilters)
            .Subscribe(_ => Table.RefreshData());
    }
}
```

### Step 3: Update AXAML Bindings
```xml
<!-- Before -->
<ListBox ItemsSource="{Binding DisplayedThreats}" />

<!-- After -->
<ListBox ItemsSource="{Binding Table.DisplayedThreats}" />
```

### Step 4: Register in DI
```csharp
// ServiceConfiguration.cs
services.AddTransient<ThreatsTableViewModel>();
services.AddTransient<ThreatsFilterViewModel>();
services.AddTransient<ThreatsDrillDownViewModel>();
services.AddTransient<ThreatsExportViewModel>();
services.AddTransient<ThreatsViewModel>();
```

## Communication Patterns

### Option A: ReactiveUI Subscriptions (Preferred)
```csharp
componentA.WhenAnyValue(x => x.SomeProperty)
    .Subscribe(value => componentB.HandleChange(value));
```

### Option B: Events
```csharp
public event EventHandler<ThreatSelectedEventArgs>? ThreatSelected;
```

### Option C: Shared Service
```csharp
// For complex state shared across many components
services.AddSingleton<IThreatsSharedState, ThreatsSharedState>();
```

## Common Mistakes to Avoid

1. **Moving too much at once** — Extract one component, verify, then next
2. **Breaking AXAML bindings** — Update all `{Binding X}` to `{Binding Component.X}`
3. **Circular dependencies** — Parent knows children, children don't know parent
4. **Missing DI registration** — Register all new ViewModels
5. **Losing functionality** — Test after each extraction

## When Done

Run the verification skill:
```
/superpowers:verification-before-completion
```
