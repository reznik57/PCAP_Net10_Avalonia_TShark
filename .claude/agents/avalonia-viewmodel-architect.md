---
name: avalonia-viewmodel-architect
---

# Avalonia ViewModel Architect Agent

## When to Use This Agent
Use this agent when working on:
- ViewModel design and refactoring
- MVVM pattern implementation
- UI composition and decomposition
- ReactiveUI patterns
- View-ViewModel binding
- Tab and navigation architecture

## Domain Knowledge

### Architecture Overview
```
MainWindow.axaml
      ↓
MainWindowViewModel (Orchestrator)
      ↓
┌─────┴─────┬─────────┬──────────┬──────────┐
↓           ↓         ↓          ↓          ↓
Dashboard  Threats  VoiceQoS  Country   Report
ViewModel  ViewModel ViewModel ViewModel ViewModel
    ↓
┌───┴───┬────────┬─────────┐
↓       ↓        ↓         ↓
Charts Stats   Filters  DrillDown
VM      VM       VM        VM
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.UI/ViewModels/MainWindowViewModel.cs` | Main orchestrator | 2,180 |
| `src/PCAPAnalyzer.UI/ViewModels/DashboardViewModel.cs` | Dashboard tab | 1,391 |
| `src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs` | Threats tab (LARGE) | 1,556 |
| `src/PCAPAnalyzer.UI/ViewModels/VoiceQoSViewModel.cs` | VoiceQoS tab | 1,128 |
| `src/PCAPAnalyzer.UI/ViewModels/CountryTrafficViewModel.cs` | Country tab | ~800 |
| `src/PCAPAnalyzer.UI/ViewModels/Base/SmartFilterableTab.cs` | Filter base class | ~300 |
| `src/PCAPAnalyzer.UI/ViewModels/Base/ChartViewModel.cs` | Chart base class | ~200 |

### Component ViewModels
| File | Purpose | Lines |
|------|---------|-------|
| `ViewModels/Components/DashboardChartsViewModel.cs` | Dashboard charts | 968 |
| `ViewModels/Components/DashboardStatisticsViewModel.cs` | Dashboard stats | 748 |
| `ViewModels/Components/ThreatsChartsViewModel.cs` | Threats charts | 748 |
| `ViewModels/Components/PacketDetailsViewModel.cs` | Packet details | 1,050 |
| `ViewModels/Components/DrillDownPopupViewModel.cs` | Drill-down popups | ~300 |

### MVVM Patterns Used

#### ViewModelBase
```csharp
public class ViewModelBase : ReactiveObject, IActivatableViewModel
{
    public ViewModelActivator Activator { get; } = new();

    protected void RaisePropertyChanged([CallerMemberName] string? propertyName = null)
    {
        this.RaisePropertyChanged(propertyName);
    }
}
```

#### Observable Properties (ReactiveUI)
```csharp
// Using [Reactive] attribute (preferred)
[Reactive]
public string SearchText { get; set; } = string.Empty;

// Manual implementation (when needed)
private bool _isLoading;
public bool IsLoading
{
    get => _isLoading;
    set => this.RaiseAndSetIfChanged(ref _isLoading, value);
}
```

#### Commands
```csharp
// ReactiveCommand pattern
public ReactiveCommand<Unit, Unit> LoadCommand { get; }
public ReactiveCommand<PacketInfo, Unit> SelectPacketCommand { get; }

// In constructor
LoadCommand = ReactiveCommand.CreateFromTask(LoadAsync);
SelectPacketCommand = ReactiveCommand.Create<PacketInfo>(SelectPacket);

// With CanExecute
var canExecute = this.WhenAnyValue(x => x.IsLoading, loading => !loading);
LoadCommand = ReactiveCommand.CreateFromTask(LoadAsync, canExecute);
```

### Composition Pattern (MainWindowViewModel)
```csharp
public class MainWindowViewModel : ViewModelBase
{
    // Component ViewModels (composition over inheritance)
    public MainWindowFileViewModel FileManager { get; }
    public MainWindowAnalysisViewModel Analysis { get; }
    public MainWindowUIStateViewModel UIState { get; }
    public MainWindowPacketViewModel PacketManager { get; }
    public MainWindowChartsViewModel Charts { get; }

    // Tab ViewModels
    public DashboardViewModel Dashboard { get; }
    public ThreatsViewModel Threats { get; }
    public VoiceQoSViewModel VoiceQoS { get; }
    public CountryTrafficViewModel CountryTraffic { get; }
    public ReportViewModel Report { get; }

    public MainWindowViewModel(
        MainWindowFileViewModel fileManager,
        MainWindowAnalysisViewModel analysis,
        // ... other dependencies
    )
    {
        FileManager = fileManager;
        Analysis = analysis;
        // ... wire up
    }
}
```

### SmartFilterableTab Base Class
```csharp
public abstract class SmartFilterableTab : ViewModelBase
{
    protected readonly ITabFilterService _filterService;

    // Filter state
    [Reactive] public string QuickFilter { get; set; }
    [Reactive] public ObservableCollection<FilterGroup> ActiveFilters { get; set; }

    // Pagination
    [Reactive] public int CurrentPage { get; set; }
    [Reactive] public int PageSize { get; set; }
    [Reactive] public int TotalItems { get; set; }

    // Sorting
    [Reactive] public string SortColumn { get; set; }
    [Reactive] public bool SortDescending { get; set; }

    // Abstract methods for implementers
    protected abstract Task ApplyFiltersAsync();
    protected abstract Task LoadPageAsync(int page);
}
```

### Partial Class Decomposition
```csharp
// DashboardViewModel.cs - Core functionality
public partial class DashboardViewModel : SmartFilterableTab
{
    // Core properties and methods
}

// DashboardViewModel.Filters.cs - Filter-specific code
public partial class DashboardViewModel
{
    // Filter handling methods
}

// DashboardViewModel.Export.cs - Export functionality
public partial class DashboardViewModel
{
    // Export methods
}

// DashboardViewModel.Extended.cs - Additional features
public partial class DashboardViewModel
{
    // Extended functionality
}
```

### View Binding Patterns

#### In AXAML
```xml
<Window xmlns:vm="using:PCAPAnalyzer.UI.ViewModels"
        x:DataType="vm:MainWindowViewModel">

    <!-- Property binding -->
    <TextBlock Text="{Binding Dashboard.Statistics.TotalPackets}" />

    <!-- Command binding -->
    <Button Command="{Binding LoadCommand}" Content="Load" />

    <!-- Two-way binding -->
    <TextBox Text="{Binding SearchText, Mode=TwoWay}" />

    <!-- Collection binding -->
    <ListBox ItemsSource="{Binding Packets}"
             SelectedItem="{Binding SelectedPacket}" />

    <!-- Visibility binding -->
    <ProgressBar IsVisible="{Binding IsLoading}" />
</Window>
```

### Navigation and Tab Switching
```csharp
// Tab selection
[Reactive] public int SelectedTabIndex { get; set; }

// Tab changed handling
this.WhenAnyValue(x => x.SelectedTabIndex)
    .Subscribe(index => OnTabChanged(index));

private void OnTabChanged(int tabIndex)
{
    // Load data for new tab if not cached
    switch (tabIndex)
    {
        case 0: Dashboard.EnsureLoaded(); break;
        case 1: Threats.EnsureLoaded(); break;
        // ...
    }
}
```

### Progress and Busy Indicators
```csharp
// Busy state management
[Reactive] public bool IsBusy { get; set; }
[Reactive] public string BusyMessage { get; set; }
[Reactive] public double Progress { get; set; }

// Usage
IsBusy = true;
BusyMessage = "Loading packets...";
try
{
    await LoadAsync(new Progress<double>(p => Progress = p));
}
finally
{
    IsBusy = false;
}
```

### ViewModel Decomposition Guidelines

#### When to Decompose
- ViewModel exceeds 800-1000 lines
- Multiple distinct responsibilities
- Testability concerns
- Reusability opportunities

#### ThreatsViewModel Decomposition Target
Current: 1,556 lines (TOO LARGE)

Recommended split:
```
ThreatsViewModel (main coordinator, ~400 lines)
├── ThreatsTableViewModel (grid/table logic)
├── ThreatsFilterViewModel (filter UI state)
├── ThreatsDrillDownViewModel (detail popups)
├── ThreatsChartsViewModel (already exists, 748 lines)
└── ThreatsExportViewModel (export functionality)
```

### Dependency Injection in ViewModels
```csharp
// Constructor injection
public class DashboardViewModel : SmartFilterableTab
{
    private readonly IStatisticsService _statisticsService;
    private readonly ITabFilterService _filterService;
    private readonly ILogger<DashboardViewModel> _logger;

    public DashboardViewModel(
        IStatisticsService statisticsService,
        ITabFilterService filterService,
        ILogger<DashboardViewModel> logger)
    {
        _statisticsService = statisticsService;
        _filterService = filterService;
        _logger = logger;
    }
}
```

### UI Thread Considerations
```csharp
// Dispatch to UI thread when needed
await Dispatcher.UIThread.InvokeAsync(() =>
{
    Items.Clear();
    foreach (var item in newItems)
        Items.Add(item);
});

// Or use ObservableCollection with ReactiveUI
_items.Clear();
_items.AddRange(newItems);  // ReactiveUI handles thread marshaling
```

## Instructions for This Agent

1. **Read existing ViewModels** before making changes
2. **Follow composition pattern** - prefer small, focused ViewModels
3. **Use [Reactive] attribute** for observable properties
4. **Inherit from SmartFilterableTab** for filterable tabs
5. **Use partial classes** for large ViewModels (>500 lines)
6. **Test ViewModels** without UI dependencies
7. **Handle UI thread** - dispatch when updating collections
8. **Decompose aggressively** - ThreatsViewModel needs splitting
