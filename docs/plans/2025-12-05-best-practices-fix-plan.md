# Best Practices Fix Plan

**Created:** 2025-12-05
**Updated:** 2025-12-05
**Status:** Active
**Audit Grade:** B+ → Target: A
**Estimated Effort:** 3-5 days focused work

---

## Executive Summary

Comprehensive best practices audit identified critical issues across the codebase. This plan provides a prioritized remediation strategy organized into 4 phases, starting with MVVM violations that block testing, then systematically addressing theme consistency and code quality.

**Key Metrics:**
| Metric | Current | Target |
|--------|---------|--------|
| ViewModels with Avalonia dependencies | 40+ | 0 |
| Hardcoded colors in AXAML | 80+ | 0 |
| PropertyChanged leaks | ~10 | 0 |
| Magic strings in ViewModels | ~20 | 0 |
| Build warnings | TBD | 0 |

---

## Phase 1: MVVM Foundation (CRITICAL)

**Priority:** P0 - Must fix before any testing
**Effort:** 4-6 hours
**Risk if unfixed:** Untestable ViewModels, framework coupling

### Task 1.1: Create IDispatcherService Abstraction

**Files to create:**
- `src/PCAPAnalyzer.UI/Services/IDispatcherService.cs`
- `src/PCAPAnalyzer.UI/Services/AvaloniaDispatcherService.cs`

**Implementation:**
```csharp
// IDispatcherService.cs
namespace PCAPAnalyzer.UI.Services;

public interface IDispatcherService
{
    Task InvokeAsync(Action action);
    Task<T> InvokeAsync<T>(Func<T> func);
    void Post(Action action);
    bool CheckAccess();
}

// AvaloniaDispatcherService.cs
namespace PCAPAnalyzer.UI.Services;

using Avalonia.Threading;

public class AvaloniaDispatcherService : IDispatcherService
{
    public Task InvokeAsync(Action action)
        => Dispatcher.UIThread.InvokeAsync(action);

    public Task<T> InvokeAsync<T>(Func<T> func)
        => Dispatcher.UIThread.InvokeAsync(func);

    public void Post(Action action)
        => Dispatcher.UIThread.Post(action);

    public bool CheckAccess()
        => Dispatcher.UIThread.CheckAccess();
}
```

**Registration in ServiceConfiguration.cs:**
```csharp
services.AddSingleton<IDispatcherService, AvaloniaDispatcherService>();
```

### Task 1.2: Refactor ViewModels to Use IDispatcherService

**Files to modify (priority order):**

| File | Dispatcher Calls | Priority |
|------|------------------|----------|
| `MainWindowViewModel.cs` | 4 | HIGH |
| `DashboardViewModel.cs` | 8 | HIGH |
| `ThreatsViewModel.cs` | 5 | HIGH |
| `VoiceQoSViewModel.cs` | 3 | MEDIUM |
| `AnomaliesViewModel.cs` | 2 | MEDIUM |
| `CountryTrafficViewModel.cs` | 2 | MEDIUM |
| `VisualizationViewModel.cs` | 4 | MEDIUM |
| `CompareViewModel.cs` | 2 | LOW |
| `ReportViewModel.cs` | 2 | LOW |
| `HostInventoryViewModel.cs` | 1 | LOW |
| Component ViewModels (25+) | 1-3 each | LOW |

**Pattern to apply:**
```csharp
// BEFORE
using Avalonia.Threading;
// ...
Dispatcher.UIThread.Post(() => UpdateUI());

// AFTER
// Remove: using Avalonia.Threading;
private readonly IDispatcherService _dispatcher;

public MyViewModel(IDispatcherService dispatcher, ...)
{
    _dispatcher = dispatcher;
}

// Usage:
_dispatcher.Post(() => UpdateUI());
```

### Task 1.3: Move Business Logic from Code-Behind

**File:** `src/PCAPAnalyzer.UI/Views/MainWindow.axaml.cs`

**Move to ViewModel:**
- `OnClosed` cleanup logic → `MainWindowViewModel.CleanupAsync()`
- `IntegrityMonitor.Report()` → `MainWindowViewModel.OnShutdown()`
- Tab navigation logic → Use behaviors or ViewModel commands

**Pattern:**
```csharp
// MainWindow.axaml.cs - AFTER
protected override async void OnClosed(EventArgs e)
{
    base.OnClosed(e);
    if (DataContext is MainWindowViewModel vm)
    {
        await vm.CleanupAsync();
    }
}
```

### Task 1.4: Audit Event Handler Disposal

**Files to verify IDisposable pattern:**
- [ ] `DashboardViewModel.cs` - 6 subscriptions
- [ ] `MainWindowViewModel.cs` - 5 subscriptions
- [ ] `VoiceQoSViewModel.cs` - 1 subscription
- [ ] `ThreatsViewModel.cs` - 3 subscriptions
- [ ] `CountryTrafficViewModel.cs` - 2 subscriptions
- [ ] `IPDetailsViewModel.cs` - Check for subscriptions
- [ ] `PortDetailsViewModel.cs` - Check for subscriptions

**Pattern to enforce:**
```csharp
public partial class DashboardViewModel : IDisposable
{
    private readonly List<(INotifyPropertyChanged Source, PropertyChangedEventHandler Handler)> _subscriptions = new();
    private bool _disposed;

    private void Subscribe(INotifyPropertyChanged source, PropertyChangedEventHandler handler)
    {
        source.PropertyChanged += handler;
        _subscriptions.Add((source, handler));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        foreach (var (source, handler) in _subscriptions)
        {
            source.PropertyChanged -= handler;
        }
        _subscriptions.Clear();
    }
}
```

---

## Phase 2: Theme Consistency (HIGH)

**Priority:** P1 - Fix within 2-3 hours
**Effort:** 2-3 hours
**Risk if unfixed:** Theme switching impossible, inconsistent UI

### Task 2.1: Fix LoadingIndicators.axaml

**File:** `src/PCAPAnalyzer.UI/Styles/LoadingIndicators.axaml`
**Violations:** 40+ hardcoded hex colors

**Color mappings:**

| Hardcoded | Theme Resource |
|-----------|----------------|
| `#2F81F7` | `{StaticResource AccentBlue}` |
| `#161B22` | `{StaticResource BackgroundLevel1}` |
| `#0D1117` | `{StaticResource BackgroundLevel0}` |
| `#30363D` | `{StaticResource BorderDefault}` |
| `#238636` | `{StaticResource StatusSuccess}` |
| `#F85149` | `{StaticResource StatusError}` |
| `#D29922` | `{StaticResource StatusWarning}` |
| `#8B949E` | `{StaticResource TextMuted}` |
| `#C9D1D9` | `{StaticResource TextPrimary}` |
| `#FFFFFF` | `{StaticResource TextInverse}` |

### Task 2.2: Fix Popup Controls

**Files to fix (by severity):

| File | Violations | Priority |
|------|------------|----------|
| `Controls/ChartDataPopup.axaml` | 40+ | CRITICAL |
| `Controls/ResizablePopupView.axaml` | 15+ | HIGH |
| `Controls/PopupDetailView.axaml` | 11+ | HIGH |
| `Controls/ProtocolLegend.axaml` | 14 | HIGH |
| `Controls/PopupTableView.axaml` | 12 | HIGH |
| `Views/Components/ThreatsDrillDownView.axaml` | 10 | MEDIUM |
| `Controls/PaginationControl.axaml` | 2 | LOW |

### 2.2 Mapping Table: Hardcoded to Theme Resource

All popup controls should use these theme resources (already defined in UnifiedDarkTheme.axaml):

| Hardcoded Value | Replace With |
|-----------------|--------------|
| `#0D1117` | `{DynamicResource PopupBg}` |
| `#161B22` | `{DynamicResource PopupBgSecondary}` |
| `#21262D` | `{DynamicResource PopupBgTertiary}` |
| `#30363D` | `{DynamicResource PopupBorder}` |
| `#F0F6FC` | `{DynamicResource PopupText}` |
| `#8B949E` | `{DynamicResource PopupTextSecondary}` |
| `#58A6FF` | `{DynamicResource PopupLink}` |
| `#3FB950` | `{DynamicResource PopupSuccess}` |
| `#1A1A24` | `{DynamicResource BackgroundLevel1}` |
| `#0F0F18` | `{DynamicResource BackgroundLevel0}` |
| `#00D4FF` | `{DynamicResource AccentCyan}` |
| `#B8D4E8` | `{DynamicResource TextSecondary}` |

### 2.3 Example Fix: ChartDataPopup.axaml

**Before:**
```axaml
<Border Background="#161B22" BorderBrush="#30363D">
    <TextBlock Foreground="#F0F6FC" Text="Title"/>
    <TextBlock Foreground="#8B949E" Text="Subtitle"/>
</Border>
```

**After:**
```axaml
<Border Background="{DynamicResource PopupBgSecondary}"
        BorderBrush="{DynamicResource PopupBorder}">
    <TextBlock Foreground="{DynamicResource PopupText}" Text="Title"/>
    <TextBlock Foreground="{DynamicResource PopupTextSecondary}" Text="Subtitle"/>
</Border>
```

### 2.4 ChartDataPopup.axaml Full Fix Checklist

- [ ] Line 48: `Background="#161B22"` → `{DynamicResource PopupBgSecondary}`
- [ ] Line 51: `Foreground="#F0F6FC"` → `{DynamicResource PopupText}`
- [ ] Line 52: `Foreground="#8B949E"` → `{DynamicResource PopupTextSecondary}`
- [ ] Line 59: `Background="#0D111720"` → `{DynamicResource PopupBg}`
- [ ] Line 65: `BorderBrush="#30363D"` → `{DynamicResource PopupBorder}`
- [ ] Line 68-69: `Background="#21262D"` → `{DynamicResource PopupBgTertiary}`
- [ ] Line 72: `Background="#58A6FF"` → `{DynamicResource AccentPrimary}`
- [ ] Line 75-78: `Background="#3FB950"` → `{DynamicResource SlackSuccess}`
- [ ] Line 87: `Foreground="#484F58"` → `{DynamicResource TextMuted}`
- [ ] Lines 132-168: All data row colors
- [ ] Lines 192-284: All chart tooltip colors

### Task 2.3: Audit StaticResource vs DynamicResource

**Rule:**
- Theme colors → `DynamicResource` (allows runtime switching)
- Structural resources (converters, templates) → `StaticResource`

**Priority files to fix:**
1. `VoiceQoSView.axaml` - Line 517-518: Uses `{StaticResource OverlayBlack70}`
2. `MainWindow.axaml` - Mixed usage throughout
3. `DashboardView.axaml` - Chart colors use wrong resource type
4. `ThreatsView.axaml` - Status colors

### Task 2.4: Replace Inline "White"/"Black" Colors

**Search pattern:** `Foreground="White"`, `Background="Black"`

**Replacements:**
```xml
<!-- BEFORE -->
<TextBlock Foreground="White" />

<!-- AFTER -->
<TextBlock Foreground="{DynamicResource TextInverse}" />
```

---

## Phase 3: Memory & Threading Safety (HIGH)

**Priority:** P1 - Fix to prevent crashes
**Effort:** 3-4 hours
**Risk if unfixed:** Memory leaks, threading crashes at scale

### Task 3.1: Fix ObservableCollection Threading

**Problem:** 440 ObservableCollection usages across 70 files, many updated from background threads.

**Pattern for large collections:**

```csharp
// Create helper class
public class ThreadSafeObservableCollection<T> : ObservableCollection<T>
{
    private readonly IDispatcherService _dispatcher;

    public ThreadSafeObservableCollection(IDispatcherService dispatcher)
    {
        _dispatcher = dispatcher;
    }

    public async Task AddRangeAsync(IEnumerable<T> items)
    {
        await _dispatcher.InvokeAsync(() =>
        {
            foreach (var item in items)
            {
                Add(item);
            }
        });
    }

    public async Task ReplaceAllAsync(IEnumerable<T> items)
    {
        await _dispatcher.InvokeAsync(() =>
        {
            Clear();
            foreach (var item in items)
            {
                Add(item);
            }
        });
    }
}
```

**Alternative: Use batch updates for performance:**
```csharp
// For large datasets, use List<T> internally + ObservableCollection for display
private List<PacketInfo> _allPackets = new();

[ObservableProperty]
private ObservableCollection<PacketInfo> _displayedPackets = new();

private async Task LoadPacketsAsync()
{
    _allPackets = await LoadFromSourceAsync();

    // Only show paginated subset
    await _dispatcherService.InvokeAsync(() =>
    {
        DisplayedPackets = new ObservableCollection<PacketInfo>(
            _allPackets.Take(PageSize)
        );
    });
}
```

### Task 3.2: Audit Task.Run Patterns

**Files with fire-and-forget issues:**

| File | Issue | Fix |
|------|-------|-----|
| `ThreatsViewModel.ThreatDetection.cs` | No cancellation | Add CancellationToken |
| `VisualizationViewModel.cs` | No error handling | Add try-catch |
| `MainWindowViewModel.AnalysisCompletion.cs` | Blocking .Result | Convert to await |

**Safe fire-and-forget pattern:**
```csharp
public static class TaskExtensions
{
    public static void FireAndForget(this Task task, Action<Exception>? onError = null)
    {
        task.ContinueWith(t =>
        {
            if (t.IsFaulted && t.Exception != null)
            {
                onError?.Invoke(t.Exception);
                DebugLogger.Log($"Fire-and-forget error: {t.Exception}");
            }
        }, TaskContinuationOptions.OnlyOnFaulted);
    }
}

// Usage
LoadDataAsync().FireAndForget(ex => Logger.Error(ex));
```

---

## Phase 4: Code Quality & Performance (MEDIUM)

**Priority:** P2 - Technical debt reduction
**Effort:** 2-3 hours

### Task 4.1: Create ViewState Constants

**File to create:** `src/PCAPAnalyzer.UI/Constants/ViewStateConstants.cs`

```csharp
namespace PCAPAnalyzer.UI.Constants;

public static class ViewModes
{
    public const string Combined = "Combined";
    public const string Source = "Source";
    public const string Destination = "Destination";
}

public static class MetricTypes
{
    public const string Packets = "Packets";
    public const string Bytes = "Bytes";
    public const string Flows = "Flows";
}

public static class FilterModes
{
    public const string All = "All";
    public const string Inbound = "Inbound";
    public const string Outbound = "Outbound";
}

public static class ChartTypes
{
    public const string Line = "Line";
    public const string Bar = "Bar";
    public const string Pie = "Pie";
    public const string Area = "Area";
}
```

**Update ViewModels to use constants:**
```csharp
// BEFORE
[ObservableProperty] private string _selectedView = "Combined";

// AFTER
[ObservableProperty] private string _selectedView = ViewModes.Combined;
```

### Task 4.2: Optimize LINQ Materializations

**Pattern to find:** `.ToList()` followed by `.Count` or index access

**Files with worst offenders:**
1. `DashboardViewModel.Extended.cs` - 8 unnecessary ToList()
2. `ThreatsViewModel.ThreatDetection.cs` - Skip/Take pattern
3. `StatisticsCalculator.cs` - Multiple group enumerations

**Fix pattern:**
```csharp
// BEFORE - Double enumeration
var items = source.Where(x => x.IsValid).ToList();
var count = items.Count;
var first = items.FirstOrDefault();

// AFTER - Single enumeration or no materialization
var items = source.Where(x => x.IsValid).ToList();
// Now use items.Count and items[0] - both O(1)

// OR for simple checks - no materialization needed
var count = source.Count(x => x.IsValid);
var first = source.FirstOrDefault(x => x.IsValid);
```

### Task 4.3: Fix N+1 in StatisticsCalculator

**File:** `src/PCAPAnalyzer.Core/Services/Statistics/StatisticsCalculator.cs`

```csharp
// BEFORE - 4x enumeration per group
.Select(g => new EndpointStatistics
{
    PacketCount = g.Count(),          // Enumeration 1
    ByteCount = g.Sum(p => p.Length), // Enumeration 2
    Percentage = (double)g.Count() / packets.Count * 100,  // Enumeration 3
    ProtocolBreakdown = g.GroupBy(p => p.Protocol)...      // Enumeration 4
})

// AFTER - Single enumeration
.Select(g => {
    var groupList = g.ToList();  // Single enumeration
    var packetCount = groupList.Count;
    var byteCount = groupList.Sum(p => p.Length);

    return new EndpointStatistics
    {
        PacketCount = packetCount,
        ByteCount = byteCount,
        Percentage = (double)packetCount / totalPackets * 100,
        ProtocolBreakdown = groupList
            .GroupBy(p => p.Protocol)
            .ToDictionary(pg => pg.Key.ToString(), pg => pg.Count()),
    };
})
```

### Task 4.4: Improve Exception Handling

**Pattern to apply:**
```csharp
// BEFORE - Swallows exception
catch (Exception ex)
{
    DebugLogger.Log($"Error: {ex.Message}");
    return new Dictionary<string, ProtocolStatistics>();
}

// AFTER - Full logging, optional rethrow
catch (Exception ex) when (ex is not OperationCanceledException)
{
    DebugLogger.Log($"Error in {nameof(CalculateProtocolStats)}: {ex}");
    return new Dictionary<string, ProtocolStatistics>();
}
```

---

## Phase 5: Theme Consolidation - Alert/Status Colors (LOW)

**Priority:** P3 - Cosmetic consistency
**Estimated Files:** 6

### 5.1 Files with Alert Color Violations

| File | Issue |
|------|-------|
| `ThreatsDrillDownView.axaml` | Custom error/success backgrounds |
| `AnomalySummaryView.axaml` | Severity colors hardcoded |
| `InteractiveTimeSeriesChart.axaml` | Custom color scheme |
| `NetworkGraphChart.axaml` | Node/edge colors hardcoded |

### 3.2 Mapping Table: Alert Colors

| Hardcoded Value | Semantic Meaning | Replace With |
|-----------------|------------------|--------------|
| `#3D2020` | Error background | `{DynamicResource DangerTint}` |
| `#F8D7DA` | Error text | `{DynamicResource SecurityCriticalText}` |
| `#1B3D2B` | Success background | `{DynamicResource SuccessTint}` |
| `#D4EDDA` | Success text | `{DynamicResource FilterSuccessText}` |
| `#F0883E` | High severity | `{DynamicResource ThreatHigh}` |
| `#D29922` | Medium severity | `{DynamicResource ThreatMedium}` |

### 3.3 Add Missing Alert Resources to Theme

Add to UnifiedDarkTheme.axaml if not present:
```axaml
<!-- Alert/Notification Backgrounds (for inline alerts) -->
<Color x:Key="AlertErrorBg">#3D2020</Color>
<Color x:Key="AlertErrorText">#F8D7DA</Color>
<Color x:Key="AlertSuccessBg">#1B3D2B</Color>
<Color x:Key="AlertSuccessText">#D4EDDA</Color>
<Color x:Key="AlertWarningBg">#3D3520</Color>
<Color x:Key="AlertWarningText">#FFF3CD</Color>
<Color x:Key="AlertInfoBg">#1B2D3D</Color>
<Color x:Key="AlertInfoText">#CFE2FF</Color>
```

---

## Phase 4: Font Size Standardization (MEDIUM)

**Priority:** P2 - Fix within 1 week
**Estimated Files:** 15+
**Estimated Violations:** 80+

### 4.1 Font Scale Already Defined

UnifiedDarkTheme.axaml already defines:
```axaml
<x:Double x:Key="FontSizeXS">10</x:Double>
<x:Double x:Key="FontSizeSmall">11</x:Double>
<x:Double x:Key="FontSizeBase">12</x:Double>
<x:Double x:Key="FontSizeMedium">13</x:Double>
<x:Double x:Key="FontSizeInput">14</x:Double>
<x:Double x:Key="FontSizeLarge">16</x:Double>
<x:Double x:Key="FontSizeXL">18</x:Double>
<x:Double x:Key="FontSizeHeading">24</x:Double>
<x:Double x:Key="FontSizeDisplay">28</x:Double>
```

### 4.2 Files with Most Font Size Violations

| File | Violations | Notes |
|------|------------|-------|
| `VoiceQoSView.axaml` | 60+ | Entire file needs cleanup |
| `ThreatsView.axaml` | 40+ | Mixed sizes |
| `PacketNumbersDetailWindow.axaml` | 5 | Quick fix |
| `FilterDialog.axaml` | 2 | Quick fix |

### 4.3 Mapping Table: Font Sizes

| Hardcoded | Replace With | Usage |
|-----------|--------------|-------|
| `FontSize="9"` | `FontSize="{StaticResource FontSizeXS}"` | Captions, small labels |
| `FontSize="10"` | `FontSize="{StaticResource FontSizeXS}"` | Captions |
| `FontSize="11"` | `FontSize="{StaticResource FontSizeSmall}"` | Secondary text |
| `FontSize="12"` | `FontSize="{StaticResource FontSizeBase}"` | Body text |
| `FontSize="13"` | `FontSize="{StaticResource FontSizeMedium}"` | Emphasized body |
| `FontSize="14"` | `FontSize="{StaticResource FontSizeInput}"` | Inputs, buttons |
| `FontSize="16"` | `FontSize="{StaticResource FontSizeLarge}"` | Subheadings |
| `FontSize="18"` | `FontSize="{StaticResource FontSizeXL}"` | Section headers |
| `FontSize="24"` | `FontSize="{StaticResource FontSizeHeading}"` | Page titles |
| `FontSize="28"` | `FontSize="{StaticResource FontSizeDisplay}"` | Hero numbers |

### 4.4 VoiceQoSView.axaml Fix Strategy

1. **Find and replace** all `FontSize="N"` with semantic resources
2. **Group by usage**:
   - Metric values: `FontSizeHeading` or `FontSizeDisplay`
   - Labels: `FontSizeSmall` or `FontSizeBase`
   - Tooltips: `FontSizeXS` or `FontSizeSmall`

---

## Phase 5: ThemeColorHelper Refactoring (LOW-MEDIUM)

**Priority:** P3 - Fix within 2 weeks
**File:** `src/PCAPAnalyzer.UI/Utilities/ThemeColorHelper.cs`
**Issue:** 100+ fallback colors create dual source of truth

### 5.1 Current Problem

```csharp
// Every color has a hardcoded fallback
_criticalBrush ??= GetBrushFromColor("ThreatCritical", "#F85149");
```

If theme changes, C# fallbacks don't update automatically.

### 5.2 Recommended Fix: Fail-Fast Pattern

**Option A: Throw on missing resource (strict)**
```csharp
public static SolidColorBrush GetRequiredBrush(string key)
{
    if (Application.Current?.TryFindResource(key, out var resource) == true
        && resource is SolidColorBrush brush)
    {
        return brush;
    }
    throw new InvalidOperationException($"Required theme resource '{key}' not found");
}
```

**Option B: Return default with warning (graceful)**
```csharp
public static SolidColorBrush GetBrush(string key, bool warnOnMissing = true)
{
    if (Application.Current?.TryFindResource(key, out var resource) == true
        && resource is SolidColorBrush brush)
    {
        return brush;
    }

    if (warnOnMissing)
    {
        Debug.WriteLine($"WARNING: Theme resource '{key}' not found, using fallback");
    }
    return _defaultFallbackBrush; // Single defined fallback
}
```

### 5.3 Properties to Refactor

All 100+ properties need review:
- Remove individual fallback colors
- Point to single source of truth (theme)
- Add debug warnings for missing resources

---

## Phase 6: God Class Decomposition (LOW)

**Priority:** P4 - Ongoing improvement
**Estimated Files:** 7 classes >1000 lines

### 6.1 Classes to Decompose

| Class | Lines | Recommended Split |
|-------|-------|-------------------|
| `MainWindowChartsViewModel.cs` | 1210 | `Timeline*`, `Protocol*`, `Traffic*` ViewModels |
| `PacketFilterViewModel.cs` | 1186 | Extract `FilterValidation`, `FilterExport` services |
| `PacketDetailsViewModel.cs` | 1170 | Already has `.Formatting.cs` - continue pattern |
| `VoiceQoSViewModel.cs` | 1133 | Extract `VoiceQoSPagination`, `VoiceQoSExport` |
| `MainWindowAnalysisViewModel.cs` | 1118 | Extract `AnalysisProgress`, `AnalysisCache` |
| `ThreatsViewModel.cs` | 1063 | Already has `.Export.cs`, `.ThreatDetection.cs` |
| `CountryTrafficViewModel.cs` | 1033 | Already has `.Export.cs` |

### 6.2 Decomposition Pattern

Use partial classes with descriptive suffixes:
```
MainWindowChartsViewModel.cs           (core logic, bindings)
MainWindowChartsViewModel.Timeline.cs  (timeline chart logic)
MainWindowChartsViewModel.Protocol.cs  (protocol chart logic)
MainWindowChartsViewModel.Traffic.cs   (traffic chart logic)
```

---

## Phase 7: Responsive Design Fixes (LOW)

**Priority:** P5 - Nice to have
**Issue:** Fixed dimensions break on different screen sizes

### 7.1 Common Violations

| File | Issue |
|------|-------|
| `ResizablePopupView.axaml` | Fixed `Width="1000"`, `Height="650"` |
| `VoiceQoSView.axaml` | Fixed column widths |
| `ThreatsView.axaml` | Fixed `Width="180"`, `Width="200"` |

### 7.2 Fix Pattern

**Before:**
```axaml
<ColumnDefinition Width="140"/>
<ColumnDefinition Width="100"/>
```

**After:**
```axaml
<ColumnDefinition Width="Auto" MinWidth="100" MaxWidth="180"/>
<ColumnDefinition Width="*" MinWidth="80"/>
```

---

## Verification Checklist

### After Each Phase

- [ ] Run `dotnet build` - no errors or warnings
- [ ] Run `dotnet test` - all tests pass
- [ ] Visual regression: Open each modified view, verify appearance matches before
- [ ] Theme toggle test: If light theme supported, verify colors work

### Phase 1 Specific

- [ ] Load 10K+ packet PCAP - no deadlock
- [ ] Monitor memory usage during capture
- [ ] Verify no event handler leaks with profiler

### Phase 2-4 Specific

- [ ] Open all popups - colors consistent
- [ ] Check all font sizes readable
- [ ] Verify theme resource warnings in debug output

---

## Progress Tracking

### Phase 1: MVVM Foundation (CRITICAL)
- [ ] Create IDispatcherService interface
- [ ] Create AvaloniaDispatcherService implementation
- [ ] Register in ServiceConfiguration.cs
- [ ] Refactor MainWindowViewModel (4 calls)
- [ ] Refactor DashboardViewModel (8 calls)
- [ ] Refactor ThreatsViewModel (5 calls)
- [ ] Refactor VoiceQoSViewModel (3 calls)
- [ ] Refactor AnomaliesViewModel (2 calls)
- [ ] Refactor CountryTrafficViewModel (2 calls)
- [ ] Refactor remaining ViewModels (25+)
- [ ] Move business logic from MainWindow.axaml.cs
- [ ] Audit DashboardViewModel subscriptions
- [ ] Audit MainWindowViewModel subscriptions
- [ ] Audit ThreatsViewModel subscriptions

### Phase 2: Theme Consistency (HIGH)
- [ ] Fix LoadingIndicators.axaml (40+ colors)
- [ ] Fix ChartDataPopup.axaml (40+ colors)
- [ ] Fix ResizablePopupView.axaml
- [ ] Fix PopupDetailView.axaml
- [ ] Fix ProtocolLegend.axaml
- [ ] Fix PopupTableView.axaml
- [ ] Fix ThreatsDrillDownView.axaml
- [ ] PaginationControl.axaml

### Phase 3: Memory & Threading Safety (HIGH)
- [ ] Create ThreadSafeObservableCollection helper
- [ ] Audit ObservableCollection threading in ViewModels
- [ ] Add CancellationToken to Task.Run calls
- [ ] Replace blocking .Result/.Wait() calls
- [ ] Add fire-and-forget error handling

### Phase 4: Code Quality & Performance (MEDIUM)
- [ ] Create ViewStateConstants.cs
- [ ] Replace magic strings in ViewModels
- [ ] Fix StatisticsCalculator N+1 pattern
- [ ] Optimize LINQ materializations
- [ ] Improve exception handling patterns

### Phase 5-7: Lower Priority (Optional)
- [ ] Alert color standardization
- [ ] Font size standardization
- [ ] ThemeColorHelper refactoring
- [ ] God class decomposition
- [ ] Responsive design fixes

---

## Appendix A: Complete File List by Priority

### P0 - CRITICAL (Do First)
1. Create `IDispatcherService` + `AvaloniaDispatcherService`
2. `MainWindowViewModel.cs` - Dispatcher abstraction
3. `DashboardViewModel.cs` - Dispatcher + subscriptions
4. `ThreatsViewModel.cs` - Dispatcher abstraction
5. `MainWindow.axaml.cs` - Move business logic out

### P1 - HIGH (Do This Week)
6. `Styles/LoadingIndicators.axaml` - 40+ hardcoded colors
7. `Controls/ChartDataPopup.axaml` - 40+ color violations
8. `Controls/ResizablePopupView.axaml` - 15+ violations
9. `Controls/PopupDetailView.axaml` - 11+ violations
10. `Controls/ProtocolLegend.axaml` - 14 violations

### P2 - MEDIUM (Do Next Week)
11. `VoiceQoSViewModel.cs` - Dispatcher + subscriptions
12. `AnomaliesViewModel.cs` - Dispatcher abstraction
13. `CountryTrafficViewModel.cs` - Dispatcher abstraction
14. Component ViewModels (25+) - Dispatcher abstraction
15. `StatisticsCalculator.cs` - N+1 fix

### P3 - LOW (Technical Debt)
16. `Constants/ViewStateConstants.cs` - Magic strings
17. `Utilities/ThemeColorHelper.cs` - Refactor fallbacks
18. God class decomposition (7 classes)
19. Responsive design improvements

---

## Appendix B: Regex Patterns for Finding Violations

### Find Hardcoded Hex Colors in AXAML
```regex
(Background|Foreground|Fill|Stroke|BorderBrush|Color)="#[0-9A-Fa-f]{6,8}"
```

### Find Hardcoded FontSize in AXAML
```regex
FontSize="[0-9]+"
```

### Find Blocking Wait() Calls in C#
```regex
\.(Wait|Result)\s*\(
```

### Find Missing IDisposable
```regex
class\s+\w+ViewModel\s*:\s*(?!.*IDisposable)
```
