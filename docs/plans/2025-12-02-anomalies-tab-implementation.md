# Anomalies Tab Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a dedicated Anomalies tab with Dashboard-style visuals for behavioral/traffic anomaly investigation.

**Architecture:** Composition-based ViewModel pattern (5 component ViewModels), global anomaly filters affecting all tabs via `AnomalyFrameIndexService`, LiveCharts time-series visualization with drill-down popups.

**Tech Stack:** .NET 10, Avalonia UI, CommunityToolkit.Mvvm, LiveChartsCore, System.Threading.Channels

**Design Reference:** `docs/plans/2025-12-02-anomalies-tab-design.md`

---

## Phase 1: Data Models & Services (Foundation)

### Task 1: Create AnomalyDisplayModels

**Files:**
- Create: `src/PCAPAnalyzer.UI/Models/AnomalyDisplayModels.cs`

**Step 1: Create the display models file**

```csharp
using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// KPI summary for the Anomalies tab header row.
/// </summary>
public class AnomalyKPIs
{
    public int TotalAnomalies { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int UniqueSourceIPs { get; set; }
    public int UniqueTargetIPs { get; set; }
    public TimeSpan TimeSpan { get; set; }
    public DateTime? FirstAnomalyTime { get; set; }
    public DateTime? LastAnomalyTime { get; set; }
}

/// <summary>
/// Display model for ranked anomaly source/target tables.
/// </summary>
public partial class AnomalyEndpointViewModel : ObservableObject
{
    [ObservableProperty] private string _ipAddress = string.Empty;
    [ObservableProperty] private int _anomalyCount;
    [ObservableProperty] private AnomalySeverity _highestSeverity;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _lowCount;
    [ObservableProperty] private double _percentage;
    [ObservableProperty] private int _rank;
    [ObservableProperty] private string _country = string.Empty;
    [ObservableProperty] private string _countryCode = string.Empty;
    [ObservableProperty] private List<AnomalyCategory> _categories = new();
    [ObservableProperty] private List<long> _affectedFrames = new();

    public string SeverityColor => HighestSeverity switch
    {
        AnomalySeverity.Critical => "#F85149",
        AnomalySeverity.High => "#F59E0B",
        AnomalySeverity.Medium => "#FCD34D",
        AnomalySeverity.Low => "#3B82F6",
        _ => "#8B949E"
    };

    public string CategoryBadges => Categories.Count switch
    {
        0 => "",
        1 => Categories[0].ToString(),
        2 => $"{Categories[0]}, {Categories[1]}",
        _ => $"{Categories[0]}, {Categories[1]}, +{Categories.Count - 2}"
    };
}

/// <summary>
/// Display model for anomalous ports bar chart.
/// </summary>
public class AnomalyPortViewModel
{
    public int Port { get; set; }
    public string ServiceName { get; set; } = string.Empty;
    public int AnomalyCount { get; set; }
    public double Percentage { get; set; }
    public AnomalySeverity HighestSeverity { get; set; }

    public string SeverityColor => HighestSeverity switch
    {
        AnomalySeverity.Critical => "#F85149",
        AnomalySeverity.High => "#F59E0B",
        AnomalySeverity.Medium => "#FCD34D",
        AnomalySeverity.Low => "#3B82F6",
        _ => "#8B949E"
    };
}

/// <summary>
/// Display model for category distribution donut chart.
/// </summary>
public class AnomalyCategoryViewModel
{
    public AnomalyCategory Category { get; set; }
    public int Count { get; set; }
    public double Percentage { get; set; }

    public string Color => Category switch
    {
        AnomalyCategory.Network => "#3B82F6",
        AnomalyCategory.TCP => "#10B981",
        AnomalyCategory.Application => "#F59E0B",
        AnomalyCategory.VoIP => "#8B5CF6",
        AnomalyCategory.IoT => "#06B6D4",
        AnomalyCategory.Security => "#F85149",
        AnomalyCategory.Malformed => "#EC4899",
        _ => "#8B949E"
    };
}

/// <summary>
/// Time-series data point for the anomaly timeline chart.
/// </summary>
public class AnomalyTimePoint
{
    public DateTime Timestamp { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int TotalCount => CriticalCount + HighCount + MediumCount + LowCount;
}

/// <summary>
/// Drill-down summary for a specific time window.
/// </summary>
public class AnomalyTimeSliceSummary
{
    public DateTime WindowStart { get; set; }
    public DateTime WindowEnd { get; set; }
    public int TotalAnomalies { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public Dictionary<AnomalyCategory, int> CategoryBreakdown { get; set; } = new();
    public List<NetworkAnomaly> TopAnomalies { get; set; } = new();
}
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/Models/AnomalyDisplayModels.cs
git commit -m "feat(anomalies): add display models for Anomalies tab"
```

---

### Task 2: Create IAnomalyFrameIndexService Interface

**Files:**
- Create: `src/PCAPAnalyzer.UI/Services/IAnomalyFrameIndexService.cs`

**Step 1: Create the interface**

```csharp
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Provides indexed access to anomalies by frame number for cross-tab filtering.
/// Singleton service populated once per analysis, used by all tabs.
/// </summary>
public interface IAnomalyFrameIndexService
{
    /// <summary>
    /// Build the frame-to-anomaly index from analysis results.
    /// Called once after analysis completes.
    /// </summary>
    void BuildIndex(IReadOnlyList<NetworkAnomaly> anomalies);

    /// <summary>
    /// Clear the index when loading a new file.
    /// </summary>
    void ClearIndex();

    /// <summary>
    /// Check if the index has been populated.
    /// </summary>
    bool HasIndex { get; }

    /// <summary>
    /// Get all frame numbers that have anomalies matching the specified filters.
    /// Returns empty set if no filters active (meaning "show all").
    /// </summary>
    HashSet<long> GetFramesMatchingFilters(
        IReadOnlyList<AnomalySeverity>? severities,
        IReadOnlyList<AnomalyCategory>? categories,
        IReadOnlyList<string>? detectors);

    /// <summary>
    /// Get all anomalies associated with a specific frame number.
    /// </summary>
    IReadOnlyList<NetworkAnomaly> GetAnomaliesForFrame(long frameNumber);

    /// <summary>
    /// Get all anomalies matching the specified filters.
    /// </summary>
    IReadOnlyList<NetworkAnomaly> GetFilteredAnomalies(
        IReadOnlyList<AnomalySeverity>? severities,
        IReadOnlyList<AnomalyCategory>? categories,
        IReadOnlyList<string>? detectors);

    /// <summary>
    /// Get all unique detector names from the current anomaly set.
    /// </summary>
    IReadOnlyList<string> GetDetectorNames();

    /// <summary>
    /// Get total anomaly count (unfiltered).
    /// </summary>
    int TotalAnomalyCount { get; }
}
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/Services/IAnomalyFrameIndexService.cs
git commit -m "feat(anomalies): add IAnomalyFrameIndexService interface"
```

---

### Task 3: Implement AnomalyFrameIndexService

**Files:**
- Create: `src/PCAPAnalyzer.UI/Services/AnomalyFrameIndexService.cs`

**Step 1: Create the implementation**

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Singleton service that indexes anomalies by frame number for efficient cross-tab filtering.
/// </summary>
public class AnomalyFrameIndexService : IAnomalyFrameIndexService
{
    private readonly ILogger<AnomalyFrameIndexService> _logger;
    private readonly object _lock = new();

    private List<NetworkAnomaly> _allAnomalies = new();
    private Dictionary<long, List<NetworkAnomaly>> _frameToAnomalies = new();
    private List<string> _detectorNames = new();

    public AnomalyFrameIndexService(ILogger<AnomalyFrameIndexService> logger)
    {
        _logger = logger;
    }

    public bool HasIndex { get; private set; }
    public int TotalAnomalyCount => _allAnomalies.Count;

    public void BuildIndex(IReadOnlyList<NetworkAnomaly> anomalies)
    {
        lock (_lock)
        {
            _logger.LogInformation("Building anomaly frame index for {Count} anomalies", anomalies.Count);
            var sw = System.Diagnostics.Stopwatch.StartNew();

            _allAnomalies = anomalies.ToList();

            // Build frame-to-anomaly mapping
            _frameToAnomalies = _allAnomalies
                .Where(a => a.AffectedFrames?.Any() == true)
                .SelectMany(a => a.AffectedFrames!.Select(f => (Frame: f, Anomaly: a)))
                .GroupBy(x => x.Frame)
                .ToDictionary(g => g.Key, g => g.Select(x => x.Anomaly).Distinct().ToList());

            // Extract unique detector names
            _detectorNames = _allAnomalies
                .Select(a => a.DetectorName)
                .Where(n => !string.IsNullOrEmpty(n))
                .Distinct()
                .OrderBy(n => n)
                .ToList();

            HasIndex = true;

            sw.Stop();
            _logger.LogInformation(
                "Anomaly frame index built in {Elapsed}ms. {FrameCount} frames mapped, {DetectorCount} detectors",
                sw.ElapsedMilliseconds, _frameToAnomalies.Count, _detectorNames.Count);
        }
    }

    public void ClearIndex()
    {
        lock (_lock)
        {
            _allAnomalies.Clear();
            _frameToAnomalies.Clear();
            _detectorNames.Clear();
            HasIndex = false;
            _logger.LogDebug("Anomaly frame index cleared");
        }
    }

    public HashSet<long> GetFramesMatchingFilters(
        IReadOnlyList<AnomalySeverity>? severities,
        IReadOnlyList<AnomalyCategory>? categories,
        IReadOnlyList<string>? detectors)
    {
        lock (_lock)
        {
            if (!HasIndex) return new HashSet<long>();

            // If no filters, return empty (meaning "no anomaly filter active")
            bool hasFilters = (severities?.Any() == true) ||
                              (categories?.Any() == true) ||
                              (detectors?.Any() == true);
            if (!hasFilters) return new HashSet<long>();

            var matching = _allAnomalies.AsEnumerable();

            if (severities?.Any() == true)
                matching = matching.Where(a => severities.Contains(a.Severity));

            if (categories?.Any() == true)
                matching = matching.Where(a => categories.Contains(a.Category));

            if (detectors?.Any() == true)
                matching = matching.Where(a => detectors.Contains(a.DetectorName));

            return matching
                .Where(a => a.AffectedFrames?.Any() == true)
                .SelectMany(a => a.AffectedFrames!)
                .ToHashSet();
        }
    }

    public IReadOnlyList<NetworkAnomaly> GetAnomaliesForFrame(long frameNumber)
    {
        lock (_lock)
        {
            if (_frameToAnomalies.TryGetValue(frameNumber, out var anomalies))
                return anomalies;
            return Array.Empty<NetworkAnomaly>();
        }
    }

    public IReadOnlyList<NetworkAnomaly> GetFilteredAnomalies(
        IReadOnlyList<AnomalySeverity>? severities,
        IReadOnlyList<AnomalyCategory>? categories,
        IReadOnlyList<string>? detectors)
    {
        lock (_lock)
        {
            if (!HasIndex) return Array.Empty<NetworkAnomaly>();

            var matching = _allAnomalies.AsEnumerable();

            if (severities?.Any() == true)
                matching = matching.Where(a => severities.Contains(a.Severity));

            if (categories?.Any() == true)
                matching = matching.Where(a => categories.Contains(a.Category));

            if (detectors?.Any() == true)
                matching = matching.Where(a => detectors.Contains(a.DetectorName));

            return matching.ToList();
        }
    }

    public IReadOnlyList<string> GetDetectorNames()
    {
        lock (_lock)
        {
            return _detectorNames.ToList();
        }
    }
}
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/Services/AnomalyFrameIndexService.cs
git commit -m "feat(anomalies): implement AnomalyFrameIndexService"
```

---

### Task 4: Write Tests for AnomalyFrameIndexService

**Files:**
- Create: `tests/PCAPAnalyzer.Tests/Services/AnomalyFrameIndexServiceTests.cs`

**Step 1: Write the tests**

```csharp
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Moq;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Services;
using Xunit;

namespace PCAPAnalyzer.Tests.Services;

public class AnomalyFrameIndexServiceTests
{
    private readonly AnomalyFrameIndexService _service;

    public AnomalyFrameIndexServiceTests()
    {
        var logger = Mock.Of<ILogger<AnomalyFrameIndexService>>();
        _service = new AnomalyFrameIndexService(logger);
    }

    private static List<NetworkAnomaly> CreateTestAnomalies()
    {
        return new List<NetworkAnomaly>
        {
            new() {
                Id = "1",
                Severity = AnomalySeverity.Critical,
                Category = AnomalyCategory.Network,
                DetectorName = "NetworkAnomalyDetector",
                AffectedFrames = new List<long> { 100, 101, 102 }
            },
            new() {
                Id = "2",
                Severity = AnomalySeverity.High,
                Category = AnomalyCategory.TCP,
                DetectorName = "TCPAnomalyDetector",
                AffectedFrames = new List<long> { 200, 201, 102 } // 102 overlaps
            },
            new() {
                Id = "3",
                Severity = AnomalySeverity.Medium,
                Category = AnomalyCategory.Application,
                DetectorName = "ApplicationAnomalyDetector",
                AffectedFrames = new List<long> { 300, 301 }
            },
            new() {
                Id = "4",
                Severity = AnomalySeverity.Low,
                Category = AnomalyCategory.Network,
                DetectorName = "NetworkAnomalyDetector",
                AffectedFrames = new List<long> { 400 }
            }
        };
    }

    [Fact]
    public void BuildIndex_SetsHasIndex()
    {
        Assert.False(_service.HasIndex);

        _service.BuildIndex(CreateTestAnomalies());

        Assert.True(_service.HasIndex);
        Assert.Equal(4, _service.TotalAnomalyCount);
    }

    [Fact]
    public void ClearIndex_ResetsState()
    {
        _service.BuildIndex(CreateTestAnomalies());
        Assert.True(_service.HasIndex);

        _service.ClearIndex();

        Assert.False(_service.HasIndex);
        Assert.Equal(0, _service.TotalAnomalyCount);
    }

    [Fact]
    public void GetFramesMatchingFilters_NoFilters_ReturnsEmpty()
    {
        _service.BuildIndex(CreateTestAnomalies());

        var frames = _service.GetFramesMatchingFilters(null, null, null);

        Assert.Empty(frames);
    }

    [Fact]
    public void GetFramesMatchingFilters_SeverityFilter_ReturnsMatchingFrames()
    {
        _service.BuildIndex(CreateTestAnomalies());

        var frames = _service.GetFramesMatchingFilters(
            new[] { AnomalySeverity.Critical },
            null,
            null);

        Assert.Equal(3, frames.Count); // 100, 101, 102
        Assert.Contains(100, frames);
        Assert.Contains(101, frames);
        Assert.Contains(102, frames);
    }

    [Fact]
    public void GetFramesMatchingFilters_CategoryFilter_ReturnsMatchingFrames()
    {
        _service.BuildIndex(CreateTestAnomalies());

        var frames = _service.GetFramesMatchingFilters(
            null,
            new[] { AnomalyCategory.TCP },
            null);

        Assert.Equal(3, frames.Count); // 200, 201, 102
    }

    [Fact]
    public void GetFramesMatchingFilters_CombinedFilters_AppliesAnd()
    {
        _service.BuildIndex(CreateTestAnomalies());

        // Critical + Network = only anomaly 1
        var frames = _service.GetFramesMatchingFilters(
            new[] { AnomalySeverity.Critical },
            new[] { AnomalyCategory.Network },
            null);

        Assert.Equal(3, frames.Count); // 100, 101, 102
    }

    [Fact]
    public void GetAnomaliesForFrame_OverlappingFrame_ReturnsBoth()
    {
        _service.BuildIndex(CreateTestAnomalies());

        var anomalies = _service.GetAnomaliesForFrame(102);

        Assert.Equal(2, anomalies.Count);
    }

    [Fact]
    public void GetAnomaliesForFrame_UnknownFrame_ReturnsEmpty()
    {
        _service.BuildIndex(CreateTestAnomalies());

        var anomalies = _service.GetAnomaliesForFrame(999);

        Assert.Empty(anomalies);
    }

    [Fact]
    public void GetDetectorNames_ReturnsDistinctSorted()
    {
        _service.BuildIndex(CreateTestAnomalies());

        var names = _service.GetDetectorNames();

        Assert.Equal(3, names.Count);
        Assert.Equal("ApplicationAnomalyDetector", names[0]);
        Assert.Equal("NetworkAnomalyDetector", names[1]);
        Assert.Equal("TCPAnomalyDetector", names[2]);
    }

    [Fact]
    public void GetFilteredAnomalies_MultipleFilters_AppliesAnd()
    {
        _service.BuildIndex(CreateTestAnomalies());

        var anomalies = _service.GetFilteredAnomalies(
            new[] { AnomalySeverity.Critical, AnomalySeverity.Low },
            new[] { AnomalyCategory.Network },
            null);

        Assert.Equal(2, anomalies.Count);
        Assert.Contains(anomalies, a => a.Id == "1");
        Assert.Contains(anomalies, a => a.Id == "4");
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `dotnet test tests/PCAPAnalyzer.Tests/PCAPAnalyzer.Tests.csproj --filter "FullyQualifiedName~AnomalyFrameIndexServiceTests" -v n`
Expected: All 9 tests pass

**Step 3: Commit**

```bash
git add tests/PCAPAnalyzer.Tests/Services/AnomalyFrameIndexServiceTests.cs
git commit -m "test(anomalies): add AnomalyFrameIndexService tests"
```

---

### Task 5: Extend GlobalFilterState with Anomaly Filters

**Files:**
- Modify: `src/PCAPAnalyzer.UI/Models/GlobalFilterState.cs`

**Step 1: Read current file to understand structure**

Read the file first to see existing properties.

**Step 2: Add anomaly filter properties**

Add these properties to the GlobalFilterState class:

```csharp
// Anomaly filters (global scope - affects all tabs)
[ObservableProperty]
private List<AnomalySeverity> _anomalySeverityFilter = new();

[ObservableProperty]
private List<AnomalyCategory> _anomalyCategoryFilter = new();

[ObservableProperty]
private List<string> _anomalyDetectorFilter = new();

/// <summary>
/// Check if any anomaly filters are active.
/// </summary>
public bool HasAnomalyFilters =>
    AnomalySeverityFilter.Count > 0 ||
    AnomalyCategoryFilter.Count > 0 ||
    AnomalyDetectorFilter.Count > 0;

/// <summary>
/// Clear all anomaly-specific filters.
/// </summary>
public void ClearAnomalyFilters()
{
    AnomalySeverityFilter = new List<AnomalySeverity>();
    AnomalyCategoryFilter = new List<AnomalyCategory>();
    AnomalyDetectorFilter = new List<string>();
}
```

Also add necessary using statement:
```csharp
using PCAPAnalyzer.Core.Models;
```

**Step 3: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.UI/Models/GlobalFilterState.cs
git commit -m "feat(filters): extend GlobalFilterState with anomaly filters"
```

---

### Task 6: Register AnomalyFrameIndexService in DI

**Files:**
- Modify: `src/PCAPAnalyzer.UI/ServiceConfiguration.cs`

**Step 1: Read current file to find service registration section**

Read the file to understand the registration pattern.

**Step 2: Add service registration**

In the appropriate section (likely near other singleton services), add:

```csharp
// Anomaly services
services.AddSingleton<IAnomalyFrameIndexService, AnomalyFrameIndexService>();
```

**Step 3: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.UI/ServiceConfiguration.cs
git commit -m "feat(anomalies): register AnomalyFrameIndexService in DI"
```

---

## Phase 2: Component ViewModels

### Task 7: Create AnomaliesStatisticsViewModel

**Files:**
- Create: `src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesStatisticsViewModel.cs`

**Step 1: Create the statistics ViewModel**

```csharp
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages KPIs and ranked table data for the Anomalies tab.
/// </summary>
public partial class AnomaliesStatisticsViewModel : ObservableObject
{
    // KPIs
    [ObservableProperty] private int _totalAnomalies;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _lowCount;
    [ObservableProperty] private int _uniqueSourceIPs;
    [ObservableProperty] private int _uniqueTargetIPs;
    [ObservableProperty] private string _timeSpanFormatted = "--";

    // Filtered state
    [ObservableProperty] private bool _isFiltered;
    [ObservableProperty] private int _filteredTotalAnomalies;

    // Ranked tables
    public ObservableCollection<AnomalyEndpointViewModel> TopSources { get; } = new();
    public ObservableCollection<AnomalyEndpointViewModel> TopTargets { get; } = new();
    public ObservableCollection<AnomalyPortViewModel> TopPorts { get; } = new();
    public ObservableCollection<AnomalyCategoryViewModel> CategoryBreakdown { get; } = new();

    public void UpdateKPIs(AnomalyKPIs kpis)
    {
        TotalAnomalies = kpis.TotalAnomalies;
        CriticalCount = kpis.CriticalCount;
        HighCount = kpis.HighCount;
        MediumCount = kpis.MediumCount;
        LowCount = kpis.LowCount;
        UniqueSourceIPs = kpis.UniqueSourceIPs;
        UniqueTargetIPs = kpis.UniqueTargetIPs;

        if (kpis.TimeSpan.TotalSeconds > 0)
        {
            TimeSpanFormatted = kpis.TimeSpan.TotalHours >= 1
                ? $"{kpis.TimeSpan.Hours}h {kpis.TimeSpan.Minutes}m"
                : kpis.TimeSpan.TotalMinutes >= 1
                    ? $"{kpis.TimeSpan.Minutes}m {kpis.TimeSpan.Seconds}s"
                    : $"{kpis.TimeSpan.Seconds}s";
        }
        else
        {
            TimeSpanFormatted = "--";
        }
    }

    public void UpdateTopSources(IEnumerable<AnomalyEndpointViewModel> sources)
    {
        TopSources.Clear();
        foreach (var source in sources.Take(20))
            TopSources.Add(source);
    }

    public void UpdateTopTargets(IEnumerable<AnomalyEndpointViewModel> targets)
    {
        TopTargets.Clear();
        foreach (var target in targets.Take(20))
            TopTargets.Add(target);
    }

    public void UpdateTopPorts(IEnumerable<AnomalyPortViewModel> ports)
    {
        TopPorts.Clear();
        foreach (var port in ports.Take(15))
            TopPorts.Add(port);
    }

    public void UpdateCategoryBreakdown(IEnumerable<AnomalyCategoryViewModel> categories)
    {
        CategoryBreakdown.Clear();
        foreach (var cat in categories.OrderByDescending(c => c.Count))
            CategoryBreakdown.Add(cat);
    }

    public void SetFilteredState(bool isFiltered, int filteredCount)
    {
        IsFiltered = isFiltered;
        FilteredTotalAnomalies = filteredCount;
    }

    public void Clear()
    {
        TotalAnomalies = 0;
        CriticalCount = 0;
        HighCount = 0;
        MediumCount = 0;
        LowCount = 0;
        UniqueSourceIPs = 0;
        UniqueTargetIPs = 0;
        TimeSpanFormatted = "--";
        IsFiltered = false;
        FilteredTotalAnomalies = 0;
        TopSources.Clear();
        TopTargets.Clear();
        TopPorts.Clear();
        CategoryBreakdown.Clear();
    }
}
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesStatisticsViewModel.cs
git commit -m "feat(anomalies): add AnomaliesStatisticsViewModel"
```

---

### Task 8: Create AnomaliesChartsViewModel

**Files:**
- Create: `src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesChartsViewModel.cs`

**Step 1: Create the charts ViewModel**

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using SkiaSharp;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages chart series and axes for the Anomalies tab.
/// </summary>
public partial class AnomaliesChartsViewModel : ObservableObject
{
    // Severity colors
    private static readonly SKColor CriticalColor = SKColor.Parse("#F85149");
    private static readonly SKColor HighColor = SKColor.Parse("#F59E0B");
    private static readonly SKColor MediumColor = SKColor.Parse("#FCD34D");
    private static readonly SKColor LowColor = SKColor.Parse("#3B82F6");

    // Category colors
    private static readonly Dictionary<AnomalyCategory, SKColor> CategoryColors = new()
    {
        { AnomalyCategory.Network, SKColor.Parse("#3B82F6") },
        { AnomalyCategory.TCP, SKColor.Parse("#10B981") },
        { AnomalyCategory.Application, SKColor.Parse("#F59E0B") },
        { AnomalyCategory.VoIP, SKColor.Parse("#8B5CF6") },
        { AnomalyCategory.IoT, SKColor.Parse("#06B6D4") },
        { AnomalyCategory.Security, SKColor.Parse("#F85149") },
        { AnomalyCategory.Malformed, SKColor.Parse("#EC4899") }
    };

    // Timeline chart
    public ISeries[] TimelineSeries { get; private set; } = Array.Empty<ISeries>();
    public Axis[] TimelineXAxes { get; private set; }
    public Axis[] TimelineYAxes { get; private set; }

    // Category donut chart
    public ISeries[] CategorySeries { get; private set; } = Array.Empty<ISeries>();

    // Ports bar chart
    public ISeries[] PortsSeries { get; private set; } = Array.Empty<ISeries>();
    public Axis[] PortsXAxes { get; private set; }
    public Axis[] PortsYAxes { get; private set; }

    // Zoom state
    [ObservableProperty] private double _timelineMinX = double.NaN;
    [ObservableProperty] private double _timelineMaxX = double.NaN;

    public AnomaliesChartsViewModel()
    {
        InitializeAxes();
    }

    private void InitializeAxes()
    {
        TimelineXAxes = new Axis[]
        {
            new Axis
            {
                Name = "Time",
                NamePaint = new SolidColorPaint(SKColor.Parse("#8B949E")),
                LabelsPaint = new SolidColorPaint(SKColor.Parse("#8B949E")),
                Labeler = value => DateTime.FromOADate(value).ToString("HH:mm:ss"),
                TextSize = 11
            }
        };

        TimelineYAxes = new Axis[]
        {
            new Axis
            {
                Name = "Anomalies/min",
                NamePaint = new SolidColorPaint(SKColor.Parse("#8B949E")),
                LabelsPaint = new SolidColorPaint(SKColor.Parse("#8B949E")),
                MinLimit = 0,
                TextSize = 11
            }
        };

        PortsXAxes = new Axis[]
        {
            new Axis
            {
                LabelsPaint = new SolidColorPaint(SKColor.Parse("#8B949E")),
                TextSize = 11
            }
        };

        PortsYAxes = new Axis[]
        {
            new Axis
            {
                Labels = Array.Empty<string>(),
                LabelsPaint = new SolidColorPaint(SKColor.Parse("#8B949E")),
                TextSize = 11
            }
        };
    }

    public void UpdateTimeline(List<AnomalyTimePoint> timePoints)
    {
        if (timePoints.Count == 0)
        {
            TimelineSeries = Array.Empty<ISeries>();
            OnPropertyChanged(nameof(TimelineSeries));
            return;
        }

        var criticalValues = new List<DateTimePoint>();
        var highValues = new List<DateTimePoint>();
        var mediumValues = new List<DateTimePoint>();
        var lowValues = new List<DateTimePoint>();

        foreach (var point in timePoints)
        {
            criticalValues.Add(new DateTimePoint(point.Timestamp, point.CriticalCount));
            highValues.Add(new DateTimePoint(point.Timestamp, point.HighCount));
            mediumValues.Add(new DateTimePoint(point.Timestamp, point.MediumCount));
            lowValues.Add(new DateTimePoint(point.Timestamp, point.LowCount));
        }

        TimelineSeries = new ISeries[]
        {
            new LineSeries<DateTimePoint>
            {
                Name = "Critical",
                Values = criticalValues,
                Stroke = new SolidColorPaint(CriticalColor, 2),
                Fill = null,
                GeometrySize = 0,
                LineSmoothness = 0.3
            },
            new LineSeries<DateTimePoint>
            {
                Name = "High",
                Values = highValues,
                Stroke = new SolidColorPaint(HighColor, 2),
                Fill = null,
                GeometrySize = 0,
                LineSmoothness = 0.3
            },
            new LineSeries<DateTimePoint>
            {
                Name = "Medium",
                Values = mediumValues,
                Stroke = new SolidColorPaint(MediumColor, 2),
                Fill = null,
                GeometrySize = 0,
                LineSmoothness = 0.3
            },
            new LineSeries<DateTimePoint>
            {
                Name = "Low",
                Values = lowValues,
                Stroke = new SolidColorPaint(LowColor, 2),
                Fill = null,
                GeometrySize = 0,
                LineSmoothness = 0.3
            }
        };

        OnPropertyChanged(nameof(TimelineSeries));
    }

    public void UpdateCategoryDonut(IEnumerable<AnomalyCategoryViewModel> categories)
    {
        var series = new List<ISeries>();

        foreach (var cat in categories.Where(c => c.Count > 0))
        {
            var color = CategoryColors.GetValueOrDefault(cat.Category, SKColor.Parse("#8B949E"));

            series.Add(new PieSeries<int>
            {
                Name = cat.Category.ToString(),
                Values = new[] { cat.Count },
                Fill = new SolidColorPaint(color),
                Pushout = 0
            });
        }

        CategorySeries = series.ToArray();
        OnPropertyChanged(nameof(CategorySeries));
    }

    public void UpdatePortsBar(IEnumerable<AnomalyPortViewModel> ports)
    {
        var portList = ports.Take(10).ToList();

        if (portList.Count == 0)
        {
            PortsSeries = Array.Empty<ISeries>();
            PortsYAxes[0].Labels = Array.Empty<string>();
            OnPropertyChanged(nameof(PortsSeries));
            return;
        }

        PortsYAxes[0].Labels = portList
            .Select(p => string.IsNullOrEmpty(p.ServiceName)
                ? p.Port.ToString()
                : $"{p.Port} ({p.ServiceName})")
            .ToArray();

        PortsSeries = new ISeries[]
        {
            new RowSeries<int>
            {
                Values = portList.Select(p => p.AnomalyCount).ToArray(),
                Fill = new SolidColorPaint(SKColor.Parse("#3B82F6")),
                Stroke = null,
                DataLabelsPaint = new SolidColorPaint(SKColor.Parse("#F0F6FC")),
                DataLabelsSize = 11,
                DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.End
            }
        };

        OnPropertyChanged(nameof(PortsSeries));
        OnPropertyChanged(nameof(PortsYAxes));
    }

    public void ZoomIn()
    {
        // Implemented in view code-behind with axis manipulation
    }

    public void ZoomOut()
    {
        // Implemented in view code-behind with axis manipulation
    }

    public void ResetZoom()
    {
        TimelineMinX = double.NaN;
        TimelineMaxX = double.NaN;
    }

    public void Clear()
    {
        TimelineSeries = Array.Empty<ISeries>();
        CategorySeries = Array.Empty<ISeries>();
        PortsSeries = Array.Empty<ISeries>();
        ResetZoom();
        OnPropertyChanged(nameof(TimelineSeries));
        OnPropertyChanged(nameof(CategorySeries));
        OnPropertyChanged(nameof(PortsSeries));
    }
}
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesChartsViewModel.cs
git commit -m "feat(anomalies): add AnomaliesChartsViewModel"
```

---

### Task 9: Create AnomaliesDrillDownViewModel

**Files:**
- Create: `src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesDrillDownViewModel.cs`

**Step 1: Create the drill-down ViewModel**

```csharp
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages time-slice and source/target drill-down state.
/// </summary>
public partial class AnomaliesDrillDownViewModel : ObservableObject
{
    // Time slice popup
    [ObservableProperty] private bool _isTimeSlicePopupOpen;
    [ObservableProperty] private AnomalyTimeSliceSummary? _timeSliceSummary;

    // Source/Target detail popup
    [ObservableProperty] private bool _isDetailPopupOpen;
    [ObservableProperty] private string _detailPopupTitle = string.Empty;
    [ObservableProperty] private string _detailPopupSubtitle = string.Empty;
    [ObservableProperty] private int _detailTotalAnomalies;
    [ObservableProperty] private int _detailCriticalCount;
    [ObservableProperty] private int _detailHighCount;
    [ObservableProperty] private int _detailMediumCount;
    [ObservableProperty] private int _detailLowCount;

    // Anomaly list in detail popup
    public ObservableCollection<NetworkAnomaly> DetailAnomalies { get; } = new();
    public ObservableCollection<AnomalyCategoryViewModel> DetailCategoryBreakdown { get; } = new();

    // Pagination
    [ObservableProperty] private int _detailCurrentPage = 1;
    [ObservableProperty] private int _detailTotalPages = 1;
    [ObservableProperty] private int _detailPageSize = 10;

    private List<NetworkAnomaly> _allDetailAnomalies = new();

    public void ShowTimeSliceDrillDown(
        DateTime timestamp,
        TimeSpan windowSize,
        IEnumerable<NetworkAnomaly> allAnomalies)
    {
        var windowStart = timestamp - TimeSpan.FromTicks(windowSize.Ticks / 2);
        var windowEnd = timestamp + TimeSpan.FromTicks(windowSize.Ticks / 2);

        var windowAnomalies = allAnomalies
            .Where(a => a.DetectedAt >= windowStart && a.DetectedAt <= windowEnd)
            .ToList();

        TimeSliceSummary = new AnomalyTimeSliceSummary
        {
            WindowStart = windowStart,
            WindowEnd = windowEnd,
            TotalAnomalies = windowAnomalies.Count,
            CriticalCount = windowAnomalies.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = windowAnomalies.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = windowAnomalies.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = windowAnomalies.Count(a => a.Severity == AnomalySeverity.Low),
            CategoryBreakdown = windowAnomalies
                .GroupBy(a => a.Category)
                .ToDictionary(g => g.Key, g => g.Count()),
            TopAnomalies = windowAnomalies
                .OrderByDescending(a => a.Severity)
                .ThenByDescending(a => a.DetectedAt)
                .Take(10)
                .ToList()
        };

        IsTimeSlicePopupOpen = true;
    }

    public void ShowSourceDetail(string ipAddress, IEnumerable<NetworkAnomaly> anomalies)
    {
        ShowDetailPopup($"Source Analysis: {ipAddress}", "Anomalies originating from this IP", anomalies);
    }

    public void ShowTargetDetail(string ipAddress, IEnumerable<NetworkAnomaly> anomalies)
    {
        ShowDetailPopup($"Target Analysis: {ipAddress}", "Anomalies targeting this IP", anomalies);
    }

    private void ShowDetailPopup(string title, string subtitle, IEnumerable<NetworkAnomaly> anomalies)
    {
        _allDetailAnomalies = anomalies
            .OrderByDescending(a => a.Severity)
            .ThenByDescending(a => a.DetectedAt)
            .ToList();

        DetailPopupTitle = title;
        DetailPopupSubtitle = subtitle;
        DetailTotalAnomalies = _allDetailAnomalies.Count;
        DetailCriticalCount = _allDetailAnomalies.Count(a => a.Severity == AnomalySeverity.Critical);
        DetailHighCount = _allDetailAnomalies.Count(a => a.Severity == AnomalySeverity.High);
        DetailMediumCount = _allDetailAnomalies.Count(a => a.Severity == AnomalySeverity.Medium);
        DetailLowCount = _allDetailAnomalies.Count(a => a.Severity == AnomalySeverity.Low);

        // Category breakdown
        DetailCategoryBreakdown.Clear();
        var categories = _allDetailAnomalies
            .GroupBy(a => a.Category)
            .Select(g => new AnomalyCategoryViewModel
            {
                Category = g.Key,
                Count = g.Count(),
                Percentage = (double)g.Count() / _allDetailAnomalies.Count * 100
            })
            .OrderByDescending(c => c.Count);

        foreach (var cat in categories)
            DetailCategoryBreakdown.Add(cat);

        // Pagination
        DetailCurrentPage = 1;
        DetailTotalPages = (int)Math.Ceiling((double)_allDetailAnomalies.Count / DetailPageSize);
        UpdateDetailPage();

        IsDetailPopupOpen = true;
    }

    private void UpdateDetailPage()
    {
        DetailAnomalies.Clear();
        var pageItems = _allDetailAnomalies
            .Skip((DetailCurrentPage - 1) * DetailPageSize)
            .Take(DetailPageSize);

        foreach (var anomaly in pageItems)
            DetailAnomalies.Add(anomaly);
    }

    [RelayCommand]
    private void NextDetailPage()
    {
        if (DetailCurrentPage < DetailTotalPages)
        {
            DetailCurrentPage++;
            UpdateDetailPage();
        }
    }

    [RelayCommand]
    private void PreviousDetailPage()
    {
        if (DetailCurrentPage > 1)
        {
            DetailCurrentPage--;
            UpdateDetailPage();
        }
    }

    [RelayCommand]
    private void CloseTimeSlicePopup()
    {
        IsTimeSlicePopupOpen = false;
        TimeSliceSummary = null;
    }

    [RelayCommand]
    private void CloseDetailPopup()
    {
        IsDetailPopupOpen = false;
        DetailAnomalies.Clear();
        DetailCategoryBreakdown.Clear();
        _allDetailAnomalies.Clear();
    }

    public void Clear()
    {
        CloseTimeSlicePopup();
        CloseDetailPopup();
    }
}
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesDrillDownViewModel.cs
git commit -m "feat(anomalies): add AnomaliesDrillDownViewModel"
```

---

### Task 10: Create AnomaliesFilterViewModel

**Files:**
- Create: `src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesFilterViewModel.cs`

**Step 1: Create the filter ViewModel**

```csharp
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages anomaly-specific filter state (severity, category, detector chips).
/// </summary>
public partial class AnomaliesFilterViewModel : ObservableObject
{
    private readonly GlobalFilterState _globalFilterState;

    // Severity toggles
    [ObservableProperty] private bool _isCriticalSelected;
    [ObservableProperty] private bool _isHighSelected;
    [ObservableProperty] private bool _isMediumSelected;
    [ObservableProperty] private bool _isLowSelected;

    // Category toggles
    [ObservableProperty] private bool _isNetworkSelected;
    [ObservableProperty] private bool _isTcpSelected;
    [ObservableProperty] private bool _isApplicationSelected;
    [ObservableProperty] private bool _isVoipSelected;
    [ObservableProperty] private bool _isIotSelected;
    [ObservableProperty] private bool _isSecuritySelected;
    [ObservableProperty] private bool _isMalformedSelected;

    // Available detectors (populated from service)
    public ObservableCollection<DetectorToggle> AvailableDetectors { get; } = new();

    public event EventHandler? FiltersChanged;

    public AnomaliesFilterViewModel(GlobalFilterState globalFilterState)
    {
        _globalFilterState = globalFilterState;

        // Initialize from global state if already set
        SyncFromGlobalState();
    }

    private void SyncFromGlobalState()
    {
        var severities = _globalFilterState.AnomalySeverityFilter;
        IsCriticalSelected = severities.Contains(AnomalySeverity.Critical);
        IsHighSelected = severities.Contains(AnomalySeverity.High);
        IsMediumSelected = severities.Contains(AnomalySeverity.Medium);
        IsLowSelected = severities.Contains(AnomalySeverity.Low);

        var categories = _globalFilterState.AnomalyCategoryFilter;
        IsNetworkSelected = categories.Contains(AnomalyCategory.Network);
        IsTcpSelected = categories.Contains(AnomalyCategory.TCP);
        IsApplicationSelected = categories.Contains(AnomalyCategory.Application);
        IsVoipSelected = categories.Contains(AnomalyCategory.VoIP);
        IsIotSelected = categories.Contains(AnomalyCategory.IoT);
        IsSecuritySelected = categories.Contains(AnomalyCategory.Security);
        IsMalformedSelected = categories.Contains(AnomalyCategory.Malformed);
    }

    partial void OnIsCriticalSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsHighSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsMediumSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsLowSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsNetworkSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsTcpSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsApplicationSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsVoipSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsIotSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsSecuritySelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsMalformedSelectedChanged(bool value) => UpdateGlobalFilters();

    private void UpdateGlobalFilters()
    {
        // Update severity filters
        var severities = new List<AnomalySeverity>();
        if (IsCriticalSelected) severities.Add(AnomalySeverity.Critical);
        if (IsHighSelected) severities.Add(AnomalySeverity.High);
        if (IsMediumSelected) severities.Add(AnomalySeverity.Medium);
        if (IsLowSelected) severities.Add(AnomalySeverity.Low);
        _globalFilterState.AnomalySeverityFilter = severities;

        // Update category filters
        var categories = new List<AnomalyCategory>();
        if (IsNetworkSelected) categories.Add(AnomalyCategory.Network);
        if (IsTcpSelected) categories.Add(AnomalyCategory.TCP);
        if (IsApplicationSelected) categories.Add(AnomalyCategory.Application);
        if (IsVoipSelected) categories.Add(AnomalyCategory.VoIP);
        if (IsIotSelected) categories.Add(AnomalyCategory.IoT);
        if (IsSecuritySelected) categories.Add(AnomalyCategory.Security);
        if (IsMalformedSelected) categories.Add(AnomalyCategory.Malformed);
        _globalFilterState.AnomalyCategoryFilter = categories;

        // Update detector filters
        var detectors = AvailableDetectors
            .Where(d => d.IsSelected)
            .Select(d => d.Name)
            .ToList();
        _globalFilterState.AnomalyDetectorFilter = detectors;

        FiltersChanged?.Invoke(this, EventArgs.Empty);
    }

    public void SetAvailableDetectors(IEnumerable<string> detectorNames)
    {
        AvailableDetectors.Clear();
        foreach (var name in detectorNames)
        {
            var toggle = new DetectorToggle(name);
            toggle.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(DetectorToggle.IsSelected))
                    UpdateGlobalFilters();
            };
            AvailableDetectors.Add(toggle);
        }
    }

    [RelayCommand]
    private void ClearAllFilters()
    {
        IsCriticalSelected = false;
        IsHighSelected = false;
        IsMediumSelected = false;
        IsLowSelected = false;
        IsNetworkSelected = false;
        IsTcpSelected = false;
        IsApplicationSelected = false;
        IsVoipSelected = false;
        IsIotSelected = false;
        IsSecuritySelected = false;
        IsMalformedSelected = false;

        foreach (var detector in AvailableDetectors)
            detector.IsSelected = false;

        _globalFilterState.ClearAnomalyFilters();
        FiltersChanged?.Invoke(this, EventArgs.Empty);
    }

    public bool HasActiveFilters =>
        IsCriticalSelected || IsHighSelected || IsMediumSelected || IsLowSelected ||
        IsNetworkSelected || IsTcpSelected || IsApplicationSelected || IsVoipSelected ||
        IsIotSelected || IsSecuritySelected || IsMalformedSelected ||
        AvailableDetectors.Any(d => d.IsSelected);
}

/// <summary>
/// Toggle state for a single detector.
/// </summary>
public partial class DetectorToggle : ObservableObject
{
    public string Name { get; }
    public string DisplayName { get; }

    [ObservableProperty] private bool _isSelected;

    public DetectorToggle(string name)
    {
        Name = name;
        DisplayName = name.Replace("Detector", "").Replace("Anomaly", "").Trim();
    }
}
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/Components/AnomaliesFilterViewModel.cs
git commit -m "feat(anomalies): add AnomaliesFilterViewModel"
```

---

## Phase 3: Main ViewModel

### Task 11: Create AnomaliesViewModel (Part 1 - Core)

**Files:**
- Create: `src/PCAPAnalyzer.UI/ViewModels/AnomaliesViewModel.cs`

**Step 1: Create the main ViewModel**

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Main ViewModel for the Anomalies tab.
/// Orchestrates component ViewModels and manages anomaly data.
/// </summary>
public partial class AnomaliesViewModel : ObservableObject, IDisposable
{
    private readonly IAnomalyFrameIndexService _frameIndexService;
    private readonly GlobalFilterState _globalFilterState;
    private readonly IGeoIPService _geoIPService;
    private readonly ILogger<AnomaliesViewModel> _logger;

    private List<NetworkAnomaly> _allAnomalies = new();
    private List<NetworkAnomaly> _filteredAnomalies = new();
    private CancellationTokenSource? _filterCts;
    private bool _disposed;

    // Component ViewModels
    public AnomaliesStatisticsViewModel Statistics { get; }
    public AnomaliesChartsViewModel Charts { get; }
    public AnomaliesDrillDownViewModel DrillDown { get; }
    public AnomaliesFilterViewModel Filters { get; }

    // Loading state
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _hasData;
    [ObservableProperty] private string _loadingMessage = "Loading anomalies...";

    // Filter progress
    [ObservableProperty] private bool _isFiltering;
    [ObservableProperty] private double _filterProgress;

    public AnomaliesViewModel(
        IAnomalyFrameIndexService frameIndexService,
        GlobalFilterState globalFilterState,
        IGeoIPService geoIPService,
        ILogger<AnomaliesViewModel> logger)
    {
        _frameIndexService = frameIndexService;
        _globalFilterState = globalFilterState;
        _geoIPService = geoIPService;
        _logger = logger;

        // Initialize component ViewModels
        Statistics = new AnomaliesStatisticsViewModel();
        Charts = new AnomaliesChartsViewModel();
        DrillDown = new AnomaliesDrillDownViewModel();
        Filters = new AnomaliesFilterViewModel(globalFilterState);

        // Subscribe to filter changes
        Filters.FiltersChanged += OnFiltersChanged;
        _globalFilterState.PropertyChanged += OnGlobalFilterStateChanged;
    }

    public async Task LoadFromAnalysisResultAsync(AnalysisResult result)
    {
        if (result?.Anomalies == null)
        {
            _logger.LogWarning("LoadFromAnalysisResultAsync called with null anomalies");
            HasData = false;
            return;
        }

        IsLoading = true;
        LoadingMessage = "Loading anomalies...";

        try
        {
            _allAnomalies = result.Anomalies.ToList();
            _filteredAnomalies = _allAnomalies;

            // Build frame index for cross-tab filtering
            _frameIndexService.BuildIndex(_allAnomalies);

            // Populate available detectors in filter panel
            Filters.SetAvailableDetectors(_frameIndexService.GetDetectorNames());

            await UpdateAllComponentsAsync();

            HasData = _allAnomalies.Count > 0;
            _logger.LogInformation("Loaded {Count} anomalies", _allAnomalies.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading anomalies");
            HasData = false;
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task UpdateAllComponentsAsync()
    {
        await Task.Run(() =>
        {
            var kpis = CalculateKPIs(_filteredAnomalies);
            var timePoints = BuildTimelineSeries(_filteredAnomalies);
            var sources = BuildRankedSources(_filteredAnomalies);
            var targets = BuildRankedTargets(_filteredAnomalies);
            var ports = BuildPortBreakdown(_filteredAnomalies);
            var categories = BuildCategoryBreakdown(_filteredAnomalies);

            Dispatcher.UIThread.Post(() =>
            {
                Statistics.UpdateKPIs(kpis);
                Statistics.UpdateTopSources(sources);
                Statistics.UpdateTopTargets(targets);
                Statistics.UpdateTopPorts(ports);
                Statistics.UpdateCategoryBreakdown(categories);
                Statistics.SetFilteredState(
                    _filteredAnomalies.Count != _allAnomalies.Count,
                    _filteredAnomalies.Count);

                Charts.UpdateTimeline(timePoints);
                Charts.UpdateCategoryDonut(categories);
                Charts.UpdatePortsBar(ports);
            });
        });
    }

    private AnomalyKPIs CalculateKPIs(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new AnomalyKPIs();

        var timestamps = anomalies
            .Select(a => a.DetectedAt)
            .OrderBy(t => t)
            .ToList();

        return new AnomalyKPIs
        {
            TotalAnomalies = anomalies.Count,
            CriticalCount = anomalies.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = anomalies.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = anomalies.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = anomalies.Count(a => a.Severity == AnomalySeverity.Low),
            UniqueSourceIPs = anomalies.Select(a => a.SourceIP).Where(ip => !string.IsNullOrEmpty(ip)).Distinct().Count(),
            UniqueTargetIPs = anomalies.Select(a => a.DestinationIP).Where(ip => !string.IsNullOrEmpty(ip)).Distinct().Count(),
            FirstAnomalyTime = timestamps.FirstOrDefault(),
            LastAnomalyTime = timestamps.LastOrDefault(),
            TimeSpan = timestamps.Count > 1 ? timestamps.Last() - timestamps.First() : TimeSpan.Zero
        };
    }

    private List<AnomalyTimePoint> BuildTimelineSeries(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new List<AnomalyTimePoint>();

        // Group by minute
        var grouped = anomalies
            .GroupBy(a => new DateTime(
                a.DetectedAt.Year, a.DetectedAt.Month, a.DetectedAt.Day,
                a.DetectedAt.Hour, a.DetectedAt.Minute, 0))
            .OrderBy(g => g.Key);

        return grouped.Select(g => new AnomalyTimePoint
        {
            Timestamp = g.Key,
            CriticalCount = g.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = g.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = g.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = g.Count(a => a.Severity == AnomalySeverity.Low)
        }).ToList();
    }

    private List<AnomalyEndpointViewModel> BuildRankedSources(List<NetworkAnomaly> anomalies)
    {
        return anomalies
            .Where(a => !string.IsNullOrEmpty(a.SourceIP))
            .GroupBy(a => a.SourceIP)
            .Select(g => BuildEndpointViewModel(g.Key!, g.ToList()))
            .OrderByDescending(e => e.CriticalCount)
            .ThenByDescending(e => e.HighCount)
            .ThenByDescending(e => e.AnomalyCount)
            .Take(20)
            .Select((e, i) => { e.Rank = i + 1; return e; })
            .ToList();
    }

    private List<AnomalyEndpointViewModel> BuildRankedTargets(List<NetworkAnomaly> anomalies)
    {
        return anomalies
            .Where(a => !string.IsNullOrEmpty(a.DestinationIP))
            .GroupBy(a => a.DestinationIP)
            .Select(g => BuildEndpointViewModel(g.Key!, g.ToList()))
            .OrderByDescending(e => e.CriticalCount)
            .ThenByDescending(e => e.HighCount)
            .ThenByDescending(e => e.AnomalyCount)
            .Take(20)
            .Select((e, i) => { e.Rank = i + 1; return e; })
            .ToList();
    }

    private AnomalyEndpointViewModel BuildEndpointViewModel(string ip, List<NetworkAnomaly> anomalies)
    {
        var total = _filteredAnomalies.Count > 0 ? _filteredAnomalies.Count : 1;
        var geoInfo = _geoIPService.GetCountryInfo(ip);

        return new AnomalyEndpointViewModel
        {
            IPAddress = ip,
            AnomalyCount = anomalies.Count,
            CriticalCount = anomalies.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = anomalies.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = anomalies.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = anomalies.Count(a => a.Severity == AnomalySeverity.Low),
            HighestSeverity = anomalies.Max(a => a.Severity),
            Percentage = (double)anomalies.Count / total * 100,
            Country = geoInfo?.CountryName ?? "Unknown",
            CountryCode = geoInfo?.CountryCode ?? "",
            Categories = anomalies.Select(a => a.Category).Distinct().ToList(),
            AffectedFrames = anomalies.SelectMany(a => a.AffectedFrames ?? Enumerable.Empty<long>()).Distinct().ToList()
        };
    }

    private List<AnomalyPortViewModel> BuildPortBreakdown(List<NetworkAnomaly> anomalies)
    {
        var portAnomalies = anomalies
            .Where(a => a.DestinationPort > 0)
            .GroupBy(a => a.DestinationPort)
            .Select(g => new AnomalyPortViewModel
            {
                Port = g.Key,
                ServiceName = GetServiceName(g.Key),
                AnomalyCount = g.Count(),
                Percentage = (double)g.Count() / anomalies.Count * 100,
                HighestSeverity = g.Max(a => a.Severity)
            })
            .OrderByDescending(p => p.AnomalyCount)
            .Take(15)
            .ToList();

        return portAnomalies;
    }

    private List<AnomalyCategoryViewModel> BuildCategoryBreakdown(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new List<AnomalyCategoryViewModel>();

        return anomalies
            .GroupBy(a => a.Category)
            .Select(g => new AnomalyCategoryViewModel
            {
                Category = g.Key,
                Count = g.Count(),
                Percentage = (double)g.Count() / anomalies.Count * 100
            })
            .OrderByDescending(c => c.Count)
            .ToList();
    }

    private static string GetServiceName(int port) => port switch
    {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1883 => "MQTT",
        3306 => "MySQL",
        3389 => "RDP",
        5060 => "SIP",
        5432 => "PostgreSQL",
        5683 => "CoAP",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        _ => ""
    };

    private void OnFiltersChanged(object? sender, EventArgs e)
    {
        _ = ApplyFiltersAsync();
    }

    private void OnGlobalFilterStateChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // React to IP/Port/Time filter changes from other tabs
        if (e.PropertyName is "SourceIPs" or "DestinationIPs" or "PortRange" or "TimeRange")
        {
            _ = ApplyFiltersAsync();
        }
    }

    [RelayCommand]
    private async Task ApplyFiltersAsync()
    {
        _filterCts?.Cancel();
        _filterCts = new CancellationTokenSource();
        var token = _filterCts.Token;

        IsFiltering = true;
        FilterProgress = 0;

        try
        {
            _filteredAnomalies = await Task.Run(() =>
            {
                var result = _frameIndexService.GetFilteredAnomalies(
                    _globalFilterState.AnomalySeverityFilter.Count > 0 ? _globalFilterState.AnomalySeverityFilter : null,
                    _globalFilterState.AnomalyCategoryFilter.Count > 0 ? _globalFilterState.AnomalyCategoryFilter : null,
                    _globalFilterState.AnomalyDetectorFilter.Count > 0 ? _globalFilterState.AnomalyDetectorFilter : null);

                // Apply IP filters if set
                var filtered = result.AsEnumerable();

                if (_globalFilterState.SourceIPs?.Count > 0)
                    filtered = filtered.Where(a => _globalFilterState.SourceIPs.Contains(a.SourceIP));

                if (_globalFilterState.DestinationIPs?.Count > 0)
                    filtered = filtered.Where(a => _globalFilterState.DestinationIPs.Contains(a.DestinationIP));

                // Apply time range if set
                if (_globalFilterState.TimeRange != null)
                {
                    var range = _globalFilterState.TimeRange;
                    filtered = filtered.Where(a =>
                        a.DetectedAt >= range.Start && a.DetectedAt <= range.End);
                }

                return filtered.ToList();
            }, token);

            FilterProgress = 50;

            if (!token.IsCancellationRequested)
            {
                await UpdateAllComponentsAsync();
                FilterProgress = 100;
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Filter operation cancelled");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error applying filters");
        }
        finally
        {
            IsFiltering = false;
        }
    }

    [RelayCommand]
    private void ShowSourceDrillDown(AnomalyEndpointViewModel source)
    {
        var sourceAnomalies = _filteredAnomalies
            .Where(a => a.SourceIP == source.IPAddress)
            .ToList();

        DrillDown.ShowSourceDetail(source.IPAddress, sourceAnomalies);
    }

    [RelayCommand]
    private void ShowTargetDrillDown(AnomalyEndpointViewModel target)
    {
        var targetAnomalies = _filteredAnomalies
            .Where(a => a.DestinationIP == target.IPAddress)
            .ToList();

        DrillDown.ShowTargetDetail(target.IPAddress, targetAnomalies);
    }

    [RelayCommand]
    private void ShowTimeSliceDrillDown(DateTime timestamp)
    {
        DrillDown.ShowTimeSliceDrillDown(timestamp, TimeSpan.FromMinutes(5), _filteredAnomalies);
    }

    public void Clear()
    {
        _allAnomalies.Clear();
        _filteredAnomalies.Clear();
        _frameIndexService.ClearIndex();
        Statistics.Clear();
        Charts.Clear();
        DrillDown.Clear();
        HasData = false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Filters.FiltersChanged -= OnFiltersChanged;
        _globalFilterState.PropertyChanged -= OnGlobalFilterStateChanged;
        _filterCts?.Cancel();
        _filterCts?.Dispose();
    }
}
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/AnomaliesViewModel.cs
git commit -m "feat(anomalies): add AnomaliesViewModel main orchestrator"
```

---

## Phase 4: Views (XAML)

### Task 12: Create AnomaliesView.axaml

**Files:**
- Create: `src/PCAPAnalyzer.UI/Views/AnomaliesView.axaml`
- Create: `src/PCAPAnalyzer.UI/Views/AnomaliesView.axaml.cs`

**Step 1: Create the XAML view**

```xml
<UserControl xmlns="https://github.com/avaloniaui"
             xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
             xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
             xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
             xmlns:vm="using:PCAPAnalyzer.UI.ViewModels"
             xmlns:lvc="using:LiveChartsCore.SkiaSharpView.Avalonia"
             mc:Ignorable="d" d:DesignWidth="1200" d:DesignHeight="900"
             x:Class="PCAPAnalyzer.UI.Views.AnomaliesView"
             x:DataType="vm:AnomaliesViewModel"
             Background="#0D1117">

    <UserControl.Styles>
        <!-- Modern Card Style -->
        <Style Selector="Border.modern-card">
            <Setter Property="Background" Value="#0D1117"/>
            <Setter Property="BorderBrush" Value="#30363D"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="20"/>
        </Style>

        <!-- KPI Card Style -->
        <Style Selector="Border.kpi-card">
            <Setter Property="Background" Value="#161B22"/>
            <Setter Property="BorderBrush" Value="#30363D"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="16"/>
        </Style>

        <!-- Section Header -->
        <Style Selector="TextBlock.section-header">
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="#F0F6FC"/>
            <Setter Property="Margin" Value="0,0,0,12"/>
        </Style>

        <!-- KPI Value -->
        <Style Selector="TextBlock.kpi-value">
            <Setter Property="FontSize" Value="24"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontFamily" Value="Consolas, monospace"/>
        </Style>

        <!-- KPI Label -->
        <Style Selector="TextBlock.kpi-label">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Foreground" Value="#8B949E"/>
            <Setter Property="Margin" Value="0,4,0,0"/>
        </Style>
    </UserControl.Styles>

    <Grid>
        <!-- Loading Overlay -->
        <Border IsVisible="{Binding IsLoading}"
                Background="#CC0D1117"
                ZIndex="100">
            <StackPanel HorizontalAlignment="Center" VerticalAlignment="Center">
                <ProgressBar IsIndeterminate="True" Width="200"/>
                <TextBlock Text="{Binding LoadingMessage}"
                           Foreground="#8B949E"
                           HorizontalAlignment="Center"
                           Margin="0,12,0,0"/>
            </StackPanel>
        </Border>

        <!-- No Data Message -->
        <Border IsVisible="{Binding !HasData}"
                Background="#0D1117">
            <StackPanel HorizontalAlignment="Center" VerticalAlignment="Center">
                <TextBlock Text="No Anomalies Detected"
                           FontSize="18"
                           FontWeight="SemiBold"
                           Foreground="#8B949E"
                           HorizontalAlignment="Center"/>
                <TextBlock Text="Load a PCAP file to analyze for anomalies"
                           FontSize="13"
                           Foreground="#6B7280"
                           HorizontalAlignment="Center"
                           Margin="0,8,0,0"/>
            </StackPanel>
        </Border>

        <!-- Main Content -->
        <ScrollViewer IsVisible="{Binding HasData}"
                      HorizontalScrollBarVisibility="Disabled"
                      VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="24" Spacing="24">

                <!-- Filter Progress Bar -->
                <ProgressBar IsVisible="{Binding IsFiltering}"
                             Value="{Binding FilterProgress}"
                             Minimum="0" Maximum="100"
                             Height="4"
                             Foreground="#3B82F6"/>

                <!-- KPI Row -->
                <Grid ColumnDefinitions="*,*,*,*,*,*">
                    <!-- Total Anomalies -->
                    <Border Classes="kpi-card" Grid.Column="0" Margin="0,0,8,0">
                        <StackPanel>
                            <TextBlock Text="{Binding Statistics.TotalAnomalies}"
                                       Classes="kpi-value"
                                       Foreground="#3B82F6"/>
                            <TextBlock Text="Total Anomalies" Classes="kpi-label"/>
                        </StackPanel>
                    </Border>

                    <!-- Critical -->
                    <Border Classes="kpi-card" Grid.Column="1" Margin="4,0">
                        <StackPanel>
                            <TextBlock Text="{Binding Statistics.CriticalCount}"
                                       Classes="kpi-value"
                                       Foreground="#F85149"/>
                            <TextBlock Text="Critical" Classes="kpi-label"/>
                        </StackPanel>
                    </Border>

                    <!-- High -->
                    <Border Classes="kpi-card" Grid.Column="2" Margin="4,0">
                        <StackPanel>
                            <TextBlock Text="{Binding Statistics.HighCount}"
                                       Classes="kpi-value"
                                       Foreground="#F59E0B"/>
                            <TextBlock Text="High" Classes="kpi-label"/>
                        </StackPanel>
                    </Border>

                    <!-- Unique Sources -->
                    <Border Classes="kpi-card" Grid.Column="3" Margin="4,0">
                        <StackPanel>
                            <TextBlock Text="{Binding Statistics.UniqueSourceIPs}"
                                       Classes="kpi-value"
                                       Foreground="#06B6D4"/>
                            <TextBlock Text="Unique Sources" Classes="kpi-label"/>
                        </StackPanel>
                    </Border>

                    <!-- Unique Targets -->
                    <Border Classes="kpi-card" Grid.Column="4" Margin="4,0">
                        <StackPanel>
                            <TextBlock Text="{Binding Statistics.UniqueTargetIPs}"
                                       Classes="kpi-value"
                                       Foreground="#EC4899"/>
                            <TextBlock Text="Unique Targets" Classes="kpi-label"/>
                        </StackPanel>
                    </Border>

                    <!-- Time Span -->
                    <Border Classes="kpi-card" Grid.Column="5" Margin="8,0,0,0">
                        <StackPanel>
                            <TextBlock Text="{Binding Statistics.TimeSpanFormatted}"
                                       Classes="kpi-value"
                                       Foreground="#A855F7"/>
                            <TextBlock Text="Time Span" Classes="kpi-label"/>
                        </StackPanel>
                    </Border>
                </Grid>

                <!-- Anomaly Timeline (Hero Chart) -->
                <Border Classes="modern-card">
                    <Grid RowDefinitions="Auto,*">
                        <!-- Header with accent bar -->
                        <Border Grid.Row="0"
                                Background="#1C2128"
                                CornerRadius="8,8,0,0"
                                Margin="-20,-20,-20,16"
                                Padding="20,0">
                            <Grid>
                                <Border Height="3"
                                        Background="#F85149"
                                        VerticalAlignment="Top"
                                        CornerRadius="0,0,0,0"
                                        Margin="-20,0"/>
                                <StackPanel Orientation="Horizontal"
                                            Height="48"
                                            VerticalAlignment="Center">
                                    <TextBlock Text="Anomalies Over Time"
                                               FontSize="14"
                                               FontWeight="SemiBold"
                                               Foreground="#F0F6FC"
                                               VerticalAlignment="Center"/>
                                    <StackPanel Orientation="Horizontal"
                                                Margin="24,0,0,0"
                                                Spacing="8">
                                        <Button Content="-"
                                                Width="28" Height="28"
                                                Command="{Binding Charts.ZoomOut}"
                                                Background="#21262D"
                                                Foreground="#F0F6FC"/>
                                        <Button Content="Reset"
                                                Height="28"
                                                Command="{Binding Charts.ResetZoom}"
                                                Background="#21262D"
                                                Foreground="#F0F6FC"/>
                                        <Button Content="+"
                                                Width="28" Height="28"
                                                Command="{Binding Charts.ZoomIn}"
                                                Background="#21262D"
                                                Foreground="#F0F6FC"/>
                                    </StackPanel>
                                </StackPanel>
                            </Grid>
                        </Border>

                        <!-- Chart -->
                        <lvc:CartesianChart Grid.Row="1"
                                            Series="{Binding Charts.TimelineSeries}"
                                            XAxes="{Binding Charts.TimelineXAxes}"
                                            YAxes="{Binding Charts.TimelineYAxes}"
                                            Height="320"
                                            ZoomMode="X"
                                            TooltipPosition="Hidden"/>
                    </Grid>
                </Border>

                <!-- Secondary Charts Row -->
                <Grid ColumnDefinitions="*,*">
                    <!-- Anomalous Ports Bar Chart -->
                    <Border Classes="modern-card" Grid.Column="0" Margin="0,0,12,0">
                        <Grid RowDefinitions="Auto,*">
                            <Border Grid.Row="0"
                                    Background="#1C2128"
                                    CornerRadius="8,8,0,0"
                                    Margin="-20,-20,-20,16"
                                    Padding="20,0">
                                <Grid>
                                    <Border Height="3"
                                            Background="#3B82F6"
                                            VerticalAlignment="Top"
                                            Margin="-20,0"/>
                                    <TextBlock Text="Anomalous Ports"
                                               FontSize="14"
                                               FontWeight="SemiBold"
                                               Foreground="#F0F6FC"
                                               Height="48"
                                               VerticalAlignment="Center"/>
                                </Grid>
                            </Border>

                            <lvc:CartesianChart Grid.Row="1"
                                                Series="{Binding Charts.PortsSeries}"
                                                XAxes="{Binding Charts.PortsXAxes}"
                                                YAxes="{Binding Charts.PortsYAxes}"
                                                Height="250"
                                                TooltipPosition="Top"/>
                        </Grid>
                    </Border>

                    <!-- Category Distribution Donut -->
                    <Border Classes="modern-card" Grid.Column="1" Margin="12,0,0,0">
                        <Grid RowDefinitions="Auto,*">
                            <Border Grid.Row="0"
                                    Background="#1C2128"
                                    CornerRadius="8,8,0,0"
                                    Margin="-20,-20,-20,16"
                                    Padding="20,0">
                                <Grid>
                                    <Border Height="3"
                                            Background="#10B981"
                                            VerticalAlignment="Top"
                                            Margin="-20,0"/>
                                    <TextBlock Text="Category Distribution"
                                               FontSize="14"
                                               FontWeight="SemiBold"
                                               Foreground="#F0F6FC"
                                               Height="48"
                                               VerticalAlignment="Center"/>
                                </Grid>
                            </Border>

                            <lvc:PieChart Grid.Row="1"
                                          Series="{Binding Charts.CategorySeries}"
                                          Height="250"
                                          TooltipPosition="Center"/>
                        </Grid>
                    </Border>
                </Grid>

                <!-- Ranked Tables Row -->
                <Grid ColumnDefinitions="*,*">
                    <!-- Top Anomalous Sources -->
                    <Border Classes="modern-card" Grid.Column="0" Margin="0,0,12,0">
                        <Grid RowDefinitions="Auto,*">
                            <Border Grid.Row="0"
                                    Background="#1C2128"
                                    CornerRadius="8,8,0,0"
                                    Margin="-20,-20,-20,16"
                                    Padding="20,0">
                                <Grid>
                                    <Border Height="3"
                                            Background="#06B6D4"
                                            VerticalAlignment="Top"
                                            Margin="-20,0"/>
                                    <TextBlock Text="Top Anomalous Sources"
                                               FontSize="14"
                                               FontWeight="SemiBold"
                                               Foreground="#F0F6FC"
                                               Height="48"
                                               VerticalAlignment="Center"/>
                                </Grid>
                            </Border>

                            <ScrollViewer Grid.Row="1" Height="440">
                                <ItemsControl ItemsSource="{Binding Statistics.TopSources}">
                                    <ItemsControl.ItemTemplate>
                                        <DataTemplate>
                                            <Border Background="#161B22"
                                                    BorderBrush="#30363D"
                                                    BorderThickness="0,0,0,1"
                                                    Padding="12,10">
                                                <Grid ColumnDefinitions="40,*,80,120,Auto">
                                                    <!-- Rank -->
                                                    <TextBlock Grid.Column="0"
                                                               Text="{Binding Rank, StringFormat='#{0}'}"
                                                               FontSize="11"
                                                               Foreground="#6B7280"
                                                               VerticalAlignment="Center"/>

                                                    <!-- IP + Country -->
                                                    <StackPanel Grid.Column="1">
                                                        <TextBlock Text="{Binding IPAddress}"
                                                                   FontFamily="Consolas, monospace"
                                                                   FontWeight="SemiBold"
                                                                   Foreground="#F0F6FC"/>
                                                        <TextBlock Text="{Binding Country}"
                                                                   FontSize="11"
                                                                   Foreground="#8B949E"/>
                                                    </StackPanel>

                                                    <!-- Severity counts -->
                                                    <StackPanel Grid.Column="2"
                                                                Orientation="Horizontal"
                                                                Spacing="4"
                                                                VerticalAlignment="Center">
                                                        <Border Background="#F85149"
                                                                CornerRadius="4"
                                                                Padding="4,2"
                                                                IsVisible="{Binding CriticalCount}">
                                                            <TextBlock Text="{Binding CriticalCount}"
                                                                       FontSize="10"
                                                                       Foreground="White"/>
                                                        </Border>
                                                        <Border Background="#F59E0B"
                                                                CornerRadius="4"
                                                                Padding="4,2"
                                                                IsVisible="{Binding HighCount}">
                                                            <TextBlock Text="{Binding HighCount}"
                                                                       FontSize="10"
                                                                       Foreground="White"/>
                                                        </Border>
                                                    </StackPanel>

                                                    <!-- Anomaly count + percentage -->
                                                    <StackPanel Grid.Column="3"
                                                                HorizontalAlignment="Right"
                                                                VerticalAlignment="Center">
                                                        <TextBlock Text="{Binding AnomalyCount, StringFormat='{0} anomalies'}"
                                                                   FontSize="12"
                                                                   Foreground="#F0F6FC"
                                                                   HorizontalAlignment="Right"/>
                                                        <TextBlock Text="{Binding Percentage, StringFormat='{0:F1}%'}"
                                                                   FontSize="11"
                                                                   Foreground="#8B949E"
                                                                   HorizontalAlignment="Right"/>
                                                    </StackPanel>

                                                    <!-- Details button -->
                                                    <Button Grid.Column="4"
                                                            Content="→"
                                                            Width="32" Height="32"
                                                            Background="Transparent"
                                                            Foreground="#8B949E"
                                                            Command="{Binding $parent[ItemsControl].((vm:AnomaliesViewModel)DataContext).ShowSourceDrillDownCommand}"
                                                            CommandParameter="{Binding}"
                                                            Margin="8,0,0,0"/>
                                                </Grid>
                                            </Border>
                                        </DataTemplate>
                                    </ItemsControl.ItemTemplate>
                                </ItemsControl>
                            </ScrollViewer>
                        </Grid>
                    </Border>

                    <!-- Top Anomalous Targets -->
                    <Border Classes="modern-card" Grid.Column="1" Margin="12,0,0,0">
                        <Grid RowDefinitions="Auto,*">
                            <Border Grid.Row="0"
                                    Background="#1C2128"
                                    CornerRadius="8,8,0,0"
                                    Margin="-20,-20,-20,16"
                                    Padding="20,0">
                                <Grid>
                                    <Border Height="3"
                                            Background="#EC4899"
                                            VerticalAlignment="Top"
                                            Margin="-20,0"/>
                                    <TextBlock Text="Top Anomalous Targets"
                                               FontSize="14"
                                               FontWeight="SemiBold"
                                               Foreground="#F0F6FC"
                                               Height="48"
                                               VerticalAlignment="Center"/>
                                </Grid>
                            </Border>

                            <ScrollViewer Grid.Row="1" Height="440">
                                <ItemsControl ItemsSource="{Binding Statistics.TopTargets}">
                                    <ItemsControl.ItemTemplate>
                                        <DataTemplate>
                                            <Border Background="#161B22"
                                                    BorderBrush="#30363D"
                                                    BorderThickness="0,0,0,1"
                                                    Padding="12,10">
                                                <Grid ColumnDefinitions="40,*,80,120,Auto">
                                                    <!-- Rank -->
                                                    <TextBlock Grid.Column="0"
                                                               Text="{Binding Rank, StringFormat='#{0}'}"
                                                               FontSize="11"
                                                               Foreground="#6B7280"
                                                               VerticalAlignment="Center"/>

                                                    <!-- IP + Country -->
                                                    <StackPanel Grid.Column="1">
                                                        <TextBlock Text="{Binding IPAddress}"
                                                                   FontFamily="Consolas, monospace"
                                                                   FontWeight="SemiBold"
                                                                   Foreground="#F0F6FC"/>
                                                        <TextBlock Text="{Binding Country}"
                                                                   FontSize="11"
                                                                   Foreground="#8B949E"/>
                                                    </StackPanel>

                                                    <!-- Severity counts -->
                                                    <StackPanel Grid.Column="2"
                                                                Orientation="Horizontal"
                                                                Spacing="4"
                                                                VerticalAlignment="Center">
                                                        <Border Background="#F85149"
                                                                CornerRadius="4"
                                                                Padding="4,2"
                                                                IsVisible="{Binding CriticalCount}">
                                                            <TextBlock Text="{Binding CriticalCount}"
                                                                       FontSize="10"
                                                                       Foreground="White"/>
                                                        </Border>
                                                        <Border Background="#F59E0B"
                                                                CornerRadius="4"
                                                                Padding="4,2"
                                                                IsVisible="{Binding HighCount}">
                                                            <TextBlock Text="{Binding HighCount}"
                                                                       FontSize="10"
                                                                       Foreground="White"/>
                                                        </Border>
                                                    </StackPanel>

                                                    <!-- Anomaly count + percentage -->
                                                    <StackPanel Grid.Column="3"
                                                                HorizontalAlignment="Right"
                                                                VerticalAlignment="Center">
                                                        <TextBlock Text="{Binding AnomalyCount, StringFormat='{0} anomalies'}"
                                                                   FontSize="12"
                                                                   Foreground="#F0F6FC"
                                                                   HorizontalAlignment="Right"/>
                                                        <TextBlock Text="{Binding Percentage, StringFormat='{0:F1}%'}"
                                                                   FontSize="11"
                                                                   Foreground="#8B949E"
                                                                   HorizontalAlignment="Right"/>
                                                    </StackPanel>

                                                    <!-- Details button -->
                                                    <Button Grid.Column="4"
                                                            Content="→"
                                                            Width="32" Height="32"
                                                            Background="Transparent"
                                                            Foreground="#8B949E"
                                                            Command="{Binding $parent[ItemsControl].((vm:AnomaliesViewModel)DataContext).ShowTargetDrillDownCommand}"
                                                            CommandParameter="{Binding}"
                                                            Margin="8,0,0,0"/>
                                                </Grid>
                                            </Border>
                                        </DataTemplate>
                                    </ItemsControl.ItemTemplate>
                                </ItemsControl>
                            </ScrollViewer>
                        </Grid>
                    </Border>
                </Grid>

            </StackPanel>
        </ScrollViewer>

        <!-- Drill-Down Popup Overlay -->
        <Border IsVisible="{Binding DrillDown.IsDetailPopupOpen}"
                Background="#80000000"
                ZIndex="50">
            <Border Background="#161B22"
                    BorderBrush="#30363D"
                    BorderThickness="1"
                    CornerRadius="12"
                    MaxWidth="700"
                    MaxHeight="600"
                    HorizontalAlignment="Center"
                    VerticalAlignment="Center"
                    Padding="24">
                <Grid RowDefinitions="Auto,Auto,Auto,*,Auto">
                    <!-- Header -->
                    <Grid Grid.Row="0" ColumnDefinitions="*,Auto">
                        <StackPanel>
                            <TextBlock Text="{Binding DrillDown.DetailPopupTitle}"
                                       FontSize="18"
                                       FontWeight="SemiBold"
                                       Foreground="#F0F6FC"/>
                            <TextBlock Text="{Binding DrillDown.DetailPopupSubtitle}"
                                       FontSize="12"
                                       Foreground="#8B949E"
                                       Margin="0,4,0,0"/>
                        </StackPanel>
                        <Button Grid.Column="1"
                                Content="✕"
                                Width="32" Height="32"
                                Background="Transparent"
                                Foreground="#8B949E"
                                Command="{Binding DrillDown.CloseDetailPopupCommand}"/>
                    </Grid>

                    <!-- Severity Summary -->
                    <Grid Grid.Row="1" ColumnDefinitions="*,*,*,*" Margin="0,16,0,0">
                        <StackPanel Grid.Column="0" HorizontalAlignment="Center">
                            <TextBlock Text="{Binding DrillDown.DetailCriticalCount}"
                                       FontSize="20"
                                       FontWeight="SemiBold"
                                       Foreground="#F85149"
                                       HorizontalAlignment="Center"/>
                            <TextBlock Text="Critical" FontSize="11" Foreground="#8B949E" HorizontalAlignment="Center"/>
                        </StackPanel>
                        <StackPanel Grid.Column="1" HorizontalAlignment="Center">
                            <TextBlock Text="{Binding DrillDown.DetailHighCount}"
                                       FontSize="20"
                                       FontWeight="SemiBold"
                                       Foreground="#F59E0B"
                                       HorizontalAlignment="Center"/>
                            <TextBlock Text="High" FontSize="11" Foreground="#8B949E" HorizontalAlignment="Center"/>
                        </StackPanel>
                        <StackPanel Grid.Column="2" HorizontalAlignment="Center">
                            <TextBlock Text="{Binding DrillDown.DetailMediumCount}"
                                       FontSize="20"
                                       FontWeight="SemiBold"
                                       Foreground="#FCD34D"
                                       HorizontalAlignment="Center"/>
                            <TextBlock Text="Medium" FontSize="11" Foreground="#8B949E" HorizontalAlignment="Center"/>
                        </StackPanel>
                        <StackPanel Grid.Column="3" HorizontalAlignment="Center">
                            <TextBlock Text="{Binding DrillDown.DetailLowCount}"
                                       FontSize="20"
                                       FontWeight="SemiBold"
                                       Foreground="#3B82F6"
                                       HorizontalAlignment="Center"/>
                            <TextBlock Text="Low" FontSize="11" Foreground="#8B949E" HorizontalAlignment="Center"/>
                        </StackPanel>
                    </Grid>

                    <Separator Grid.Row="2" Margin="0,16" Background="#30363D"/>

                    <!-- Anomaly List -->
                    <ScrollViewer Grid.Row="3" MaxHeight="300">
                        <ItemsControl ItemsSource="{Binding DrillDown.DetailAnomalies}">
                            <ItemsControl.ItemTemplate>
                                <DataTemplate>
                                    <Border BorderBrush="#30363D"
                                            BorderThickness="0,0,0,1"
                                            Padding="8,10">
                                        <Grid ColumnDefinitions="80,*,Auto">
                                            <TextBlock Grid.Column="0"
                                                       Text="{Binding DetectedAt, StringFormat='{0:HH:mm:ss}'}"
                                                       FontFamily="Consolas, monospace"
                                                       FontSize="11"
                                                       Foreground="#8B949E"
                                                       VerticalAlignment="Center"/>
                                            <StackPanel Grid.Column="1">
                                                <TextBlock Text="{Binding Type}"
                                                           FontWeight="SemiBold"
                                                           Foreground="#F0F6FC"/>
                                                <TextBlock Text="{Binding Description}"
                                                           FontSize="11"
                                                           Foreground="#8B949E"
                                                           TextTrimming="CharacterEllipsis"
                                                           MaxWidth="400"/>
                                            </StackPanel>
                                            <Border Grid.Column="2"
                                                    CornerRadius="4"
                                                    Padding="8,4"
                                                    VerticalAlignment="Center">
                                                <Border.Background>
                                                    <MultiBinding>
                                                        <Binding Path="Severity"/>
                                                    </MultiBinding>
                                                </Border.Background>
                                                <TextBlock Text="{Binding Severity}"
                                                           FontSize="10"
                                                           Foreground="White"/>
                                            </Border>
                                        </Grid>
                                    </Border>
                                </DataTemplate>
                            </ItemsControl.ItemTemplate>
                        </ItemsControl>
                    </ScrollViewer>

                    <!-- Pagination -->
                    <StackPanel Grid.Row="4"
                                Orientation="Horizontal"
                                HorizontalAlignment="Center"
                                Margin="0,16,0,0"
                                Spacing="8">
                        <Button Content="← Previous"
                                Command="{Binding DrillDown.PreviousDetailPageCommand}"
                                Background="#21262D"
                                Foreground="#F0F6FC"/>
                        <TextBlock VerticalAlignment="Center"
                                   Foreground="#8B949E">
                            <TextBlock.Text>
                                <MultiBinding StringFormat="Page {0} of {1}">
                                    <Binding Path="DrillDown.DetailCurrentPage"/>
                                    <Binding Path="DrillDown.DetailTotalPages"/>
                                </MultiBinding>
                            </TextBlock.Text>
                        </TextBlock>
                        <Button Content="Next →"
                                Command="{Binding DrillDown.NextDetailPageCommand}"
                                Background="#21262D"
                                Foreground="#F0F6FC"/>
                    </StackPanel>
                </Grid>
            </Border>
        </Border>
    </Grid>
</UserControl>
```

**Step 2: Create the code-behind file**

```csharp
using Avalonia.Controls;

namespace PCAPAnalyzer.UI.Views;

public partial class AnomaliesView : UserControl
{
    public AnomaliesView()
    {
        InitializeComponent();
    }
}
```

**Step 3: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.UI/Views/AnomaliesView.axaml src/PCAPAnalyzer.UI/Views/AnomaliesView.axaml.cs
git commit -m "feat(anomalies): add AnomaliesView XAML and code-behind"
```

---

## Phase 5: Integration

### Task 13: Register AnomaliesViewModel in ServiceConfiguration

**Files:**
- Modify: `src/PCAPAnalyzer.UI/ServiceConfiguration.cs`

**Step 1: Add ViewModel registration**

Add in the ViewModels section:

```csharp
// Anomalies tab ViewModels
services.AddTransient<AnomaliesViewModel>();
```

**Step 2: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ServiceConfiguration.cs
git commit -m "feat(anomalies): register AnomaliesViewModel in DI"
```

---

### Task 14: Add Anomalies Tab to MainWindow

**Files:**
- Modify: `src/PCAPAnalyzer.UI/ViewModels/MainWindowViewModel.cs`
- Modify: `src/PCAPAnalyzer.UI/Views/MainWindow.axaml`

**Step 1: Add AnomaliesViewModel property to MainWindowViewModel**

Read the file first, then add:

```csharp
// In constructor parameters, add:
AnomaliesViewModel anomaliesViewModel,

// Add property:
public AnomaliesViewModel AnomaliesViewModel { get; }

// In constructor body:
AnomaliesViewModel = anomaliesViewModel;

// In LoadFromAnalysisResultAsync or equivalent method, add:
await AnomaliesViewModel.LoadFromAnalysisResultAsync(result);

// In Clear/Reset method, add:
AnomaliesViewModel.Clear();
```

**Step 2: Add tab in MainWindow.axaml**

Find the TabControl and add the Anomalies tab after Dashboard, before Threats:

```xml
<TabItem Header="Anomalies">
    <views:AnomaliesView DataContext="{Binding AnomaliesViewModel}"/>
</TabItem>
```

Add namespace if not present:
```xml
xmlns:views="using:PCAPAnalyzer.UI.Views"
```

**Step 3: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/MainWindowViewModel.cs src/PCAPAnalyzer.UI/Views/MainWindow.axaml
git commit -m "feat(anomalies): integrate Anomalies tab into MainWindow"
```

---

### Task 15: Wire Up Global Anomaly Filters in Dashboard

**Files:**
- Modify: `src/PCAPAnalyzer.UI/ViewModels/DashboardViewModel.cs`

**Step 1: Read the file to understand filter application**

**Step 2: Add anomaly frame filtering**

In the filter application logic, add check for anomaly filters:

```csharp
// Inject IAnomalyFrameIndexService in constructor

// In filter logic, after existing filters:
if (_globalFilterState.HasAnomalyFilters)
{
    var matchingFrames = _anomalyFrameIndexService.GetFramesMatchingFilters(
        _globalFilterState.AnomalySeverityFilter,
        _globalFilterState.AnomalyCategoryFilter,
        _globalFilterState.AnomalyDetectorFilter);

    if (matchingFrames.Count > 0)
    {
        filteredPackets = filteredPackets.Where(p => matchingFrames.Contains(p.FrameNumber));
    }
}
```

**Step 3: Verify build succeeds**

Run: `dotnet build src/PCAPAnalyzer.UI/PCAPAnalyzer.UI.csproj`
Expected: Build succeeded with 0 errors

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/DashboardViewModel.cs
git commit -m "feat(filters): apply global anomaly filters in Dashboard"
```

---

## Phase 6: Final Testing & Polish

### Task 16: Run Full Build and Tests

**Step 1: Clean and rebuild**

Run: `dotnet clean && dotnet build`
Expected: Build succeeded with 0 errors, 0 warnings

**Step 2: Run all tests**

Run: `dotnet test`
Expected: All tests pass

**Step 3: Commit any fixes**

If any fixes were needed, commit them with appropriate messages.

---

### Task 17: Manual Smoke Test

**Step 1: Launch application**

Run: `dotnet run --project src/PCAPAnalyzer.UI`

**Step 2: Verify checklist**

- [ ] Anomalies tab appears between Dashboard and Threats
- [ ] Loading a PCAP shows anomaly data
- [ ] KPIs display correct counts
- [ ] Timeline chart renders with severity colors
- [ ] Category donut shows distribution
- [ ] Ports bar chart shows top ports
- [ ] Source/Target tables populate with ranked entries
- [ ] Clicking "→" opens drill-down popup
- [ ] Drill-down pagination works
- [ ] Closing popup works
- [ ] Filter chips toggle correctly
- [ ] Applying anomaly filters updates data
- [ ] Dashboard respects anomaly filters (packets filtered)

**Step 3: Document any issues found**

Create issues in `docs/bugs.md` if needed.

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | 1-6 | Data models, services, DI registration |
| 2 | 7-10 | Component ViewModels |
| 3 | 11 | Main AnomaliesViewModel |
| 4 | 12 | XAML View |
| 5 | 13-15 | Integration with MainWindow and Dashboard |
| 6 | 16-17 | Testing and verification |

**Total Tasks:** 17
**Estimated Implementation Time:** Tasks are bite-sized (2-5 min each)

**Critical Path:**
1. Models → Services → Component VMs → Main VM → View → Integration → Test

**Dependencies:**
- Task 3 depends on Task 2
- Task 11 depends on Tasks 7-10
- Task 12 depends on Task 11
- Tasks 13-15 depend on Tasks 11-12
