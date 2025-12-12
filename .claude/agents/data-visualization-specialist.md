---
name: data-visualization-specialist
---

# Data Visualization Specialist Agent

## When to Use This Agent
Use this agent when working on:
- Chart creation and modification
- LiveCharts2 integration
- Time series visualization
- Heatmaps and network graphs
- Chart interactivity and drill-down
- Chart export functionality
- Visual styling and theming

## Domain Knowledge

### Architecture Overview
```
Data Source (Statistics, Anomalies, etc.)
            ↓
    ChartViewModel (base)
            ↓
┌───────────┼───────────┬───────────────┐
↓           ↓           ↓               ↓
Dashboard   Threats    VoiceQoS      Custom
ChartsVM    ChartsVM   ChartsVM      Controls
            ↓
    ChartDataService
            ↓
    LiveCharts2 Components
            ↓
    Avalonia Rendering
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.UI/ViewModels/Base/ChartViewModel.cs` | Chart base class | ~200 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/DashboardChartsViewModel.cs` | Dashboard charts | 968 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/ThreatsChartsViewModel.cs` | Threats charts | 748 |
| `src/PCAPAnalyzer.UI/ViewModels/VoiceQoS/VoiceQoSChartsViewModel.cs` | VoiceQoS charts | ~400 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/MainWindowChartsViewModel.cs` | Main window charts | ~300 |
| `src/PCAPAnalyzer.UI/Services/Visualization/ChartDataService.cs` | Data transformation | ~200 |
| `src/PCAPAnalyzer.UI/Services/Visualization/ChartExportService.cs` | Chart export | ~150 |
| `src/PCAPAnalyzer.UI/Models/ChartInteractionModels.cs` | Interaction models | ~100 |

### Custom Chart Controls
| File | Purpose |
|------|---------|
| `Controls/Charts/HeatmapChart.axaml.cs` | Traffic heatmap |
| `Controls/Charts/InteractiveTimeSeriesChart.axaml.cs` | Time series with zoom |
| `Controls/Charts/NetworkGraphChart.axaml.cs` | Network topology |
| `Controls/ChartZoomControl.axaml.cs` | Zoom functionality |
| `Controls/PopupChartView.axaml.cs` | Chart in popup |
| `Controls/ChartDataPopup.axaml.cs` | Data point details |

### LiveCharts2 Basics

#### NuGet Packages
```xml
<PackageReference Include="LiveChartsCore.SkiaSharpView.Avalonia" Version="2.x.x" />
```

#### Chart Types Used
- **CartesianChart**: Line, bar, scatter plots
- **PieChart**: Protocol distribution
- **PolarChart**: Directional traffic (optional)
- **GeoMap**: Country traffic (custom implementation)

### Chart Creation Patterns

#### Basic Line Chart
```csharp
public ISeries[] TrafficOverTimeSeries { get; set; }

private void CreateTrafficChart(IReadOnlyList<TimeSeriesPoint> data)
{
    TrafficOverTimeSeries = new ISeries[]
    {
        new LineSeries<TimeSeriesPoint>
        {
            Values = data,
            Mapping = (point, index) => new Coordinate(
                point.Timestamp.ToOADate(),
                point.BytesPerSecond),
            Name = "Traffic (bytes/sec)",
            Stroke = new SolidColorPaint(SKColors.DodgerBlue) { StrokeThickness = 2 },
            Fill = null,
            GeometrySize = 0
        }
    };
}
```

#### Pie Chart (Protocol Distribution)
```csharp
public ISeries[] ProtocolDistributionSeries { get; set; }

private void CreateProtocolChart(Dictionary<string, int> protocols)
{
    ProtocolDistributionSeries = protocols
        .Select(kvp => new PieSeries<int>
        {
            Values = new[] { kvp.Value },
            Name = kvp.Key,
            DataLabelsPosition = PolarLabelsPosition.Middle,
            DataLabelsFormatter = point => $"{kvp.Key}: {point.PrimaryValue:N0}"
        })
        .ToArray<ISeries>();
}
```

#### Bar Chart (Top Talkers)
```csharp
public ISeries[] TopTalkersSeries { get; set; }

private void CreateTopTalkersChart(IReadOnlyList<TopTalker> talkers)
{
    TopTalkersSeries = new ISeries[]
    {
        new RowSeries<TopTalker>
        {
            Values = talkers,
            Mapping = (talker, index) => new Coordinate(index, talker.ByteCount),
            Name = "Bytes",
            DataLabelsFormatter = point => FormatBytes(point.PrimaryValue)
        }
    };

    TopTalkersXAxes = new Axis[]
    {
        new Axis
        {
            Labels = talkers.Select(t => t.IpAddress).ToArray()
        }
    };
}
```

### Axis Configuration

#### Time Axis (X)
```csharp
public Axis[] TimeXAxes { get; set; } = new Axis[]
{
    new Axis
    {
        Name = "Time",
        Labeler = value => DateTime.FromOADate(value).ToString("HH:mm:ss"),
        UnitWidth = TimeSpan.FromMinutes(1).TotalDays,
        MinStep = TimeSpan.FromSeconds(30).TotalDays
    }
};
```

#### Bytes Axis (Y)
```csharp
public Axis[] BytesYAxes { get; set; } = new Axis[]
{
    new Axis
    {
        Name = "Bytes/sec",
        Labeler = value => FormatBytes((long)value),
        MinLimit = 0
    }
};

private static string FormatBytes(long bytes)
{
    string[] sizes = { "B", "KB", "MB", "GB", "TB" };
    double len = bytes;
    int order = 0;
    while (len >= 1024 && order < sizes.Length - 1)
    {
        order++;
        len /= 1024;
    }
    return $"{len:0.##} {sizes[order]}";
}
```

### Chart Interactivity

#### Click/Selection Handling
```csharp
// In AXAML
<lvc:CartesianChart
    Series="{Binding TrafficSeries}"
    ChartPointPointerDown="OnChartPointClicked" />

// In code-behind
private void OnChartPointClicked(IChartView chart, ChartPoint? point)
{
    if (point?.Context?.DataSource is TimeSeriesPoint data)
    {
        ViewModel.OnPointSelected(data);
    }
}

// In ViewModel
public void OnPointSelected(TimeSeriesPoint point)
{
    // Show drill-down popup or filter to time range
    ShowDrillDown(point.Timestamp);
}
```

#### Zoom and Pan
```csharp
public Axis[] ZoomableXAxes { get; set; } = new Axis[]
{
    new Axis
    {
        Name = "Time",
        MinLimit = null,  // Allow zoom
        MaxLimit = null,
        // Initial visible range
        MinVisibleValue = startTime.ToOADate(),
        MaxVisibleValue = endTime.ToOADate()
    }
};

// Enable zoom in AXAML
<lvc:CartesianChart
    ZoomMode="X"
    TooltipPosition="Top" />
```

### Chart Data Service
```csharp
public class ChartDataService
{
    // Transform raw data to chart-ready format
    public IReadOnlyList<TimeSeriesPoint> CreateTimeSeries(
        IReadOnlyList<PacketInfo> packets,
        TimeSpan bucketSize)
    {
        return packets
            .GroupBy(p => RoundToInterval(p.Timestamp, bucketSize))
            .Select(g => new TimeSeriesPoint
            {
                Timestamp = g.Key,
                PacketCount = g.Count(),
                ByteCount = g.Sum(p => p.Length)
            })
            .OrderBy(p => p.Timestamp)
            .ToList();
    }

    // Aggregate for performance
    public IReadOnlyList<TimeSeriesPoint> DownsampleTimeSeries(
        IReadOnlyList<TimeSeriesPoint> data,
        int maxPoints)
    {
        if (data.Count <= maxPoints) return data;

        var sampleRate = (int)Math.Ceiling((double)data.Count / maxPoints);
        return data
            .Where((_, i) => i % sampleRate == 0)
            .ToList();
    }
}
```

### Chart Export Service
```csharp
public class ChartExportService
{
    public async Task<byte[]> ExportToPngAsync(IChartView chart, int width, int height)
    {
        var skChart = (CartesianChart)chart;
        using var surface = SKSurface.Create(new SKImageInfo(width, height));
        var canvas = surface.Canvas;
        canvas.Clear(SKColors.White);

        // Render chart to canvas
        skChart.CoreChart.DrawOnCanvas(canvas);

        using var image = surface.Snapshot();
        using var data = image.Encode(SKEncodedImageFormat.Png, 100);

        return data.ToArray();
    }

    public async Task ExportToCsvAsync(ISeries[] series, string filePath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Label,Value");

        foreach (var s in series)
        {
            if (s.Values is IEnumerable<IChartEntity> values)
            {
                foreach (var v in values)
                {
                    sb.AppendLine($"{s.Name},{v.PrimaryValue}");
                }
            }
        }

        await File.WriteAllTextAsync(filePath, sb.ToString());
    }
}
```

### Theme and Styling

#### Color Palette
```csharp
public static class ChartColors
{
    public static readonly SKColor Primary = SKColor.Parse("#1E88E5");
    public static readonly SKColor Secondary = SKColor.Parse("#43A047");
    public static readonly SKColor Warning = SKColor.Parse("#FB8C00");
    public static readonly SKColor Danger = SKColor.Parse("#E53935");
    public static readonly SKColor Info = SKColor.Parse("#00ACC1");

    public static readonly SKColor[] ProtocolColors = new[]
    {
        SKColor.Parse("#1E88E5"),  // TCP - Blue
        SKColor.Parse("#43A047"),  // UDP - Green
        SKColor.Parse("#FB8C00"),  // ICMP - Orange
        SKColor.Parse("#8E24AA"),  // Other - Purple
    };
}
```

#### Dark/Light Mode
```csharp
public void ApplyTheme(bool isDarkMode)
{
    var textColor = isDarkMode ? SKColors.White : SKColors.Black;
    var gridColor = isDarkMode ? SKColor.Parse("#424242") : SKColor.Parse("#E0E0E0");

    foreach (var axis in XAxes.Concat(YAxes))
    {
        axis.LabelsPaint = new SolidColorPaint(textColor);
        axis.SeparatorsPaint = new SolidColorPaint(gridColor) { StrokeThickness = 1 };
    }
}
```

### Performance Considerations

#### Large Dataset Handling
```csharp
// BAD - All points rendered
Series = new LineSeries<double> { Values = allPoints };  // ❌ 100k+ points

// GOOD - Downsampled for rendering
var displayPoints = _chartDataService.DownsampleTimeSeries(allPoints, maxPoints: 1000);
Series = new LineSeries<double> { Values = displayPoints };  // ✅ Smooth rendering
```

#### Lazy Loading
```csharp
// Load chart data only when tab is visible
public async Task EnsureLoadedAsync()
{
    if (_isLoaded) return;

    var data = await _dataService.GetChartDataAsync();
    CreateCharts(data);
    _isLoaded = true;
}
```

## Instructions for This Agent

1. **Read ChartViewModel base class** before creating new charts
2. **Use LiveCharts2 patterns** consistently across views
3. **Downsample large datasets** - never render >2000 points directly
4. **Support dark/light themes** - respect user preference
5. **Add interactivity** - click, zoom, drill-down where appropriate
6. **Export functionality** - PNG and CSV for all charts
7. **Test performance** - charts with 40M packets backing data
8. **Handle empty data** - graceful display when no data available
