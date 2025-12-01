---
name: pcap:add-chart-type
description: Use when creating a new visualization (chart, graph, heatmap) - ensures proper LiveCharts2 integration, data service implementation, and UI binding
---

# Add Chart Type Skill

This skill guides you through adding a new chart or visualization type to the PCAP analyzer.

## Prerequisites

Before starting, determine:
- Chart type (line, bar, pie, scatter, heatmap, custom)
- Data source and transformation needs
- Interactivity requirements (click, zoom, tooltip)
- Where the chart will be displayed (which tab/view)

## Mandatory Checklist

Create TodoWrite todos for EACH of these items:

### Phase 1: Data Model
- [ ] Define data model for chart points
- [ ] Add data transformation method to `ChartDataService`
- [ ] Handle empty/null data gracefully

### Phase 2: ViewModel Implementation
- [ ] Create chart properties in appropriate ViewModel
- [ ] Implement `ISeries[]` for chart data
- [ ] Implement `Axis[]` for X and Y axes
- [ ] Add chart creation method

### Phase 3: AXAML Integration
- [ ] Add `CartesianChart`/`PieChart` to view
- [ ] Bind Series, XAxes, YAxes properties
- [ ] Configure chart options (zoom, tooltip, legend)

### Phase 4: Interactivity
- [ ] Implement click/selection handler if needed
- [ ] Add tooltip customization
- [ ] Wire up drill-down functionality

### Phase 5: Export Support
- [ ] Add chart to export service (PNG, SVG)
- [ ] Add data to CSV export if applicable

### Phase 6: Testing & Validation
- [ ] Test with various data sizes (0, 10, 10000 points)
- [ ] Test responsiveness and performance
- [ ] Verify theme support (dark/light mode)
- [ ] Run `dotnet build` — zero warnings

## LiveCharts2 Chart Types

### Line Chart (Time Series)
```csharp
public ISeries[] TrafficSeries { get; set; }
public Axis[] TimeXAxes { get; set; }
public Axis[] BytesYAxes { get; set; }

private void CreateTrafficChart(IReadOnlyList<TimeSeriesPoint> data)
{
    TrafficSeries = new ISeries[]
    {
        new LineSeries<TimeSeriesPoint>
        {
            Values = data,
            Mapping = (point, _) => new Coordinate(
                point.Timestamp.ToOADate(),
                point.Value),
            Name = "Traffic",
            Stroke = new SolidColorPaint(SKColors.DodgerBlue) { StrokeThickness = 2 },
            Fill = null,
            GeometrySize = 0,  // No markers for performance
            LineSmoothness = 0  // Straight lines
        }
    };

    TimeXAxes = new Axis[]
    {
        new Axis
        {
            Name = "Time",
            Labeler = value => DateTime.FromOADate(value).ToString("HH:mm:ss"),
            UnitWidth = TimeSpan.FromMinutes(1).TotalDays
        }
    };

    BytesYAxes = new Axis[]
    {
        new Axis
        {
            Name = "Bytes/sec",
            Labeler = FormatBytes,
            MinLimit = 0
        }
    };
}
```

### Bar Chart (Categorical)
```csharp
public ISeries[] TopTalkersSeries { get; set; }

private void CreateTopTalkersChart(IReadOnlyList<TopTalker> data)
{
    TopTalkersSeries = new ISeries[]
    {
        new ColumnSeries<TopTalker>
        {
            Values = data,
            Mapping = (talker, index) => new Coordinate(index, talker.ByteCount),
            Name = "Traffic Volume",
            Fill = new SolidColorPaint(SKColors.SteelBlue)
        }
    };

    // X axis with IP labels
    XAxes = new Axis[]
    {
        new Axis
        {
            Labels = data.Select(t => t.IpAddress).ToArray(),
            LabelsRotation = 45
        }
    };
}
```

### Pie/Doughnut Chart
```csharp
public ISeries[] ProtocolSeries { get; set; }

private void CreateProtocolChart(Dictionary<string, int> protocols)
{
    ProtocolSeries = protocols
        .OrderByDescending(kvp => kvp.Value)
        .Take(10)  // Limit for readability
        .Select((kvp, index) => new PieSeries<int>
        {
            Values = new[] { kvp.Value },
            Name = kvp.Key,
            Fill = new SolidColorPaint(GetProtocolColor(kvp.Key)),
            DataLabelsPosition = PolarLabelsPosition.Outer,
            DataLabelsFormatter = _ => $"{kvp.Key}: {kvp.Value:N0}"
        })
        .ToArray<ISeries>();
}
```

### Stacked Area Chart
```csharp
public ISeries[] StackedTrafficSeries { get; set; }

private void CreateStackedTrafficChart(
    IReadOnlyList<TimeSeriesPoint> tcpData,
    IReadOnlyList<TimeSeriesPoint> udpData)
{
    StackedTrafficSeries = new ISeries[]
    {
        new StackedAreaSeries<TimeSeriesPoint>
        {
            Values = tcpData,
            Mapping = (p, _) => new Coordinate(p.Timestamp.ToOADate(), p.Value),
            Name = "TCP",
            Fill = new SolidColorPaint(SKColors.DodgerBlue.WithAlpha(180)),
            Stroke = null
        },
        new StackedAreaSeries<TimeSeriesPoint>
        {
            Values = udpData,
            Mapping = (p, _) => new Coordinate(p.Timestamp.ToOADate(), p.Value),
            Name = "UDP",
            Fill = new SolidColorPaint(SKColors.Orange.WithAlpha(180)),
            Stroke = null
        }
    };
}
```

## AXAML Integration

### Basic Chart
```xml
<lvc:CartesianChart
    Series="{Binding TrafficSeries}"
    XAxes="{Binding TimeXAxes}"
    YAxes="{Binding BytesYAxes}"
    ZoomMode="X"
    TooltipPosition="Top">
</lvc:CartesianChart>
```

### With Click Handling
```xml
<lvc:CartesianChart
    Series="{Binding TrafficSeries}"
    XAxes="{Binding TimeXAxes}"
    YAxes="{Binding BytesYAxes}"
    ChartPointPointerDown="OnChartPointClicked">
</lvc:CartesianChart>
```

```csharp
// Code-behind
private void OnChartPointClicked(IChartView chart, ChartPoint? point)
{
    if (point?.Context?.DataSource is TimeSeriesPoint data)
    {
        (DataContext as MyViewModel)?.OnPointSelected(data);
    }
}
```

### Pie Chart
```xml
<lvc:PieChart
    Series="{Binding ProtocolSeries}"
    InitialRotation="-90"
    MaxAngle="360">
</lvc:PieChart>
```

## Data Transformation Service

```csharp
// ChartDataService.cs
public class ChartDataService
{
    public IReadOnlyList<TimeSeriesPoint> CreateTimeSeries(
        IReadOnlyList<PacketInfo> packets,
        TimeSpan bucketSize)
    {
        if (packets.Count == 0)
            return Array.Empty<TimeSeriesPoint>();

        var minTime = packets.Min(p => p.Timestamp);
        var maxTime = packets.Max(p => p.Timestamp);

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

    public IReadOnlyList<TimeSeriesPoint> Downsample(
        IReadOnlyList<TimeSeriesPoint> data,
        int maxPoints)
    {
        if (data.Count <= maxPoints)
            return data;

        // LTTB or simple sampling
        var sampleRate = (int)Math.Ceiling((double)data.Count / maxPoints);
        return data
            .Where((_, i) => i % sampleRate == 0)
            .ToList();
    }

    private DateTime RoundToInterval(DateTime dt, TimeSpan interval)
    {
        var ticks = dt.Ticks / interval.Ticks;
        return new DateTime(ticks * interval.Ticks);
    }
}
```

## Performance Guidelines

### For Large Datasets
```csharp
// BAD - All points rendered
Series = new LineSeries<double>
{
    Values = allPoints  // 100k+ points = slow
};

// GOOD - Downsampled
var displayPoints = _chartService.Downsample(allPoints, maxPoints: 1000);
Series = new LineSeries<double>
{
    Values = displayPoints,
    GeometrySize = 0  // No markers
};
```

### Lazy Chart Loading
```csharp
public async Task EnsureChartsLoadedAsync()
{
    if (_chartsLoaded) return;

    await Task.Run(() =>
    {
        var data = PrepareChartData();
        Dispatcher.UIThread.Post(() => CreateCharts(data));
    }).ConfigureAwait(false);

    _chartsLoaded = true;
}
```

## Color Palette

```csharp
public static class ChartColors
{
    public static SKColor Primary => SKColor.Parse("#1E88E5");
    public static SKColor Secondary => SKColor.Parse("#43A047");
    public static SKColor Warning => SKColor.Parse("#FB8C00");
    public static SKColor Danger => SKColor.Parse("#E53935");

    public static SKColor GetProtocolColor(string protocol)
    {
        return protocol.ToUpperInvariant() switch
        {
            "TCP" => SKColor.Parse("#1E88E5"),
            "UDP" => SKColor.Parse("#43A047"),
            "ICMP" => SKColor.Parse("#FB8C00"),
            "TLS" => SKColor.Parse("#8E24AA"),
            "HTTP" => SKColor.Parse("#00ACC1"),
            "DNS" => SKColor.Parse("#7CB342"),
            _ => SKColor.Parse("#757575")
        };
    }
}
```

## Export Integration

```csharp
// Add to ChartExportService
public async Task<byte[]> ExportChartToPngAsync(
    IChartView chart,
    int width = 1200,
    int height = 600)
{
    using var surface = SKSurface.Create(new SKImageInfo(width, height));
    var canvas = surface.Canvas;
    canvas.Clear(SKColors.White);

    // Render chart
    ((CartesianChart)chart).CoreChart.DrawOnCanvas(canvas);

    using var image = surface.Snapshot();
    using var data = image.Encode(SKEncodedImageFormat.Png, 100);

    return data.ToArray();
}
```

## Common Mistakes to Avoid

1. **Not downsampling large datasets** — Causes UI freezes
2. **Missing null checks** — Empty data should show placeholder
3. **Hardcoded colors** — Use theme-aware colors
4. **Forgetting GeometrySize = 0** — Markers slow rendering
5. **Not disposing chart resources** — Memory leaks
6. **Blocking UI thread** — Use Task.Run for data preparation

## When Done

Run the verification skill:
```
/superpowers:verification-before-completion
```
