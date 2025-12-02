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
    public Axis[] TimelineXAxes { get; private set; } = Array.Empty<Axis>();
    public Axis[] TimelineYAxes { get; private set; } = Array.Empty<Axis>();

    // Category donut chart
    public ISeries[] CategorySeries { get; private set; } = Array.Empty<ISeries>();

    // Ports bar chart
    public ISeries[] PortsSeries { get; private set; } = Array.Empty<ISeries>();
    public Axis[] PortsXAxes { get; private set; } = Array.Empty<Axis>();
    public Axis[] PortsYAxes { get; private set; } = Array.Empty<Axis>();

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
