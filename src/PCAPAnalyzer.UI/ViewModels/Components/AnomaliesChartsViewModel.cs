using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;
using SkiaSharp;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages chart series and axes for the Anomalies tab.
/// </summary>
public partial class AnomaliesChartsViewModel : ObservableObject
{
    // Severity colors - delegate to ThemeColorHelper SKColor API
    private static SKColor CriticalColor => ThemeColorHelper.GetAnomalySeveritySKColor("critical");
    private static SKColor HighColor => ThemeColorHelper.GetAnomalySeveritySKColor("high");
    private static SKColor MediumColor => ThemeColorHelper.GetAnomalySeveritySKColor("medium");
    private static SKColor LowColor => ThemeColorHelper.GetAnomalySeveritySKColor("low");

    // Category colors - delegate to ThemeColorHelper SKColor API
    private static SKColor GetCategoryColor(AnomalyCategory category) => category switch
    {
        AnomalyCategory.Network => ThemeColorHelper.GetChartSKColor(0),    // Blue
        AnomalyCategory.TCP => ThemeColorHelper.GetChartSKColor(1),        // Green
        AnomalyCategory.Application => ThemeColorHelper.GetChartSKColor(2), // Amber
        AnomalyCategory.VoIP => ThemeColorHelper.GetChartSKColor(4),       // Purple
        AnomalyCategory.IoT => ThemeColorHelper.GetChartSKColor(6),        // Cyan
        AnomalyCategory.Security => ThemeColorHelper.GetChartSKColor(3),   // Red
        AnomalyCategory.Malformed => ThemeColorHelper.GetChartSKColor(5),  // Pink
        _ => ThemeColorHelper.ChartGraySK
    };

    // Timeline chart - ObservableCollection for dynamic highlight series
    public ObservableCollection<ISeries> TimelineSeriesCollection { get; } = new();

    // Legacy property for binding compatibility (returns the collection as array)
    public ISeries[] TimelineSeries => TimelineSeriesCollection.ToArray();

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
        var axisLabelColor = ThemeColorHelper.ChartGraySK;

        TimelineXAxes = new Axis[]
        {
            new Axis
            {
                Name = "Time",
                NamePaint = new SolidColorPaint(axisLabelColor),
                LabelsPaint = new SolidColorPaint(axisLabelColor),
                Labeler = value => SafeFromTicks(value),
                TextSize = 11
            }
        };

        TimelineYAxes = new Axis[]
        {
            new Axis
            {
                Name = "Anomalies/min",
                NamePaint = new SolidColorPaint(axisLabelColor),
                LabelsPaint = new SolidColorPaint(axisLabelColor),
                MinLimit = 0,
                TextSize = 11
            }
        };

        PortsXAxes = new Axis[]
        {
            new Axis
            {
                LabelsPaint = new SolidColorPaint(axisLabelColor),
                TextSize = 11
            }
        };

        PortsYAxes = new Axis[]
        {
            new Axis
            {
                Labels = Array.Empty<string>(),
                LabelsPaint = new SolidColorPaint(axisLabelColor),
                TextSize = 11
            }
        };
    }

    /// <summary>
    /// Safely converts DateTime ticks to string, handling invalid values.
    /// DateTimePoint uses ticks, not OLE dates.
    /// </summary>
    private static string SafeFromTicks(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value))
        {
            return "---";
        }

        try
        {
            var ticks = (long)value;
            // Valid DateTime ticks range
            if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
            {
                return "---";
            }
            return new DateTime(ticks).ToString("HH:mm:ss");
        }
        catch
        {
            return "---";
        }
    }

    public void UpdateTimeline(List<AnomalyTimePoint> timePoints)
    {
        // Clear existing series (preserve highlight series if present)
        var highlightSeries = TimelineSeriesCollection
            .Where(s => s.Name is "Highlight" or "VerticalLine")
            .ToList();

        TimelineSeriesCollection.Clear();

        if (timePoints.Count == 0)
        {
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

        // Add data series
        TimelineSeriesCollection.Add(new LineSeries<DateTimePoint>
        {
            Name = "Critical",
            Values = criticalValues,
            Stroke = new SolidColorPaint(CriticalColor, 2),
            Fill = null,
            GeometrySize = 0,
            LineSmoothness = 0.3
        });

        TimelineSeriesCollection.Add(new LineSeries<DateTimePoint>
        {
            Name = "High",
            Values = highValues,
            Stroke = new SolidColorPaint(HighColor, 2),
            Fill = null,
            GeometrySize = 0,
            LineSmoothness = 0.3
        });

        TimelineSeriesCollection.Add(new LineSeries<DateTimePoint>
        {
            Name = "Medium",
            Values = mediumValues,
            Stroke = new SolidColorPaint(MediumColor, 2),
            Fill = null,
            GeometrySize = 0,
            LineSmoothness = 0.3
        });

        TimelineSeriesCollection.Add(new LineSeries<DateTimePoint>
        {
            Name = "Low",
            Values = lowValues,
            Stroke = new SolidColorPaint(LowColor, 2),
            Fill = null,
            GeometrySize = 0,
            LineSmoothness = 0.3
        });

        // Re-add highlight series (they'll be recreated by the view if needed)
        // We don't restore them here to avoid stale state

        OnPropertyChanged(nameof(TimelineSeries));
    }

    public void UpdateCategoryDonut(IEnumerable<AnomalyCategoryViewModel> categories)
    {
        var series = new List<ISeries>();

        foreach (var cat in categories.Where(c => c.Count > 0))
        {
            var color = GetCategoryColor(cat.Category);

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
                Fill = ThemeColorHelper.GetChartSolidColorPaint(0),
                Stroke = null,
                DataLabelsPaint = ThemeColorHelper.GetSolidColorPaint("PopupText", "#F0F6FC"),
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
        TimelineSeriesCollection.Clear();
        CategorySeries = Array.Empty<ISeries>();
        PortsSeries = Array.Empty<ISeries>();
        ResetZoom();
        OnPropertyChanged(nameof(TimelineSeries));
        OnPropertyChanged(nameof(CategorySeries));
        OnPropertyChanged(nameof(PortsSeries));
    }
}
