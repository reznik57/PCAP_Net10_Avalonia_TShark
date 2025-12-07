using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia.Controls;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.Constants;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views;

/// <summary>
/// DashboardView.TooltipManager - Tooltip display and visual highlight logic.
/// Refactored to use centralized constants and factory methods.
/// </summary>
public partial class DashboardView
{
    /// <summary>
    /// Adds a highlight dot and vertical line to indicate the current data point.
    /// Uses factory methods to eliminate code duplication between chart types.
    /// </summary>
    private void AddHighlightWithLine(CartesianChart chart, int index, DateTime timestamp, double[] values, bool isTraffic, double xPosition)
    {
        try
        {
            if (DataContext is not DashboardViewModel vm)
                return;

            var value = values.Length > 0 ? values[0] : 0;

            // Get chart-specific series and bounds
            var (highlightScatter, highlightLine, seriesCollection, minY, maxY) = isTraffic
                ? GetTrafficHighlightConfig(vm)
                : GetPortHighlightConfig(vm);

            // Ensure valid Y range
            if (Math.Abs(maxY - minY) < ChartConstants.MinYRange)
                maxY = minY + 1;

            // Create or update highlight scatter
            if (isTraffic)
            {
                _trafficHighlightScatter ??= CreateHighlightScatter(seriesCollection);
                UpdateScatterPoint(_trafficHighlightScatter, timestamp, value);
                highlightScatter = _trafficHighlightScatter;
            }
            else
            {
                _portHighlightScatter ??= CreateHighlightScatter(seriesCollection);
                UpdateScatterPoint(_portHighlightScatter, timestamp, value);
                highlightScatter = _portHighlightScatter;
            }

            // Create or update highlight line
            if (isTraffic)
            {
                _trafficHighlightLine ??= CreateHighlightLine(seriesCollection);
                UpdateLinePoints(_trafficHighlightLine, timestamp, minY, maxY);
                highlightLine = _trafficHighlightLine;
            }
            else
            {
                _portHighlightLine ??= CreateHighlightLine(seriesCollection);
                UpdateLinePoints(_portHighlightLine, timestamp, minY, maxY);
                highlightLine = _portHighlightLine;
            }

            SetSeriesVisibility(highlightScatter, true);
            SetSeriesVisibility(highlightLine, true);
            _lastHighlightedIndex = index;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardView] AddHighlightWithLine error: {ex.Message}");
        }
    }

    /// <summary>
    /// Gets highlight configuration for Traffic chart.
    /// </summary>
    private (ScatterSeries<DateTimePoint>?, LineSeries<DateTimePoint>?, ObservableCollection<ISeries>?, double minY, double maxY) GetTrafficHighlightConfig(DashboardViewModel vm)
    {
        // Use maximum across ALL traffic axes for vertical line
        var minY = Math.Min(_cachedThroughputMinY, Math.Min(_cachedPacketsMinY, _cachedAnomaliesMinY));
        var maxY = Math.Max(_cachedThroughputMaxY, Math.Max(_cachedPacketsMaxY, _cachedAnomaliesMaxY));
        return (_trafficHighlightScatter, _trafficHighlightLine, vm.TimelineSeries, minY, maxY);
    }

    /// <summary>
    /// Gets highlight configuration for Port chart.
    /// </summary>
    private (ScatterSeries<DateTimePoint>?, LineSeries<DateTimePoint>?, ObservableCollection<ISeries>?, double minY, double maxY) GetPortHighlightConfig(DashboardViewModel vm)
    {
        return (_portHighlightScatter, _portHighlightLine, vm.PortActivitySeries, _cachedPortMinY, _cachedPortMaxY);
    }

    /// <summary>
    /// Factory method to create highlight scatter series with consistent styling.
    /// </summary>
    private static ScatterSeries<DateTimePoint> CreateHighlightScatter(ObservableCollection<ISeries>? seriesCollection)
    {
        var scatter = new ScatterSeries<DateTimePoint>
        {
            Values = new ObservableCollection<DateTimePoint>(),
            GeometrySize = ChartConstants.HighlightDotSize,
            Fill = ChartConstants.HighlightFillPaint,
            Stroke = ChartConstants.HighlightStrokePaint,
            Name = "Highlight",
            IsVisibleAtLegend = false,
            ZIndex = ChartConstants.HighlightScatterZIndex,
            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
            IsHoverable = false
        };
        seriesCollection?.Add(scatter);
        return scatter;
    }

    /// <summary>
    /// Factory method to create highlight vertical line series with consistent styling.
    /// </summary>
    private static LineSeries<DateTimePoint> CreateHighlightLine(ObservableCollection<ISeries>? seriesCollection)
    {
        var line = new LineSeries<DateTimePoint>
        {
            Values = new ObservableCollection<DateTimePoint>(),
            Stroke = ChartConstants.HighlightLinePaint,
            Fill = null,
            GeometrySize = 0,
            LineSmoothness = 0,
            Name = "VerticalLine",
            IsVisibleAtLegend = false,
            ZIndex = ChartConstants.HighlightLineZIndex,
            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
            IsHoverable = false
        };
        seriesCollection?.Add(line);
        return line;
    }

    /// <summary>
    /// Removes highlight from the specified chart.
    /// </summary>
    private void RemoveHighlight(CartesianChart? chart, bool isTraffic)
    {
        try
        {
            if (isTraffic)
            {
                SetSeriesVisibility(_trafficHighlightScatter, false);
                SetSeriesVisibility(_trafficHighlightLine, false);
            }
            else
            {
                SetSeriesVisibility(_portHighlightScatter, false);
                SetSeriesVisibility(_portHighlightLine, false);
            }

            _lastHighlightedIndex = -1;
            chart?.CoreChart?.Update();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardView] RemoveHighlight error: {ex.Message}");
        }
    }

    /// <summary>
    /// Sets the visibility of a series.
    /// </summary>
    private static void SetSeriesVisibility(ISeries? series, bool visible)
    {
        if (series is not null)
            series.IsVisible = visible;
    }

    /// <summary>
    /// Updates a scatter series point for DateTimePoint data.
    /// </summary>
    private static void UpdateScatterPoint(ScatterSeries<DateTimePoint> series, DateTime timestamp, double value)
    {
        if (series.Values is IList<DateTimePoint> list)
        {
            if (list.Count == 0)
                list.Add(new DateTimePoint(timestamp, value));
            else
                list[0] = new DateTimePoint(timestamp, value);
        }
        else
        {
            series.Values = new ObservableCollection<DateTimePoint> { new(timestamp, value) };
        }
    }

    /// <summary>
    /// Updates a line series points for vertical line.
    /// </summary>
    private static void UpdateLinePoints(LineSeries<DateTimePoint> series, DateTime timestamp, double minY, double maxY)
    {
        if (series.Values is IList<DateTimePoint> list)
        {
            if (list.Count < 2)
            {
                list.Clear();
                list.Add(new DateTimePoint(timestamp, minY));
                list.Add(new DateTimePoint(timestamp, maxY));
            }
            else
            {
                list[0] = new DateTimePoint(timestamp, minY);
                list[1] = new DateTimePoint(timestamp, maxY);
            }
        }
        else
        {
            series.Values = new ObservableCollection<DateTimePoint>
            {
                new(timestamp, minY),
                new(timestamp, maxY)
            };
        }
    }
}
