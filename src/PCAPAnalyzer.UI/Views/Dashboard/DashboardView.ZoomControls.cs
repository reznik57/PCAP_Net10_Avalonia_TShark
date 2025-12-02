using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia.Interactivity;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.Constants;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.Defaults;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views;

/// <summary>
/// DashboardView.ZoomControls - Unified zoom functionality for all charts.
/// Refactored to eliminate code duplication using template method pattern.
/// </summary>
public partial class DashboardView
{
    #region Traffic Chart Zoom (Event Handlers)

    private void OnTrafficZoomIn(object? sender, RoutedEventArgs e) =>
        ZoomChart(ChartType.Traffic, ZoomDirection.In);

    private void OnTrafficZoomOut(object? sender, RoutedEventArgs e) =>
        ZoomChart(ChartType.Traffic, ZoomDirection.Out);

    private void OnTrafficZoomReset(object? sender, RoutedEventArgs e) =>
        ZoomChart(ChartType.Traffic, ZoomDirection.Reset);

    #endregion

    #region Port Chart Zoom (Event Handlers)

    private void OnPortZoomIn(object? sender, RoutedEventArgs e) =>
        ZoomChart(ChartType.Port, ZoomDirection.In);

    private void OnPortZoomOut(object? sender, RoutedEventArgs e) =>
        ZoomChart(ChartType.Port, ZoomDirection.Out);

    private void OnPortZoomReset(object? sender, RoutedEventArgs e) =>
        ZoomChart(ChartType.Port, ZoomDirection.Reset);

    #endregion

    #region Unified Zoom Logic

    private enum ChartType { Traffic, Port }
    private enum ZoomDirection { In, Out, Reset }

    /// <summary>
    /// Unified zoom implementation for both charts.
    /// Eliminates ~200 lines of duplicated code.
    /// </summary>
    private void ZoomChart(ChartType chartType, ZoomDirection direction)
    {
        try
        {
            if (DataContext is not DashboardViewModel vm)
                return;

            // Get chart-specific configuration
            var (chartName, axis, getDataBounds) = chartType switch
            {
                ChartType.Traffic => (
                    "NetworkTrafficChart",
                    vm.XAxes?.FirstOrDefault() as LiveChartsCore.SkiaSharpView.Axis,
                    new Func<(double? min, double? max)>(() => GetTrafficDataBounds(vm))
                ),
                ChartType.Port => (
                    "PortActivityChart",
                    vm.PortActivityXAxes?.FirstOrDefault() as LiveChartsCore.SkiaSharpView.Axis,
                    new Func<(double? min, double? max)>(() => GetPortDataBounds(vm))
                ),
                _ => throw new ArgumentOutOfRangeException(nameof(chartType))
            };

            if (axis == null)
                return;

            // Execute zoom operation
            switch (direction)
            {
                case ZoomDirection.In:
                    ApplyZoom(axis, getDataBounds, ChartConstants.ZoomInFactor, clampToBounds: false);
                    break;
                case ZoomDirection.Out:
                    ApplyZoom(axis, getDataBounds, ChartConstants.ZoomOutFactor, clampToBounds: true);
                    break;
                case ZoomDirection.Reset:
                    axis.MinLimit = null;
                    axis.MaxLimit = null;
                    break;
            }

            DebugLogger.Log($"[DashboardView] {chartName} zoom {direction}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardView] ZoomChart error: {ex.Message}");
        }
    }

    /// <summary>
    /// Applies zoom transformation to an axis.
    /// </summary>
    private static void ApplyZoom(
        LiveChartsCore.SkiaSharpView.Axis axis,
        Func<(double? min, double? max)> getDataBounds,
        double factor,
        bool clampToBounds)
    {
        var (dataMin, dataMax) = getDataBounds();

        // Get current range or fall back to data bounds
        double? currentMin = axis.MinLimit ?? dataMin;
        double? currentMax = axis.MaxLimit ?? dataMax;

        if (currentMin == null || currentMax == null)
            return;

        var range = currentMax.Value - currentMin.Value;
        var newRange = range * factor;
        var center = currentMin.Value + (range / 2);

        var newMin = center - (newRange / 2);
        var newMax = center + (newRange / 2);

        // Clamp to data bounds on zoom out to prevent infinite expansion
        if (clampToBounds)
        {
            if (dataMin.HasValue && newMin < dataMin.Value)
                newMin = dataMin.Value;
            if (dataMax.HasValue && newMax > dataMax.Value)
                newMax = dataMax.Value;
        }

        axis.MinLimit = newMin;
        axis.MaxLimit = newMax;
    }

    /// <summary>
    /// Gets data bounds from Traffic chart series.
    /// </summary>
    private static (double? min, double? max) GetTrafficDataBounds(DashboardViewModel vm)
    {
        var dataPoints = vm.TimelineSeries?
            .SelectMany(s => s.Values?.Cast<DateTimePoint>() ?? Enumerable.Empty<DateTimePoint>())
            .Where(p => p != null)
            .ToList();

        if (dataPoints == null || dataPoints.Count == 0)
            return (null, null);

        return (
            dataPoints.Min(p => p.DateTime.Ticks),
            dataPoints.Max(p => p.DateTime.Ticks)
        );
    }

    /// <summary>
    /// Gets data bounds from Port Activity chart series.
    /// </summary>
    private static (double? min, double? max) GetPortDataBounds(DashboardViewModel vm)
    {
        var dataPoints = vm.PortActivitySeries?
            .SelectMany(s => s.Values?.Cast<DateTimePoint>() ?? Enumerable.Empty<DateTimePoint>())
            .Where(p => p != null)
            .ToList();

        if (dataPoints == null || dataPoints.Count == 0)
            return (null, null);

        return (
            dataPoints.Min(p => p.DateTime.Ticks),
            dataPoints.Max(p => p.DateTime.Ticks)
        );
    }

    #endregion
}
