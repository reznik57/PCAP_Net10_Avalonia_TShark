using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Interactivity;
using PCAPAnalyzer.UI.ViewModels;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.Defaults;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views
{
    /// <summary>
    /// DashboardView.ZoomControls - Zoom and pan functionality
    /// </summary>
    /// <remarks>
    /// This partial class handles:
    /// - Traffic chart zoom in/out/reset
    /// - Port activity chart zoom in/out/reset
    /// - Zoom level calculations
    /// - Data bounds validation
    ///
    /// Separated from the main DashboardView.axaml.cs for better organization
    /// </remarks>
    public partial class DashboardView
    {
        #region Zoom Control Event Handlers

        // Traffic Chart Zoom Controls
        private void OnTrafficZoomIn(object? sender, RoutedEventArgs e)
        {
            try
            {
                var chart = this.FindControl<CartesianChart>("NetworkTrafficChart");
                if (chart == null || DataContext is not DashboardViewModel vm) return;

                // Zoom in by reducing the visible range by 50%
                if (vm.XAxes != null && vm.XAxes.Length > 0)
                {
                    var axis = vm.XAxes[0];
                    if (axis is LiveChartsCore.SkiaSharpView.Axis dateTimeAxis)
                    {
                        // Get current range or use full data range
                        double? currentMin = dateTimeAxis.MinLimit;
                        double? currentMax = dateTimeAxis.MaxLimit;

                        // If no limits set, get from data
                        if (currentMin == null || currentMax == null)
                        {
                            // Get data range from series
                            var dataPoints = vm.TimelineSeries?.SelectMany(s => s.Values?.Cast<DateTimePoint>() ?? Enumerable.Empty<DateTimePoint>())
                                                               .Where(p => p != null)
                                                               .ToList();
                            if (dataPoints != null && dataPoints.Count > 0)
                            {
                                currentMin = dataPoints.Min(p => p.DateTime.Ticks);
                                currentMax = dataPoints.Max(p => p.DateTime.Ticks);
                            }
                        }

                        if (currentMin != null && currentMax != null)
                        {
                            var range = currentMax.Value - currentMin.Value;
                            var newRange = range * 0.5; // Zoom in by 50%
                            var center = currentMin.Value + (range / 2);

                            dateTimeAxis.MinLimit = center - (newRange / 2);
                            dateTimeAxis.MaxLimit = center + (newRange / 2);
                        }
                    }
                }

                DebugLogger.Log("[DashboardView] Traffic chart zoomed in");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnTrafficZoomIn error: {ex.Message}");
            }
        }

        private void OnTrafficZoomOut(object? sender, RoutedEventArgs e)
        {
            try
            {
                var chart = this.FindControl<CartesianChart>("NetworkTrafficChart");
                if (chart == null || DataContext is not DashboardViewModel vm) return;

                // Zoom out by increasing the visible range by 100%
                if (vm.XAxes != null && vm.XAxes.Length > 0)
                {
                    var axis = vm.XAxes[0];
                    if (axis is LiveChartsCore.SkiaSharpView.Axis dateTimeAxis)
                    {
                        // Get current range
                        double? currentMin = dateTimeAxis.MinLimit;
                        double? currentMax = dateTimeAxis.MaxLimit;

                        // Get data bounds
                        double? dataMin = null;
                        double? dataMax = null;
                        var dataPoints = vm.TimelineSeries?.SelectMany(s => s.Values?.Cast<DateTimePoint>() ?? Enumerable.Empty<DateTimePoint>())
                                                           .Where(p => p != null)
                                                           .ToList();
                        if (dataPoints != null && dataPoints.Count > 0)
                        {
                            dataMin = dataPoints.Min(p => p.DateTime.Ticks);
                            dataMax = dataPoints.Max(p => p.DateTime.Ticks);
                        }

                        // If no limits set, use data bounds
                        if (currentMin == null || currentMax == null)
                        {
                            currentMin = dataMin;
                            currentMax = dataMax;
                        }

                        if (currentMin != null && currentMax != null)
                        {
                            var range = currentMax.Value - currentMin.Value;
                            var newRange = range * 2; // Zoom out by 100%
                            var center = currentMin.Value + (range / 2);

                            // Don't zoom out beyond data bounds
                            var newMin = center - (newRange / 2);
                            var newMax = center + (newRange / 2);

                            if (dataMin != null && newMin < dataMin)
                                newMin = dataMin.Value;
                            if (dataMax != null && newMax > dataMax)
                                newMax = dataMax.Value;

                            dateTimeAxis.MinLimit = newMin;
                            dateTimeAxis.MaxLimit = newMax;
                        }
                    }
                }

                DebugLogger.Log("[DashboardView] Traffic chart zoomed out");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnTrafficZoomOut error: {ex.Message}");
            }
        }

        private void OnTrafficZoomReset(object? sender, RoutedEventArgs e)
        {
            try
            {
                var chart = this.FindControl<CartesianChart>("NetworkTrafficChart");
                if (chart == null || DataContext is not DashboardViewModel vm) return;

                // Reset zoom to show all data
                if (vm.XAxes != null && vm.XAxes.Length > 0)
                {
                    var axis = vm.XAxes[0];
                    if (axis is LiveChartsCore.SkiaSharpView.Axis dateTimeAxis)
                    {
                        dateTimeAxis.MinLimit = null; // Reset to auto
                        dateTimeAxis.MaxLimit = null; // Reset to auto
                    }
                }

                DebugLogger.Log("[DashboardView] Traffic chart zoom reset");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnTrafficZoomReset error: {ex.Message}");
            }
        }

        // Port Activity Chart Zoom Controls
        private void OnPortZoomIn(object? sender, RoutedEventArgs e)
        {
            try
            {
                var chart = this.FindControl<CartesianChart>("PortActivityChart");
                if (chart == null || DataContext is not DashboardViewModel vm) return;

                // Zoom in by reducing the visible range by 50%
                if (vm.PortActivityXAxes != null && vm.PortActivityXAxes.Length > 0)
                {
                    var axis = vm.PortActivityXAxes[0];
                    if (axis is LiveChartsCore.SkiaSharpView.Axis xAxis)
                    {
                        // Get current range or use full data range
                        double? currentMin = xAxis.MinLimit;
                        double? currentMax = xAxis.MaxLimit;

                        // If no limits set, get from data
                        if (currentMin == null || currentMax == null)
                        {
                            // Get data range from series
                            var dataPoints = vm.PortActivitySeries?.SelectMany(s => s.Values?.Cast<ObservablePoint>() ?? Enumerable.Empty<ObservablePoint>())
                                                                   .Where(p => p != null && p.X.HasValue)
                                                                   .ToList();
                            if (dataPoints != null && dataPoints.Count > 0)
                            {
                                currentMin = dataPoints.Min(p => p.X ?? 0);
                                currentMax = dataPoints.Max(p => p.X ?? 0);
                            }
                        }

                        if (currentMin != null && currentMax != null)
                        {
                            var range = currentMax.Value - currentMin.Value;
                            var newRange = range * 0.5; // Zoom in by 50%
                            var center = currentMin.Value + (range / 2);

                            xAxis.MinLimit = center - (newRange / 2);
                            xAxis.MaxLimit = center + (newRange / 2);
                        }
                    }
                }

                DebugLogger.Log("[DashboardView] Port Activity chart zoomed in");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnPortZoomIn error: {ex.Message}");
            }
        }

        private void OnPortZoomOut(object? sender, RoutedEventArgs e)
        {
            try
            {
                var chart = this.FindControl<CartesianChart>("PortActivityChart");
                if (chart == null || DataContext is not DashboardViewModel vm) return;

                // Zoom out by increasing the visible range by 100%
                if (vm.PortActivityXAxes != null && vm.PortActivityXAxes.Length > 0)
                {
                    var axis = vm.PortActivityXAxes[0];
                    if (axis is LiveChartsCore.SkiaSharpView.Axis xAxis)
                    {
                        // Get current range
                        double? currentMin = xAxis.MinLimit;
                        double? currentMax = xAxis.MaxLimit;

                        // Get data bounds
                        double? dataMin = null;
                        double? dataMax = null;
                        var dataPoints = vm.PortActivitySeries?.SelectMany(s => s.Values?.Cast<ObservablePoint>() ?? Enumerable.Empty<ObservablePoint>())
                                                               .Where(p => p != null && p.X.HasValue)
                                                               .ToList();
                        if (dataPoints != null && dataPoints.Count > 0)
                        {
                            dataMin = dataPoints.Min(p => p.X ?? 0);
                            dataMax = dataPoints.Max(p => p.X ?? 0);
                        }

                        // If no limits set, use data bounds
                        if (currentMin == null || currentMax == null)
                        {
                            currentMin = dataMin;
                            currentMax = dataMax;
                        }

                        if (currentMin != null && currentMax != null)
                        {
                            var range = currentMax.Value - currentMin.Value;
                            var newRange = range * 2; // Zoom out by 100%
                            var center = currentMin.Value + (range / 2);

                            // Don't zoom out beyond data bounds
                            var newMin = center - (newRange / 2);
                            var newMax = center + (newRange / 2);

                            if (dataMin != null && newMin < dataMin)
                                newMin = dataMin.Value;
                            if (dataMax != null && newMax > dataMax)
                                newMax = dataMax.Value;

                            xAxis.MinLimit = newMin;
                            xAxis.MaxLimit = newMax;
                        }
                    }
                }

                DebugLogger.Log("[DashboardView] Port Activity chart zoomed out");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnPortZoomOut error: {ex.Message}");
            }
        }

        private void OnPortZoomReset(object? sender, RoutedEventArgs e)
        {
            try
            {
                var chart = this.FindControl<CartesianChart>("PortActivityChart");
                if (chart == null || DataContext is not DashboardViewModel vm) return;

                // Reset zoom to show all data
                if (vm.PortActivityXAxes != null && vm.PortActivityXAxes.Length > 0)
                {
                    var axis = vm.PortActivityXAxes[0];
                    if (axis is LiveChartsCore.SkiaSharpView.Axis xAxis)
                    {
                        xAxis.MinLimit = null; // Reset to auto
                        xAxis.MaxLimit = null; // Reset to auto
                    }
                }

                DebugLogger.Log("[DashboardView] Port Activity chart zoom reset");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnPortZoomReset error: {ex.Message}");
            }
        }

        #endregion
    }
}
