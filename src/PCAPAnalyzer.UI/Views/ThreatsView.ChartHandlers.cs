using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Input;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.Utilities;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;
using ObservablePoint = LiveChartsCore.Defaults.ObservablePoint;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views
{
    /// <summary>
    /// ThreatsView.TooltipManager - Chart hover tooltip and highlight logic
    /// </summary>
    public partial class ThreatsView
    {
        // Highlight series for threat chart
        private ScatterSeries<DateTimePoint>? _threatHighlightScatter;
        private LineSeries<DateTimePoint>? _threatHighlightLine;

        // Cached Y-axis ranges for vertical line
        private double _cachedThreatMinY;
        private double _cachedThreatMaxY;

        // Track last highlighted point
        private int _lastHighlightedIndex = -1;

        // Debounce tracking for error suppression
        private DateTime _lastErrorLogTime = DateTime.MinValue;
        private int _consecutiveErrors;
        private const int MAX_ERROR_LOG_PER_SECOND = 5;

        /// <summary>
        /// Enhanced threat chart pointer moved handler with full tooltip implementation
        /// FIX: Uses Ticks instead of OleAut date conversion (LiveCharts2 uses DateTime.Ticks for X values)
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Tooltip handler requires handling multiple series types (DateTimePoint/ObservablePoint), bounds validation, error debouncing, and data extraction - complexity justified for robust chart interaction")]
        private void OnThreatChartPointerMoved(object? sender, PointerEventArgs e)
        {
            try
            {
                if (sender is not CartesianChart chart || DataContext is not ThreatsViewModel vm)
                    return;

                var position = e.GetPosition(chart);

                // Convert Avalonia Point to LvcPointD
                var lvcPosition = new LiveChartsCore.Drawing.LvcPointD(position.X, position.Y);
                var chartPoint = chart.ScalePixelsToData(lvcPosition);

                if (vm.ThreatTimelineSeries == null)
                    return;

                // FIX: LiveCharts2 uses DateTime.Ticks for X values (NOT OleAutomation dates)
                // Validate ticks are in valid DateTime range before conversion
                long ticks = (long)chartPoint.X;
                if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                    return;

                DateTime targetTime = new DateTime(ticks);
                int closestIndex = -1;
                double minDistance = double.MaxValue;

                // Find closest point across all series (handle both LineSeries<DateTimePoint> and LineSeries<ObservablePoint>)
                foreach (var series in vm.ThreatTimelineSeries)
                {
                    // Handle LineSeries<DateTimePoint> (legacy)
                    if (series is LineSeries<DateTimePoint> dateLineSeries && dateLineSeries.Values != null)
                    {
                        var values = dateLineSeries.Values as IEnumerable<DateTimePoint>;
                        if (values == null) continue;

                        int index = 0;
                        foreach (var point in values)
                        {
                            var distance = Math.Abs((point.DateTime - targetTime).TotalSeconds);
                            if (distance < minDistance)
                            {
                                minDistance = distance;
                                closestIndex = index;
                            }
                            index++;
                        }
                    }
                    // Handle LineSeries<ObservablePoint> (current implementation - uses Ticks)
                    else if (series is LineSeries<ObservablePoint> obsLineSeries && obsLineSeries.Values != null)
                    {
                        var values = obsLineSeries.Values as IEnumerable<ObservablePoint>;
                        if (values == null) continue;

                        int index = 0;
                        foreach (var point in values)
                        {
                            if (point.X == null) continue;
                            var pointTicks = (long)(point.X.Value);
                            if (pointTicks < DateTime.MinValue.Ticks || pointTicks > DateTime.MaxValue.Ticks) continue;

                            var pointTime = new DateTime(pointTicks);
                            var distance = Math.Abs((pointTime - targetTime).TotalSeconds);
                            if (distance < minDistance)
                            {
                                minDistance = distance;
                                closestIndex = index;
                            }
                            index++;
                        }
                    }
                }

                if (closestIndex >= 0 && closestIndex != _lastHighlightedIndex)
                {
                    // Extract data at this index
                    DateTime timestamp = DateTime.MinValue;
                    var threatCounts = new List<(string label, double value)>();

                    foreach (var series in vm.ThreatTimelineSeries)
                    {
                        // Handle LineSeries<DateTimePoint>
                        if (series is LineSeries<DateTimePoint> dateLineSeries && dateLineSeries.Values != null)
                        {
                            var values = dateLineSeries.Values as IList<DateTimePoint>;
                            if (values != null && closestIndex < values.Count)
                            {
                                var point = values[closestIndex];
                                timestamp = point.DateTime;
                                threatCounts.Add((dateLineSeries.Name ?? "Unknown", point.Value ?? 0));
                            }
                        }
                        // Handle LineSeries<ObservablePoint> (current)
                        else if (series is LineSeries<ObservablePoint> obsLineSeries && obsLineSeries.Values != null)
                        {
                            var values = obsLineSeries.Values as IList<ObservablePoint>;
                            if (values != null && closestIndex < values.Count)
                            {
                                var point = values[closestIndex];
                                if (point.X != null)
                                {
                                    var pointTicks = (long)(point.X.Value);
                                    if (pointTicks >= DateTime.MinValue.Ticks && pointTicks <= DateTime.MaxValue.Ticks)
                                    {
                                        timestamp = new DateTime(pointTicks);
                                        threatCounts.Add((obsLineSeries.Name ?? "Unknown", point.Y ?? 0));
                                    }
                                }
                            }
                        }
                    }

                    if (timestamp != DateTime.MinValue && threatCounts.Count > 0)
                    {
                        // Build tooltip text
                        var tooltipParts = new List<string> { timestamp.ToString("yyyy-MM-dd HH:mm:ss") };
                        foreach (var (label, value) in threatCounts)
                        {
                            tooltipParts.Add($"{label}: {value:N2}/s");
                        }
                        ThreatTooltipText.Text = string.Join(" | ", tooltipParts);

                        // Add highlight with yellow vertical line
                        var values = threatCounts.Select(t => t.value).ToArray();
                        AddThreatHighlight(chart, closestIndex, timestamp, values, position.X);
                    }
                }

                // Reset error counter on success
                _consecutiveErrors = 0;
            }
            catch (Exception ex)
            {
                // Debounce error logging to prevent spam (max 5 logs per second)
                var now = DateTime.Now;
                if ((now - _lastErrorLogTime).TotalSeconds >= 1)
                {
                    _consecutiveErrors = 0;
                    _lastErrorLogTime = now;
                }

                _consecutiveErrors++;
                if (_consecutiveErrors <= MAX_ERROR_LOG_PER_SECOND)
                {
                    DebugLogger.Log($"[EnhancedThreatsView] OnThreatChartPointerMoved error: {ex.Message}");
                    if (_consecutiveErrors == MAX_ERROR_LOG_PER_SECOND)
                    {
                        DebugLogger.Log($"[EnhancedThreatsView] Error logging suppressed (too many consecutive errors)");
                    }
                }
            }
        }

        /// <summary>
        /// Clear highlights when pointer exits
        /// </summary>
        private void OnThreatChartPointerExited(object? sender, PointerEventArgs e)
        {
            try
            {
                ThreatTooltipText.Text = "";
                RemoveThreatHighlight(sender as CartesianChart);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] OnThreatChartPointerExited error: {ex.Message}");
            }
        }

        /// <summary>
        /// Adds yellow highlight dot and vertical line to threat chart
        /// </summary>
        private void AddThreatHighlight(CartesianChart chart, int index, DateTime timestamp, double[] values, double xPosition)
        {
            try
            {
                if (DataContext is not ThreatsViewModel vm)
                    return;

                var value = values.Length > 0 ? values.Max() : 0;

                // Calculate Y-axis range
                _cachedThreatMinY = 0;
                _cachedThreatMaxY = values.Length > 0 ? values.Max() * 1.1 : 10;

                if (Math.Abs(_cachedThreatMaxY - _cachedThreatMinY) < 0.0001)
                {
                    _cachedThreatMaxY = _cachedThreatMinY + 1;
                }

                // Create or update scatter series for highlight dot
                if (_threatHighlightScatter == null)
                {
                    _threatHighlightScatter = new ScatterSeries<DateTimePoint>
                    {
                        Values = new ObservableCollection<DateTimePoint> { new(timestamp, value) },
                        GeometrySize = 12,
                        Fill = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.HighlightYellowHex)),
                        Stroke = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.HighlightOrangeHex)) { StrokeThickness = 2 },
                        Name = "Highlight",
                        IsVisibleAtLegend = false,
                        ZIndex = 1000,
                        DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                        IsHoverable = false
                    };
                    vm.ThreatTimelineSeries?.Add(_threatHighlightScatter);
                }

                UpdateScatterPoint(_threatHighlightScatter, timestamp, value);

                // Create or update line series for vertical line
                if (_threatHighlightLine == null)
                {
                    _threatHighlightLine = new LineSeries<DateTimePoint>
                    {
                        Values = new ObservableCollection<DateTimePoint>
                        {
                            new(timestamp, _cachedThreatMinY),
                            new(timestamp, _cachedThreatMaxY)
                        },
                        Stroke = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.HighlightYellowHex)) { StrokeThickness = 4f },
                        Fill = null,
                        GeometrySize = 0,
                        LineSmoothness = 0,
                        Name = "VerticalLine",
                        IsVisibleAtLegend = false,
                        ZIndex = 999,
                        DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                        IsHoverable = false
                    };
                    vm.ThreatTimelineSeries?.Add(_threatHighlightLine);
                }

                UpdateLinePoints(_threatHighlightLine, timestamp, _cachedThreatMinY, _cachedThreatMaxY);

                SetSeriesVisibility(_threatHighlightScatter, true);
                SetSeriesVisibility(_threatHighlightLine, true);

                _lastHighlightedIndex = index;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] AddThreatHighlight error: {ex.Message}");
            }
        }

        /// <summary>
        /// Removes highlight from threat chart
        /// </summary>
        private void RemoveThreatHighlight(CartesianChart? chart)
        {
            try
            {
                SetSeriesVisibility(_threatHighlightScatter, false);
                SetSeriesVisibility(_threatHighlightLine, false);
                _lastHighlightedIndex = -1;
                chart?.CoreChart?.Update();
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] RemoveThreatHighlight error: {ex.Message}");
            }
        }

        /// <summary>
        /// Cleans up highlight series from the chart series collection.
        /// Call this when chart data is refreshed to prevent orphaned series.
        /// </summary>
        public void CleanupHighlightSeries()
        {
            try
            {
                if (DataContext is not ThreatsViewModel vm || vm.ThreatTimelineSeries == null)
                    return;

                // Remove highlight series from collection if they exist
                if (_threatHighlightScatter != null && vm.ThreatTimelineSeries.Contains(_threatHighlightScatter))
                {
                    vm.ThreatTimelineSeries.Remove(_threatHighlightScatter);
                }

                if (_threatHighlightLine != null && vm.ThreatTimelineSeries.Contains(_threatHighlightLine))
                {
                    vm.ThreatTimelineSeries.Remove(_threatHighlightLine);
                }

                // Reset references so they can be recreated cleanly
                _threatHighlightScatter = null;
                _threatHighlightLine = null;
                _lastHighlightedIndex = -1;

                DebugLogger.Log("[EnhancedThreatsView] Highlight series cleaned up");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] CleanupHighlightSeries error: {ex.Message}");
            }
        }

        /// <summary>
        /// Sets series visibility
        /// </summary>
        private static void SetSeriesVisibility(ISeries? series, bool visible)
        {
            if (series == null) return;
            series.IsVisible = visible;
        }

        /// <summary>
        /// Updates scatter point for DateTimePoint
        /// </summary>
        private static void UpdateScatterPoint(ScatterSeries<DateTimePoint> series, DateTime timestamp, double value)
        {
            if (series.Values is IList<DateTimePoint> list)
            {
                if (list.Count == 0)
                {
                    list.Add(new DateTimePoint(timestamp, value));
                }
                else
                {
                    list[0] = new DateTimePoint(timestamp, value);
                }
            }
            else
            {
                series.Values = new ObservableCollection<DateTimePoint> { new DateTimePoint(timestamp, value) };
            }
        }

        /// <summary>
        /// Updates line points for vertical line
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
                    new DateTimePoint(timestamp, minY),
                    new DateTimePoint(timestamp, maxY)
                };
            }
        }

        // ==================== CLICK-TO-DRILLDOWN (Dashboard pattern) ====================

        /// <summary>
        /// Handle click on threat timeline chart - opens DrillDown for threat at that time
        /// </summary>
        private void OnThreatChartPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            try
            {
                if (sender is not CartesianChart chart || DataContext is not ThreatsViewModel vm)
                    return;

                var position = e.GetPosition(chart);
                var lvcPosition = new LiveChartsCore.Drawing.LvcPointD(position.X, position.Y);
                var chartPoint = chart.ScalePixelsToData(lvcPosition);

                // Convert ticks to DateTime
                long ticks = (long)chartPoint.X;
                if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                    return;

                DateTime clickedTime = new DateTime(ticks);
                DebugLogger.Log($"[EnhancedThreatsView] Chart clicked at time: {clickedTime:HH:mm:ss}");

                // Find threat near this time point (5 minute tolerance)
                var nearbyThreat = vm.SecurityThreatsPagination.PagedItems?
                    .FirstOrDefault(t => Math.Abs((t.FirstSeen - clickedTime).TotalMinutes) < 5);

                if (nearbyThreat != null)
                {
                    vm.ShowThreatDetailsCommand.Execute(nearbyThreat);
                    DebugLogger.Log($"[EnhancedThreatsView] Opening DrillDown for threat: {nearbyThreat.ThreatName}");
                }
                else
                {
                    DebugLogger.Log("[EnhancedThreatsView] No threats found near clicked time");
                    ThreatTooltipText.Text = $"No threats at {clickedTime:HH:mm:ss} - try clicking closer to data points";
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] OnThreatChartPointerPressed error: {ex.Message}");
            }
        }

        // ==================== ZOOM HANDLERS (Dashboard pattern) ====================

        /// <summary>
        /// Zoom in on threat timeline chart (30% zoom)
        /// </summary>
        private void OnThreatZoomIn(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (DataContext is not ThreatsViewModel vm || vm.XAxes == null || vm.XAxes.Length == 0)
                    return;

                var xAxis = vm.XAxes[0];
                var minLimit = xAxis.MinLimit ?? 0;
                var maxLimit = xAxis.MaxLimit ?? 1;
                var range = maxLimit - minLimit;
                var center = (minLimit + maxLimit) / 2;
                var newRange = range * 0.7; // Zoom in 30%

                xAxis.MinLimit = center - newRange / 2;
                xAxis.MaxLimit = center + newRange / 2;

                DebugLogger.Log($"[EnhancedThreatsView] Zoom in: range {range:F0} → {newRange:F0}");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] OnThreatZoomIn error: {ex.Message}");
            }
        }

        /// <summary>
        /// Zoom out on threat timeline chart (40% zoom)
        /// </summary>
        private void OnThreatZoomOut(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (DataContext is not ThreatsViewModel vm || vm.XAxes == null || vm.XAxes.Length == 0)
                    return;

                var xAxis = vm.XAxes[0];
                var minLimit = xAxis.MinLimit ?? 0;
                var maxLimit = xAxis.MaxLimit ?? 1;
                var range = maxLimit - minLimit;
                var center = (minLimit + maxLimit) / 2;
                var newRange = range * 1.4; // Zoom out 40%

                xAxis.MinLimit = center - newRange / 2;
                xAxis.MaxLimit = center + newRange / 2;

                DebugLogger.Log($"[EnhancedThreatsView] Zoom out: range {range:F0} → {newRange:F0}");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] OnThreatZoomOut error: {ex.Message}");
            }
        }

        /// <summary>
        /// Reset zoom on threat timeline chart
        /// </summary>
        private void OnThreatZoomReset(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (DataContext is not ThreatsViewModel vm || vm.XAxes == null || vm.XAxes.Length == 0)
                    return;

                var xAxis = vm.XAxes[0];
                xAxis.MinLimit = null;
                xAxis.MaxLimit = null;

                DebugLogger.Log("[EnhancedThreatsView] Zoom reset to auto-fit");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] OnThreatZoomReset error: {ex.Message}");
            }
        }

        // ==================== THREAT PORT ACTIVITY CHART HANDLERS ====================

        /// <summary>
        /// Handle pointer moved on threat port activity chart
        /// </summary>
        private void OnThreatPortChartPointerMoved(object? sender, PointerEventArgs e)
        {
            try
            {
                if (sender is not CartesianChart chart || DataContext is not ThreatsViewModel vm)
                    return;

                var position = e.GetPosition(chart);
                var lvcPosition = new LiveChartsCore.Drawing.LvcPointD(position.X, position.Y);
                var chartPoint = chart.ScalePixelsToData(lvcPosition);

                if (vm.Charts.ThreatPortActivitySeries == null || !vm.Charts.ThreatPortActivitySeries.Any())
                    return;

                long ticks = (long)chartPoint.X;
                if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                    return;

                DateTime targetTime = new DateTime(ticks);
                var tooltipParts = new List<string> { targetTime.ToString("HH:mm:ss") };

                // Gather values from each port series
                foreach (var series in vm.Charts.ThreatPortActivitySeries)
                {
                    if (series is LineSeries<ObservablePoint> lineSeries && lineSeries.Values != null)
                    {
                        var values = lineSeries.Values as IList<ObservablePoint>;
                        if (values == null) continue;

                        // Find closest point
                        ObservablePoint? closest = null;
                        double minDist = double.MaxValue;
                        foreach (var point in values)
                        {
                            if (point.X == null) continue;
                            var dist = Math.Abs(point.X.Value - ticks);
                            if (dist < minDist)
                            {
                                minDist = dist;
                                closest = point;
                            }
                        }

                        if (closest != null && closest.Y.HasValue)
                        {
                            var valueStr = $"{closest.Y.Value:F2}/s";
                            tooltipParts.Add($"{lineSeries.Name}: {valueStr}");
                        }
                    }
                }

                if (tooltipParts.Count > 1)
                {
                    ThreatPortActivityTooltipText.Text = string.Join(" | ", tooltipParts);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ThreatsView] OnThreatPortChartPointerMoved error: {ex.Message}");
            }
        }

        /// <summary>
        /// Clear tooltip when pointer exits threat port activity chart
        /// </summary>
        private void OnThreatPortChartPointerExited(object? sender, PointerEventArgs e)
        {
            ThreatPortActivityTooltipText.Text = "";
        }

        /// <summary>
        /// Handle click on threat port activity chart
        /// </summary>
        private void OnThreatPortChartPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            // Future: Could filter threats by clicked port
            DebugLogger.Log("[ThreatsView] Threat Port Activity chart clicked");
        }

        /// <summary>
        /// Zoom in on threat port activity chart
        /// </summary>
        private void OnThreatPortZoomIn(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (DataContext is not ThreatsViewModel vm || vm.Charts.ThreatPortActivityXAxes == null || vm.Charts.ThreatPortActivityXAxes.Length == 0)
                    return;

                var xAxis = vm.Charts.ThreatPortActivityXAxes[0];
                var minLimit = xAxis.MinLimit ?? 0;
                var maxLimit = xAxis.MaxLimit ?? 1;
                var range = maxLimit - minLimit;
                var center = (minLimit + maxLimit) / 2;
                var newRange = range * 0.7; // Zoom in 30%

                xAxis.MinLimit = center - newRange / 2;
                xAxis.MaxLimit = center + newRange / 2;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ThreatsView] OnThreatPortZoomIn error: {ex.Message}");
            }
        }

        /// <summary>
        /// Zoom out on threat port activity chart
        /// </summary>
        private void OnThreatPortZoomOut(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (DataContext is not ThreatsViewModel vm || vm.Charts.ThreatPortActivityXAxes == null || vm.Charts.ThreatPortActivityXAxes.Length == 0)
                    return;

                var xAxis = vm.Charts.ThreatPortActivityXAxes[0];
                var minLimit = xAxis.MinLimit ?? 0;
                var maxLimit = xAxis.MaxLimit ?? 1;
                var range = maxLimit - minLimit;
                var center = (minLimit + maxLimit) / 2;
                var newRange = range * 1.4; // Zoom out 40%

                xAxis.MinLimit = center - newRange / 2;
                xAxis.MaxLimit = center + newRange / 2;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ThreatsView] OnThreatPortZoomOut error: {ex.Message}");
            }
        }

        /// <summary>
        /// Reset zoom on threat port activity chart
        /// </summary>
        private void OnThreatPortZoomReset(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (DataContext is not ThreatsViewModel vm || vm.Charts.ThreatPortActivityXAxes == null || vm.Charts.ThreatPortActivityXAxes.Length == 0)
                    return;

                var xAxis = vm.Charts.ThreatPortActivityXAxes[0];
                xAxis.MinLimit = null;
                xAxis.MaxLimit = null;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ThreatsView] OnThreatPortZoomReset error: {ex.Message}");
            }
        }

    }
}
