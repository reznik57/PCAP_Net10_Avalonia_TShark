using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia.Controls;
using PCAPAnalyzer.UI.ViewModels;
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
    /// DashboardView.TooltipManager - Tooltip display and visual highlight logic
    /// </summary>
    /// <remarks>
    /// This partial class handles:
    /// - Adding highlight dots and vertical lines to charts
    /// - Removing highlights when mouse leaves
    /// - Managing highlight series (scatter + line)
    /// - Visibility control for highlight elements
    ///
    /// Separated from the main DashboardView.axaml.cs for better organization
    /// </remarks>
    public partial class DashboardView
    {
        /// <summary>
        /// Adds a highlight dot and vertical line to indicate the current data point under the cursor
        /// </summary>
        /// <param name="chart">The chart to highlight</param>
        /// <param name="index">Data point index</param>
        /// <param name="timestamp">Timestamp of the data point</param>
        /// <param name="values">Y values for the highlight</param>
        /// <param name="isTraffic">True for traffic chart, false for port chart</param>
        /// <param name="xPosition">Mouse X position for vertical line</param>
        private void AddHighlightWithLine(CartesianChart chart, int index, DateTime timestamp, double[] values, bool isTraffic, double xPosition)
        {
            try
            {
                if (DataContext is not DashboardViewModel vm)
                    return;

                var value = values.Length > 0 ? values[0] : 0;

                if (isTraffic)
                {
                    // Use the maximum across ALL traffic axes for the vertical line
                    // This ensures the line spans the full chart height
                    var minY = Math.Min(_cachedThroughputMinY, Math.Min(_cachedPacketsMinY, _cachedAnomaliesMinY));
                    var maxY = Math.Max(_cachedThroughputMaxY, Math.Max(_cachedPacketsMaxY, _cachedAnomaliesMaxY));

                    // Ensure we have a valid range
                    if (Math.Abs(maxY - minY) < 0.0001)
                    {
                        maxY = minY + 1;
                    }

                    // Create or update scatter series for highlight dot
                    if (_trafficHighlightScatter == null)
                    {
                        _trafficHighlightScatter = new ScatterSeries<DateTimePoint>
                        {
                            Values = new ObservableCollection<DateTimePoint> { new(timestamp, value) },
                            GeometrySize = 12,
                            Fill = new SolidColorPaint(SKColor.Parse("#FFD700")),
                            Stroke = new SolidColorPaint(SKColor.Parse("#FFA500")) { StrokeThickness = 2 },
                            Name = "Highlight",
                            IsVisibleAtLegend = false,
                            ZIndex = 1000,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                            IsHoverable = false
                        };
                        vm.TimelineSeries?.Add(_trafficHighlightScatter);
                    }

                    UpdateScatterPoint(_trafficHighlightScatter, timestamp, value);

                    // Create or update line series for vertical line (prominent yellow marker)
                    if (_trafficHighlightLine == null)
                    {
                        _trafficHighlightLine = new LineSeries<DateTimePoint>
                        {
                            Values = new ObservableCollection<DateTimePoint>
                            {
                                new(timestamp, minY),
                                new(timestamp, maxY)
                            },
                            Stroke = new SolidColorPaint(SKColor.Parse("#FFD700")) { StrokeThickness = 4f },  // Thick yellow line for visibility
                            Fill = null,
                            GeometrySize = 0,
                            LineSmoothness = 0,
                            Name = "VerticalLine",
                            IsVisibleAtLegend = false,
                            ZIndex = 999,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                            IsHoverable = false
                        };
                        vm.TimelineSeries?.Add(_trafficHighlightLine);
                    }

                    UpdateLinePoints(_trafficHighlightLine, timestamp, minY, maxY);

                    SetSeriesVisibility(_trafficHighlightScatter, true);
                    SetSeriesVisibility(_trafficHighlightLine, true);
                }
                else
                {
                    // Port Activity chart: Use min/max from cached port data for vertical line
                    var minY = _cachedPortMinY;
                    var maxY = _cachedPortMaxY;

                    // Ensure we have a valid range
                    if (Math.Abs(maxY - minY) < 0.0001)
                    {
                        maxY = minY + 1;
                    }

                    // Create or update scatter series for highlight dot (on max value line)
                    if (_portHighlightScatter == null)
                    {
                        _portHighlightScatter = new ScatterSeries<DateTimePoint>
                        {
                            Values = new ObservableCollection<DateTimePoint> { new(timestamp, value) },
                            GeometrySize = 12,
                            Fill = new SolidColorPaint(SKColor.Parse("#FFD700")),
                            Stroke = new SolidColorPaint(SKColor.Parse("#FFA500")) { StrokeThickness = 2 },
                            Name = "Highlight",
                            IsVisibleAtLegend = false,
                            ZIndex = 1000,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                            IsHoverable = false
                        };
                        vm.PortActivitySeries?.Add(_portHighlightScatter);
                    }

                    UpdateScatterPoint(_portHighlightScatter, timestamp, value);

                    // Create or update line series for vertical line (yellow marker)
                    if (_portHighlightLine == null)
                    {
                        _portHighlightLine = new LineSeries<DateTimePoint>
                        {
                            Values = new ObservableCollection<DateTimePoint>
                            {
                                new(timestamp, minY),
                                new(timestamp, maxY)
                            },
                            Stroke = new SolidColorPaint(SKColor.Parse("#FFD700")) { StrokeThickness = 4f },  // Thick yellow line
                            Fill = null,
                            GeometrySize = 0,
                            LineSmoothness = 0,
                            Name = "VerticalLine",
                            IsVisibleAtLegend = false,
                            ZIndex = 999,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                            IsHoverable = false
                        };
                        vm.PortActivitySeries?.Add(_portHighlightLine);
                    }

                    UpdateLinePoints(_portHighlightLine, timestamp, minY, maxY);

                    SetSeriesVisibility(_portHighlightScatter, true);
                    SetSeriesVisibility(_portHighlightLine, true);
                }

                _lastHighlightedIndex = index;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] AddHighlightWithLine error: {ex.Message}");
            }
        }

        /// <summary>
        /// Removes highlight from the specified chart
        /// </summary>
        /// <param name="chart">The chart to remove highlights from</param>
        /// <param name="isTraffic">True for traffic chart, false for port chart</param>
        private void RemoveHighlight(CartesianChart? chart, bool isTraffic)
        {
            try
            {
                if (DataContext is not DashboardViewModel vm)
                    return;

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
        /// Sets the visibility of a series
        /// </summary>
        private static void SetSeriesVisibility(ISeries? series, bool visible)
        {
            if (series == null) return;
            series.IsVisible = visible;
        }

        /// <summary>
        /// Updates a scatter series point for DateTimePoint data
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
        /// Updates a line series points for vertical line (DateTimePoint data)
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
    }
}
