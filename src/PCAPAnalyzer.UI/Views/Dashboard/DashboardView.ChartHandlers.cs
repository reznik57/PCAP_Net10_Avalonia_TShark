using System;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Avalonia.Controls;
using Avalonia.Input;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.ViewModels;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.Defaults;
using ObservablePoint = LiveChartsCore.Defaults.ObservablePoint;

namespace PCAPAnalyzer.UI.Views
{
    /// <summary>
    /// DashboardView.ChartHandlers - Chart event handlers partial class
    /// </summary>
    /// <remarks>
    /// This partial class contains all chart-related event handlers:
    /// - Traffic chart pointer moved/exited
    /// - Port activity chart pointer moved/exited
    /// - Internal tooltip update logic
    ///
    /// Separated from the main DashboardView.axaml.cs for better organization
    /// </remarks>
    public partial class DashboardView
    {
        /// <summary>
        /// Event handler for Traffic chart PointerMoved (called from XAML)
        /// </summary>
        private void OnTrafficChartPointerMoved(object? sender, PointerEventArgs e)
        {
            try
            {
                var chart = sender as CartesianChart;
                var tooltipText = this.FindControl<TextBlock>("TrafficTooltipText");

                if (chart == null || tooltipText == null)
                {
                    DebugLogger.Log("[DashboardView] Traffic chart or tooltip not found");
                    return;
                }

                OnTrafficChartPointerMovedInternal(chart, tooltipText, e);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnTrafficChartPointerMoved error: {ex.Message}");
            }
        }

        /// <summary>
        /// Event handler for Traffic chart PointerExited (called from XAML)
        /// </summary>
        private void OnTrafficChartPointerExited(object? sender, PointerEventArgs e)
        {
            try
            {
                var tooltipText = this.FindControl<TextBlock>("TrafficTooltipText");
                if (tooltipText != null)
                {
                    tooltipText.Text = "";
                }
                RemoveHighlight(sender as CartesianChart, true);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnTrafficChartPointerExited error: {ex.Message}");
            }
        }

        /// <summary>
        /// Event handler for Port chart PointerMoved (called from XAML)
        /// </summary>
        private void OnPortChartPointerMoved(object? sender, PointerEventArgs e)
        {
            try
            {
                var chart = sender as CartesianChart;
                var tooltipText = this.FindControl<TextBlock>("PortActivityTooltipText");

                if (chart == null || tooltipText == null)
                {
                    DebugLogger.Log("[DashboardView] Port chart or tooltip not found");
                    return;
                }

                OnPortChartPointerMovedInternal(chart, tooltipText, e);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnPortChartPointerMoved error: {ex.Message}");
            }
        }

        /// <summary>
        /// Event handler for Port chart PointerExited (called from XAML)
        /// </summary>
        private void OnPortChartPointerExited(object? sender, PointerEventArgs e)
        {
            try
            {
                var tooltipText = this.FindControl<TextBlock>("PortActivityTooltipText");
                if (tooltipText != null)
                {
                    tooltipText.Text = "";
                }
                RemoveHighlight(sender as CartesianChart, false);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnPortChartPointerExited error: {ex.Message}");
            }
        }

        /// <summary>
        /// Internal handler for Traffic chart pointer movement with tooltip logic
        /// </summary>
        [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
            Justification = "Chart pointer handling requires processing multiple chart elements including throughput, packets/s, anomalies, calculating relative positions, and updating detailed tooltip display")]
        private void OnTrafficChartPointerMovedInternal(CartesianChart chart, TextBlock tooltipText, PointerEventArgs e)
        {
            try
            {
                var position = e.GetPosition(chart);

                // Get the actual plot area bounds from LiveCharts Core (accurate drawable area)
                var drawMargin = chart.CoreChart.DrawMarginLocation;
                var drawSize = chart.CoreChart.DrawMarginSize;

                // Use actual drawable area if available, otherwise fall back to approximation
                double plotAreaLeft = drawMargin.X > 0 ? drawMargin.X : 50;
                double plotAreaWidth = drawSize.Width > 0 ? drawSize.Width : chart.Bounds.Width - 70;

                var adjustedX = position.X - plotAreaLeft;

                // Calculate relative X position (0 to 1) within the plot area
                var relativeX = Math.Max(0, Math.Min(1, adjustedX / plotAreaWidth));

                // Initialize values
                DateTime? timestamp = null;
                double throughputMBs = 0;
                double packetsPerSec = 0;
                double anomalies = 0;
                double threats = 0;
                int dataIndex = -1;

                // Try to get values from cached data
                if (_cachedTrafficData.Count > 0)
                {
                    // Get throughput data (primary series for positioning)
                    var throughputKey = _cachedTrafficData.Keys.FirstOrDefault(k => k.StartsWith("Throughput", StringComparison.OrdinalIgnoreCase));
                    if (!string.IsNullOrEmpty(throughputKey))
                    {
                        var throughputData = _cachedTrafficData[throughputKey];
                        if (throughputData.Count > 0)
                        {
                            dataIndex = (int)(relativeX * (throughputData.Count - 1));
                            dataIndex = Math.Max(0, Math.Min(throughputData.Count - 1, dataIndex));
                            var point = throughputData[dataIndex];
                            timestamp = point.DateTime;
                            throughputMBs = point.Value ?? 0;
                        }
                    }

                    // Get packets/s data
                    var packetsKey = _cachedTrafficData.Keys.FirstOrDefault(k => k.StartsWith("Packets/s", StringComparison.OrdinalIgnoreCase));
                    if (!string.IsNullOrEmpty(packetsKey))
                    {
                        var packetsData = _cachedTrafficData[packetsKey];
                        if (packetsData.Count > 0 && dataIndex >= 0 && dataIndex < packetsData.Count)
                        {
                            packetsPerSec = packetsData[dataIndex].Value ?? 0;
                        }
                    }

                    // Get anomalies data
                    var anomaliesKey = _cachedTrafficData.Keys.FirstOrDefault(k => k.StartsWith("Anomalies", StringComparison.OrdinalIgnoreCase));
                    if (!string.IsNullOrEmpty(anomaliesKey))
                    {
                        var anomaliesData = _cachedTrafficData[anomaliesKey];
                        if (anomaliesData.Count > 0 && dataIndex >= 0 && dataIndex < anomaliesData.Count)
                        {
                            anomalies = anomaliesData[dataIndex].Value ?? 0;
                        }
                    }

                    // Get threats data
                    var threatsKey = _cachedTrafficData.Keys.FirstOrDefault(k => k.StartsWith("Threats", StringComparison.OrdinalIgnoreCase));
                    if (!string.IsNullOrEmpty(threatsKey))
                    {
                        var threatsData = _cachedTrafficData[threatsKey];
                        if (threatsData.Count > 0 && dataIndex >= 0 && dataIndex < threatsData.Count)
                        {
                            threats = threatsData[dataIndex].Value ?? 0;
                        }
                    }
                }

                // If we still don't have data, try direct access
                if (timestamp == null && DataContext is DashboardViewModel vm && vm.TimelineSeries != null)
                {
                    foreach (var s in vm.TimelineSeries)
                    {
                        if (s is LineSeries<DateTimePoint> dateTimeSeries && dateTimeSeries.Values != null)
                        {
                            var values = dateTimeSeries.Values.Cast<DateTimePoint>().ToList();
                            if (values.Count > 0)
                            {
                                dataIndex = (int)(relativeX * (values.Count - 1));
                                dataIndex = Math.Max(0, Math.Min(values.Count - 1, dataIndex));
                                var point = values[dataIndex];

                                if (timestamp == null)
                                {
                                    timestamp = point.DateTime;
                                }

                                var name = dateTimeSeries.Name ?? "";
                                if (name.Contains("Throughput", StringComparison.Ordinal))
                                {
                                    throughputMBs = point.Value ?? 0;
                                }
                                else if (name.Contains("Packets", StringComparison.Ordinal))
                                {
                                    packetsPerSec = point.Value ?? 0;
                                }
                                else if (name.Contains("Anomalies", StringComparison.Ordinal))
                                {
                                    anomalies = point.Value ?? 0;
                                }
                                else if (name.Contains("Threats", StringComparison.Ordinal))
                                {
                                    threats = point.Value ?? 0;
                                }
                            }
                        }
                    }
                }

                // Display the tooltip with colored text for each value
                if (timestamp.HasValue)
                {
                    // Clear existing inlines and build colored tooltip
                    tooltipText.Inlines?.Clear();

                    // Time prefix (white)
                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"🕐 {timestamp.Value:HH:mm:ss}  •  ")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#F0F6FC"))
                    });

                    // Throughput (green - #3FB950)
                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"📊 {throughputMBs:F2} MB/s")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#3FB950")),
                        FontWeight = Avalonia.Media.FontWeight.Bold
                    });

                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run("  •  ")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#F0F6FC"))
                    });

                    // Packets/s (blue - #58A6FF)
                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"📦 {packetsPerSec:N0} pkt/s")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#58A6FF")),
                        FontWeight = Avalonia.Media.FontWeight.Bold
                    });

                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run("  •  ")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#F0F6FC"))
                    });

                    // Anomalies (red - #F85149)
                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"⚠️ {anomalies:N0} anomalies")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#F85149")),
                        FontWeight = Avalonia.Media.FontWeight.Bold
                    });

                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run("  •  ")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#F0F6FC"))
                    });

                    // Threats (purple - #A855F7)
                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"🛡️ {threats:N0} threats")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#A855F7")),
                        FontWeight = Avalonia.Media.FontWeight.Bold
                    });

                    tooltipText.FontWeight = Avalonia.Media.FontWeight.Medium;

                    // Add visual highlight and vertical line
                    if (dataIndex >= 0 && timestamp.HasValue)
                    {
                        AddHighlightWithLine(chart, dataIndex, timestamp.Value, new double[] { throughputMBs, packetsPerSec, anomalies, threats }, true, position.X);
                    }
                }
                else
                {
                    tooltipText.Inlines?.Clear();
                    tooltipText.Text = "";
                    RemoveHighlight(chart, true);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnTrafficChartPointerMoved error: {ex.Message}");
                tooltipText.Text = "Error reading data";
            }
        }

        /// <summary>
        /// Internal handler for Port chart pointer movement with tooltip logic
        /// </summary>
        [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
            Justification = "Port chart pointer handling requires processing port activity data across multiple series, highlighting maximum values, calculating positions, and updating detailed tooltip information")]
        private void OnPortChartPointerMovedInternal(CartesianChart chart, TextBlock tooltipText, PointerEventArgs e)
        {
            try
            {
                var position = e.GetPosition(chart);

                // Get the actual plot area bounds from LiveCharts Core (accurate drawable area)
                var drawMargin = chart.CoreChart.DrawMarginLocation;
                var drawSize = chart.CoreChart.DrawMarginSize;

                // Use actual drawable area if available, otherwise fall back to approximation
                double plotAreaLeft = drawMargin.X > 0 ? drawMargin.X : 50;
                double plotAreaWidth = drawSize.Width > 0 ? drawSize.Width : chart.Bounds.Width - 70;

                var adjustedX = position.X - plotAreaLeft;

                // Calculate relative X position (0 to 1) within the plot area
                var relativeX = Math.Max(0, Math.Min(1, adjustedX / plotAreaWidth));

                // Initialize
                var tooltipParts = new List<string>();
                DateTime? timestamp = null;
                int dataIndex = -1;
                var values = new List<double>();
                double maxValue = 0; // Track the max value for highlighting

                // First, try to get data directly from the ViewModel (most reliable)
                if (DataContext is DashboardViewModel vm && vm.PortActivitySeries != null && vm.PortActivitySeries.Count > 0)
                {
                    // Skip the highlight and vertical line series
                    var dataSeries = vm.PortActivitySeries.Where(s => s.Name != "Highlight" && s.Name != "VerticalLine").ToList();

                    foreach (var s in dataSeries)
                    {
                        var name = s.Name ?? "Port";

                        if (s is LineSeries<DateTimePoint> dateTimeSeries && dateTimeSeries.Values != null)
                        {
                            var seriesValues = dateTimeSeries.Values.Cast<DateTimePoint>().ToList();
                            if (seriesValues.Count > 0)
                            {
                                dataIndex = (int)(relativeX * (seriesValues.Count - 1));
                                dataIndex = Math.Max(0, Math.Min(seriesValues.Count - 1, dataIndex));
                                var point = seriesValues[dataIndex];

                                if (!timestamp.HasValue)
                                {
                                    timestamp = point.DateTime;
                                }

                                var value = point.Value ?? 0;
                                values.Add(value);
                                maxValue = Math.Max(maxValue, value);
                                tooltipParts.Add($"{name}: {value:F2}");
                            }
                        }
                        else if (s is LineSeries<ObservablePoint> observableSeries && observableSeries.Values != null)
                        {
                            var seriesValues = observableSeries.Values.Cast<ObservablePoint>().ToList();
                            if (seriesValues.Count > 0)
                            {
                                dataIndex = (int)(relativeX * (seriesValues.Count - 1));
                                dataIndex = Math.Max(0, Math.Min(seriesValues.Count - 1, dataIndex));
                                var point = seriesValues[dataIndex];

                                // ObservablePoint: X = ticks, Y = value
                                if (!timestamp.HasValue && point.X.HasValue)
                                {
                                    try
                                    {
                                        var ticks = (long)point.X.Value;
                                        if (ticks > 0 && ticks >= DateTime.MinValue.Ticks && ticks <= DateTime.MaxValue.Ticks)
                                        {
                                            timestamp = new DateTime(ticks);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        DebugLogger.Log($"[DashboardView] Error converting ticks to DateTime: {ex.Message}");
                                    }
                                }

                                var value = point.Y ?? 0;
                                values.Add(value);
                                maxValue = Math.Max(maxValue, value);

                                // Format based on whether it's throughput or packets
                                var formattedValue = vm.ShowPortActivityAsThroughput
                                    ? NumberFormatter.FormatBytes((long)value) + "/s"
                                    : $"{value:F0} pkt/s";
                                tooltipParts.Add($"{name}: {formattedValue}");
                            }
                        }
                    }
                }

                // If direct access didn't work, try cached data
                if (tooltipParts.Count == 0 && _cachedPortData.Count > 0)
                {
                    foreach (var kvp in _cachedPortData)
                    {
                        var seriesName = kvp.Key;
                        var cachedValues = kvp.Value;

                        if (cachedValues.Count > 0)
                        {
                            dataIndex = (int)(relativeX * (cachedValues.Count - 1));
                            dataIndex = Math.Max(0, Math.Min(cachedValues.Count - 1, dataIndex));

                            var value = cachedValues[dataIndex];

                            if (value is DateTimePoint dtp)
                            {
                                if (!timestamp.HasValue)
                                {
                                    timestamp = dtp.DateTime;
                                }
                                var v = dtp.Value ?? 0;
                                values.Add(v);
                                tooltipParts.Add($"{seriesName}: {v:F2}");
                            }
                            else if (value is LiveChartsCore.Defaults.ObservablePoint op)
                            {
                                var v = op.Y ?? 0;
                                values.Add(v);
                                tooltipParts.Add($"{seriesName}: {v:F2}");
                            }
                        }
                    }
                }

                // Build final tooltip with colored text for each port
                if (tooltipParts.Count > 0)
                {
                    tooltipText.Inlines?.Clear();

                    // Time prefix (white)
                    var timeStr = timestamp.HasValue ? $"🕐 {timestamp.Value:HH:mm:ss}" : $"📍 Index {dataIndex}";
                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"{timeStr}  •  ")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#F0F6FC"))
                    });

                    // Port color palette (same as DashboardViewModelExtensions.cs:519)
                    var portColors = new[] { "#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6",
                                           "#06B6D4", "#EC4899", "#F97316", "#84CC16", "#6366F1" };

                    // Add each port with its corresponding color
                    for (int i = 0; i < tooltipParts.Count; i++)
                    {
                        if (i > 0)
                        {
                            tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run("  •  ")
                            {
                                Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#F0F6FC"))
                            });
                        }

                        var colorHex = i < portColors.Length ? portColors[i] : "#6B7280"; // Default gray for ports beyond color array
                        tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"🔌 {tooltipParts[i]}")
                        {
                            Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse(colorHex)),
                            FontWeight = Avalonia.Media.FontWeight.Bold
                        });
                    }

                    tooltipText.FontWeight = Avalonia.Media.FontWeight.Medium;

                    // Add visual highlight with vertical line
                    if (dataIndex >= 0 && timestamp.HasValue)
                    {
                        AddHighlightWithLine(chart, dataIndex, timestamp.Value, new[] { maxValue }, false, position.X);
                    }
                }
                else
                {
                    tooltipText.Inlines?.Clear();
                    tooltipText.Text = "";
                    RemoveHighlight(chart, false);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnPortChartPointerMoved error: {ex.Message}");
                DebugLogger.Log($"[DashboardView] Stack: {ex.StackTrace}");
                tooltipText.Text = "Error reading data";
            }
        }
    }
}
