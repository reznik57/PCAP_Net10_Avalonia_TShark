using System;
using System.Linq;
using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.Defaults;
using SkiaSharp;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Constants;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views;

/// <summary>
/// VoiceQoSView - Voice/QoS traffic analysis view with mouseover support
/// </summary>
public partial class VoiceQoSView : UserControl
{
    // Cached data for efficient tooltip rendering (7 series)
    private Dictionary<string, List<DateTimePoint>> _cachedTimelineData = new();
    private double _cachedMinY;
    private double _cachedMaxY;

    // Highlight series for visual feedback
    private ScatterSeries<DateTimePoint>? _highlightScatter;
    private LineSeries<DateTimePoint>? _highlightLine;
    private int _lastHighlightedIndex = -1;

    // Series color mapping (NEVER changes)
    private static readonly Dictionary<string, string> SeriesColors = new()
    {
        { "QoS Packets", "#3FB950" },
        { "Latency Min", "#58A6FF" },
        { "Latency P5", "#87CEEB" },
        { "Latency Avg", "#1F6FEB" },
        { "Latency P95", "#4682B4" },
        { "Latency Max", "#0969DA" },
        { "Jitter Min", "#FFA657" },
        { "Jitter P5", "#FFFACD" },
        { "Jitter Avg", "#F85149" },
        { "Jitter P95", "#FF6347" },
        { "Jitter Max", "#DA3633" }
    };

    public VoiceQoSView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    /// <summary>
    /// Subscribe to ViewModel property changes for data caching
    /// </summary>
    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
        {
            vm.ChartsViewModel.PropertyChanged += (s, args) =>
            {
                if (args.PropertyName == nameof(vm.ChartsViewModel.TimelineSeries))
                {
                    CacheTimelineData();
                }
            };
        }
    }

    /// <summary>
    /// Cache timeline series data for fast tooltip rendering
    /// </summary>
    private void CacheTimelineData()
    {
        var startTime = DateTime.Now;
        var timestamp = startTime.ToString("HH:mm:ss.fff");
        DebugLogger.Log($"[{timestamp}] [VoiceQoSView] CacheTimelineData - BEGIN");

        try
        {
            _cachedTimelineData.Clear();
            _cachedMinY = double.MaxValue;
            _cachedMaxY = double.MinValue;

            if (DataContext is not VoiceQoSViewModel vm || vm.ChartsViewModel.TimelineSeries == null)
            {
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [VoiceQoSView] CacheTimelineData - No data to cache");
                return;
            }

            foreach (var series in vm.ChartsViewModel.TimelineSeries)
            {
                if (series is LineSeries<DateTimePoint> lineSeries &&
                    lineSeries.Values != null &&
                    !string.IsNullOrEmpty(lineSeries.Name))
                {
                    var points = lineSeries.Values.Cast<DateTimePoint>().ToList();
                    _cachedTimelineData[lineSeries.Name] = points;

                    // Calculate min/max for vertical line height
                    foreach (var point in points)
                    {
                        if (point.Value.HasValue)
                        {
                            _cachedMinY = Math.Min(_cachedMinY, point.Value.Value);
                            _cachedMaxY = Math.Max(_cachedMaxY, point.Value.Value);
                        }
                    }
                }
            }

            var elapsed = (DateTime.Now - startTime).TotalMilliseconds;
            var timestamp2 = DateTime.Now.ToString("HH:mm:ss.fff");
            DebugLogger.Log($"[{timestamp2}] [VoiceQoSView] Cached {_cachedTimelineData.Count} series, Y range: {_cachedMinY:F2} - {_cachedMaxY:F2} in {elapsed:F0}ms");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSView] Error caching data: {ex.Message}");
        }
    }

    /// <summary>
    /// Handle mouse movement over Timeline chart
    /// </summary>
    private void OnTimelineChartPointerMoved(object? sender, PointerEventArgs e)
    {
        try
        {
            var chart = sender as CartesianChart;
            var tooltipText = this.FindControl<TextBlock>("TimelineTooltipText");

            if (chart == null || tooltipText == null)
            {
                DebugLogger.Log("[VoiceQoSView] Timeline chart or tooltip not found");
                return;
            }

            var position = e.GetPosition(chart);

            // Get the actual plot area bounds from LiveCharts Core (accurate drawable area)
            var drawMargin = chart.CoreChart.DrawMarginLocation;
            var drawSize = chart.CoreChart.DrawMarginSize;

            // Use actual drawable area if available, otherwise fall back to approximation
            double plotAreaLeft = drawMargin.X > 0 ? drawMargin.X : 50;
            double plotAreaWidth = drawSize.Width > 0 ? drawSize.Width : chart.Bounds.Width - 70;

            var adjustedX = position.X - plotAreaLeft;

            // Calculate relative X position (0 to 1)
            var relativeX = Math.Max(0, Math.Min(1, adjustedX / plotAreaWidth));

            // Get data from cached series
            if (_cachedTimelineData.Count == 0)
            {
                CacheTimelineData();
            }

            if (_cachedTimelineData.Count == 0)
            {
                tooltipText.Inlines?.Clear();
                tooltipText.Text = "";
                return;
            }

            // Find data index based on first available series
            var firstSeries = _cachedTimelineData.Values.FirstOrDefault();
            if (firstSeries == null || firstSeries.Count == 0)
            {
                tooltipText.Inlines?.Clear();
                tooltipText.Text = "";
                return;
            }

            var dataIndex = (int)(relativeX * (firstSeries.Count - 1));
            dataIndex = Math.Max(0, Math.Min(firstSeries.Count - 1, dataIndex));

            // Extract values for all 7 series at this index
            var timestamp = firstSeries[dataIndex].DateTime;
            var values = new Dictionary<string, double>();

            foreach (var kvp in _cachedTimelineData)
            {
                if (dataIndex < kvp.Value.Count)
                {
                    var value = kvp.Value[dataIndex].Value ?? 0;
                    values[kvp.Key] = value;
                }
            }

            // Build colored tooltip
            tooltipText.Inlines?.Clear();

            // Time prefix (white)
            tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"🕐 {timestamp:HH:mm:ss}  •  ")
            {
                Foreground = new SolidColorBrush(Color.Parse("#F0F6FC"))
            });

            // Add each series value with its color
            var seriesOrder = new[] { "QoS Packets", "Latency Min", "Latency P5", "Latency Avg", "Latency P95", "Latency Max",
                                     "Jitter Min", "Jitter P5", "Jitter Avg", "Jitter P95", "Jitter Max" };

            bool first = true;
            foreach (var seriesName in seriesOrder)
            {
                if (values.TryGetValue(seriesName, out var value))
                {
                    if (!first)
                    {
                        tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run("  •  ")
                        {
                            Foreground = new SolidColorBrush(Color.Parse("#F0F6FC"))
                        });
                    }
                    first = false;

                    var colorHex = SeriesColors[seriesName];
                    var emoji = seriesName == "QoS Packets" ? "📊" :
                               seriesName.Contains("Latency", StringComparison.Ordinal) ? "⏱️" : "📡";

                    var formatString = seriesName == "QoS Packets" ? $"{emoji} {value:N0}" : $"{emoji} {value:F2}ms";

                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run(formatString)
                    {
                        Foreground = new SolidColorBrush(Color.Parse(colorHex)),
                        FontWeight = FontWeight.Bold
                    });
                }
            }

            tooltipText.FontWeight = FontWeight.Medium;

            // Add highlight with vertical line
            AddHighlightWithLine(chart, dataIndex, timestamp, values.Values.ToArray());
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSView] OnTimelineChartPointerMoved error: {ex.Message}");
        }
    }

    /// <summary>
    /// Handle mouse exit from Timeline chart
    /// </summary>
    private void OnTimelineChartPointerExited(object? sender, PointerEventArgs e)
    {
        try
        {
            var tooltipText = this.FindControl<TextBlock>("TimelineTooltipText");
            if (tooltipText != null)
            {
                tooltipText.Inlines?.Clear();
                tooltipText.Text = "";
            }
            RemoveHighlight(sender as CartesianChart);
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSView] OnTimelineChartPointerExited error: {ex.Message}");
        }
    }

    /// <summary>
    /// Add highlight scatter point and vertical line at mouse position
    /// </summary>
    private void AddHighlightWithLine(CartesianChart chart, int dataIndex, DateTime timestamp, double[] values)
    {
        try
        {
            if (chart == null || DataContext is not VoiceQoSViewModel vm)
                return;

            // Don't add duplicate highlight at same position
            if (_lastHighlightedIndex == dataIndex)
                return;

            _lastHighlightedIndex = dataIndex;

            // Remove existing highlight
            RemoveHighlight(chart);

            // Find the highest value for scatter point positioning
            var maxValue = values.Length > 0 ? values.Max() : 0;

            // Create scatter point at data location
            _highlightScatter = new ScatterSeries<DateTimePoint>
            {
                Values = new[] { new DateTimePoint(timestamp, maxValue) },
                Name = "Highlight",
                GeometrySize = 12,
                Fill = new SolidColorPaint(SKColors.White.WithAlpha(200)),
                Stroke = new SolidColorPaint(SKColors.Black) { StrokeThickness = 2f },
                ScalesYAt = 1 // Right Y-axis
            };

            // Create vertical line from min to max Y
            _highlightLine = new LineSeries<DateTimePoint>
            {
                Values = new[]
                {
                    new DateTimePoint(timestamp, _cachedMinY),
                    new DateTimePoint(timestamp, _cachedMaxY)
                },
                Name = "VerticalLine",
                GeometrySize = 0, // No points
                LineSmoothness = 0, // Straight line
                Stroke = new SolidColorPaint(SKColors.White.WithAlpha(100)) { StrokeThickness = 1.5f },
                Fill = null,
                ScalesYAt = 1 // Right Y-axis
            };

            // Add to chart
            var series = vm.ChartsViewModel.TimelineSeries;
            if (series != null)
            {
                series.Add(_highlightScatter);
                series.Add(_highlightLine);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSView] Error adding highlight: {ex.Message}");
        }
    }

    /// <summary>
    /// Remove highlight series from chart
    /// </summary>
    private void RemoveHighlight(CartesianChart? chart)
    {
        try
        {
            if (DataContext is not VoiceQoSViewModel vm)
                return;

            _lastHighlightedIndex = -1;

            var series = vm.ChartsViewModel.TimelineSeries;
            if (series == null)
                return;

            // Remove scatter
            if (_highlightScatter != null)
            {
                series.Remove(_highlightScatter);
                _highlightScatter = null;
            }

            // Remove line
            if (_highlightLine != null)
            {
                series.Remove(_highlightLine);
                _highlightLine = null;
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSView] Error removing highlight: {ex.Message}");
        }
    }

    // PAGINATION EVENT HANDLERS - QoS Traffic
    private void QosPageSize30_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.QosTrafficSetPageSize(30);
    }

    private void QosPageSize100_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.QosTrafficSetPageSize(100);
    }

    private void QosFirstPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.QosTrafficFirstPage();
    }

    private void QosLastPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.QosTrafficLastPage();
    }

    private void QosPrevPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.QosTrafficPreviousPage();
    }

    private void QosNextPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.QosTrafficNextPage();
    }

    private void QosJumpBack10_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.QosTrafficJumpBackward10();
    }

    private void QosJumpForward10_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.QosTrafficJumpForward10();
    }

    // PAGINATION EVENT HANDLERS - High Latency
    private void LatencyPageSize30_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.LatencySetPageSize(30);
    }

    private void LatencyPageSize100_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.LatencySetPageSize(100);
    }

    private void LatencyFirstPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.LatencyFirstPage();
    }

    private void LatencyLastPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.LatencyLastPage();
    }

    private void LatencyPrevPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.LatencyPreviousPage();
    }

    private void LatencyNextPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.LatencyNextPage();
    }

    private void LatencyJumpBack10_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.LatencyJumpBackward10();
    }

    private void LatencyJumpForward10_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.LatencyJumpForward10();
    }

    // PAGINATION EVENT HANDLERS - High Jitter
    private void JitterPageSize30_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.JitterSetPageSize(30);
    }

    private void JitterPageSize100_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.JitterSetPageSize(100);
    }

    private void JitterFirstPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.JitterFirstPage();
    }

    private void JitterLastPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.JitterLastPage();
    }

    private void JitterPrevPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.JitterPreviousPage();
    }

    private void JitterNextPage_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.JitterNextPage();
    }

    private void JitterJumpBack10_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.JitterJumpBackward10();
    }

    private void JitterJumpForward10_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is VoiceQoSViewModel vm)
            vm.JitterJumpForward10();
    }

    /// <summary>
    /// Handles filter copy button click - copies CommonFilters to selected destination tab
    /// </summary>
    private void OnFilterCopyClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            var filterCopyService = App.Services?.GetService<FilterCopyService>();
            if (filterCopyService == null)
            {
                DebugLogger.Log("[VoiceQoSView] FilterCopyService not available");
                return;
            }

            var comboBox = this.FindControl<ComboBox>("FilterCopyDestination");
            if (comboBox?.SelectedItem is ComboBoxItem selectedItem)
            {
                var destinationTabName = selectedItem.Content?.ToString();
                if (string.IsNullOrEmpty(destinationTabName))
                {
                    DebugLogger.Log("[VoiceQoSView] No destination tab selected");
                    return;
                }

                var success = filterCopyService.CopyFilters(TabNames.VoiceQoS, destinationTabName);

                if (success)
                {
                    DebugLogger.Log($"[VoiceQoSView] Successfully copied filters to {destinationTabName}");
                }
                else
                {
                    DebugLogger.Log($"[VoiceQoSView] Failed to copy filters to {destinationTabName}");
                }
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSView] OnFilterCopyClick error: {ex.Message}");
        }
    }
}
