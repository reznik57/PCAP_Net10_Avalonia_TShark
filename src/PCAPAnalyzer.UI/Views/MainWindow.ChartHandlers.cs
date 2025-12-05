using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.Defaults;
using SkiaSharp;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Views;

/// <summary>
/// MainWindow.ChartHandlers - Chart event handlers partial class
/// </summary>
/// <remarks>
/// This partial class contains all chart-related event handlers for the Packets Over Time chart:
/// - Pointer moved (hover) with colored tooltip
/// - Pointer exited (clear highlights)
/// - Pointer pressed (click for popup)
/// - Highlight series management (scatter + vertical line)
/// </remarks>
public partial class MainWindow
{
    // Highlight series for Packets Over Time chart
    private ScatterSeries<ObservablePoint>? _packetsHighlightScatter;
    private LineSeries<ObservablePoint>? _packetsHighlightLine;
    private int _lastPacketsHighlightIndex = -1;

    // Stream colors (must match MainWindowChartsViewModel.StreamColors) - lazy initialized for theme support
    private static string[]? _streamColorsCache;
    private static string[] StreamColors => _streamColorsCache ??= new[] {
        ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6"),
        ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"),
        ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B"),
        ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444"),
        ThemeColorHelper.GetColorHex("AccentPurple", "#8B5CF6")
    };

    /// <summary>
    /// Resets highlight series references when the chart series collection is rebuilt.
    /// Must be called when PacketsOverTimeSeries is replaced (e.g., after toggle changes).
    /// </summary>
    public void ResetPacketsChartHighlight()
    {
        _packetsHighlightScatter = null;
        _packetsHighlightLine = null;
        _lastPacketsHighlightIndex = -1;
        DebugLogger.Log("[MainWindow] Packets chart highlight reset (series collection rebuilt)");
    }

    /// <summary>
    /// Event handler for Packets Over Time chart PointerMoved (called from XAML)
    /// </summary>
    private void OnPacketsChartPointerMoved(object? sender, PointerEventArgs e)
    {
        try
        {
            var chart = sender as CartesianChart;
            var tooltipText = this.FindControl<TextBlock>("PacketsOverTimeTooltipText");

            if (chart == null || tooltipText == null || DataContext is not MainWindowViewModel vm)
            {
                return;
            }

            OnPacketsChartPointerMovedInternal(chart, tooltipText, vm, e);
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] OnPacketsChartPointerMoved error: {ex.Message}");
        }
    }

    /// <summary>
    /// Event handler for Packets Over Time chart PointerExited (called from XAML)
    /// </summary>
    private void OnPacketsChartPointerExited(object? sender, PointerEventArgs e)
    {
        try
        {
            var tooltipText = this.FindControl<TextBlock>("PacketsOverTimeTooltipText");
            if (tooltipText != null)
            {
                tooltipText.Inlines?.Clear();
                tooltipText.Text = "";
            }
            RemovePacketsHighlight(sender as CartesianChart);
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] OnPacketsChartPointerExited error: {ex.Message}");
        }
    }

    /// <summary>
    /// Event handler for Packets Over Time chart PointerPressed (click for popup)
    /// </summary>
    private void OnPacketsChartPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        try
        {
            if (DataContext is not MainWindowViewModel vm)
                return;

            var chart = sender as CartesianChart;
            if (chart == null)
                return;

            var position = e.GetPosition(chart);

            // Get the actual plot area bounds from LiveCharts Core (accurate drawable area)
            var drawMargin = chart.CoreChart.DrawMarginLocation;
            var drawSize = chart.CoreChart.DrawMarginSize;

            // Use actual drawable area if available, otherwise fall back to approximation
            double plotAreaLeft = drawMargin.X > 0 ? drawMargin.X : 50;
            double plotAreaWidth = drawSize.Width > 0 ? drawSize.Width : chart.Bounds.Width - 70;

            var adjustedX = position.X - plotAreaLeft;
            var relativeX = Math.Max(0, Math.Min(1, adjustedX / plotAreaWidth));

            // Get data at this position
            var dataIndex = vm.Charts.GetDataIndexForRelativeX(relativeX);
            var dataPoint = vm.Charts.GetDataPointAtIndex(dataIndex);

            if (dataPoint != null)
            {
                // Show popup with detailed information
                ShowPacketsChartPopup(dataPoint, vm.Charts.TopStreams);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] OnPacketsChartPointerPressed error: {ex.Message}");
        }
    }

    /// <summary>
    /// Internal handler for Packets Over Time chart pointer movement with tooltip logic
    /// </summary>
    private void OnPacketsChartPointerMovedInternal(CartesianChart chart, TextBlock tooltipText, MainWindowViewModel vm, PointerEventArgs e)
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

            // Get data at this position
            var dataIndex = vm.Charts.GetDataIndexForRelativeX(relativeX);
            var dataPoint = vm.Charts.GetDataPointAtIndex(dataIndex);

            if (dataPoint != null)
            {
                // Build colored tooltip
                tooltipText.Inlines?.Clear();

                // Time prefix (white)
                tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"🕐 {dataPoint.Time:HH:mm:ss}  •  ")
                {
                    Foreground = new Avalonia.Media.SolidColorBrush(ThemeColorHelper.GetColor("TextPrimary", "#F0F6FC"))
                });

                // Total packets (blue)
                tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"📦 Total: {dataPoint.TotalCount:N0}")
                {
                    Foreground = new Avalonia.Media.SolidColorBrush(ThemeColorHelper.GetColor("AccentBlue", "#58A6FF")),
                    FontWeight = Avalonia.Media.FontWeight.Bold
                });

                // Top streams with their colors
                var topStreams = vm.Charts.TopStreams;
                for (int i = 0; i < topStreams.Count && i < StreamColors.Length; i++)
                {
                    var stream = topStreams[i];
                    dataPoint.StreamCounts.TryGetValue(stream.StreamKey, out var streamCount);

                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run("  •  ")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(ThemeColorHelper.GetColor("TextPrimary", "#F0F6FC"))
                    });

                    var colorHex = StreamColors[i];
                    var streamLabel = TruncateIP(stream.SourceIP, 12) + "→" + TruncateIP(stream.DestIP, 12);
                    tooltipText.Inlines?.Add(new Avalonia.Controls.Documents.Run($"🔗 {streamLabel}: {streamCount:N0}")
                    {
                        Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse(colorHex)),
                        FontWeight = Avalonia.Media.FontWeight.Bold
                    });
                }

                tooltipText.FontWeight = Avalonia.Media.FontWeight.Medium;

                // Add visual highlight
                AddPacketsHighlight(chart, vm, dataIndex, dataPoint);
            }
            else
            {
                tooltipText.Inlines?.Clear();
                tooltipText.Text = "";
                RemovePacketsHighlight(chart);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] OnPacketsChartPointerMovedInternal error: {ex.Message}");
            tooltipText.Text = "Error reading data";
        }
    }

    /// <summary>
    /// Adds highlight to the Packets Over Time chart
    /// </summary>
    private void AddPacketsHighlight(CartesianChart chart, MainWindowViewModel vm, int index, PacketsTimelineDataPoint dataPoint)
    {
        try
        {
            var (minY, maxY) = vm.Charts.CachedYRange;
            if (Math.Abs(maxY - minY) < 0.0001)
            {
                maxY = minY + 1;
            }

            var timestamp = dataPoint.Time;
            var value = dataPoint.TotalCount;

            // Create or update scatter series for highlight dot
            if (_packetsHighlightScatter == null)
            {
                _packetsHighlightScatter = new ScatterSeries<ObservablePoint>
                {
                    Values = new ObservableCollection<ObservablePoint> { new(timestamp.Ticks, value) },
                    GeometrySize = 12,
                    Fill = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("AccentGold", "#FFD700"))),
                    Stroke = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("AccentOrange", "#FFA500"))) { StrokeThickness = 2 },
                    Name = "Highlight",
                    IsVisibleAtLegend = false,
                    ZIndex = 1000,
                    DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                    IsHoverable = false
                };
                vm.Charts.PacketsOverTimeSeries?.Add(_packetsHighlightScatter);
            }

            UpdateObservablePoint(_packetsHighlightScatter, timestamp.Ticks, value);

            // Create or update line series for vertical line (thick yellow marker like Dashboard)
            if (_packetsHighlightLine == null)
            {
                _packetsHighlightLine = new LineSeries<ObservablePoint>
                {
                    Values = new ObservableCollection<ObservablePoint>
                    {
                        new(timestamp.Ticks, minY),
                        new(timestamp.Ticks, maxY)
                    },
                    Stroke = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("AccentGold", "#FFD700"))) { StrokeThickness = 4f },  // Thick like Dashboard
                    Fill = null,
                    GeometrySize = 0,
                    LineSmoothness = 0,
                    Name = "VerticalLine",
                    IsVisibleAtLegend = false,
                    ZIndex = 999,
                    DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                    IsHoverable = false
                };
                vm.Charts.PacketsOverTimeSeries?.Add(_packetsHighlightLine);
            }

            UpdateObservableLine(_packetsHighlightLine, timestamp.Ticks, minY, maxY);

            SetSeriesVisibility(_packetsHighlightScatter, true);
            SetSeriesVisibility(_packetsHighlightLine, true);

            _lastPacketsHighlightIndex = index;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] AddPacketsHighlight error: {ex.Message}");
        }
    }

    /// <summary>
    /// Removes highlight from the Packets Over Time chart
    /// </summary>
    private void RemovePacketsHighlight(CartesianChart? chart)
    {
        try
        {
            SetSeriesVisibility(_packetsHighlightScatter, false);
            SetSeriesVisibility(_packetsHighlightLine, false);
            _lastPacketsHighlightIndex = -1;
            chart?.CoreChart?.Update();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] RemovePacketsHighlight error: {ex.Message}");
        }
    }

    /// <summary>
    /// Shows popup with detailed chart data
    /// </summary>
    private void ShowPacketsChartPopup(PacketsTimelineDataPoint dataPoint, IReadOnlyList<StreamInfo> topStreams)
    {
        if (DataContext is not MainWindowViewModel vm)
            return;

        // Call the ViewModel's ShowStreamPopup method
        vm.Charts.ShowStreamPopup(dataPoint);
    }

    /// <summary>
    /// Event handler for clicking the popup background (closes stream popup)
    /// </summary>
    private void OnStreamPopupBackgroundPressed(object? sender, PointerPressedEventArgs e)
    {
        try
        {
            if (DataContext is MainWindowViewModel vm)
            {
                vm.Charts.IsStreamPopupOpen = false;
                vm.Charts.StreamPopupViewModel = null;
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] OnStreamPopupBackgroundPressed error: {ex.Message}");
        }
    }

    /// <summary>
    /// Truncates an IP address for display
    /// </summary>
    private static string TruncateIP(string ip, int maxLength)
    {
        if (string.IsNullOrEmpty(ip) || ip.Length <= maxLength)
            return ip;
        return ip[..(maxLength - 2)] + "..";
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
    /// Updates a scatter series point for ObservablePoint data
    /// </summary>
    private static void UpdateObservablePoint(ScatterSeries<ObservablePoint> series, long ticks, double value)
    {
        if (series.Values is IList<ObservablePoint> list)
        {
            if (list.Count == 0)
            {
                list.Add(new ObservablePoint(ticks, value));
            }
            else
            {
                list[0] = new ObservablePoint(ticks, value);
            }
        }
        else
        {
            series.Values = new ObservableCollection<ObservablePoint> { new ObservablePoint(ticks, value) };
        }
    }

    /// <summary>
    /// Updates a line series points for vertical line (ObservablePoint data)
    /// </summary>
    private static void UpdateObservableLine(LineSeries<ObservablePoint> series, long ticks, double minY, double maxY)
    {
        if (series.Values is IList<ObservablePoint> list)
        {
            if (list.Count < 2)
            {
                list.Clear();
                list.Add(new ObservablePoint(ticks, minY));
                list.Add(new ObservablePoint(ticks, maxY));
            }
            else
            {
                list[0] = new ObservablePoint(ticks, minY);
                list[1] = new ObservablePoint(ticks, maxY);
            }
        }
        else
        {
            series.Values = new ObservableCollection<ObservablePoint>
            {
                new ObservablePoint(ticks, minY),
                new ObservablePoint(ticks, maxY)
            };
        }
    }
}
