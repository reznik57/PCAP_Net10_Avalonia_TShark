using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Input;
using Avalonia.Media;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Constants;
using PCAPAnalyzer.UI.Utilities;
using PCAPAnalyzer.UI.ViewModels;
using SkiaSharp;

namespace PCAPAnalyzer.UI.Views;

public partial class AnomaliesView : UserControl
{
    // Severity colors - resolved from theme via ThemeColorHelper
    private static SolidColorBrush CriticalColor => ThemeColorHelper.CriticalBrush;
    private static SolidColorBrush HighColor => ThemeColorHelper.HighBrush;
    private static SolidColorBrush MediumColor => ThemeColorHelper.MediumBrush;
    private static SolidColorBrush LowColor => ThemeColorHelper.LowBrush;
    private static SolidColorBrush DefaultColor => ThemeColorHelper.DefaultTextBrush;

    // Highlight series for vertical line indicator
    private ScatterSeries<DateTimePoint>? _highlightScatter;
    private LineSeries<DateTimePoint>? _highlightLine;
    private int _lastHighlightedIndex = -1;

    // Cached Y-axis range for vertical line
    private double _cachedMinY;
    private double _cachedMaxY = 100;

    // Cached chart data to avoid ToList() allocation on every mouse move
    private Dictionary<string, IReadOnlyList<DateTimePoint>>? _cachedChartData;
    private int _cachedDataVersion;

    public AnomaliesView()
    {
        InitializeComponent();
    }

    private AnomaliesViewModel? ViewModel => DataContext as AnomaliesViewModel;

    // Zoom button handlers
    private void OnAnomalyZoomIn(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (ViewModel?.Charts?.TimelineXAxes is { Length: > 0 } axes)
        {
            var axis = axes[0];
            var minLimit = axis.MinLimit ?? 0;
            var maxLimit = axis.MaxLimit ?? 1;
            var range = maxLimit - minLimit;
            var center = (minLimit + maxLimit) / 2;
            var newRange = range * 0.7; // Zoom in by 30%
            axis.MinLimit = center - newRange / 2;
            axis.MaxLimit = center + newRange / 2;
        }
    }

    private void OnAnomalyZoomOut(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (ViewModel?.Charts?.TimelineXAxes is { Length: > 0 } axes)
        {
            var axis = axes[0];
            var minLimit = axis.MinLimit ?? 0;
            var maxLimit = axis.MaxLimit ?? 1;
            var range = maxLimit - minLimit;
            var center = (minLimit + maxLimit) / 2;
            var newRange = range * 1.4; // Zoom out by 40%
            axis.MinLimit = center - newRange / 2;
            axis.MaxLimit = center + newRange / 2;
        }
    }

    private void OnAnomalyZoomReset(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (ViewModel?.Charts?.TimelineXAxes is { Length: > 0 } axes)
        {
            var axis = axes[0];
            axis.MinLimit = null;
            axis.MaxLimit = null;
        }
        ViewModel?.Charts?.ResetZoom();
    }

    // Chart pointer event handlers for tooltip with colored text matching line colors
    private void OnAnomalyChartPointerMoved(object? sender, PointerEventArgs e)
    {
        if (sender is not CartesianChart chart || ViewModel?.Charts?.TimelineSeries is null)
            return;

        try
        {
            var relativeX = CalculateRelativeX(chart, e);
            var (timestamp, critical, high, medium, low, dataIndex) = ExtractChartDataWithIndex(relativeX);

            if (timestamp.HasValue)
            {
                BuildColoredTooltip(timestamp.Value, critical, high, medium, low);

                // Add yellow highlight with vertical line
                var maxValue = Math.Max(Math.Max(critical, high), Math.Max(medium, low));
                AddHighlightWithLine(chart, dataIndex, timestamp.Value, maxValue);
            }
            else
            {
                ResetTooltip();
                RemoveHighlight(chart);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AnomaliesView] OnAnomalyChartPointerMoved error: {ex.Message}");
            ResetTooltip();
            RemoveHighlight(sender as CartesianChart);
        }
    }

    private double CalculateRelativeX(CartesianChart chart, PointerEventArgs e)
    {
        var position = e.GetPosition(chart);
        var drawMargin = chart.CoreChart.DrawMarginLocation;
        var drawSize = chart.CoreChart.DrawMarginSize;

        double plotAreaLeft = drawMargin.X > 0 ? drawMargin.X : 50;
        double plotAreaWidth = drawSize.Width > 0 ? drawSize.Width : chart.Bounds.Width - 70;

        var adjustedX = position.X - plotAreaLeft;
        return Math.Max(0, Math.Min(1, adjustedX / plotAreaWidth));
    }

    private (DateTime? timestamp, double critical, double high, double medium, double low, int dataIndex) ExtractChartDataWithIndex(double relativeX)
    {
        DateTime? timestamp = null;
        double critical = 0, high = 0, medium = 0, low = 0;
        int resultIndex = -1;

        // Rebuild cache if series changed (check version from Charts ViewModel)
        var series = ViewModel!.Charts!.TimelineSeries;
        var currentVersion = series?.Length ?? 0;
        if (_cachedChartData is null || _cachedDataVersion != currentVersion)
        {
            _cachedChartData = new Dictionary<string, IReadOnlyList<DateTimePoint>>();
            if (series is not null)
            {
                foreach (var s in series)
                {
                    if (s.Name is "Highlight" or "VerticalLine")
                        continue;
                    if (s is LineSeries<DateTimePoint> dateTimeSeries && dateTimeSeries.Values is not null)
                        _cachedChartData[s.Name ?? ""] = dateTimeSeries.Values.ToList();
                }
            }
            _cachedDataVersion = currentVersion;
        }

        foreach (var kvp in _cachedChartData)
        {
            var values = kvp.Value;
            if (values.Count == 0) continue;

            var dataIndex = Math.Clamp((int)(relativeX * (values.Count - 1)), 0, values.Count - 1);
            var point = values[dataIndex];

            timestamp ??= point.DateTime;
            resultIndex = dataIndex;
            var value = point.Value ?? 0;

            // Update cached Y-axis max for vertical line
            _cachedMaxY = Math.Max(_cachedMaxY, value * 1.1);

            (critical, high, medium, low) = MapSeriesValue(kvp.Key, value, critical, high, medium, low);
        }

        return (timestamp, critical, high, medium, low, resultIndex);
    }

    private static (double critical, double high, double medium, double low) MapSeriesValue(
        string name, double value, double critical, double high, double medium, double low)
    {
        if (name.Contains("Critical", StringComparison.OrdinalIgnoreCase)) return (value, high, medium, low);
        if (name.Contains("High", StringComparison.OrdinalIgnoreCase)) return (critical, value, medium, low);
        if (name.Contains("Medium", StringComparison.OrdinalIgnoreCase)) return (critical, high, value, low);
        if (name.Contains("Low", StringComparison.OrdinalIgnoreCase)) return (critical, high, medium, value);
        return (critical, high, medium, low);
    }

    private void BuildColoredTooltip(DateTime timestamp, double critical, double high, double medium, double low)
    {
        AnomalyTooltipText.Inlines?.Clear();
        AddTooltipRun($"{timestamp:HH:mm:ss}  |  ", DefaultColor, false);
        AddTooltipRun($"Critical: {critical:N0}", CriticalColor, true);
        AddTooltipRun("  |  ", DefaultColor, false);
        AddTooltipRun($"High: {high:N0}", HighColor, true);
        AddTooltipRun("  |  ", DefaultColor, false);
        AddTooltipRun($"Medium: {medium:N0}", MediumColor, true);
        AddTooltipRun("  |  ", DefaultColor, false);
        AddTooltipRun($"Low: {low:N0}", LowColor, true);
    }

    private void AddTooltipRun(string text, IBrush color, bool bold)
    {
        AnomalyTooltipText.Inlines?.Add(new Run(text)
        {
            Foreground = color,
            FontWeight = bold ? FontWeight.Bold : FontWeight.Normal
        });
    }

    private void ResetTooltip()
    {
        AnomalyTooltipText.Inlines?.Clear();
        AnomalyTooltipText.Text = "Hover over chart for details";
    }

    private void OnAnomalyChartPointerExited(object? sender, PointerEventArgs e)
    {
        AnomalyTooltipText.Inlines?.Clear();
        AnomalyTooltipText.Text = "Hover over chart for details";
        RemoveHighlight(sender as CartesianChart);
    }

    // ==================== HIGHLIGHT MANAGEMENT ====================

    /// <summary>
    /// Adds yellow highlight dot and vertical line to indicate current data point
    /// </summary>
    private void AddHighlightWithLine(CartesianChart chart, int index, DateTime timestamp, double maxValue)
    {
        try
        {
            if (ViewModel?.Charts?.TimelineSeriesCollection is null)
                return;

            // Ensure valid Y range for vertical line
            _cachedMinY = 0;
            if (Math.Abs(_cachedMaxY - _cachedMinY) < ChartConstants.MinYRange)
                _cachedMaxY = _cachedMinY + 1;

            // Create or update scatter series for highlight dot
            if (_highlightScatter is null)
            {
                _highlightScatter = new ScatterSeries<DateTimePoint>
                {
                    Values = new ObservableCollection<DateTimePoint> { new(timestamp, maxValue) },
                    GeometrySize = ChartConstants.HighlightDotSize,
                    Fill = ChartConstants.HighlightFillPaint,
                    Stroke = ChartConstants.HighlightStrokePaint,
                    Name = "Highlight",
                    IsVisibleAtLegend = false,
                    ZIndex = ChartConstants.HighlightScatterZIndex,
                    DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                    IsHoverable = false
                };
                ViewModel.Charts.TimelineSeriesCollection.Add(_highlightScatter);
            }
            UpdateScatterPoint(_highlightScatter, timestamp, maxValue);

            // Create or update line series for vertical line
            if (_highlightLine is null)
            {
                _highlightLine = new LineSeries<DateTimePoint>
                {
                    Values = new ObservableCollection<DateTimePoint>
                    {
                        new(timestamp, _cachedMinY),
                        new(timestamp, _cachedMaxY)
                    },
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
                ViewModel.Charts.TimelineSeriesCollection.Add(_highlightLine);
            }
            UpdateLinePoints(_highlightLine, timestamp, _cachedMinY, _cachedMaxY);

            SetSeriesVisibility(_highlightScatter, true);
            SetSeriesVisibility(_highlightLine, true);
            _lastHighlightedIndex = index;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AnomaliesView] AddHighlightWithLine error: {ex.Message}");
        }
    }

    /// <summary>
    /// Removes highlight from the chart
    /// </summary>
    private void RemoveHighlight(CartesianChart? chart)
    {
        try
        {
            SetSeriesVisibility(_highlightScatter, false);
            SetSeriesVisibility(_highlightLine, false);
            _lastHighlightedIndex = -1;
            chart?.CoreChart?.Update();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AnomaliesView] RemoveHighlight error: {ex.Message}");
        }
    }

    private static void SetSeriesVisibility(ISeries? series, bool visible)
    {
        if (series is not null)
            series.IsVisible = visible;
    }

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

    // ==================== CHART CLICK HANDLER ====================

    /// <summary>
    /// Handle click on anomaly timeline chart - opens time-point details popup
    /// </summary>
    private void OnAnomalyChartPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        try
        {
            if (sender is not CartesianChart chart || ViewModel is null)
                return;

            var relativeX = CalculateRelativeX(chart, e);
            var (timestamp, critical, high, medium, low, _) = ExtractChartDataWithIndex(relativeX);

            if (timestamp.HasValue)
            {
                DebugLogger.Log($"[AnomaliesView] Chart clicked at time: {timestamp.Value:HH:mm:ss}");
                ViewModel.ShowTimePointDetailsCommand.Execute(timestamp.Value);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AnomaliesView] OnAnomalyChartPointerPressed error: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up highlight series when chart data is refreshed
    /// </summary>
    public void CleanupHighlightSeries()
    {
        try
        {
            if (ViewModel?.Charts?.TimelineSeriesCollection is null)
                return;

            if (_highlightScatter is not null && ViewModel.Charts.TimelineSeriesCollection.Contains(_highlightScatter))
                ViewModel.Charts.TimelineSeriesCollection.Remove(_highlightScatter);

            if (_highlightLine is not null && ViewModel.Charts.TimelineSeriesCollection.Contains(_highlightLine))
                ViewModel.Charts.TimelineSeriesCollection.Remove(_highlightLine);

            _highlightScatter = null;
            _highlightLine = null;
            _lastHighlightedIndex = -1;
            _cachedMaxY = 100;

            // Invalidate chart data cache to force rebuild on next hover
            _cachedChartData = null;
            _cachedDataVersion = 0;

            DebugLogger.Log("[AnomaliesView] Highlight series cleaned up");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AnomaliesView] CleanupHighlightSeries error: {ex.Message}");
        }
    }

    // ==================== ANOMALY PACKET TABLE ====================

    /// <summary>
    /// Handle click on anomaly packet row - selects the packet
    /// </summary>
    private void AnomalyPacketRow_PointerPressed(object? sender, PointerPressedEventArgs e)
    {
        try
        {
            if (ViewModel?.PacketTable is null)
                return;

            // Get the AnomalyPacketViewModel from the row's DataContext
            object? dataContext = sender switch
            {
                Border border => border.DataContext,
                Grid grid => grid.DataContext,
                _ => null
            };

            if (dataContext is Models.AnomalyPacketViewModel packet)
            {
                ViewModel.PacketTable.SelectPacketCommand.Execute(packet);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AnomaliesView] AnomalyPacketRow_PointerPressed error: {ex.Message}");
        }
    }
}
