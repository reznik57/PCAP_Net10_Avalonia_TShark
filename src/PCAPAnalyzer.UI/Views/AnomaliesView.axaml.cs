using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Input;
using Avalonia.Media;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Avalonia;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views;

public partial class AnomaliesView : UserControl
{
    // Severity colors matching the chart lines
    private static readonly SolidColorBrush CriticalColor = new(Color.Parse("#F85149"));
    private static readonly SolidColorBrush HighColor = new(Color.Parse("#F59E0B"));
    private static readonly SolidColorBrush MediumColor = new(Color.Parse("#FCD34D"));
    private static readonly SolidColorBrush LowColor = new(Color.Parse("#3B82F6"));
    private static readonly SolidColorBrush DefaultColor = new(Color.Parse("#F0F6FC"));

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
        if (sender is not CartesianChart chart || ViewModel?.Charts?.TimelineSeries == null)
            return;

        try
        {
            var relativeX = CalculateRelativeX(chart, e);
            var (timestamp, critical, high, medium, low) = ExtractChartData(relativeX);

            if (timestamp.HasValue)
                BuildColoredTooltip(timestamp.Value, critical, high, medium, low);
            else
                ResetTooltip();
        }
        catch
        {
            ResetTooltip();
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

    private (DateTime? timestamp, double critical, double high, double medium, double low) ExtractChartData(double relativeX)
    {
        DateTime? timestamp = null;
        double critical = 0, high = 0, medium = 0, low = 0;

        foreach (var s in ViewModel!.Charts!.TimelineSeries!)
        {
            if (s is not LineSeries<DateTimePoint> dateTimeSeries || dateTimeSeries.Values == null)
                continue;

            var values = dateTimeSeries.Values.ToList();
            if (values.Count == 0) continue;

            var dataIndex = Math.Clamp((int)(relativeX * (values.Count - 1)), 0, values.Count - 1);
            var point = values[dataIndex];

            timestamp ??= point.DateTime;
            var value = point.Value ?? 0;

            (critical, high, medium, low) = MapSeriesValue(dateTimeSeries.Name ?? "", value, critical, high, medium, low);
        }

        return (timestamp, critical, high, medium, low);
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
    }
}
