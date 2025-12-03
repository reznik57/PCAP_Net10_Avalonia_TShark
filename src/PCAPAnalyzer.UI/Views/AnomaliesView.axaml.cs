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
            var position = e.GetPosition(chart);

            // Get the actual plot area bounds from LiveCharts Core
            var drawMargin = chart.CoreChart.DrawMarginLocation;
            var drawSize = chart.CoreChart.DrawMarginSize;

            double plotAreaLeft = drawMargin.X > 0 ? drawMargin.X : 50;
            double plotAreaWidth = drawSize.Width > 0 ? drawSize.Width : chart.Bounds.Width - 70;

            var adjustedX = position.X - plotAreaLeft;
            var relativeX = Math.Max(0, Math.Min(1, adjustedX / plotAreaWidth));

            // Find data from series
            DateTime? timestamp = null;
            double critical = 0, high = 0, medium = 0, low = 0;

            foreach (var s in ViewModel.Charts.TimelineSeries)
            {
                if (s is LineSeries<DateTimePoint> dateTimeSeries && dateTimeSeries.Values != null)
                {
                    var values = dateTimeSeries.Values.ToList();
                    if (values.Count > 0)
                    {
                        var dataIndex = (int)(relativeX * (values.Count - 1));
                        dataIndex = Math.Max(0, Math.Min(values.Count - 1, dataIndex));
                        var point = values[dataIndex];

                        timestamp ??= point.DateTime;

                        var name = dateTimeSeries.Name ?? "";
                        var value = point.Value ?? 0;

                        if (name.Contains("Critical", StringComparison.OrdinalIgnoreCase))
                            critical = value;
                        else if (name.Contains("High", StringComparison.OrdinalIgnoreCase))
                            high = value;
                        else if (name.Contains("Medium", StringComparison.OrdinalIgnoreCase))
                            medium = value;
                        else if (name.Contains("Low", StringComparison.OrdinalIgnoreCase))
                            low = value;
                    }
                }
            }

            if (timestamp.HasValue)
            {
                // Build colored tooltip with inline formatting
                AnomalyTooltipText.Inlines?.Clear();

                // Timestamp (white)
                AnomalyTooltipText.Inlines?.Add(new Run($"{timestamp.Value:HH:mm:ss}  |  ")
                {
                    Foreground = DefaultColor
                });

                // Critical (red - #F85149)
                AnomalyTooltipText.Inlines?.Add(new Run($"Critical: {critical:N0}")
                {
                    Foreground = CriticalColor,
                    FontWeight = FontWeight.Bold
                });

                AnomalyTooltipText.Inlines?.Add(new Run("  |  ") { Foreground = DefaultColor });

                // High (orange - #F59E0B)
                AnomalyTooltipText.Inlines?.Add(new Run($"High: {high:N0}")
                {
                    Foreground = HighColor,
                    FontWeight = FontWeight.Bold
                });

                AnomalyTooltipText.Inlines?.Add(new Run("  |  ") { Foreground = DefaultColor });

                // Medium (yellow - #FCD34D)
                AnomalyTooltipText.Inlines?.Add(new Run($"Medium: {medium:N0}")
                {
                    Foreground = MediumColor,
                    FontWeight = FontWeight.Bold
                });

                AnomalyTooltipText.Inlines?.Add(new Run("  |  ") { Foreground = DefaultColor });

                // Low (blue - #3B82F6)
                AnomalyTooltipText.Inlines?.Add(new Run($"Low: {low:N0}")
                {
                    Foreground = LowColor,
                    FontWeight = FontWeight.Bold
                });
            }
            else
            {
                AnomalyTooltipText.Inlines?.Clear();
                AnomalyTooltipText.Text = "Hover over chart for details";
            }
        }
        catch
        {
            AnomalyTooltipText.Inlines?.Clear();
            AnomalyTooltipText.Text = "Hover over chart for details";
        }
    }

    private void OnAnomalyChartPointerExited(object? sender, PointerEventArgs e)
    {
        AnomalyTooltipText.Inlines?.Clear();
        AnomalyTooltipText.Text = "Hover over chart for details";
    }
}
