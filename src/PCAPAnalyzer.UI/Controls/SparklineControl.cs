using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Controls;

/// <summary>
/// A lightweight sparkline control that displays mini bar charts for timeline visualization.
/// Shows traffic distribution over time in a compact format.
/// </summary>
public class SparklineControl : Control
{
    // Default colors from theme (resolved once)
    private static readonly IBrush DefaultBarBrush = new SolidColorBrush(ThemeColorHelper.GetColor("StatPackets", "#3B82F6"));
    private static readonly IBrush DefaultBackgroundBrush = new SolidColorBrush(ThemeColorHelper.GetColor("BackgroundLevel1", "#21262D"));

    /// <summary>
    /// The values to display as bars (normalized 0-1 range expected)
    /// </summary>
    public static readonly StyledProperty<IReadOnlyList<double>?> ValuesProperty =
        AvaloniaProperty.Register<SparklineControl, IReadOnlyList<double>?>(nameof(Values));

    /// <summary>
    /// Color for the bars
    /// </summary>
    public static readonly StyledProperty<IBrush> BarBrushProperty =
        AvaloniaProperty.Register<SparklineControl, IBrush>(nameof(BarBrush), DefaultBarBrush);

    /// <summary>
    /// Background color for empty space
    /// </summary>
    public static readonly StyledProperty<IBrush> BackgroundBrushProperty =
        AvaloniaProperty.Register<SparklineControl, IBrush>(nameof(BackgroundBrush), DefaultBackgroundBrush);

    /// <summary>
    /// Gap between bars (in pixels)
    /// </summary>
    public static readonly StyledProperty<double> BarGapProperty =
        AvaloniaProperty.Register<SparklineControl, double>(nameof(BarGap), 1.0);

    /// <summary>
    /// Number of buckets to display
    /// </summary>
    public static readonly StyledProperty<int> BucketCountProperty =
        AvaloniaProperty.Register<SparklineControl, int>(nameof(BucketCount), 20);

    public IReadOnlyList<double>? Values
    {
        get => GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public IBrush BarBrush
    {
        get => GetValue(BarBrushProperty);
        set => SetValue(BarBrushProperty, value);
    }

    public IBrush BackgroundBrush
    {
        get => GetValue(BackgroundBrushProperty);
        set => SetValue(BackgroundBrushProperty, value);
    }

    public double BarGap
    {
        get => GetValue(BarGapProperty);
        set => SetValue(BarGapProperty, value);
    }

    public int BucketCount
    {
        get => GetValue(BucketCountProperty);
        set => SetValue(BucketCountProperty, value);
    }

    static SparklineControl()
    {
        AffectsRender<SparklineControl>(ValuesProperty, BarBrushProperty, BackgroundBrushProperty, BarGapProperty, BucketCountProperty);
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        var bounds = Bounds;
        if (bounds.Width <= 0 || bounds.Height <= 0)
            return;

        // Draw background
        context.DrawRectangle(BackgroundBrush, null, new Rect(0, 0, bounds.Width, bounds.Height), 2, 2);

        var values = Values;
        if (values == null || values.Count == 0)
            return;

        // Calculate bar dimensions
        var bucketCount = Math.Min(BucketCount, values.Count);
        var totalGaps = (bucketCount - 1) * BarGap;
        var barWidth = (bounds.Width - totalGaps - 4) / bucketCount; // 4px padding (2 each side)

        if (barWidth <= 0)
            return;

        // Normalize values if not already normalized
        var maxValue = values.Max();
        var normalizedValues = maxValue > 0
            ? values.Select(v => v / maxValue).ToList()
            : values.Select(_ => 0.0).ToList();

        // Draw bars
        for (int i = 0; i < bucketCount && i < normalizedValues.Count; i++)
        {
            var normalizedValue = Math.Clamp(normalizedValues[i], 0, 1);
            var barHeight = Math.Max(2, normalizedValue * (bounds.Height - 4)); // Minimum 2px, 4px padding
            var x = 2 + i * (barWidth + BarGap);
            var y = bounds.Height - 2 - barHeight;

            context.DrawRectangle(BarBrush, null, new Rect(x, y, barWidth, barHeight), 1, 1);
        }
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        // Default size if not specified
        return new Size(
            double.IsInfinity(availableSize.Width) ? 100 : availableSize.Width,
            double.IsInfinity(availableSize.Height) ? 20 : availableSize.Height
        );
    }
}
