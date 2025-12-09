using System;
using LiveChartsCore.SkiaSharpView;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Charts;

/// <summary>
/// Factory for creating pre-configured LiveCharts axes.
/// Centralizes axis configuration to reduce code duplication across chart ViewModels.
/// </summary>
public static class ChartAxisBuilder
{
    /// <summary>
    /// Creates a time-based X-axis for timeline charts.
    /// Formats DateTime ticks as HH:mm:ss with 45° rotation.
    /// </summary>
    public static Axis CreateTimelineXAxis()
    {
        return new Axis
        {
            Labeler = value =>
            {
                try
                {
                    var ticks = (long)value;
                    if (ticks <= 0 || ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                        return "";
                    return new DateTime(ticks).ToString("HH:mm:ss");
                }
                catch
                {
                    return "";
                }
            },
            LabelsRotation = 45,
            TextSize = 10,
            SeparatorsPaint = ThemeColorHelper.LightGrayAlpha50Paint,
            LabelsPaint = ThemeColorHelper.GetSolidColorPaint("TextMuted", "#8B949E")
        };
    }

    /// <summary>
    /// Creates a packet count Y-axis (blue theme).
    /// Formats values with K suffix for thousands.
    /// </summary>
    public static Axis CreatePacketCountYAxis()
    {
        return new Axis
        {
            Name = "Packets",
            Position = LiveChartsCore.Measure.AxisPosition.Start,
            Labeler = value => value >= 1000 ? $"{value / 1000:F1}K" : $"{value:F0}",
            TextSize = 10,
            SeparatorsPaint = ThemeColorHelper.LightGrayAlpha50Paint,
            MinLimit = 0,
            NamePaint = ThemeColorHelper.GetSolidColorPaint("AccentBlue", "#58A6FF"),
            LabelsPaint = ThemeColorHelper.GetSolidColorPaint("AccentBlue", "#58A6FF")
        };
    }

    /// <summary>
    /// Creates a throughput Y-axis (green theme).
    /// Formats values as bytes (KB, MB, GB).
    /// </summary>
    public static Axis CreateThroughputYAxis()
    {
        return new Axis
        {
            Name = "Throughput",
            Position = LiveChartsCore.Measure.AxisPosition.Start,
            Labeler = value => Core.Utilities.NumberFormatter.FormatBytes((long)value),
            TextSize = 10,
            SeparatorsPaint = ThemeColorHelper.LightGrayAlpha50Paint,
            MinLimit = 0,
            NamePaint = ThemeColorHelper.GetSolidColorPaint("ColorSuccess", "#10B981"),
            LabelsPaint = ThemeColorHelper.GetSolidColorPaint("ColorSuccess", "#10B981")
        };
    }

    /// <summary>
    /// Creates a generic count Y-axis with custom name and color.
    /// </summary>
    public static Axis CreateCountYAxis(string name, string colorKey, string fallbackColor)
    {
        return new Axis
        {
            Name = name,
            Position = LiveChartsCore.Measure.AxisPosition.Start,
            Labeler = value => value >= 1000 ? $"{value / 1000:F1}K" : $"{value:F0}",
            TextSize = 10,
            SeparatorsPaint = ThemeColorHelper.LightGrayAlpha50Paint,
            MinLimit = 0,
            NamePaint = ThemeColorHelper.GetSolidColorPaint(colorKey, fallbackColor),
            LabelsPaint = ThemeColorHelper.GetSolidColorPaint(colorKey, fallbackColor)
        };
    }

    /// <summary>
    /// Creates a percentage Y-axis (0-100 range).
    /// </summary>
    public static Axis CreatePercentageYAxis()
    {
        return new Axis
        {
            Name = "%",
            Position = LiveChartsCore.Measure.AxisPosition.Start,
            Labeler = value => $"{value:F0}%",
            TextSize = 10,
            SeparatorsPaint = ThemeColorHelper.LightGrayAlpha50Paint,
            MinLimit = 0,
            MaxLimit = 100,
            NamePaint = ThemeColorHelper.GetSolidColorPaint("TextMuted", "#8B949E"),
            LabelsPaint = ThemeColorHelper.GetSolidColorPaint("TextMuted", "#8B949E")
        };
    }

    /// <summary>
    /// Configures a Y-axis for packets or throughput mode.
    /// </summary>
    public static void ConfigureYAxisMode(Axis axis, bool throughputMode)
    {
        if (throughputMode)
        {
            axis.Name = "Throughput";
            axis.Labeler = value => Core.Utilities.NumberFormatter.FormatBytes((long)value);
            axis.NamePaint = ThemeColorHelper.GetSolidColorPaint("ColorSuccess", "#10B981");
            axis.LabelsPaint = ThemeColorHelper.GetSolidColorPaint("ColorSuccess", "#10B981");
        }
        else
        {
            axis.Name = "Packets";
            axis.Labeler = value => value >= 1000 ? $"{value / 1000:F1}K" : $"{value:F0}";
            axis.NamePaint = ThemeColorHelper.GetSolidColorPaint("AccentBlue", "#58A6FF");
            axis.LabelsPaint = ThemeColorHelper.GetSolidColorPaint("AccentBlue", "#58A6FF");
        }
    }
}
