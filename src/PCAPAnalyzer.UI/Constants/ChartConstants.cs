using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Constants;

/// <summary>
/// Centralized constants for chart rendering across Dashboard views.
/// Eliminates magic values scattered throughout chart handlers.
/// </summary>
public static class ChartConstants
{
    // ==================== ZOOM FACTORS ====================

    /// <summary>Zoom in reduces visible range by this factor (0.5 = 50% reduction)</summary>
    public const double ZoomInFactor = 0.5;

    /// <summary>Zoom out increases visible range by this factor (2.0 = 100% increase)</summary>
    public const double ZoomOutFactor = 2.0;

    // ==================== HIGHLIGHT STYLING ====================

    /// <summary>Size of highlight dot on data points</summary>
    public const int HighlightDotSize = 12;

    /// <summary>Stroke thickness for highlight dot border</summary>
    public const float HighlightDotStrokeThickness = 2f;

    /// <summary>Stroke thickness for vertical highlight line</summary>
    public const float HighlightLineStrokeThickness = 4f;

    /// <summary>Z-index for highlight scatter (renders above data)</summary>
    public const int HighlightScatterZIndex = 1000;

    /// <summary>Z-index for highlight vertical line (just below scatter)</summary>
    public const int HighlightLineZIndex = 999;

    // ==================== HIGHLIGHT COLORS ====================

    /// <summary>Fill color for highlight dot (gold)</summary>
    public static string HighlightFillColor => ThemeColorHelper.HighlightYellowHex;

    /// <summary>Stroke color for highlight dot (orange)</summary>
    public static string HighlightStrokeColor => ThemeColorHelper.HighlightOrangeHex;

    // ==================== HIGHLIGHT SOLID COLOR PAINTS ====================

    /// <summary>Fill paint for highlight dot (gold)</summary>
    public static LiveChartsCore.SkiaSharpView.Painting.SolidColorPaint HighlightFillPaint
        => ThemeColorHelper.ParseSolidColorPaint(HighlightFillColor);

    /// <summary>Stroke paint for highlight dot (orange with stroke)</summary>
    public static LiveChartsCore.SkiaSharpView.Painting.SolidColorPaint HighlightStrokePaint
        => ThemeColorHelper.ParseSolidColorPaint(HighlightStrokeColor, HighlightDotStrokeThickness);

    /// <summary>Stroke paint for vertical highlight line (gold with line thickness)</summary>
    public static LiveChartsCore.SkiaSharpView.Painting.SolidColorPaint HighlightLinePaint
        => ThemeColorHelper.ParseSolidColorPaint(HighlightFillColor, HighlightLineStrokeThickness);

    // ==================== CHART LAYOUT ====================

    /// <summary>Left offset for plot area calculations</summary>
    public const double PlotAreaLeftOffset = 50;

    /// <summary>Width offset for plot area calculations</summary>
    public const double PlotAreaWidthOffset = 70;

    /// <summary>Minimum Y-range to prevent division by zero</summary>
    public const double MinYRange = 0.0001;

    // ==================== DRILL-DOWN ====================

    /// <summary>Time window (±seconds) for click-to-drill-down</summary>
    public static readonly System.TimeSpan DrillDownTimeWindow = System.TimeSpan.FromSeconds(1);

    // ==================== PORT CHART COLORS ====================

    /// <summary>Color palette for top 10 ports (resolved from theme)</summary>
    public static string[] PortColorPalette => ThemeColorHelper.GetChartColorPalette();

    // ==================== TRAFFIC CHART COLORS ====================

    /// <summary>Throughput series color (blue)</summary>
    public static string ThroughputColor => ThemeColorHelper.ChartThroughputColorHex;

    /// <summary>Packets series color (green)</summary>
    public static string PacketsColor => ThemeColorHelper.ChartPacketsColorHex;

    /// <summary>Anomalies series color (amber)</summary>
    public static string AnomaliesColor => ThemeColorHelper.ChartAnomaliesColorHex;

    /// <summary>Threats series color (red)</summary>
    public static string ThreatsColor => ThemeColorHelper.ChartThreatsColorHex;
}
