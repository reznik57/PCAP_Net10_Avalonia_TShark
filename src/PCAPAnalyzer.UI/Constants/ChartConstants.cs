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
    public const string HighlightFillColor = "#FFD700";

    /// <summary>Stroke color for highlight dot (orange)</summary>
    public const string HighlightStrokeColor = "#FFA500";

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

    /// <summary>Color palette for top 10 ports (matches DashboardViewModel)</summary>
    public static readonly string[] PortColorPalette =
    [
        "#3B82F6", // Blue
        "#10B981", // Green
        "#F59E0B", // Amber
        "#EF4444", // Red
        "#8B5CF6", // Purple
        "#EC4899", // Pink
        "#06B6D4", // Cyan
        "#84CC16", // Lime
        "#F97316", // Orange
        "#6366F1"  // Indigo
    ];

    // ==================== TRAFFIC CHART COLORS ====================

    /// <summary>Throughput series color (blue)</summary>
    public const string ThroughputColor = "#3B82F6";

    /// <summary>Packets series color (green)</summary>
    public const string PacketsColor = "#10B981";

    /// <summary>Anomalies series color (amber)</summary>
    public const string AnomaliesColor = "#F59E0B";

    /// <summary>Threats series color (red)</summary>
    public const string ThreatsColor = "#EF4444";
}
