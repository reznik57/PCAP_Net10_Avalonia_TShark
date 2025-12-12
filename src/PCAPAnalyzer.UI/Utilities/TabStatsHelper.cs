using System.Globalization;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Utilities;

/// <summary>
/// Provides consistent stats bar formatting across all tabs.
/// Uses the Packet Analysis pattern: "Total: X" with "Filtered: Y (Z%)" secondary text.
/// </summary>
public static class TabStatsHelper
{
    private static readonly CultureInfo GermanCulture = new("de-DE");

    // Standard colors from theme
    private static string AccentBlue => ThemeColorHelper.GetColorHex("AccentBlue", "#58A6FF");
    private static string SuccessGreen => ThemeColorHelper.GetColorHex("ColorSuccess", "#3FB950");
    private static string WarningYellow => ThemeColorHelper.GetColorHex("ColorWarning", "#D29922");
    private static string ErrorRed => ThemeColorHelper.GetColorHex("ColorDanger", "#F85149");

    /// <summary>
    /// Adds a numeric stat with Total/Filtered pattern.
    /// When filter is active: "Total: X" with "Filtered: Y (Z%)"
    /// When no filter: Just the number
    /// </summary>
    public static void AddNumericStat(
        StatsBarControlViewModel statsBar,
        string label,
        string icon,
        long totalValue,
        long filteredValue,
        bool isFilterActive,
        string? valueColor = null)
    {
        var color = valueColor ?? AccentBlue;

        if (isFilterActive)
        {
            var percentage = totalValue > 0 ? (filteredValue * 100.0 / totalValue) : 0.0;
            var totalText = $"Total: {totalValue.ToString("N0", GermanCulture)}";
            var filteredText = $"Filtered: {filteredValue.ToString("N0", GermanCulture)} ({percentage:F1}%)";
            statsBar.AddStat(label, totalText, icon, color, filteredText, SuccessGreen);
        }
        else
        {
            statsBar.AddStat(label, totalValue.ToString("N0", GermanCulture), icon, color);
        }
    }

    /// <summary>
    /// Adds a bytes stat with Total/Filtered pattern (auto-formatted as KB/MB/GB).
    /// </summary>
    public static void AddBytesStat(
        StatsBarControlViewModel statsBar,
        string label,
        string icon,
        long totalBytes,
        long filteredBytes,
        bool isFilterActive,
        string? valueColor = null)
    {
        var color = valueColor ?? AccentBlue;

        if (isFilterActive)
        {
            var percentage = totalBytes > 0 ? (filteredBytes * 100.0 / totalBytes) : 0.0;
            var totalText = $"Total: {NumberFormatter.FormatBytesGerman(totalBytes)}";
            var filteredText = $"Filtered: {NumberFormatter.FormatBytesGerman(filteredBytes)} ({percentage:F1}%)";
            statsBar.AddStat(label, totalText, icon, color, filteredText, SuccessGreen);
        }
        else
        {
            statsBar.AddStat(label, NumberFormatter.FormatBytesGerman(totalBytes), icon, color);
        }
    }

    /// <summary>
    /// Adds a count stat with severity-based coloring (e.g., threats, anomalies).
    /// </summary>
    public static void AddCountStat(
        StatsBarControlViewModel statsBar,
        string label,
        string icon,
        int totalCount,
        int filteredCount,
        bool isFilterActive,
        int warningThreshold = 10,
        int dangerThreshold = 50)
    {
        var color = totalCount >= dangerThreshold ? ErrorRed
                  : totalCount >= warningThreshold ? WarningYellow
                  : AccentBlue;

        if (isFilterActive)
        {
            var percentage = totalCount > 0 ? (filteredCount * 100.0 / totalCount) : 0.0;
            var totalText = $"Total: {totalCount.ToString("N0", GermanCulture)}";
            var filteredText = $"Filtered: {filteredCount.ToString("N0", GermanCulture)} ({percentage:F1}%)";
            statsBar.AddStat(label, totalText, icon, color, filteredText, SuccessGreen);
        }
        else
        {
            statsBar.AddStat(label, totalCount.ToString("N0", GermanCulture), icon, color);
        }
    }

    /// <summary>
    /// Adds a quality metric stat (e.g., latency, jitter, MOS score).
    /// Shows current value with optional comparison to baseline.
    /// </summary>
    public static void AddQualityMetricStat(
        StatsBarControlViewModel statsBar,
        string label,
        string icon,
        string currentValue,
        string? baselineValue = null,
        string? valueColor = null)
    {
        var color = valueColor ?? AccentBlue;

        if (!string.IsNullOrEmpty(baselineValue))
        {
            statsBar.AddStat(label, currentValue, icon, color, $"Baseline: {baselineValue}", ThemeColorHelper.GetColorHex("TextMuted", "#6E7681"));
        }
        else
        {
            statsBar.AddStat(label, currentValue, icon, color);
        }
    }

    /// <summary>
    /// Adds a simple stat with no filtering context (e.g., duration, file name).
    /// </summary>
    public static void AddSimpleStat(
        StatsBarControlViewModel statsBar,
        string label,
        string icon,
        string value,
        string? secondaryText = null,
        string? valueColor = null)
    {
        var color = valueColor ?? AccentBlue;
        statsBar.AddStat(label, value, icon, color, secondaryText ?? "", ThemeColorHelper.GetColorHex("TextMuted", "#6E7681"));
    }

    /// <summary>
    /// Configures a stats bar with standard tab settings.
    /// </summary>
    public static void ConfigureStatsBar(
        StatsBarControlViewModel statsBar,
        string sectionTitle,
        int columnCount = 5,
        string? accentColor = null)
    {
        statsBar.SectionTitle = sectionTitle;
        statsBar.AccentColor = accentColor ?? AccentBlue;
        statsBar.ColumnCount = columnCount;
    }
}
