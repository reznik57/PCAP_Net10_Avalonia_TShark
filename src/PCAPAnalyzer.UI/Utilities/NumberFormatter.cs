using System;

namespace PCAPAnalyzer.UI.Utilities;

/// <summary>
/// Provides standardized number and time formatting utilities for PCAP Analyzer UI.
/// Centralizes formatting logic to eliminate duplication across 15+ ViewModels.
/// </summary>
public static class NumberFormatter
{
    /// <summary>
    /// Formats large numbers with abbreviated suffixes (e.g., 1,106,728 → "1.1M")
    /// </summary>
    /// <param name="count">Number to format</param>
    /// <returns>Formatted string with K/M suffix</returns>
    public static string FormatCount(long count)
    {
        if (count >= 1_000_000)
            return $"{count / 1_000_000.0:F1}M";
        if (count >= 1_000)
            return $"{count / 1_000.0:F1}K";
        return count.ToString("N0");
    }

    /// <summary>
    /// Formats number with European thousand separators (dots instead of commas).
    /// Example: 1106937 → "1.106.937"
    /// </summary>
    /// <param name="number">Number to format</param>
    /// <returns>Formatted string with dot separators</returns>
    public static string FormatNumberEuropean(long number)
    {
        if (number == 0)
            return "0";

        // Use ToString with grouping, then replace commas with dots
        return number.ToString("N0").Replace(",", ".", StringComparison.Ordinal);
    }

    /// <summary>
    /// Formats TimeSpan to HH:MM:SS format for capture durations.
    /// Always shows full format for clarity.
    /// </summary>
    /// <param name="timeSpan">TimeSpan to format</param>
    /// <returns>Formatted time string in HH:MM:SS format</returns>
    public static string FormatTimeSpan(TimeSpan timeSpan)
    {
        // Always use full format for capture duration clarity
        // For very long captures (24+ hours), show total hours
        if (timeSpan.TotalHours >= 24)
            return $"{(int)timeSpan.TotalHours:D2}:{timeSpan.Minutes:D2}:{timeSpan.Seconds:D2}";

        return timeSpan.ToString(@"hh\:mm\:ss");
    }

    /// <summary>
    /// Formats bytes to human-readable size with appropriate unit (B, KB, MB, GB, TB).
    /// Uses 1000-based scaling (not 1024).
    /// </summary>
    /// <param name="bytes">Number of bytes</param>
    /// <returns>Formatted string with unit</returns>
    public static string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        var order = 0;
        var size = (double)bytes;

        while (size >= 1000 && order < sizes.Length - 1)
        {
            order++;
            size /= 1000;
        }

        return $"{size:F2} {sizes[order]}";
    }
}
