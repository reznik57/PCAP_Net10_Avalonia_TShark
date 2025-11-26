using System;

namespace PCAPAnalyzer.Core.Utilities;

/// <summary>
/// Provides standardized number and time formatting utilities for PCAP Analyzer.
/// Centralizes formatting logic to eliminate duplication across ViewModels, Models, and Services.
/// NOTE: Moved from UI layer to Core layer to resolve circular dependency.
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
    /// Formats TimeSpan to HH:MM:SS or MM:SS depending on duration.
    /// Uses shorter format for durations under 1 hour.
    /// </summary>
    /// <param name="timeSpan">TimeSpan to format</param>
    /// <returns>Formatted time string</returns>
    public static string FormatTimeSpan(TimeSpan timeSpan)
    {
        return timeSpan.TotalHours >= 1
            ? timeSpan.ToString(@"hh\:mm\:ss")
            : timeSpan.ToString(@"mm\:ss");
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
