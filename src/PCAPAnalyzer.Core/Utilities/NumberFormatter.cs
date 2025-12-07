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

    /// <summary>
    /// Formats bytes per second with appropriate unit (B/s, KB/s, MB/s, GB/s).
    /// </summary>
    /// <param name="bytesPerSecond">Bytes per second rate</param>
    /// <returns>Formatted string with rate unit</returns>
    public static string FormatBytesPerSecond(long bytesPerSecond)
    {
        if (bytesPerSecond >= 1_000_000_000) return $"{bytesPerSecond / 1_000_000_000.0:F1} GB/s";
        if (bytesPerSecond >= 1_000_000) return $"{bytesPerSecond / 1_000_000.0:F1} MB/s";
        if (bytesPerSecond >= 1_000) return $"{bytesPerSecond / 1_000.0:F1} KB/s";
        return $"{bytesPerSecond} B/s";
    }

    /// <summary>
    /// Formats bytes with European/German thousand separators (dots).
    /// Example: 1106937 bytes → "1,08 MB" (using comma as decimal separator)
    /// </summary>
    /// <param name="bytes">Number of bytes</param>
    /// <returns>Formatted string with German locale</returns>
    public static string FormatBytesGerman(long bytes)
    {
        if (bytes == 0) return "0 B";

        var germanCulture = new System.Globalization.CultureInfo("de-DE");
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        int order = 0;
        double size = bytes;

        while (size >= 1000 && order < sizes.Length - 1)
        {
            order++;
            size /= 1000;
        }

        return $"{size.ToString("F2", germanCulture)} {sizes[order]}";
    }
}
