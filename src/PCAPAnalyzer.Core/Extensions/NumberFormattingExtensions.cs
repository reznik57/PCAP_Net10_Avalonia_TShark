using System;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Extensions;

/// <summary>
/// C# 14-ready extension methods for number and time formatting.
/// Provides fluent syntax for common formatting operations.
/// </summary>
public static class NumberFormattingExtensions
{
    #region Count Formatting

    /// <summary>
    /// Formats number with abbreviated suffixes (e.g., 1,106,728 → "1.1M").
    /// </summary>
    public static string ToAbbreviatedCount(this long count) =>
        NumberFormatter.FormatCount(count);

    /// <summary>
    /// Formats number with abbreviated suffixes (e.g., 1,106,728 → "1.1M").
    /// </summary>
    public static string ToAbbreviatedCount(this int count) =>
        NumberFormatter.FormatCount(count);

    #endregion

    #region European Formatting

    /// <summary>
    /// Formats number with European thousand separators (dots instead of commas).
    /// Example: 1106937 → "1.106.937"
    /// </summary>
    public static string ToEuropeanFormat(this long number) =>
        NumberFormatter.FormatNumberEuropean(number);

    /// <summary>
    /// Formats number with European thousand separators (dots instead of commas).
    /// Example: 1106937 → "1.106.937"
    /// </summary>
    public static string ToEuropeanFormat(this int number) =>
        NumberFormatter.FormatNumberEuropean(number);

    #endregion

    #region Byte Formatting

    /// <summary>
    /// Formats bytes to human-readable size with appropriate unit (B, KB, MB, GB, TB).
    /// </summary>
    public static string ToFormattedBytes(this long bytes) =>
        NumberFormatter.FormatBytes(bytes);

    /// <summary>
    /// Formats bytes to human-readable size with appropriate unit (B, KB, MB, GB, TB).
    /// </summary>
    public static string ToFormattedBytes(this int bytes) =>
        NumberFormatter.FormatBytes(bytes);

    /// <summary>
    /// Formats bytes to human-readable size with appropriate unit (B, KB, MB, GB, TB).
    /// </summary>
    public static string ToFormattedBytes(this ulong bytes) =>
        NumberFormatter.FormatBytes((long)bytes);

    #endregion

    #region Throughput Formatting

    /// <summary>
    /// Formats bytes per second to human-readable throughput (B/s, KB/s, MB/s, GB/s).
    /// </summary>
    public static string ToFormattedBytesPerSecond(this long bytesPerSecond)
    {
        if (bytesPerSecond >= 1_000_000_000) return $"{bytesPerSecond / 1_000_000_000.0:F1} GB/s";
        if (bytesPerSecond >= 1_000_000) return $"{bytesPerSecond / 1_000_000.0:F1} MB/s";
        if (bytesPerSecond >= 1_000) return $"{bytesPerSecond / 1_000.0:F1} KB/s";
        return $"{bytesPerSecond} B/s";
    }

    /// <summary>
    /// Formats bytes per second to human-readable throughput (B/s, KB/s, MB/s, GB/s).
    /// </summary>
    public static string ToFormattedBytesPerSecond(this int bytesPerSecond) =>
        ((long)bytesPerSecond).ToFormattedBytesPerSecond();

    /// <summary>
    /// Formats KB/s to human-readable throughput (KB/s, MB/s, GB/s).
    /// Input is already in KB/s units.
    /// </summary>
    public static string ToFormattedKBps(this double kbps)
    {
        if (kbps >= 1024 * 1024)
            return $"{kbps / 1024 / 1024:F2} GB/s";
        if (kbps >= 1024)
            return $"{kbps / 1024:F2} MB/s";
        return $"{kbps:F2} KB/s";
    }

    #endregion

    #region TimeSpan Formatting

    /// <summary>
    /// Formats TimeSpan to HH:MM:SS or MM:SS depending on duration.
    /// Uses shorter format for durations under 1 hour.
    /// </summary>
    public static string ToFormattedTime(this TimeSpan timeSpan) =>
        NumberFormatter.FormatTimeSpan(timeSpan);

    /// <summary>
    /// Formats TimeSpan as seconds with 1 decimal place (e.g., "14.1s").
    /// Useful for short durations like connection times.
    /// </summary>
    public static string ToFormattedSeconds(this TimeSpan duration) =>
        $"{duration.TotalSeconds:F1}s";

    #endregion
}
