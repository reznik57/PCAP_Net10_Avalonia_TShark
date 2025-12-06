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

    #region TimeSpan Formatting

    /// <summary>
    /// Formats TimeSpan to HH:MM:SS or MM:SS depending on duration.
    /// Uses shorter format for durations under 1 hour.
    /// </summary>
    public static string ToFormattedTime(this TimeSpan timeSpan) =>
        NumberFormatter.FormatTimeSpan(timeSpan);

    #endregion
}
