using System;
using PCAPAnalyzer.Core.Extensions;
using CoreFormatter = PCAPAnalyzer.Core.Utilities.NumberFormatter;

namespace PCAPAnalyzer.UI.Utilities;

/// <summary>
/// UI facade for number formatting. Delegates to Core utilities and extensions.
/// Maintained for backward compatibility with existing UI code.
/// New code should use PCAPAnalyzer.Core.Extensions directly.
/// </summary>
public static class NumberFormatter
{
    /// <summary>
    /// Formats large numbers with abbreviated suffixes (e.g., 1,106,728 → "1.1M")
    /// </summary>
    public static string FormatCount(long count) => CoreFormatter.FormatCount(count);

    /// <summary>
    /// Formats number with European thousand separators (dots instead of commas).
    /// </summary>
    public static string FormatNumberEuropean(long number) => CoreFormatter.FormatNumberEuropean(number);

    /// <summary>
    /// Formats TimeSpan to HH:MM:SS format for capture durations.
    /// </summary>
    public static string FormatTimeSpan(TimeSpan timeSpan) => CoreFormatter.FormatTimeSpan(timeSpan);

    /// <summary>
    /// Formats bytes to human-readable size with appropriate unit (B, KB, MB, GB, TB).
    /// </summary>
    public static string FormatBytes(long bytes) => bytes.ToFormattedBytes();

    /// <summary>
    /// Formats bytes with European/German thousand separators (dots).
    /// Example: 1106937 bytes → "1,08 MB" (using comma as decimal separator)
    /// </summary>
    public static string FormatBytesGerman(long bytes) => CoreFormatter.FormatBytesGerman(bytes);
}
