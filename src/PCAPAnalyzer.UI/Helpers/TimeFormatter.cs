using System;
using PCAPAnalyzer.Core.Extensions;

namespace PCAPAnalyzer.UI.Helpers;

/// <summary>
/// UI facade for time formatting. Delegates to Core extensions where available.
/// Maintained for backward compatibility with existing UI code.
/// New code should use PCAPAnalyzer.Core.Extensions directly.
/// </summary>
public static class TimeFormatter
{
    /// <summary>
    /// Formats a TimeSpan as seconds with 1 decimal place.
    /// Examples: "0.2s", "14.1s", "72.0s"
    /// </summary>
    public static string FormatAsSeconds(TimeSpan duration) => duration.ToFormattedSeconds();

    /// <summary>
    /// Formats milliseconds as seconds with 1 decimal place.
    /// Examples: "0.2s" (from 216ms), "1.0s" (from 1000ms)
    /// </summary>
    public static string FormatAsSeconds(double milliseconds) => $"{milliseconds / 1000.0:F1}s";

    /// <summary>
    /// Formats seconds as seconds with 1 decimal place.
    /// Examples: "0.5s", "14.1s", "120.0s"
    /// </summary>
    public static string FormatSeconds(double seconds) => $"{seconds:F1}s";

    /// <summary>
    /// Formats elapsed time between two DateTimes as seconds.
    /// </summary>
    public static string FormatElapsed(DateTime start, DateTime end) => (end - start).ToFormattedSeconds();
}
