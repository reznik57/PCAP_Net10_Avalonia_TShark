using System;

namespace PCAPAnalyzer.UI.Helpers;

/// <summary>
/// Standardized time formatting utility for consistent display across the application.
/// All time values are formatted as seconds with 1 decimal place (e.g., "14.1s").
/// </summary>
public static class TimeFormatter
{
    /// <summary>
    /// Formats a TimeSpan as seconds with 1 decimal place.
    /// Examples: "0.2s", "14.1s", "72.0s"
    /// </summary>
    public static string FormatAsSeconds(TimeSpan duration)
    {
        return $"{duration.TotalSeconds:F1}s";
    }

    /// <summary>
    /// Formats milliseconds as seconds with 1 decimal place.
    /// Examples: "0.2s" (from 216ms), "1.0s" (from 1000ms)
    /// </summary>
    public static string FormatAsSeconds(double milliseconds)
    {
        var seconds = milliseconds / 1000.0;
        return $"{seconds:F1}s";
    }

    /// <summary>
    /// Formats seconds as seconds with 1 decimal place.
    /// Examples: "0.5s", "14.1s", "120.0s"
    /// </summary>
    public static string FormatSeconds(double seconds)
    {
        return $"{seconds:F1}s";
    }

    /// <summary>
    /// Formats elapsed time between two DateTimes as seconds.
    /// </summary>
    public static string FormatElapsed(DateTime start, DateTime end)
    {
        var duration = end - start;
        return FormatAsSeconds(duration);
    }
}
