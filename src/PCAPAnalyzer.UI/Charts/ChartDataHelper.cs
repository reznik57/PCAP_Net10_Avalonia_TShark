using System;
using System.Linq;
using LiveChartsCore.Defaults;

namespace PCAPAnalyzer.UI.Charts;

/// <summary>
/// Utility methods for chart data processing.
/// Centralizes common operations like downsampling and axis step calculations.
/// </summary>
public static class ChartDataHelper
{
    /// <summary>
    /// Downsamples time series data to reduce rendering overhead.
    /// Takes every Nth point to reduce count to maxDataPoints.
    /// </summary>
    public static DateTimePoint[] Downsample(DateTimePoint[] data, int maxDataPoints = 100)
    {
        if (data.Length <= maxDataPoints)
            return data;

        var step = Math.Max(1, (int)Math.Floor(data.Length / (double)maxDataPoints));
        return data.Where((_, i) => i % step == 0).Take(maxDataPoints).ToArray();
    }

    /// <summary>
    /// Calculates appropriate Y-axis step for anomaly counts.
    /// Reduces label density for better readability.
    /// </summary>
    public static double CalculateAnomalyStep(double maxValue)
    {
        return maxValue switch
        {
            < 5 => 1,
            < 20 => 2,
            < 50 => 5,
            < 100 => 10,
            < 200 => 20,
            < 500 => 50,
            _ => 100
        };
    }

    /// <summary>
    /// Calculates appropriate Y-axis step for threat counts.
    /// Same logic as anomalies - could be parameterized if needed.
    /// </summary>
    public static double CalculateThreatStep(double maxValue) => CalculateAnomalyStep(maxValue);

    /// <summary>
    /// Calculates appropriate Y-axis step for packet counts.
    /// Uses larger steps for packet-scale values.
    /// </summary>
    public static double CalculatePacketStep(double maxValue)
    {
        return maxValue switch
        {
            < 100 => 10,
            < 1000 => 100,
            < 10000 => 1000,
            < 100000 => 10000,
            _ => 100000
        };
    }

    /// <summary>
    /// Formats throughput value with appropriate unit.
    /// </summary>
    public static string FormatThroughput(double kbps)
    {
        if (kbps >= 1024 * 1024)
            return $"{kbps / 1024 / 1024:F2} GB/s";
        if (kbps >= 1024)
            return $"{kbps / 1024:F2} MB/s";
        return $"{kbps:F2} KB/s";
    }

    /// <summary>
    /// Formats large numbers with K/M suffix.
    /// </summary>
    public static string FormatCount(double value)
    {
        if (value >= 1_000_000)
            return $"{value / 1_000_000:F1}M";
        if (value >= 1000)
            return $"{value / 1000:F1}K";
        return $"{value:F0}";
    }

    /// <summary>
    /// Formats bytes with appropriate unit (KB, MB, GB).
    /// </summary>
    public static string FormatBytes(double bytes)
    {
        if (bytes >= 1024 * 1024 * 1024)
            return $"{bytes / (1024 * 1024 * 1024):F1} GB";
        if (bytes >= 1024 * 1024)
            return $"{bytes / (1024 * 1024):F1} MB";
        if (bytes >= 1024)
            return $"{bytes / 1024:F1} KB";
        return $"{bytes:F0} B";
    }
}
