using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Service for analyzing packet size distributions and statistics.
/// Provides detailed insights into packet size patterns.
/// </summary>
public interface IPacketSizeAnalyzer
{
    /// <summary>
    /// Calculates packet size distribution using standard buckets.
    /// </summary>
    PacketSizeDistribution CalculateDistribution(IEnumerable<PacketInfo> packets);

    /// <summary>
    /// Calculates packet size distribution using detailed buckets for granular analysis.
    /// </summary>
    PacketSizeDistribution CalculateDetailedDistribution(IEnumerable<PacketInfo> packets);

    /// <summary>
    /// Calculates packet size distribution using custom bucket definitions.
    /// </summary>
    PacketSizeDistribution CalculateCustomDistribution(
        IEnumerable<PacketInfo> packets,
        List<(int MinSize, int MaxSize, string Label, PacketSizeCategory Category, string Description)> bucketDefinitions);
}

/// <summary>
/// Implementation of packet size analysis service.
/// </summary>
public class PacketSizeAnalyzer : IPacketSizeAnalyzer
{
    /// <inheritdoc/>
    public PacketSizeDistribution CalculateDistribution(IEnumerable<PacketInfo> packets)
    {
        return CalculateCustomDistribution(packets, PacketSizeBucketDefinitions.StandardBuckets);
    }

    /// <inheritdoc/>
    public PacketSizeDistribution CalculateDetailedDistribution(IEnumerable<PacketInfo> packets)
    {
        return CalculateCustomDistribution(packets, PacketSizeBucketDefinitions.DetailedBuckets);
    }

    /// <inheritdoc/>
    public PacketSizeDistribution CalculateCustomDistribution(
        IEnumerable<PacketInfo> packets,
        List<(int MinSize, int MaxSize, string Label, PacketSizeCategory Category, string Description)> bucketDefinitions)
    {
        var packetList = packets.ToList();

        if (packetList.Count == 0)
        {
            return new PacketSizeDistribution
            {
                Buckets = bucketDefinitions.Select(b => new PacketSizeBucket
                {
                    MinSize = b.MinSize,
                    MaxSize = b.MaxSize,
                    Label = b.Label,
                    Category = b.Category,
                    Description = b.Description,
                    PacketCount = 0,
                    TotalBytes = 0,
                    PacketPercentage = 0,
                    BytePercentage = 0
                }).ToList()
            };
        }

        // Calculate basic statistics
        var sizes = packetList.Select(p => (int)p.Length).OrderBy(s => s).ToList();
        var totalPackets = packetList.Count;
        var totalBytes = sizes.Sum(s => (long)s);
        var averageSize = totalBytes / (double)totalPackets;

        // Calculate percentiles
        var minSize = sizes.First();
        var maxSize = sizes.Last();
        var medianSize = GetPercentile(sizes, 50);
        var q1Size = GetPercentile(sizes, 25);
        var q3Size = GetPercentile(sizes, 75);
        var p95Size = GetPercentile(sizes, 95);
        var p99Size = GetPercentile(sizes, 99);

        // Calculate standard deviation
        var variance = sizes.Average(s => Math.Pow(s - averageSize, 2));
        var stdDev = Math.Sqrt(variance);

        // Calculate mode (most common packet size)
        var sizeGroups = sizes.GroupBy(s => s).OrderByDescending(g => g.Count());
        var mode = sizeGroups.First().Key;

        // Initialize buckets
        var buckets = new List<PacketSizeBucket>();

        foreach (var bucketDef in bucketDefinitions)
        {
            var packetsInBucket = packetList.Where(p =>
            {
                var size = p.Length;
                if (bucketDef.MaxSize == int.MaxValue)
                {
                    return size >= bucketDef.MinSize;
                }
                return size >= bucketDef.MinSize && size <= bucketDef.MaxSize;
            }).ToList();

            var bucketPacketCount = packetsInBucket.Count;
            var bucketTotalBytes = packetsInBucket.Sum(p => (long)p.Length);

            buckets.Add(new PacketSizeBucket
            {
                MinSize = bucketDef.MinSize,
                MaxSize = bucketDef.MaxSize,
                Label = bucketDef.Label,
                Category = bucketDef.Category,
                Description = bucketDef.Description,
                PacketCount = bucketPacketCount,
                TotalBytes = bucketTotalBytes,
                PacketPercentage = totalPackets > 0 ? (bucketPacketCount * 100.0) / totalPackets : 0,
                BytePercentage = totalBytes > 0 ? (bucketTotalBytes * 100.0) / totalBytes : 0
            });
        }

        return new PacketSizeDistribution
        {
            Buckets = buckets,
            TotalPackets = totalPackets,
            TotalBytes = totalBytes,
            AveragePacketSize = averageSize,
            MedianPacketSize = medianSize,
            MinPacketSize = minSize,
            MaxPacketSize = maxSize,
            StandardDeviation = stdDev,
            ModePacketSize = mode,
            Q1PacketSize = q1Size,
            Q3PacketSize = q3Size,
            P95PacketSize = p95Size,
            P99PacketSize = p99Size
        };
    }

    /// <summary>
    /// Calculates a percentile value from a sorted list.
    /// </summary>
    private int GetPercentile(List<int> sortedSizes, int percentile)
    {
        if (sortedSizes.Count == 0)
            return 0;

        if (percentile <= 0)
            return sortedSizes.First();

        if (percentile >= 100)
            return sortedSizes.Last();

        var index = (percentile / 100.0) * (sortedSizes.Count - 1);
        var lower = (int)Math.Floor(index);
        var upper = (int)Math.Ceiling(index);

        if (lower == upper)
            return sortedSizes[lower];

        // Linear interpolation
        var fraction = index - lower;
        return (int)(sortedSizes[lower] + fraction * (sortedSizes[upper] - sortedSizes[lower]));
    }
}

/// <summary>
/// Extension methods for packet size analysis.
/// </summary>
public static class PacketSizeAnalysisExtensions
{
    /// <summary>
    /// Gets a summary string for a packet size distribution.
    /// </summary>
    public static string GetSummary(this PacketSizeDistribution distribution)
    {
        if (distribution is null || distribution.TotalPackets == 0)
            return "No packets analyzed";

        return $"Packets: {distribution.TotalPackets.ToString("N0", CultureInfo.InvariantCulture)} | " +
               $"Avg: {distribution.AveragePacketSize.ToString("F1", CultureInfo.InvariantCulture)} bytes | " +
               $"Median: {distribution.MedianPacketSize} bytes | " +
               $"Range: {distribution.MinPacketSize}-{distribution.MaxPacketSize} bytes";
    }

    /// <summary>
    /// Gets a detailed statistics string for display.
    /// </summary>
    public static string GetDetailedStats(this PacketSizeDistribution distribution)
    {
        if (distribution is null || distribution.TotalPackets == 0)
            return "No data available";

        return $"Total Packets: {distribution.TotalPackets.ToString("N0", CultureInfo.InvariantCulture)}\n" +
               $"Total Bytes: {NumberFormatter.FormatBytes(distribution.TotalBytes)}\n" +
               $"Average Size: {distribution.AveragePacketSize.ToString("F1", CultureInfo.InvariantCulture)} bytes\n" +
               $"Median Size: {distribution.MedianPacketSize} bytes\n" +
               $"Std Deviation: {distribution.StandardDeviation.ToString("F1", CultureInfo.InvariantCulture)} bytes\n" +
               $"Min/Max: {distribution.MinPacketSize}/{distribution.MaxPacketSize} bytes\n" +
               $"Q1/Q3: {distribution.Q1PacketSize}/{distribution.Q3PacketSize} bytes\n" +
               $"95th/99th: {distribution.P95PacketSize}/{distribution.P99PacketSize} bytes\n" +
               $"Mode: {distribution.ModePacketSize} bytes";
    }

    /// <summary>
    /// Gets the top N buckets by packet count.
    /// </summary>
    public static List<PacketSizeBucket> GetTopBucketsByPackets(this PacketSizeDistribution distribution, int topN = 5)
    {
        return distribution.Buckets?
            .OrderByDescending(b => b.PacketCount)
            .Take(topN)
            .ToList() ?? new List<PacketSizeBucket>();
    }

    /// <summary>
    /// Gets the top N buckets by byte count.
    /// </summary>
    public static List<PacketSizeBucket> GetTopBucketsByBytes(this PacketSizeDistribution distribution, int topN = 5)
    {
        return distribution.Buckets?
            .OrderByDescending(b => b.TotalBytes)
            .Take(topN)
            .ToList() ?? new List<PacketSizeBucket>();
    }

    /// <summary>
    /// Determines if the packet size distribution is typical or anomalous.
    /// </summary>
    public static string ClassifyDistribution(this PacketSizeDistribution distribution)
    {
        if (distribution is null || distribution.TotalPackets == 0)
            return "Unknown";

        // Check for normal distribution patterns
        var mostCommon = distribution.MostCommonBucket;
        if (mostCommon is null)
            return "Unknown";

        // Typical patterns:
        // 1. High percentage of tiny packets (ACKs) = 40-60%
        // 2. MTU-sized packets for data transfer = 20-40%
        // 3. Medium packets for application data = 10-30%

        var tinyPackets = distribution.Buckets?.FirstOrDefault(b => b.Category == PacketSizeCategory.Tiny);
        var jumboPackets = distribution.Buckets?.FirstOrDefault(b => b.Category == PacketSizeCategory.Jumbo);

        if (tinyPackets is not null && tinyPackets.PacketPercentage > 60)
            return "Control-Heavy (High ACK traffic)";

        if (jumboPackets is not null && jumboPackets.PacketPercentage > 50)
            return "Data-Heavy (Large file transfers)";

        if (tinyPackets is not null && tinyPackets.PacketPercentage > 40 &&
            jumboPackets is not null && jumboPackets.PacketPercentage > 20)
            return "Typical Mixed Traffic";

        return "Varied Distribution";
    }
}
