using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.Charts;

/// <summary>
/// Result of stream analysis containing all computed data.
/// </summary>
public sealed class StreamAnalysisResult
{
    public List<StreamInfo> TopStreams { get; init; } = [];
    public Dictionary<DateTime, PacketsTimelineDataPoint> Buckets { get; init; } = [];
    public List<TopStreamTableItem> TopByPackets { get; init; } = [];
    public List<TopStreamTableItem> TopByBytes { get; init; } = [];
    public DateTime MinTime { get; init; }
    public DateTime MaxTime { get; init; }
    public TimeSpan BucketSize { get; init; }
}

/// <summary>
/// Stream statistics for analysis.
/// </summary>
public sealed class StreamStats
{
    public string StreamKey { get; set; } = "";
    public string SourceIP { get; set; } = "";
    public int SourcePort { get; set; }
    public string DestIP { get; set; } = "";
    public int DestPort { get; set; }
    public int Count { get; set; }
    public long Bytes { get; set; }
}

/// <summary>
/// Analyzes packet streams for chart visualization.
/// Extracts top streams, calculates bucket statistics, and builds timeline data.
/// </summary>
public sealed class StreamAnalyzer
{
    private readonly int _displayCount;
    private readonly bool _sortByBytes;

    public StreamAnalyzer(int displayCount = 5, bool sortByBytes = false)
    {
        _displayCount = displayCount;
        _sortByBytes = sortByBytes;
    }

    /// <summary>
    /// Analyzes packets and returns complete stream statistics.
    /// </summary>
    public StreamAnalysisResult Analyze(IReadOnlyList<PacketInfo> packets)
    {
        if (packets is null || packets.Count == 0)
            return new StreamAnalysisResult();

        // Filter and order packets
        var orderedPackets = packets
            .Where(p => p.Timestamp != default && p.Timestamp != DateTime.MinValue)
            .OrderBy(p => p.Timestamp)
            .ToList();

        if (orderedPackets.Count == 0)
            return new StreamAnalysisResult();

        var minTime = orderedPackets.First().Timestamp;
        var maxTime = orderedPackets.Last().Timestamp;
        var timeRange = maxTime - minTime;
        var bucketSize = CalculateBucketSize(timeRange, orderedPackets.Count);

        // Build stream statistics
        var streamStats = BuildStreamStats(orderedPackets);

        // Get top streams
        var topStreams = GetTopStreams(streamStats, _displayCount, _sortByBytes);
        var topStreamKeys = topStreams.Select(s => s.StreamKey).ToHashSet();

        // Build tables (top 30)
        var (topByPackets, topByBytes) = BuildTopStreamsTables(streamStats);

        // Build time buckets
        var buckets = BuildTimeBuckets(orderedPackets, bucketSize, minTime, topStreamKeys);

        return new StreamAnalysisResult
        {
            TopStreams = topStreams,
            Buckets = buckets,
            TopByPackets = topByPackets,
            TopByBytes = topByBytes,
            MinTime = minTime,
            MaxTime = maxTime,
            BucketSize = bucketSize
        };
    }

    /// <summary>
    /// Builds stream statistics from packets.
    /// </summary>
    public static Dictionary<string, StreamStats> BuildStreamStats(IReadOnlyList<PacketInfo> packets)
    {
        var stats = new Dictionary<string, StreamStats>();

        foreach (var packet in packets)
        {
            var (streamKey, srcIP, srcPort, dstIP, dstPort) = GetStreamKey(packet);

            if (stats.TryGetValue(streamKey, out var existing))
            {
                existing.Count++;
                existing.Bytes += packet.Length;
            }
            else
            {
                stats[streamKey] = new StreamStats
                {
                    StreamKey = streamKey,
                    SourceIP = srcIP,
                    SourcePort = srcPort,
                    DestIP = dstIP,
                    DestPort = dstPort,
                    Count = 1,
                    Bytes = packet.Length
                };
            }
        }

        return stats;
    }

    /// <summary>
    /// Creates a canonical stream key from packet endpoints.
    /// </summary>
    public static (string Key, string SrcIP, int SrcPort, string DstIP, int DstPort) GetStreamKey(PacketInfo packet)
    {
        var srcEndpoint = $"{packet.SourceIP ?? ""}:{packet.SourcePort}";
        var dstEndpoint = $"{packet.DestinationIP ?? ""}:{packet.DestinationPort}";
        var endpoints = new[] { srcEndpoint, dstEndpoint }.OrderBy(x => x).ToArray();
        var streamKey = $"{endpoints[0]}↔{endpoints[1]}";

        var isReversed = srcEndpoint != endpoints[0];
        var canonicalSrcIP = isReversed ? (packet.DestinationIP ?? "") : (packet.SourceIP ?? "");
        var canonicalSrcPort = isReversed ? packet.DestinationPort : packet.SourcePort;
        var canonicalDstIP = isReversed ? (packet.SourceIP ?? "") : (packet.DestinationIP ?? "");
        var canonicalDstPort = isReversed ? packet.SourcePort : packet.DestinationPort;

        return (streamKey, canonicalSrcIP, canonicalSrcPort, canonicalDstIP, canonicalDstPort);
    }

    private static List<StreamInfo> GetTopStreams(
        Dictionary<string, StreamStats> stats,
        int count,
        bool sortByBytes)
    {
        return stats.Values
            .OrderByDescending(s => sortByBytes ? s.Bytes : s.Count)
            .Take(count)
            .Select(s => new StreamInfo
            {
                SourceIP = s.SourceIP,
                SourcePort = s.SourcePort,
                DestIP = s.DestIP,
                DestPort = s.DestPort,
                StreamKey = s.StreamKey,
                TotalPackets = s.Count,
                TotalBytes = s.Bytes
            })
            .ToList();
    }

    private static (List<TopStreamTableItem>, List<TopStreamTableItem>) BuildTopStreamsTables(
        Dictionary<string, StreamStats> stats)
    {
        var totalPackets = stats.Values.Sum(s => s.Count);
        var totalBytes = stats.Values.Sum(s => s.Bytes);

        var topByPackets = stats.Values
            .OrderByDescending(s => s.Count)
            .Take(30)
            .Select((s, index) => new TopStreamTableItem
            {
                Rank = index + 1,
                SourceIP = s.SourceIP,
                SourcePort = s.SourcePort,
                DestinationIP = s.DestIP,
                DestPort = s.DestPort,
                StreamKey = s.StreamKey,
                PacketCount = s.Count,
                ByteCount = s.Bytes,
                Percentage = totalPackets > 0 ? (s.Count * 100.0) / totalPackets : 0
            })
            .ToList();

        var topByBytes = stats.Values
            .OrderByDescending(s => s.Bytes)
            .Take(30)
            .Select((s, index) => new TopStreamTableItem
            {
                Rank = index + 1,
                SourceIP = s.SourceIP,
                SourcePort = s.SourcePort,
                DestinationIP = s.DestIP,
                DestPort = s.DestPort,
                StreamKey = s.StreamKey,
                PacketCount = s.Count,
                ByteCount = s.Bytes,
                Percentage = totalBytes > 0 ? (s.Bytes * 100.0) / totalBytes : 0
            })
            .ToList();

        return (topByPackets, topByBytes);
    }

    private static Dictionary<DateTime, PacketsTimelineDataPoint> BuildTimeBuckets(
        IReadOnlyList<PacketInfo> packets,
        TimeSpan bucketSize,
        DateTime minTime,
        HashSet<string> topStreamKeys)
    {
        var buckets = new Dictionary<DateTime, PacketsTimelineDataPoint>();

        foreach (var packet in packets)
        {
            var bucketTime = RoundToNearestBucket(packet.Timestamp, bucketSize, minTime);

            if (!buckets.TryGetValue(bucketTime, out var dataPoint))
            {
                dataPoint = new PacketsTimelineDataPoint { Time = bucketTime };
                buckets[bucketTime] = dataPoint;
            }

            dataPoint.TotalCount++;
            dataPoint.TotalBytes += packet.Length;

            var (streamKey, _, _, _, _) = GetStreamKey(packet);
            if (topStreamKeys.Contains(streamKey))
            {
                if (dataPoint.StreamCounts.TryGetValue(streamKey, out var count))
                {
                    dataPoint.StreamCounts[streamKey] = count + 1;
                    dataPoint.StreamBytes[streamKey] = dataPoint.StreamBytes[streamKey] + packet.Length;
                }
                else
                {
                    dataPoint.StreamCounts[streamKey] = 1;
                    dataPoint.StreamBytes[streamKey] = packet.Length;
                }
            }
        }

        return buckets;
    }

    /// <summary>
    /// Calculates appropriate bucket size based on time range.
    /// </summary>
    public static TimeSpan CalculateBucketSize(TimeSpan timeRange, int packetCount)
    {
        if (timeRange.TotalMinutes < 5)
            return TimeSpan.FromSeconds(1);
        if (timeRange.TotalMinutes < 15)
            return TimeSpan.FromSeconds(5);
        if (timeRange.TotalMinutes < 60)
            return TimeSpan.FromSeconds(15);
        if (timeRange.TotalHours < 6)
            return TimeSpan.FromMinutes(1);
        if (timeRange.TotalHours < 24)
            return TimeSpan.FromMinutes(5);

        const int targetBuckets = 120;
        var secondsPerBucket = timeRange.TotalSeconds / targetBuckets;
        return TimeSpan.FromSeconds(Math.Max(60, secondsPerBucket));
    }

    private static DateTime RoundToNearestBucket(DateTime time, TimeSpan bucketSize, DateTime minTime)
    {
        var ticksSinceMin = time.Ticks - minTime.Ticks;
        var bucketTicks = bucketSize.Ticks;
        var bucketIndex = ticksSinceMin / bucketTicks;
        return new DateTime(minTime.Ticks + (bucketIndex * bucketTicks));
    }
}
