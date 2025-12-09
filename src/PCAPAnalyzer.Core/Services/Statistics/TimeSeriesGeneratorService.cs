using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Interfaces.Statistics;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// Time series generation service for traffic visualization.
    /// Implements ITimeSeriesGenerator for DI injection and testability.
    ///
    /// PERFORMANCE: Uses single-pass O(n+m) bucketing instead of O(n×m) per-bucket scanning.
    /// For 5.8M packets over 285 seconds: 1.65B ops → 6M ops (275× faster)
    /// </summary>
    public sealed class TimeSeriesGeneratorService : ITimeSeriesGenerator
    {
        /// <summary>
        /// Bucket aggregator for pre-computed packet statistics per time interval.
        /// Using struct to avoid heap allocations for millions of updates.
        /// </summary>
        private struct PacketBucket
        {
            public long TotalBytes;
            public int PacketCount;
            public int AnomalyCount; // Pre-computed anomalies (tiny/jumbo/suspicious packets)
        }

        public (List<TimeSeriesDataPoint> ThroughputSeries,
                List<TimeSeriesDataPoint> PacketsSeries,
                List<TimeSeriesDataPoint> AnomaliesSeries)
            GenerateTimeSeriesWithMetrics(
                IEnumerable<PacketInfo> packets,
                TimeSpan interval,
                List<SecurityThreat> securityThreats)
        {
            var packetList = packets as IList<PacketInfo> ?? packets.ToList();
            if (packetList.Count == 0)
                return (new List<TimeSeriesDataPoint>(), new List<TimeSeriesDataPoint>(), new List<TimeSeriesDataPoint>());

            var sw = System.Diagnostics.Stopwatch.StartNew();

            // ═══════════════════════════════════════════════════════════════════
            // STEP 1: Find time range in single pass - O(n)
            // ═══════════════════════════════════════════════════════════════════
            DateTime minTime = DateTime.MaxValue, maxTime = DateTime.MinValue;
            foreach (var p in packetList)
            {
                if (p.Timestamp < minTime) minTime = p.Timestamp;
                if (p.Timestamp > maxTime) maxTime = p.Timestamp;
            }

            var startTime = minTime;
            var endTime = maxTime;
            var intervalTicks = interval.Ticks;

            // Calculate total buckets needed
            var totalBuckets = (int)((endTime.Ticks - startTime.Ticks) / intervalTicks) + 1;

            // ═══════════════════════════════════════════════════════════════════
            // STEP 2: Pre-bucket packets in single pass - O(n)
            // Using Dictionary for sparse buckets (most captures have gaps)
            // ═══════════════════════════════════════════════════════════════════
            var packetBuckets = new Dictionary<int, PacketBucket>(Math.Min(totalBuckets, 10000));

            foreach (var packet in packetList)
            {
                var bucketIndex = (int)((packet.Timestamp.Ticks - startTime.Ticks) / intervalTicks);

                if (!packetBuckets.TryGetValue(bucketIndex, out var bucket))
                {
                    bucket = new PacketBucket();
                }

                bucket.TotalBytes += packet.Length;
                bucket.PacketCount++;

                // Pre-compute anomaly indicators during bucketing (avoids second pass)
                if (IsNetworkAnomaly(packet))
                {
                    bucket.AnomalyCount++;
                }

                packetBuckets[bucketIndex] = bucket;
            }

            // ═══════════════════════════════════════════════════════════════════
            // STEP 3: Pre-bucket security threats - O(t) where t = threat count
            // ═══════════════════════════════════════════════════════════════════
            var threatBuckets = new Dictionary<int, int>(Math.Min(totalBuckets, 1000));

            if (securityThreats is { Count: > 0 })
            {
                foreach (var threat in securityThreats)
                {
                    if (threat.DetectedAt >= startTime && threat.DetectedAt <= endTime)
                    {
                        var bucketIndex = (int)((threat.DetectedAt.Ticks - startTime.Ticks) / intervalTicks);
                        threatBuckets.TryGetValue(bucketIndex, out var count);
                        threatBuckets[bucketIndex] = count + 1;
                    }
                }
            }

            var bucketingTime = sw.ElapsedMilliseconds;

            // ═══════════════════════════════════════════════════════════════════
            // STEP 4: Generate time series from pre-computed buckets - O(m)
            // ═══════════════════════════════════════════════════════════════════
            var throughputSeries = new List<TimeSeriesDataPoint>(totalBuckets);
            var packetsSeries = new List<TimeSeriesDataPoint>(totalBuckets);
            var anomaliesSeries = new List<TimeSeriesDataPoint>(totalBuckets);

            var currentTime = startTime;
            var intervalSeconds = interval.TotalSeconds;

            for (int i = 0; i < totalBuckets; i++)
            {
                packetBuckets.TryGetValue(i, out var packetData);
                threatBuckets.TryGetValue(i, out var threatCount);

                var totalBytes = packetData.TotalBytes;
                var packetCount = packetData.PacketCount;
                var avgSize = packetCount > 0 ? (double)totalBytes / packetCount : 0;

                // Throughput in KB/s
                var throughputKBps = (totalBytes / 1024.0) / intervalSeconds;
                throughputSeries.Add(new TimeSeriesDataPoint
                {
                    Timestamp = currentTime,
                    Value = throughputKBps,
                    Series = "Throughput",
                    PacketsPerSecond = packetCount / intervalSeconds,
                    AdditionalMetrics = new Dictionary<string, double>
                    {
                        { "PacketCount", packetCount },
                        { "AverageSize", avgSize }
                    }
                });

                // Packets per second
                var pps = packetCount / intervalSeconds;
                packetsSeries.Add(new TimeSeriesDataPoint
                {
                    Timestamp = currentTime,
                    Value = pps,
                    PacketsPerSecond = pps,
                    Series = "PacketsPerSecond"
                });

                // Security threats per second (from pre-bucketed threats)
                var tps = threatCount / intervalSeconds;
                anomaliesSeries.Add(new TimeSeriesDataPoint
                {
                    Timestamp = currentTime,
                    Value = tps,
                    AnomaliesPerSecond = tps,
                    Series = "AnomaliesPerSecond"
                });

                currentTime = currentTime.Add(interval);
            }

            sw.Stop();
            DebugLogger.Log($"[TimeSeries] Generated {totalBuckets} buckets from {packetList.Count:N0} packets in {sw.ElapsedMilliseconds}ms " +
                          $"(bucketing: {bucketingTime}ms, series: {sw.ElapsedMilliseconds - bucketingTime}ms)");

            return (throughputSeries, packetsSeries, anomaliesSeries);
        }

        /// <summary>
        /// Checks if a packet represents a network anomaly.
        /// Inlined for performance during bucketing pass.
        /// </summary>
        private static bool IsNetworkAnomaly(PacketInfo p)
        {
            // Tiny packets (potential scans, keep-alives, or malformed)
            if (p.Length < 64)
                return true;
            // Jumbo frames (unusual for most networks)
            if (p.Length > 1500)
                return true;
            // TCP packets with no payload and both high ports
            if (p.Protocol == Protocol.TCP && p.Length < 80 &&
                p.SourcePort > 49152 && p.DestinationPort > 49152)
                return true;
            // ICMP traffic
            if (p.Protocol == Protocol.ICMP)
                return true;

            return false;
        }

        public List<TimeSeriesDataPoint> GenerateTrafficThreatsTimeSeries(
            List<PacketInfo> packets,
            DateTime startTime,
            DateTime endTime,
            TimeSpan interval)
        {
            var series = new List<TimeSeriesDataPoint>();
            if (packets is null || packets.Count == 0 || startTime >= endTime)
                return series;

            var intervalTicks = interval.Ticks;
            // Original used while(currentTime < endTime) - exclusive end, so no +1
            var totalBuckets = (int)((endTime.Ticks - startTime.Ticks) / intervalTicks);

            // ═══════════════════════════════════════════════════════════════════
            // Single-pass bucketing with anomaly counting - O(n)
            // ═══════════════════════════════════════════════════════════════════
            var anomalyBuckets = new Dictionary<int, int>(Math.Min(totalBuckets, 10000));

            foreach (var packet in packets)
            {
                // Exclusive end (original: currentTime < endTime)
                if (packet.Timestamp < startTime || packet.Timestamp >= endTime)
                    continue;

                var bucketIndex = (int)((packet.Timestamp.Ticks - startTime.Ticks) / intervalTicks);

                if (IsNetworkAnomaly(packet))
                {
                    anomalyBuckets.TryGetValue(bucketIndex, out var count);
                    anomalyBuckets[bucketIndex] = count + 1;
                }
            }

            // ═══════════════════════════════════════════════════════════════════
            // Generate series from buckets - O(m)
            // ═══════════════════════════════════════════════════════════════════
            series.Capacity = totalBuckets;
            var currentTime = startTime;
            var intervalSeconds = interval.TotalSeconds;

            for (int i = 0; i < totalBuckets; i++)
            {
                anomalyBuckets.TryGetValue(i, out var threatIndicators);
                var tps = threatIndicators / intervalSeconds;

                series.Add(new TimeSeriesDataPoint
                {
                    Timestamp = currentTime,
                    Value = tps,
                    Series = "ThreatsPerSecond"
                });

                currentTime = currentTime.Add(interval);
            }

            return series;
        }

        /// <summary>
        /// Counts network anomalies in a packet list.
        /// Kept for API compatibility - callers may use this directly.
        /// </summary>
        public int CountNetworkAnomalies(List<PacketInfo> packets)
        {
            if (packets is null || packets.Count == 0)
                return 0;

            var count = 0;
            foreach (var p in packets)
            {
                if (IsNetworkAnomaly(p))
                    count++;
            }
            return count;
        }

        public int CalculateMaxPacketsPerWindow(
            List<PacketInfo> packets,
            TimeSpan window,
            DateTime start,
            DateTime end)
        {
            if (packets is null || packets.Count == 0)
                return 0;

            var windowTicks = window.Ticks;
            var halfWindowTicks = windowTicks / 2; // 50% overlap step

            // ═══════════════════════════════════════════════════════════════════
            // Single-pass bucket counting - O(n)
            // Use half-window granularity to support 50% overlap efficiently
            // ═══════════════════════════════════════════════════════════════════
            var totalHalfBuckets = (int)((end.Ticks - start.Ticks) / halfWindowTicks) + 2;
            var halfBuckets = new int[Math.Min(totalHalfBuckets, 100000)];

            foreach (var packet in packets)
            {
                if (packet.Timestamp < start || packet.Timestamp > end)
                    continue;

                var halfBucketIndex = (int)((packet.Timestamp.Ticks - start.Ticks) / halfWindowTicks);
                if (halfBucketIndex >= 0 && halfBucketIndex < halfBuckets.Length)
                {
                    halfBuckets[halfBucketIndex]++;
                }
            }

            // ═══════════════════════════════════════════════════════════════════
            // Find max by summing adjacent half-buckets (simulates full window)
            // Each full window = 2 consecutive half-buckets - O(m)
            // ═══════════════════════════════════════════════════════════════════
            var maxCount = 0;
            for (int i = 0; i < halfBuckets.Length - 1; i++)
            {
                var windowCount = halfBuckets[i] + halfBuckets[i + 1];
                if (windowCount > maxCount)
                    maxCount = windowCount;
            }

            return maxCount;
        }
    }
}
