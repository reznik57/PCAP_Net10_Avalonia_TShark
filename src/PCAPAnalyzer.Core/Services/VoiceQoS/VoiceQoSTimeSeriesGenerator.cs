using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.VoiceQoS
{
    /// <summary>
    /// Generates time-series data for VoiceQoS metrics.
    /// OPTIMIZED: Single-pass O(N) bucketing with zero-allocation flow keys.
    /// </summary>
    public class VoiceQoSTimeSeriesGenerator
    {
        // Bucket structure for efficient aggregation
        private class TimeBucket
        {
            public DateTime Timestamp;
            public List<PacketInfo> QoSPackets = [];
            public List<PacketInfo> LatencyPackets = [];
            public List<PacketInfo> JitterPackets = [];
        }

        // Zero-allocation flow key (struct instead of string)
        private readonly struct FlowKey : IEquatable<FlowKey>
        {
            private readonly string _ip1;
            private readonly string _ip2;
            private readonly int _port1;
            private readonly int _port2;
            private readonly int _hashCode;

            public FlowKey(string srcIp, string dstIp, int srcPort, int dstPort)
            {
                // Normalize direction for bidirectional flow
                var cmp = string.CompareOrdinal(srcIp, dstIp);
                if (cmp < 0 || (cmp == 0 && srcPort < dstPort))
                {
                    _ip1 = srcIp;
                    _ip2 = dstIp;
                    _port1 = srcPort;
                    _port2 = dstPort;
                }
                else
                {
                    _ip1 = dstIp;
                    _ip2 = srcIp;
                    _port1 = dstPort;
                    _port2 = srcPort;
                }

                // Pre-compute hash code
                _hashCode = HashCode.Combine(_ip1, _ip2, _port1, _port2);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public bool Equals(FlowKey other) =>
                _port1 == other._port1 && _port2 == other._port2 &&
                _ip1 == other._ip1 && _ip2 == other._ip2;

            public override bool Equals(object? obj) => obj is FlowKey other && Equals(other);
            public override int GetHashCode() => _hashCode;
        }

        /// <summary>
        /// Generate time-bucketed QoS metrics from flow collections (OPTIMIZED: Zero-copy streaming).
        /// Each flow's packets are already sorted, so we can bucket directly without flattening/sorting.
        /// This eliminates 16s+ flattening/sorting overhead for 11.5M packets.
        /// </summary>
        public VoiceQoSTimeSeriesData GenerateTimeSeriesFromFlows(
            IEnumerable<IEnumerable<PacketInfo>> qosFlows,
            IEnumerable<IEnumerable<PacketInfo>> latencyFlows,
            IEnumerable<IEnumerable<PacketInfo>> jitterFlows,
            TimeSpan? interval = null)
        {
            var bucketInterval = interval ?? TimeSpan.FromSeconds(1);

            // Find time range across all flows (streaming, no materialization)
            var startTime = DateTime.MaxValue;
            var endTime = DateTime.MinValue;

            foreach (var flow in qosFlows.Concat(latencyFlows).Concat(jitterFlows))
            {
                foreach (var packet in flow)
                {
                    if (packet.Timestamp != default)
                    {
                        if (packet.Timestamp < startTime) startTime = packet.Timestamp;
                        if (packet.Timestamp > endTime) endTime = packet.Timestamp;
                    }
                }
            }

            if (startTime == DateTime.MaxValue)
                return CreateEmptyTimeSeriesData(bucketInterval);

            var buckets = new Dictionary<long, TimeBucket>();
            var bucketIntervalTicks = bucketInterval.Ticks;

            // Stream-bucket each flow's packets (leverages existing per-flow sorting)
            foreach (var flow in qosFlows)
            {
                foreach (var packet in flow)
                {
                    if (packet.Timestamp == default) continue;
                    var bucketKey = (packet.Timestamp.Ticks - startTime.Ticks) / bucketIntervalTicks;
                    if (!buckets.TryGetValue(bucketKey, out var bucket))
                    {
                        bucket = new TimeBucket { Timestamp = startTime.AddTicks(bucketKey * bucketIntervalTicks) };
                        buckets[bucketKey] = bucket;
                    }
                    bucket.QoSPackets.Add(packet);
                }
            }

            foreach (var flow in latencyFlows)
            {
                foreach (var packet in flow)
                {
                    if (packet.Timestamp == default) continue;
                    var bucketKey = (packet.Timestamp.Ticks - startTime.Ticks) / bucketIntervalTicks;
                    if (!buckets.TryGetValue(bucketKey, out var bucket))
                    {
                        bucket = new TimeBucket { Timestamp = startTime.AddTicks(bucketKey * bucketIntervalTicks) };
                        buckets[bucketKey] = bucket;
                    }
                    bucket.LatencyPackets.Add(packet);
                }
            }

            foreach (var flow in jitterFlows)
            {
                foreach (var packet in flow)
                {
                    if (packet.Timestamp == default) continue;
                    var bucketKey = (packet.Timestamp.Ticks - startTime.Ticks) / bucketIntervalTicks;
                    if (!buckets.TryGetValue(bucketKey, out var bucket))
                    {
                        bucket = new TimeBucket { Timestamp = startTime.AddTicks(bucketKey * bucketIntervalTicks) };
                        buckets[bucketKey] = bucket;
                    }
                    bucket.JitterPackets.Add(packet);
                }
            }

            var dataPoints = GenerateDataPoints(buckets);

            var result = new VoiceQoSTimeSeriesData
            {
                StartTime = startTime,
                EndTime = endTime,
                Interval = bucketInterval,
                DataPoints = dataPoints
            };

            CalculateOverallStatistics(result);
            return result;
        }

        /// <summary>
        /// Generate time-bucketed QoS metrics from packet collections.
        /// OPTIMIZED: Single-pass bucketing with Dictionary lookup.
        /// </summary>
        public VoiceQoSTimeSeriesData GenerateTimeSeries(
            IEnumerable<PacketInfo> qosPackets,
            IEnumerable<PacketInfo> latencyPackets,
            IEnumerable<PacketInfo> jitterPackets,
            TimeSpan? interval = null)
        {
            var bucketInterval = interval ?? TimeSpan.FromSeconds(1);

            // Convert to arrays for single-pass processing
            var qosArray = qosPackets?.ToArray() ?? Array.Empty<PacketInfo>();
            var latencyArray = latencyPackets?.ToArray() ?? Array.Empty<PacketInfo>();
            var jitterArray = jitterPackets?.ToArray() ?? Array.Empty<PacketInfo>();

            // Quick exit if no data
            if (qosArray.Length == 0 && latencyArray.Length == 0 && jitterArray.Length == 0)
            {
                return CreateEmptyTimeSeriesData(bucketInterval);
            }

            // Find time range
            var (startTime, endTime) = FindTimeRange(qosArray, latencyArray, jitterArray);
            if (startTime == DateTime.MaxValue)
            {
                return CreateEmptyTimeSeriesData(bucketInterval);
            }

            // Build buckets
            var buckets = BuildTimeBuckets(qosArray, latencyArray, jitterArray, startTime, bucketInterval.Ticks);

            // Generate data points
            var dataPoints = GenerateDataPoints(buckets);

            // Create and populate result
            var result = new VoiceQoSTimeSeriesData
            {
                StartTime = startTime,
                EndTime = endTime,
                Interval = bucketInterval,
                DataPoints = dataPoints
            };

            CalculateOverallStatistics(result);
            return result;
        }

        /// <summary>
        /// Create empty time-series data with default timestamps.
        /// </summary>
        private VoiceQoSTimeSeriesData CreateEmptyTimeSeriesData(TimeSpan interval)
        {
            var now = DateTime.UtcNow;
            return new VoiceQoSTimeSeriesData
            {
                StartTime = now,
                EndTime = now,
                Interval = interval,
                DataPoints = new List<VoiceQoSTimeSeriesPoint>()
            };
        }

        /// <summary>
        /// Find time range across all packet arrays in single pass.
        /// </summary>
        private (DateTime startTime, DateTime endTime) FindTimeRange(
            PacketInfo[] qosArray,
            PacketInfo[] latencyArray,
            PacketInfo[] jitterArray)
        {
            DateTime startTime = DateTime.MaxValue;
            DateTime endTime = DateTime.MinValue;

            UpdateTimeRange(qosArray, ref startTime, ref endTime);
            UpdateTimeRange(latencyArray, ref startTime, ref endTime);
            UpdateTimeRange(jitterArray, ref startTime, ref endTime);

            return (startTime, endTime);
        }

        /// <summary>
        /// Update time range from packet array.
        /// </summary>
        private void UpdateTimeRange(PacketInfo[] packets, ref DateTime startTime, ref DateTime endTime)
        {
            foreach (var p in packets)
            {
                if (p.Timestamp != default)
                {
                    if (p.Timestamp < startTime) startTime = p.Timestamp;
                    if (p.Timestamp > endTime) endTime = p.Timestamp;
                }
            }
        }

        /// <summary>
        /// Build time buckets from packet arrays using Dictionary for O(1) lookup.
        /// </summary>
        private Dictionary<long, TimeBucket> BuildTimeBuckets(
            PacketInfo[] qosArray,
            PacketInfo[] latencyArray,
            PacketInfo[] jitterArray,
            DateTime startTime,
            long bucketIntervalTicks)
        {
            var buckets = new Dictionary<long, TimeBucket>();

            AddPacketsToBuckets(buckets, qosArray, startTime, bucketIntervalTicks,
                (bucket, packet) => bucket.QoSPackets.Add(packet));
            AddPacketsToBuckets(buckets, latencyArray, startTime, bucketIntervalTicks,
                (bucket, packet) => bucket.LatencyPackets.Add(packet));
            AddPacketsToBuckets(buckets, jitterArray, startTime, bucketIntervalTicks,
                (bucket, packet) => bucket.JitterPackets.Add(packet));

            return buckets;
        }

        /// <summary>
        /// Add packets to buckets using provided action.
        /// </summary>
        private void AddPacketsToBuckets(
            Dictionary<long, TimeBucket> buckets,
            PacketInfo[] packets,
            DateTime startTime,
            long bucketIntervalTicks,
            Action<TimeBucket, PacketInfo> addAction)
        {
            foreach (var packet in packets)
            {
                if (packet.Timestamp == default) continue;

                var bucketKey = (packet.Timestamp.Ticks - startTime.Ticks) / bucketIntervalTicks;
                if (!buckets.TryGetValue(bucketKey, out var bucket))
                {
                    bucket = new TimeBucket
                    {
                        Timestamp = startTime.AddTicks(bucketKey * bucketIntervalTicks)
                    };
                    buckets[bucketKey] = bucket;
                }
                addAction(bucket, packet);
            }
        }

        /// <summary>
        /// Generate data points from sorted buckets (OPTIMIZED: avoid LINQ allocation).
        /// </summary>
        private List<VoiceQoSTimeSeriesPoint> GenerateDataPoints(Dictionary<long, TimeBucket> buckets)
        {
            // Sort bucket keys directly (avoids LINQ allocation)
            var keys = new long[buckets.Count];
            int index = 0;
            foreach (var key in buckets.Keys)
            {
                keys[index++] = key;
            }
            Array.Sort(keys);

            var dataPoints = new List<VoiceQoSTimeSeriesPoint>(keys.Length);

            foreach (var key in keys)
            {
                var dataPoint = CreateDataPoint(buckets[key]);
                dataPoints.Add(dataPoint);
            }

            return dataPoints;
        }

        /// <summary>
        /// Create data point from bucket (OPTIMIZED: use ArrayPool, calculate min/max/avg in one pass).
        /// NOTE: Input packets are assumed to be pre-sorted by timestamp, but auto-sorts if needed.
        /// Auto-sorting handles cache restoration where packets may not be pre-sorted.
        /// </summary>
        private VoiceQoSTimeSeriesPoint CreateDataPoint(TimeBucket bucket)
        {
            // DEFENSIVE: Auto-sort if not already sorted (handles cache restoration edge cases)
            // Cost is minimal (<100ms) and prevents infinite retry loop on validation failure
            if (bucket.LatencyPackets.Count > 1 && !IsSorted(bucket.LatencyPackets))
            {
                bucket.LatencyPackets.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
            }

            if (bucket.JitterPackets.Count > 1 && !IsSorted(bucket.JitterPackets))
            {
                bucket.JitterPackets.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
            }

            // Calculate metrics (using pooled arrays)
            var (latencyMin, latencyAvg, latencyMax, latencyP5, latencyP95, latencySampleCount) =
                CalculateInterPacketStatsWithPercentiles(bucket.LatencyPackets);

            var (jitterMin, jitterAvg, jitterMax, jitterP5, jitterP95, jitterSampleCount) =
                CalculateJitterStatsWithPercentiles(bucket.JitterPackets);

            var activeConnections = CalculateActiveConnectionsFast(bucket.LatencyPackets, bucket.JitterPackets);

            return new VoiceQoSTimeSeriesPoint
            {
                Timestamp = bucket.Timestamp,
                QoSPacketCount = bucket.QoSPackets.Count,
                LatencyMin = latencyMin,
                LatencyAvg = latencyAvg,
                LatencyMax = latencyMax,
                LatencyP5 = latencyP5,
                LatencyP95 = latencyP95,
                JitterMin = jitterMin,
                JitterAvg = jitterAvg,
                JitterMax = jitterMax,
                JitterP5 = jitterP5,
                JitterP95 = jitterP95,
                ActiveConnections = activeConnections,
                Metadata = new Dictionary<string, object>
                {
                    { "LatencySampleCount", latencySampleCount },
                    { "JitterSampleCount", jitterSampleCount },
                    { "QoSPacketCount", bucket.QoSPackets.Count }
                }
            };
        }

        /// <summary>
        /// Calculate inter-packet statistics (min/avg/max) in single pass (OPTIMIZED: no intermediate arrays).
        /// </summary>
        private (double min, double avg, double max, int sampleCount) CalculateInterPacketStatsFast(List<PacketInfo> sortedPackets)
        {
            if (sortedPackets.Count < 2) return (0, 0, 0, 0);

            double sum = 0;
            double min = double.MaxValue;
            double max = double.MinValue;
            int validCount = 0;

            for (int i = 1; i < sortedPackets.Count; i++)
            {
                var interval = (sortedPackets[i].Timestamp - sortedPackets[i - 1].Timestamp).TotalMilliseconds;

                // Filter outliers
                if (interval > 0 && interval < 10000)
                {
                    sum += interval;
                    if (interval < min) min = interval;
                    if (interval > max) max = interval;
                    validCount++;
                }
            }

            if (validCount == 0) return (0, 0, 0, 0);

            double avg = sum / validCount;
            return (min, avg, max, validCount);
        }

        /// <summary>
        /// Calculate jitter statistics (min/avg/max) in single pass (OPTIMIZED: use ArrayPool, avoid multiple passes).
        /// </summary>
        private (double min, double avg, double max, int sampleCount) CalculateJitterStatsFast(List<PacketInfo> sortedPackets)
        {
            if (sortedPackets.Count < 2) return (0, 0, 0, 0);

            // Rent array from pool (max size needed)
            double[]? intervalArray = null;
            try
            {
                intervalArray = ArrayPool<double>.Shared.Rent(sortedPackets.Count);
                Span<double> intervals = intervalArray.AsSpan(0, sortedPackets.Count - 1);

                int validCount = 0;
                double sum = 0;

                // Calculate intervals
                for (int i = 1; i < sortedPackets.Count; i++)
                {
                    var interval = (sortedPackets[i].Timestamp - sortedPackets[i - 1].Timestamp).TotalMilliseconds;
                    if (interval > 0 && interval < 10000)
                    {
                        intervals[validCount++] = interval;
                        sum += interval;
                    }
                }

                if (validCount < 2) return (0, 0, 0, 0);

                double mean = sum / validCount;

                // Calculate jitter (absolute deviations) in single pass with min/max tracking
                double jitterSum = 0;
                double jitterMin = double.MaxValue;
                double jitterMax = double.MinValue;

                for (int i = 0; i < validCount; i++)
                {
                    double jitter = Math.Abs(intervals[i] - mean);
                    jitterSum += jitter;
                    if (jitter < jitterMin) jitterMin = jitter;
                    if (jitter > jitterMax) jitterMax = jitter;
                }

                double jitterAvg = jitterSum / validCount;
                return (jitterMin, jitterAvg, jitterMax, validCount);
            }
            finally
            {
                if (intervalArray is not null)
                {
                    ArrayPool<double>.Shared.Return(intervalArray);
                }
            }
        }

        /// <summary>
        /// Calculate inter-packet statistics with P5/P95 percentiles.
        /// </summary>
        private (double min, double avg, double max, double p5, double p95, int sampleCount) CalculateInterPacketStatsWithPercentiles(List<PacketInfo> sortedPackets)
        {
            if (sortedPackets.Count < 2) return (0, 0, 0, 0, 0, 0);

            double[]? intervalArray = null;
            try
            {
                intervalArray = ArrayPool<double>.Shared.Rent(sortedPackets.Count);
                Span<double> intervals = intervalArray.AsSpan(0, sortedPackets.Count - 1);

                double sum = 0;
                double min = double.MaxValue;
                double max = double.MinValue;
                int validCount = 0;

                for (int i = 1; i < sortedPackets.Count; i++)
                {
                    var interval = (sortedPackets[i].Timestamp - sortedPackets[i - 1].Timestamp).TotalMilliseconds;

                    // Filter outliers
                    if (interval > 0 && interval < 10000)
                    {
                        intervals[validCount++] = interval;
                        sum += interval;
                        if (interval < min) min = interval;
                        if (interval > max) max = interval;
                    }
                }

                if (validCount == 0) return (0, 0, 0, 0, 0, 0);

                double avg = sum / validCount;

                // Calculate P5 and P95
                var validIntervals = intervals.Slice(0, validCount).ToArray();
                Array.Sort(validIntervals);
                double p5 = CalculatePercentile(validIntervals, 5);
                double p95 = CalculatePercentile(validIntervals, 95);

                return (min, avg, max, p5, p95, validCount);
            }
            finally
            {
                if (intervalArray is not null)
                {
                    ArrayPool<double>.Shared.Return(intervalArray);
                }
            }
        }

        /// <summary>
        /// Calculate jitter statistics with P5/P95 percentiles.
        /// </summary>
        private (double min, double avg, double max, double p5, double p95, int sampleCount) CalculateJitterStatsWithPercentiles(List<PacketInfo> sortedPackets)
        {
            if (sortedPackets.Count < 2) return (0, 0, 0, 0, 0, 0);

            double[]? intervalArray = null;
            try
            {
                intervalArray = ArrayPool<double>.Shared.Rent(sortedPackets.Count);
                Span<double> intervals = intervalArray.AsSpan(0, sortedPackets.Count - 1);

                int validCount = 0;
                double sum = 0;

                // Calculate intervals
                for (int i = 1; i < sortedPackets.Count; i++)
                {
                    var interval = (sortedPackets[i].Timestamp - sortedPackets[i - 1].Timestamp).TotalMilliseconds;
                    if (interval > 0 && interval < 10000)
                    {
                        intervals[validCount++] = interval;
                        sum += interval;
                    }
                }

                if (validCount < 2) return (0, 0, 0, 0, 0, 0);

                double mean = sum / validCount;

                // Calculate jitter values (absolute deviations)
                double[]? jitterArray = null;
                try
                {
                    jitterArray = ArrayPool<double>.Shared.Rent(validCount);
                    Span<double> jitters = jitterArray.AsSpan(0, validCount);

                    double jitterSum = 0;
                    double jitterMin = double.MaxValue;
                    double jitterMax = double.MinValue;

                    for (int i = 0; i < validCount; i++)
                    {
                        double jitter = Math.Abs(intervals[i] - mean);
                        jitters[i] = jitter;
                        jitterSum += jitter;
                        if (jitter < jitterMin) jitterMin = jitter;
                        if (jitter > jitterMax) jitterMax = jitter;
                    }

                    double jitterAvg = jitterSum / validCount;

                    // Calculate P5 and P95 from jitter values
                    var jitterValues = jitters.Slice(0, validCount).ToArray();
                    Array.Sort(jitterValues);
                    double p5 = CalculatePercentile(jitterValues, 5);
                    double p95 = CalculatePercentile(jitterValues, 95);

                    return (jitterMin, jitterAvg, jitterMax, p5, p95, validCount);
                }
                finally
                {
                    if (jitterArray is not null)
                    {
                        ArrayPool<double>.Shared.Return(jitterArray);
                    }
                }
            }
            finally
            {
                if (intervalArray is not null)
                {
                    ArrayPool<double>.Shared.Return(intervalArray);
                }
            }
        }

        /// <summary>
        /// Calculate percentile using linear interpolation (matches ViewModel implementation).
        /// </summary>
        private static double CalculatePercentile(double[] sortedValues, double percentile)
        {
            if (sortedValues.Length == 0) return 0;
            if (sortedValues.Length == 1) return sortedValues[0];

            double position = (percentile / 100.0) * (sortedValues.Length - 1);
            int lowerIndex = (int)Math.Floor(position);
            int upperIndex = (int)Math.Ceiling(position);

            if (lowerIndex == upperIndex)
                return sortedValues[lowerIndex];

            double weight = position - lowerIndex;
            return sortedValues[lowerIndex] * (1 - weight) + sortedValues[upperIndex] * weight;
        }

        /// <summary>
        /// Calculate active connections (OPTIMIZED: zero-allocation struct-based FlowKey).
        /// </summary>
        private int CalculateActiveConnectionsFast(List<PacketInfo> latencyPackets, List<PacketInfo> jitterPackets)
        {
            // Use HashSet with struct FlowKey for zero-allocation distinct flow counting
            var uniqueFlows = new HashSet<FlowKey>(latencyPackets.Count + jitterPackets.Count);

            foreach (var p in latencyPackets)
            {
                if (string.IsNullOrEmpty(p.SourceIP) || string.IsNullOrEmpty(p.DestinationIP))
                    continue;

                // Create bidirectional flow identifier (zero allocation)
                var flowKey = new FlowKey(p.SourceIP, p.DestinationIP, p.SourcePort, p.DestinationPort);
                uniqueFlows.Add(flowKey);
            }

            foreach (var p in jitterPackets)
            {
                if (string.IsNullOrEmpty(p.SourceIP) || string.IsNullOrEmpty(p.DestinationIP))
                    continue;

                var flowKey = new FlowKey(p.SourceIP, p.DestinationIP, p.SourcePort, p.DestinationPort);
                uniqueFlows.Add(flowKey);
            }

            return uniqueFlows.Count;
        }

        /// <summary>
        /// Check if packets are sorted by timestamp (non-throwing, for defensive auto-sort).
        /// </summary>
        private bool IsSorted(List<PacketInfo> packets)
        {
            for (int i = 1; i < packets.Count; i++)
            {
                if (packets[i].Timestamp < packets[i - 1].Timestamp)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Calculate overall summary statistics.
        /// </summary>
        private void CalculateOverallStatistics(VoiceQoSTimeSeriesData result)
        {
            if (result.DataPoints.Count == 0)
                return;

            result.TotalQoSPackets = 0;
            double latencySum = 0;
            int latencyCount = 0;
            double jitterSum = 0;
            int jitterCount = 0;
            int maxConnections = 0;
            int bucketsWithQoS = 0;

            foreach (var point in result.DataPoints)
            {
                result.TotalQoSPackets += point.QoSPacketCount;

                if (point.LatencyAvg > 0)
                {
                    latencySum += point.LatencyAvg;
                    latencyCount++;
                }

                if (point.JitterAvg > 0)
                {
                    jitterSum += point.JitterAvg;
                    jitterCount++;
                }

                if (point.ActiveConnections > maxConnections)
                {
                    maxConnections = point.ActiveConnections;
                }

                if (point.QoSPacketCount > 0)
                {
                    bucketsWithQoS++;
                }
            }

            result.OverallAvgLatency = latencyCount > 0 ? latencySum / latencyCount : 0;
            result.OverallAvgJitter = jitterCount > 0 ? jitterSum / jitterCount : 0;

            result.Metadata = new Dictionary<string, object>
            {
                { "BucketsWithLatencyData", latencyCount },
                { "BucketsWithJitterData", jitterCount },
                { "BucketsWithQoSPackets", bucketsWithQoS },
                { "MaxActiveConnections", maxConnections }
            };
        }
    }
}
