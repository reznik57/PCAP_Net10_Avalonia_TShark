using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Interfaces.Statistics;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// Time series generation service for traffic visualization.
    /// Implements ITimeSeriesGenerator for DI injection and testability.
    /// </summary>
    public sealed class TimeSeriesGeneratorService : ITimeSeriesGenerator
    {
        public (List<TimeSeriesDataPoint> ThroughputSeries,
                List<TimeSeriesDataPoint> PacketsSeries,
                List<TimeSeriesDataPoint> AnomaliesSeries)
            GenerateTimeSeriesWithMetrics(
                IEnumerable<PacketInfo> packets,
                TimeSpan interval,
                List<SecurityThreat> securityThreats)
        {
            var packetList = packets.OrderBy(p => p.Timestamp).ToList();
            if (!packetList.Any())
                return (new List<TimeSeriesDataPoint>(), new List<TimeSeriesDataPoint>(), new List<TimeSeriesDataPoint>());

            var throughputSeries = new List<TimeSeriesDataPoint>();
            var packetsSeries = new List<TimeSeriesDataPoint>();
            var anomaliesSeries = new List<TimeSeriesDataPoint>();

            var startTime = packetList.First().Timestamp;
            var endTime = packetList.Last().Timestamp;
            var currentTime = startTime;

            while (currentTime <= endTime)
            {
                var intervalEnd = currentTime.Add(interval);
                var intervalPackets = packetList
                    .Where(p => p.Timestamp >= currentTime && p.Timestamp < intervalEnd)
                    .ToList();

                // Calculate throughput in KB/s
                var totalBytes = intervalPackets.Sum(static p => (long)p.Length);
                var throughputKBps = (totalBytes / 1024.0) / interval.TotalSeconds;
                throughputSeries.Add(new TimeSeriesDataPoint
                {
                    Timestamp = currentTime,
                    Value = throughputKBps,
                    Series = "Throughput",
                    PacketsPerSecond = intervalPackets.Count / interval.TotalSeconds,
                    AdditionalMetrics = new Dictionary<string, double>
                    {
                        { "PacketCount", intervalPackets.Count },
                        { "AverageSize", intervalPackets.Any() ? intervalPackets.Average(p => p.Length) : 0 }
                    }
                });

                // Calculate packets per second
                var pps = intervalPackets.Count / interval.TotalSeconds;
                packetsSeries.Add(new TimeSeriesDataPoint
                {
                    Timestamp = currentTime,
                    Value = pps,
                    PacketsPerSecond = pps,
                    Series = "PacketsPerSecond"
                });

                // Calculate security anomalies per second
                var intervalSecurityThreats = securityThreats.Count(t =>
                    t.DetectedAt >= currentTime && t.DetectedAt < intervalEnd);
                var aps = intervalSecurityThreats / interval.TotalSeconds;
                anomaliesSeries.Add(new TimeSeriesDataPoint
                {
                    Timestamp = currentTime,
                    Value = aps,
                    AnomaliesPerSecond = aps,
                    Series = "AnomaliesPerSecond"
                });

                currentTime = intervalEnd;
            }

            return (throughputSeries, packetsSeries, anomaliesSeries);
        }

        public List<TimeSeriesDataPoint> GenerateTrafficThreatsTimeSeries(
            List<PacketInfo> packets,
            DateTime startTime,
            DateTime endTime,
            TimeSpan interval)
        {
            var series = new List<TimeSeriesDataPoint>();
            if (packets is null || !packets.Any() || startTime >= endTime)
                return series;

            var currentTime = startTime;
            while (currentTime < endTime)
            {
                var intervalEnd = currentTime.Add(interval);
                var intervalPackets = packets
                    .Where(p => p.Timestamp >= currentTime && p.Timestamp < intervalEnd)
                    .ToList();

                var threatIndicators = CountNetworkAnomalies(intervalPackets);
                var tps = threatIndicators / interval.TotalSeconds;

                series.Add(new TimeSeriesDataPoint
                {
                    Timestamp = currentTime,
                    Value = tps,
                    Series = "ThreatsPerSecond"
                });

                currentTime = intervalEnd;
            }

            return series;
        }

        public int CountNetworkAnomalies(List<PacketInfo> packets)
        {
            if (packets is null || packets.Count == 0)
                return 0;

            var count = 0;
            foreach (var p in packets)
            {
                // Tiny packets (potential scans, keep-alives, or malformed)
                if (p.Length < 64)
                    count++;
                // Jumbo frames (unusual for most networks)
                else if (p.Length > 1500)
                    count++;
                // TCP packets with no payload and both high ports
                else if (p.Protocol == Protocol.TCP && p.Length < 80 &&
                         p.SourcePort > 49152 && p.DestinationPort > 49152)
                    count++;
                // ICMP traffic
                else if (p.Protocol == Protocol.ICMP)
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
            if (!packets.Any())
                return 0;

            var maxCount = 0;
            var currentTime = start;

            while (currentTime <= end)
            {
                var windowEnd = currentTime.Add(window);
                var count = packets.Count(p => p.Timestamp >= currentTime && p.Timestamp < windowEnd);
                maxCount = Math.Max(maxCount, count);
                currentTime = currentTime.AddSeconds(window.TotalSeconds / 2); // 50% overlap
            }

            return maxCount;
        }
    }
}
