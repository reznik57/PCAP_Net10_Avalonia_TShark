using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces.Statistics
{
    /// <summary>
    /// Time series generation service for traffic visualization.
    /// </summary>
    public interface ITimeSeriesGenerator
    {
        /// <summary>
        /// Generates time series data for throughput, packets/sec, and anomalies/sec.
        /// </summary>
        (List<TimeSeriesDataPoint> ThroughputSeries,
         List<TimeSeriesDataPoint> PacketsSeries,
         List<TimeSeriesDataPoint> AnomaliesSeries)
            GenerateTimeSeriesWithMetrics(
                IEnumerable<PacketInfo> packets,
                TimeSpan interval,
                List<SecurityThreat> securityThreats);

        /// <summary>
        /// Generates time series of threat indicators per interval.
        /// </summary>
        List<TimeSeriesDataPoint> GenerateTrafficThreatsTimeSeries(
            List<PacketInfo> packets,
            DateTime startTime,
            DateTime endTime,
            TimeSpan interval);

        /// <summary>
        /// Counts network anomaly indicators in a set of packets.
        /// </summary>
        int CountNetworkAnomalies(List<PacketInfo> packets);

        /// <summary>
        /// Calculates maximum packets in any sliding window of specified duration.
        /// </summary>
        int CalculateMaxPacketsPerWindow(
            List<PacketInfo> packets,
            TimeSpan window,
            DateTime start,
            DateTime end);
    }
}
