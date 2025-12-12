using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects TCP-specific anomalies: retransmissions, duplicate ACKs, out-of-order packets, zero window.
///
/// MEMORY OPTIMIZATION: Uses single-pass O(n) aggregation instead of GroupBy().ToList().
/// Old approach copied ALL TCP packets into per-stream lists - catastrophic for 5M+ packet files.
/// New approach tracks per-stream statistics without copying packets.
/// </summary>
public sealed class TCPAnomalyDetector : IAnomalyDetector
{
    private const int RETRANSMISSION_THRESHOLD = 3; // % threshold
    private const int DUP_ACK_THRESHOLD = 3; // Triple duplicate ACK triggers fast retransmit
    private const double OUT_OF_ORDER_THRESHOLD = 0.05; // 5% out of order packets
    private const int MAX_AFFECTED_FRAMES = 100; // Cap frame storage per anomaly type

    public string Name => "TCP Anomaly Detector";
    public AnomalyCategory Category => AnomalyCategory.TCP;

    /// <summary>
    /// Per-stream statistics tracker - lightweight alternative to storing full packet lists.
    /// </summary>
    private sealed class StreamStats
    {
        public int TotalCount;
        public int RetransmissionCount;
        public int DupAckCount;
        public int OutOfOrderCount;
        public int ZeroWindowCount;

        // Representative frames (capped at MAX_AFFECTED_FRAMES each)
        public List<long> RetransmissionFrames = new(MAX_AFFECTED_FRAMES);
        public List<long> DupAckFrames = new(MAX_AFFECTED_FRAMES);
        public List<long> OutOfOrderFrames = new(MAX_AFFECTED_FRAMES);
        public List<long> ZeroWindowFrames = new(MAX_AFFECTED_FRAMES);

        // First packet metadata for anomaly creation
        public string? SourceIP;
        public string? DestinationIP;
        public int SourcePort;
        public int DestinationPort;
        public DateTime FirstTimestamp = DateTime.MaxValue;
        public DateTime RetransmissionFirstTime = DateTime.MaxValue;
        public DateTime DupAckFirstTime = DateTime.MaxValue;
        public DateTime OutOfOrderFirstTime = DateTime.MaxValue;
        public DateTime ZeroWindowFirstTime = DateTime.MaxValue;
    }

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var streamStats = AggregateStreamStats(packets);
        return GenerateAnomalies(streamStats);
    }

    /// <summary>
    /// Single-pass aggregation of TCP packet statistics per stream.
    /// MEMORY FIX: No GroupBy().ToList() - tracks counts without copying packets.
    /// </summary>
    private Dictionary<string, StreamStats> AggregateStreamStats(IEnumerable<PacketInfo> packets)
    {
        var streamStats = new Dictionary<string, StreamStats>();

        foreach (var p in packets)
        {
            if (!p.IsTcp())
                continue;

            var streamKey = GetTCPStreamKey(p);

            if (!streamStats.TryGetValue(streamKey, out var stats))
            {
                stats = new StreamStats
                {
                    SourceIP = p.SourceIP,
                    DestinationIP = p.DestinationIP,
                    SourcePort = p.SourcePort,
                    DestinationPort = p.DestinationPort
                };
                streamStats[streamKey] = stats;
            }

            stats.TotalCount++;
            if (p.Timestamp < stats.FirstTimestamp)
                stats.FirstTimestamp = p.Timestamp;

            TrackRetransmission(p, stats);
            TrackDuplicateAck(p, stats);
            TrackOutOfOrder(p, stats);
            TrackZeroWindow(p, stats);
        }

        return streamStats;
    }

    private static void TrackRetransmission(PacketInfo p, StreamStats stats)
    {
        if (!p.IsTcpRetransmission()) return;
        stats.RetransmissionCount++;
        if (stats.RetransmissionFrames.Count < MAX_AFFECTED_FRAMES)
            stats.RetransmissionFrames.Add(p.FrameNumber);
        if (p.Timestamp < stats.RetransmissionFirstTime)
            stats.RetransmissionFirstTime = p.Timestamp;
    }

    private static void TrackDuplicateAck(PacketInfo p, StreamStats stats)
    {
        if (!p.IsTcpDuplicateAck()) return;
        stats.DupAckCount++;
        if (stats.DupAckFrames.Count < MAX_AFFECTED_FRAMES)
            stats.DupAckFrames.Add(p.FrameNumber);
        if (p.Timestamp < stats.DupAckFirstTime)
            stats.DupAckFirstTime = p.Timestamp;
    }

    private static void TrackOutOfOrder(PacketInfo p, StreamStats stats)
    {
        if (!p.IsTcpOutOfOrder()) return;
        stats.OutOfOrderCount++;
        if (stats.OutOfOrderFrames.Count < MAX_AFFECTED_FRAMES)
            stats.OutOfOrderFrames.Add(p.FrameNumber);
        if (p.Timestamp < stats.OutOfOrderFirstTime)
            stats.OutOfOrderFirstTime = p.Timestamp;
    }

    private static void TrackZeroWindow(PacketInfo p, StreamStats stats)
    {
        if (!p.IsTcpZeroWindow()) return;
        stats.ZeroWindowCount++;
        if (stats.ZeroWindowFrames.Count < MAX_AFFECTED_FRAMES)
            stats.ZeroWindowFrames.Add(p.FrameNumber);
        if (p.Timestamp < stats.ZeroWindowFirstTime)
            stats.ZeroWindowFirstTime = p.Timestamp;
    }

    /// <summary>
    /// Generate NetworkAnomaly objects from aggregated stream statistics.
    /// </summary>
    private List<NetworkAnomaly> GenerateAnomalies(Dictionary<string, StreamStats> streamStats)
    {
        var anomalies = new List<NetworkAnomaly>();

        foreach (var (streamId, stats) in streamStats)
        {
            TryAddRetransmissionAnomaly(anomalies, streamId, stats);
            TryAddDuplicateAckAnomaly(anomalies, streamId, stats);
            TryAddOutOfOrderAnomaly(anomalies, streamId, stats);
            TryAddZeroWindowAnomaly(anomalies, streamId, stats);
        }

        return anomalies;
    }

    private void TryAddRetransmissionAnomaly(List<NetworkAnomaly> anomalies, string streamId, StreamStats stats)
    {
        if (stats.RetransmissionCount <= 0) return;

        var rate = (double)stats.RetransmissionCount / stats.TotalCount * 100;
        if (rate < RETRANSMISSION_THRESHOLD) return;

        anomalies.Add(new NetworkAnomaly
        {
            Category = AnomalyCategory.TCP,
            Type = "TCP Retransmission",
            Description = $"High TCP retransmission rate: {rate:F2}% ({stats.RetransmissionCount} retransmissions)",
            DetectedAt = stats.RetransmissionFirstTime,
            DetectorName = Name,
            SourceIP = stats.SourceIP ?? "",
            DestinationIP = stats.DestinationIP ?? "",
            SourcePort = stats.SourcePort,
            DestinationPort = stats.DestinationPort,
            Protocol = "TCP",
            Severity = rate > 10 ? AnomalySeverity.Critical :
                      rate > 5 ? AnomalySeverity.High : AnomalySeverity.Medium,
            AffectedFrames = stats.RetransmissionFrames,
            TCPStream = streamId,
            Metrics = new Dictionary<string, object>
            {
                { "RetransmissionRate", rate },
                { "RetransmittedPackets", stats.RetransmissionCount },
                { "TotalStreamPackets", stats.TotalCount }
            },
            Recommendation = rate > 10
                ? "Critical: Network issues detected. Check network infrastructure for packet loss, congestion, or faulty equipment."
                : "Monitor network performance. Consider QoS adjustments if retransmissions persist."
        });
    }

    private void TryAddDuplicateAckAnomaly(List<NetworkAnomaly> anomalies, string streamId, StreamStats stats)
    {
        if (stats.DupAckCount < DUP_ACK_THRESHOLD) return;

        anomalies.Add(new NetworkAnomaly
        {
            Category = AnomalyCategory.TCP,
            Type = "TCP Duplicate ACK",
            Description = $"{stats.DupAckCount} duplicate ACKs detected in stream",
            DetectedAt = stats.DupAckFirstTime,
            DetectorName = Name,
            SourceIP = stats.SourceIP ?? "",
            DestinationIP = stats.DestinationIP ?? "",
            SourcePort = stats.SourcePort,
            DestinationPort = stats.DestinationPort,
            Protocol = "TCP",
            Severity = stats.DupAckCount > 10 ? AnomalySeverity.High : AnomalySeverity.Medium,
            AffectedFrames = stats.DupAckFrames,
            TCPStream = streamId,
            Metrics = new Dictionary<string, object>
            {
                { "DuplicateACKCount", stats.DupAckCount }
            },
            Recommendation = "Duplicate ACKs indicate packet loss or out-of-order delivery. Check network path and routing."
        });
    }

    private void TryAddOutOfOrderAnomaly(List<NetworkAnomaly> anomalies, string streamId, StreamStats stats)
    {
        if (stats.OutOfOrderCount <= 0) return;

        var rate = (double)stats.OutOfOrderCount / stats.TotalCount;
        if (rate < OUT_OF_ORDER_THRESHOLD) return;

        anomalies.Add(new NetworkAnomaly
        {
            Category = AnomalyCategory.TCP,
            Type = "TCP Out-of-Order",
            Description = $"{stats.OutOfOrderCount} out-of-order packets detected ({rate * 100:F2}%)",
            DetectedAt = stats.OutOfOrderFirstTime,
            DetectorName = Name,
            SourceIP = stats.SourceIP ?? "",
            DestinationIP = stats.DestinationIP ?? "",
            SourcePort = stats.SourcePort,
            DestinationPort = stats.DestinationPort,
            Protocol = "TCP",
            Severity = rate > 0.1 ? AnomalySeverity.High : AnomalySeverity.Medium,
            AffectedFrames = stats.OutOfOrderFrames,
            TCPStream = streamId,
            Metrics = new Dictionary<string, object>
            {
                { "OutOfOrderRate", rate },
                { "OutOfOrderCount", stats.OutOfOrderCount }
            },
            Recommendation = "Out-of-order packets suggest routing issues or load balancing problems. Verify network path consistency."
        });
    }

    private void TryAddZeroWindowAnomaly(List<NetworkAnomaly> anomalies, string streamId, StreamStats stats)
    {
        if (stats.ZeroWindowCount <= 0) return;

        anomalies.Add(new NetworkAnomaly
        {
            Category = AnomalyCategory.TCP,
            Type = "TCP Zero Window",
            Description = $"{stats.ZeroWindowCount} zero window advertisements detected",
            DetectedAt = stats.ZeroWindowFirstTime,
            DetectorName = Name,
            SourceIP = stats.SourceIP ?? "",
            DestinationIP = stats.DestinationIP ?? "",
            SourcePort = stats.SourcePort,
            DestinationPort = stats.DestinationPort,
            Protocol = "TCP",
            Severity = stats.ZeroWindowCount > 5 ? AnomalySeverity.High : AnomalySeverity.Medium,
            AffectedFrames = stats.ZeroWindowFrames,
            TCPStream = streamId,
            Metrics = new Dictionary<string, object>
            {
                { "ZeroWindowCount", stats.ZeroWindowCount }
            },
            Recommendation = "Zero window indicates receiver buffer exhaustion. Check application performance and receiver capacity."
        });
    }

    private static string GetTCPStreamKey(PacketInfo packet)
    {
        // Normalize: lower endpoint first for consistent bidirectional matching
        var ep1 = $"{packet.SourceIP}:{packet.SourcePort}";
        var ep2 = $"{packet.DestinationIP}:{packet.DestinationPort}";
        return string.Compare(ep1, ep2, StringComparison.Ordinal) < 0
            ? $"{ep1}<->{ep2}"
            : $"{ep2}<->{ep1}";
    }
}
