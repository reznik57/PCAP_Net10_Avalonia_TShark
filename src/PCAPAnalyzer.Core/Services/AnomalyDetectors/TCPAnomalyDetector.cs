using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects TCP-specific anomalies: retransmissions, duplicate ACKs, out-of-order packets, zero window
/// </summary>
public sealed class TCPAnomalyDetector : IAnomalyDetector
{
    private const int RETRANSMISSION_THRESHOLD = 3; // % threshold
    private const int DUP_ACK_THRESHOLD = 3; // Triple duplicate ACK triggers fast retransmit
    private const double OUT_OF_ORDER_THRESHOLD = 0.05; // 5% out of order packets

    public string Name => "TCP Anomaly Detector";
    public AnomalyCategory Category => AnomalyCategory.TCP;

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var tcpPackets = packets.Where(p => p.IsTcp()).ToList();

        if (!tcpPackets.Any())
            return anomalies;

        // Group by TCP stream
        var streams = GroupByTCPStream(tcpPackets);

        foreach (var stream in streams)
        {
            var streamPackets = stream.Value.OrderBy(p => p.Timestamp).ToList();

            anomalies.AddRange(DetectRetransmissions(streamPackets, stream.Key));
            anomalies.AddRange(DetectDuplicateACKs(streamPackets, stream.Key));
            anomalies.AddRange(DetectOutOfOrder(streamPackets, stream.Key));
            anomalies.AddRange(DetectZeroWindow(streamPackets, stream.Key));
        }

        return anomalies;
    }

    private Dictionary<string, List<PacketInfo>> GroupByTCPStream(List<PacketInfo> packets)
    {
        return packets
            .GroupBy(p => GetTCPStreamKey(p))
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    private string GetTCPStreamKey(PacketInfo packet)
    {
        var endpoints = new[]
        {
            $"{packet.SourceIP}:{packet.SourcePort}",
            $"{packet.DestinationIP}:{packet.DestinationPort}"
        };
        Array.Sort(endpoints);
        return string.Join("<->", endpoints);
    }

    private List<NetworkAnomaly> DetectRetransmissions(List<PacketInfo> packets, string streamId)
    {
        var anomalies = new List<NetworkAnomaly>();
        var retransmissions = packets.Where(p => p.IsTcpRetransmission()).ToList();

        if (retransmissions.Any())
        {
            var rate = (double)retransmissions.Count / packets.Count * 100;

            if (rate >= RETRANSMISSION_THRESHOLD)
            {
                var firstPacket = packets.First();
                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.TCP,
                    Type = "TCP Retransmission",
                    Description = $"High TCP retransmission rate: {rate:F2}% ({retransmissions.Count} retransmissions)",
                    DetectedAt = firstPacket.Timestamp,
                    DetectorName = Name,
                    SourceIP = firstPacket.SourceIP ?? "",
                    DestinationIP = firstPacket.DestinationIP ?? "",
                    SourcePort = firstPacket.SourcePort,
                    DestinationPort = firstPacket.DestinationPort,
                    Protocol = "TCP",
                    Severity = rate > 10 ? AnomalySeverity.Critical :
                              rate > 5 ? AnomalySeverity.High : AnomalySeverity.Medium,
                    AffectedFrames = retransmissions.Select(p => (long)p.FrameNumber).ToList(),
                    TCPStream = streamId,
                    Metrics = new Dictionary<string, object>
                    {
                        { "RetransmissionRate", rate },
                        { "RetransmittedPackets", retransmissions.Count },
                        { "TotalStreamPackets", packets.Count }
                    },
                    Recommendation = rate > 10
                        ? "Critical: Network issues detected. Check network infrastructure for packet loss, congestion, or faulty equipment."
                        : "Monitor network performance. Consider QoS adjustments if retransmissions persist."
                });
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectDuplicateACKs(List<PacketInfo> packets, string streamId)
    {
        var anomalies = new List<NetworkAnomaly>();
        var dupAcks = packets.Where(p => p.IsTcpDuplicateAck()).ToList();

        if (dupAcks.Count >= DUP_ACK_THRESHOLD)
        {
            var firstPacket = packets.First();
            anomalies.Add(new NetworkAnomaly
            {
                Category = AnomalyCategory.TCP,
                Type = "TCP Duplicate ACK",
                Description = $"{dupAcks.Count} duplicate ACKs detected in stream",
                DetectedAt = dupAcks.First().Timestamp,
                DetectorName = Name,
                SourceIP = firstPacket.SourceIP ?? "",
                DestinationIP = firstPacket.DestinationIP ?? "",
                SourcePort = firstPacket.SourcePort,
                DestinationPort = firstPacket.DestinationPort,
                Protocol = "TCP",
                Severity = dupAcks.Count > 10 ? AnomalySeverity.High : AnomalySeverity.Medium,
                AffectedFrames = dupAcks.Select(p => (long)p.FrameNumber).ToList(),
                TCPStream = streamId,
                Metrics = new Dictionary<string, object>
                {
                    { "DuplicateACKCount", dupAcks.Count }
                },
                Recommendation = "Duplicate ACKs indicate packet loss or out-of-order delivery. Check network path and routing."
            });
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectOutOfOrder(List<PacketInfo> packets, string streamId)
    {
        var anomalies = new List<NetworkAnomaly>();
        var outOfOrder = packets.Where(p => p.IsTcpOutOfOrder()).ToList();

        if (outOfOrder.Any())
        {
            var rate = (double)outOfOrder.Count / packets.Count;

            if (rate >= OUT_OF_ORDER_THRESHOLD)
            {
                var firstPacket = packets.First();
                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.TCP,
                    Type = "TCP Out-of-Order",
                    Description = $"{outOfOrder.Count} out-of-order packets detected ({rate * 100:F2}%)",
                    DetectedAt = outOfOrder.First().Timestamp,
                    DetectorName = Name,
                    SourceIP = firstPacket.SourceIP ?? "",
                    DestinationIP = firstPacket.DestinationIP ?? "",
                    SourcePort = firstPacket.SourcePort,
                    DestinationPort = firstPacket.DestinationPort,
                    Protocol = "TCP",
                    Severity = rate > 0.1 ? AnomalySeverity.High : AnomalySeverity.Medium,
                    AffectedFrames = outOfOrder.Select(p => (long)p.FrameNumber).ToList(),
                    TCPStream = streamId,
                    Metrics = new Dictionary<string, object>
                    {
                        { "OutOfOrderRate", rate },
                        { "OutOfOrderCount", outOfOrder.Count }
                    },
                    Recommendation = "Out-of-order packets suggest routing issues or load balancing problems. Verify network path consistency."
                });
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectZeroWindow(List<PacketInfo> packets, string streamId)
    {
        var anomalies = new List<NetworkAnomaly>();
        var zeroWindow = packets.Where(p => p.IsTcpZeroWindow()).ToList();

        if (zeroWindow.Any())
        {
            var firstPacket = packets.First();
            anomalies.Add(new NetworkAnomaly
            {
                Category = AnomalyCategory.TCP,
                Type = "TCP Zero Window",
                Description = $"{zeroWindow.Count} zero window advertisements detected",
                DetectedAt = zeroWindow.First().Timestamp,
                DetectorName = Name,
                SourceIP = firstPacket.SourceIP ?? "",
                DestinationIP = firstPacket.DestinationIP ?? "",
                SourcePort = firstPacket.SourcePort,
                DestinationPort = firstPacket.DestinationPort,
                Protocol = "TCP",
                Severity = zeroWindow.Count > 5 ? AnomalySeverity.High : AnomalySeverity.Medium,
                AffectedFrames = zeroWindow.Select(p => (long)p.FrameNumber).ToList(),
                TCPStream = streamId,
                Metrics = new Dictionary<string, object>
                {
                    { "ZeroWindowCount", zeroWindow.Count }
                },
                Recommendation = "Zero window indicates receiver buffer exhaustion. Check application performance and receiver capacity."
            });
        }

        return anomalies;
    }
}
