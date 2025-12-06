using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects network-layer anomalies: SYN floods, ARP spoofing, ICMP floods
/// </summary>
public class NetworkAnomalyDetector : IAnomalyDetector
{
    private const int SYN_FLOOD_THRESHOLD = 100; // SYN packets per second
    private const int ICMP_FLOOD_THRESHOLD = 50; // ICMP packets per second

    public string Name => "Network Anomaly Detector";
    public AnomalyCategory Category => AnomalyCategory.Network;

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var packetList = packets.ToList();

        if (!packetList.Any())
            return anomalies;

        anomalies.AddRange(DetectSYNFloods(packetList));
        anomalies.AddRange(DetectARPSpoofing(packetList));
        anomalies.AddRange(DetectICMPFloods(packetList));

        return anomalies;
    }

    private List<NetworkAnomaly> DetectSYNFloods(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var tcpPackets = packets.Where(p => p.IsTcp()).ToList();

        if (!tcpPackets.Any())
            return anomalies;

        // Look for TCP SYN packets without corresponding ACKs
        var synPackets = tcpPackets.Where(p => p.IsSynPacket()).ToList();
        var synAckPackets = tcpPackets.Where(p => p.IsSynAckPacket()).ToList();

        // Group by destination to detect targets
        var targetGroups = synPackets.GroupBy(p => new { p.DestinationIP, p.DestinationPort });

        foreach (var target in targetGroups)
        {
            var targetSyns = target.ToList();
            var timeWindow = targetSyns.Max(p => p.Timestamp) - targetSyns.Min(p => p.Timestamp);

            if (timeWindow.TotalSeconds > 0)
            {
                var synsPerSecond = targetSyns.Count / timeWindow.TotalSeconds;

                if (synsPerSecond >= SYN_FLOOD_THRESHOLD)
                {
                    // Check for corresponding SYN-ACKs
                    var synAcks = synAckPackets.Where(p =>
                        p.SourceIP == target.Key.DestinationIP &&
                        p.SourcePort == target.Key.DestinationPort).ToList();

                    var synAckRatio = synAcks.Count > 0 ? (double)synAcks.Count / targetSyns.Count : 0;

                    if (synAckRatio < 0.5) // Less than 50% of SYNs have SYN-ACKs
                    {
                        // Get the most active source (attacker)
                        var topSource = targetSyns
                            .GroupBy(p => p.SourceIP)
                            .OrderByDescending(g => g.Count())
                            .First();

                        anomalies.Add(new NetworkAnomaly
                        {
                            Category = AnomalyCategory.Network,
                            Type = "SYN Flood Attack",
                            Severity = AnomalySeverity.Critical,
                            Description = $"Potential SYN flood attack detected against {target.Key.DestinationIP}:{target.Key.DestinationPort}",
                            DetectedAt = targetSyns.First().Timestamp,
                            DetectorName = Name,
                            SourceIP = topSource.Key ?? "",
                            DestinationIP = target.Key.DestinationIP ?? "",
                            DestinationPort = target.Key.DestinationPort,
                            Protocol = "TCP",
                            AffectedFrames = targetSyns.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                            Metrics = new Dictionary<string, object>
                            {
                                { "SYNsPerSecond", synsPerSecond },
                                { "TotalSYNs", targetSyns.Count },
                                { "SYNACKRatio", synAckRatio },
                                { "UniqueSources", targetSyns.Select(p => p.SourceIP).Distinct().Count() },
                                { "TopSourceIP", topSource.Key ?? "" },
                                { "TopSourcePackets", topSource.Count() }
                            },
                            Recommendation = "Immediate action required: Enable SYN cookies, implement rate limiting, and consider blocking suspicious source IPs."
                        });
                    }
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectARPSpoofing(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var arpPackets = packets.Where(p => p.IsArp()).ToList();

        if (!arpPackets.Any())
            return anomalies;

        // Track IP-to-MAC mappings
        var ipMacMappings = new Dictionary<string, HashSet<string>>();

        foreach (var packet in arpPackets)
        {
            if (packet.IsArpReply())
            {
                // Extract IP and MAC from ARP reply (simplified)
                var ip = packet.SourceIP;
                var mac = ExtractMACFromInfo(packet.Info ?? "");

                if (!string.IsNullOrEmpty(ip) && !string.IsNullOrEmpty(mac))
                {
                    if (!ipMacMappings.ContainsKey(ip))
                    {
                        ipMacMappings[ip] = new HashSet<string>();
                    }

                    ipMacMappings[ip].Add(mac);
                }
            }
        }

        // Detect IPs with multiple MAC addresses
        foreach (var mapping in ipMacMappings.Where(m => m.Value.Count > 1))
        {
            var relatedPackets = arpPackets.Where(p => p.SourceIP == mapping.Key).ToList();
            // Get the most common destination from ARP replies involving this IP
            var topDestination = relatedPackets
                .Where(p => !string.IsNullOrEmpty(p.DestinationIP))
                .GroupBy(p => p.DestinationIP)
                .OrderByDescending(g => g.Count())
                .FirstOrDefault()?.Key ?? "";

            anomalies.Add(new NetworkAnomaly
            {
                Category = AnomalyCategory.Network,
                Type = "ARP Spoofing",
                Severity = AnomalySeverity.High,
                Description = $"Potential ARP spoofing detected: IP {mapping.Key} has {mapping.Value.Count} different MAC addresses",
                DetectedAt = relatedPackets.First().Timestamp,
                DetectorName = Name,
                SourceIP = mapping.Key,
                DestinationIP = topDestination,
                Protocol = "ARP",
                AffectedFrames = relatedPackets.Select(p => (long)p.FrameNumber).ToList(),
                Metrics = new Dictionary<string, object>
                {
                    { "MACAddressCount", mapping.Value.Count },
                    { "MACAddresses", mapping.Value.ToList() }
                },
                Recommendation = "Investigate ARP traffic. Consider implementing static ARP entries or using ARP inspection features."
            });
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectICMPFloods(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var icmpPackets = packets.Where(p => p.IsIcmp()).ToList();

        if (!icmpPackets.Any())
            return anomalies;

        // Group by target
        var targetGroups = icmpPackets.GroupBy(p => p.DestinationIP);

        foreach (var target in targetGroups)
        {
            var targetPackets = target.ToList();
            var timeWindow = targetPackets.Max(p => p.Timestamp) - targetPackets.Min(p => p.Timestamp);

            if (timeWindow.TotalSeconds > 0)
            {
                var icmpPerSecond = targetPackets.Count / timeWindow.TotalSeconds;

                if (icmpPerSecond >= ICMP_FLOOD_THRESHOLD)
                {
                    // Get the most active source (attacker)
                    var topSource = targetPackets
                        .GroupBy(p => p.SourceIP)
                        .OrderByDescending(g => g.Count())
                        .First();

                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.Network,
                        Type = "ICMP Flood",
                        Severity = icmpPerSecond > 100 ? AnomalySeverity.Critical : AnomalySeverity.High,
                        Description = $"ICMP flood detected against {target.Key}: {icmpPerSecond:F1} packets/second",
                        DetectedAt = targetPackets.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = topSource.Key ?? "",
                        DestinationIP = target.Key ?? "",
                        Protocol = "ICMP",
                        AffectedFrames = targetPackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "ICMPPerSecond", icmpPerSecond },
                            { "TotalICMP", targetPackets.Count },
                            { "UniqueSources", targetPackets.Select(p => p.SourceIP).Distinct().Count() },
                            { "TopSourceIP", topSource.Key ?? "" },
                            { "TopSourcePackets", topSource.Count() }
                        },
                        Recommendation = "Implement ICMP rate limiting and consider filtering ICMP traffic at the network edge."
                    });
                }
            }
        }

        return anomalies;
    }

    private string ExtractMACFromInfo(string info)
    {
        // Simplified MAC extraction from ARP info string
        // Real implementation would parse properly
        var parts = info.Split(' ');
        foreach (var part in parts)
        {
            if (part.Contains(':', StringComparison.Ordinal) && part.Split(':').Length == 6)
            {
                return part;
            }
        }
        return "";
    }
}
