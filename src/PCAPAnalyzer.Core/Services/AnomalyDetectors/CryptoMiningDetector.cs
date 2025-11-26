using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects cryptocurrency mining and cryptojacking activity
/// </summary>
public class CryptoMiningDetector : ISpecializedDetector
{
    private const int MINING_CONNECTION_THRESHOLD = 5; // Minimum concurrent connections to mining pools
    private const int MINING_TRAFFIC_BYTES_THRESHOLD = 1024 * 1024; // 1MB of traffic to mining pools

    // Common mining pool ports
    private static readonly HashSet<int> MiningPorts = new()
    {
        3333, 3334, 3335, 3336, // Stratum protocol
        4444, // Monero
        5555, 5556, // Alternative Stratum
        7777, 8008, 8332, 8333, // Bitcoin
        9332, 9999, // Various pools
        14444, 14433, // Zcash
        45560, 45700 // Monero/XMR
    };

    // Known mining pool domains/IPs patterns (simplified - real implementation would have comprehensive list)
    private static readonly string[] MiningPoolPatterns = new[]
    {
        "pool", "mining", "nicehash", "ethermine", "f2pool", "antpool",
        "slushpool", "viaBTC", "btc.com", "poolin", "nanopool", "sparkpool",
        "2miners", "hiveon", "ezil", "flexpool", "herominers", "moneroocean",
        "supportxmr", "minexmr", "xmrpool", "hashvault", "miningpoolhub"
    };

    public string Name => "Cryptocurrency Mining Detector";
    public AnomalyCategory Category => AnomalyCategory.Security;
    public int Priority => 6;

    public bool CanDetect(IEnumerable<PacketInfo> packets)
    {
        // Run if there's traffic to known mining ports
        return packets.Any(p =>
            MiningPorts.Contains(p.DestinationPort) ||
            MiningPorts.Contains(p.SourcePort) ||
            IsPotentialMiningTraffic(p));
    }

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var packetList = packets.ToList();

        if (!packetList.Any())
            return anomalies;

        anomalies.AddRange(DetectMiningPoolConnections(packetList));
        anomalies.AddRange(DetectExcessiveConnections(packetList));
        anomalies.AddRange(DetectStratumProtocol(packetList));

        return anomalies;
    }

    private List<NetworkAnomaly> DetectMiningPoolConnections(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Find packets to known mining ports or domains
        var miningPackets = packets.Where(p => IsPotentialMiningTraffic(p)).ToList();

        if (!miningPackets.Any())
            return anomalies;

        // Group by source IP (potential mining host)
        var sourceGroups = miningPackets.GroupBy(p => p.SourceIP);

        foreach (var source in sourceGroups)
        {
            var sourcePackets = source.ToList();
            var uniqueDestinations = sourcePackets.Select(p => $"{p.DestinationIP}:{p.DestinationPort}").Distinct().ToList();
            var totalBytes = sourcePackets.Sum(p => (long)p.Length);

            // Check if traffic volume and connection count indicate mining
            if (uniqueDestinations.Count >= MINING_CONNECTION_THRESHOLD || totalBytes >= MINING_TRAFFIC_BYTES_THRESHOLD)
            {
                var timeWindow = sourcePackets.Max(p => p.Timestamp) - sourcePackets.Min(p => p.Timestamp);
                var duration = timeWindow.TotalMinutes;

                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.Security,
                    Type = "Cryptomining",
                    Severity = totalBytes > 10 * 1024 * 1024 ? AnomalySeverity.Critical : AnomalySeverity.High,
                    Description = $"Cryptocurrency mining activity detected from {source.Key} to {uniqueDestinations.Count} mining pools",
                    DetectedAt = sourcePackets.First().Timestamp,
                    DetectorName = Name,
                    SourceIP = source.Key ?? "",
                    Protocol = "TCP",
                    AffectedFrames = sourcePackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                    Metrics = new Dictionary<string, object>
                    {
                        { "MiningPoolConnections", uniqueDestinations.Count },
                        { "TotalBytes", totalBytes },
                        { "PacketCount", sourcePackets.Count },
                        { "DurationMinutes", duration },
                        { "MiningPools", uniqueDestinations.Take(10).ToList() }
                    },
                    Evidence = new Dictionary<string, object>
                    {
                        { "DetectedPorts", sourcePackets.Select(p => p.DestinationPort).Distinct().Where(port => MiningPorts.Contains(port)).ToList() }
                    },
                    Recommendation = "Cryptomining detected - potential cryptojacking or unauthorized mining. Block mining pool connections, investigate source host for malware, and review system resource usage."
                });
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectExcessiveConnections(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Look for hosts with excessive outbound connections to same ports
        var tcpPackets = packets.Where(p => p.Protocol == Protocol.TCP).ToList();

        if (!tcpPackets.Any())
            return anomalies;

        // Group by source and destination port
        var portGroups = tcpPackets.GroupBy(p => new { p.SourceIP, p.DestinationPort });

        foreach (var group in portGroups)
        {
            if (MiningPorts.Contains(group.Key.DestinationPort))
            {
                var connections = group.Select(p => p.DestinationIP).Distinct().Count();

                if (connections >= 10) // Connecting to 10+ different IPs on same mining port
                {
                    var groupPackets = group.ToList();
                    var totalBytes = groupPackets.Sum(p => (long)p.Length);

                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.Security,
                        Type = "Cryptomining Pool Scanning",
                        Severity = AnomalySeverity.High,
                        Description = $"Host {group.Key.SourceIP} connecting to {connections} different mining pools on port {group.Key.DestinationPort}",
                        DetectedAt = groupPackets.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = group.Key.SourceIP ?? "",
                        DestinationPort = group.Key.DestinationPort,
                        Protocol = "TCP",
                        AffectedFrames = groupPackets.Select(p => (long)p.FrameNumber).Take(50).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "UniqueConnections", connections },
                            { "Port", group.Key.DestinationPort },
                            { "TotalBytes", totalBytes },
                            { "PacketCount", groupPackets.Count }
                        },
                        Recommendation = "Multiple connections to mining pools detected. This may indicate mining malware searching for active pools. Investigate and clean the source host."
                    });
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectStratumProtocol(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Stratum protocol is JSON-RPC based, look for characteristic patterns
        var tcpPackets = packets.Where(p =>
            p.Protocol == Protocol.TCP &&
            (MiningPorts.Contains(p.DestinationPort) || MiningPorts.Contains(p.SourcePort))).ToList();

        if (!tcpPackets.Any())
            return anomalies;

        // Look for Stratum-related keywords in packet info
        var stratumPackets = tcpPackets.Where(p =>
            p.Info?.Contains("mining.subscribe", StringComparison.OrdinalIgnoreCase) == true ||
            p.Info?.Contains("mining.authorize", StringComparison.OrdinalIgnoreCase) == true ||
            p.Info?.Contains("mining.submit", StringComparison.OrdinalIgnoreCase) == true ||
            p.Info?.Contains("stratum", StringComparison.OrdinalIgnoreCase) == true ||
            p.Info?.Contains("\"method\":", StringComparison.OrdinalIgnoreCase) == true).ToList();

        if (stratumPackets.Any())
        {
            // Group by source
            var sourceGroups = stratumPackets.GroupBy(p => p.SourceIP);

            foreach (var source in sourceGroups)
            {
                var sourcePackets = source.ToList();
                var subscribes = sourcePackets.Count(p => p.Info?.Contains("mining.subscribe", StringComparison.OrdinalIgnoreCase) == true);
                var authorizes = sourcePackets.Count(p => p.Info?.Contains("mining.authorize", StringComparison.OrdinalIgnoreCase) == true);
                var submits = sourcePackets.Count(p => p.Info?.Contains("mining.submit", StringComparison.OrdinalIgnoreCase) == true);

                if (subscribes > 0 || authorizes > 0 || submits > 0)
                {
                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.Security,
                        Type = "Stratum Mining Protocol",
                        Severity = AnomalySeverity.Critical,
                        Description = $"Stratum mining protocol detected from {source.Key}: {subscribes} subscribes, {authorizes} authorizes, {submits} submits",
                        DetectedAt = sourcePackets.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = source.Key ?? "",
                        Protocol = "Stratum/TCP",
                        AffectedFrames = sourcePackets.Select(p => (long)p.FrameNumber).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "StratumSubscribes", subscribes },
                            { "StratumAuthorizes", authorizes },
                            { "StratumSubmits", submits },
                            { "TotalStratumPackets", sourcePackets.Count },
                            { "UniquePools", sourcePackets.Select(p => $"{p.DestinationIP}:{p.DestinationPort}").Distinct().Count() }
                        },
                        Recommendation = "Active cryptocurrency mining detected using Stratum protocol. This is strong evidence of cryptomining activity. Block connections immediately and scan for malware."
                    });
                }
            }
        }

        return anomalies;
    }

    private bool IsPotentialMiningTraffic(PacketInfo packet)
    {
        // Check if packet is to a known mining port
        if (MiningPorts.Contains(packet.DestinationPort) || MiningPorts.Contains(packet.SourcePort))
            return true;

        // Check if packet info contains mining-related keywords
        if (packet.Info != null)
        {
            foreach (var pattern in MiningPoolPatterns)
            {
                if (packet.Info.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        // Check destination IP against mining pool patterns (simplified)
        if (!string.IsNullOrEmpty(packet.DestinationIP))
        {
            foreach (var pattern in MiningPoolPatterns)
            {
                if (packet.DestinationIP.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }
}
