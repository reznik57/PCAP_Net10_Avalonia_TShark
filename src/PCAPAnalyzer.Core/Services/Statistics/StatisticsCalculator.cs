using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using PCAPAnalyzer.Core.Interfaces.Statistics;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// Pure calculation service for statistics computation.
    /// Implements IStatisticsCalculator for DI injection and testability.
    /// </summary>
    public class StatisticsCalculator : IStatisticsCalculator
    {
        public Dictionary<string, ProtocolStatistics> CalculateProtocolStatistics(
            List<PacketInfo> packets,
            Dictionary<string, string> protocolColors)
        {
            try
            {
                var totalPackets = packets.Count;
                var protocolGroups = packets
                    .GroupBy(p => p.Protocol)
                    .Select(g =>
                    {
                        var groupList = g.ToList();
                        var packetCount = groupList.Count;
                        return new ProtocolStatistics
                        {
                            Protocol = g.Key.ToString(),
                            PacketCount = packetCount,
                            ByteCount = groupList.Sum(static p => (long)p.Length),
                            Percentage = totalPackets > 0 ? (double)packetCount / totalPackets * 100 : 0,
                            Color = protocolColors.TryGetValue(g.Key.ToString(), out var color) ? color : protocolColors.GetValueOrDefault("Other", "#808080")
                        };
                    })
                    .OrderByDescending(p => p.PacketCount)
                    .Take(10)
                    .ToDictionary(p => p.Protocol);

                return protocolGroups;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                DebugLogger.Log($"[{nameof(StatisticsCalculator)}.{nameof(CalculateProtocolStatistics)}] Error: {ex.Message}");
                return new Dictionary<string, ProtocolStatistics>();
            }
        }

        public List<EndpointStatistics> CalculateTopEndpoints(List<PacketInfo> packets, bool isSource)
        {
            var totalPackets = packets.Count;
            var endpoints = packets
                .GroupBy(p => isSource ? p.SourceIP : p.DestinationIP)
                .Select(g =>
                {
                    var groupList = g.ToList();
                    var packetCount = groupList.Count;
                    return new EndpointStatistics
                    {
                        Address = g.Key,
                        PacketCount = packetCount,
                        ByteCount = groupList.Sum(static p => (long)p.Length),
                        Percentage = totalPackets > 0 ? (double)packetCount / totalPackets * 100 : 0,
                        ProtocolBreakdown = groupList
                            .GroupBy(p => p.Protocol)
                            .ToDictionary(pg => pg.Key.ToString(), pg => (long)pg.Count()),
                        IsInternal = IsInternalIP(g.Key)
                    };
                })
                .OrderByDescending(e => e.PacketCount)
                .Take(30)
                .ToList();

            return endpoints;
        }

        public (List<ConversationStatistics> TopConversations, int TotalCount) CalculateTopConversations(List<PacketInfo> packets)
        {
            var allConversations = packets
                .Where(p => p.SourcePort > 0 && p.DestinationPort > 0)
                .GroupBy(p => new
                {
                    Source = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0 ? p.SourceIP : p.DestinationIP,
                    Destination = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0 ? p.DestinationIP : p.SourceIP,
                    SrcPort = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0 ? p.SourcePort : p.DestinationPort,
                    DstPort = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0 ? p.DestinationPort : p.SourcePort,
                    p.Protocol
                })
                .Select(g =>
                {
                    var groupList = g.ToList();
                    return new ConversationStatistics
                    {
                        SourceAddress = g.Key.Source,
                        DestinationAddress = g.Key.Destination,
                        SourcePort = g.Key.SrcPort,
                        DestinationPort = g.Key.DstPort,
                        Protocol = g.Key.Protocol.ToString(),
                        PacketCount = groupList.Count,
                        ByteCount = groupList.Sum(static p => (long)p.Length),
                        StartTime = groupList.Min(p => p.Timestamp),
                        EndTime = groupList.Max(p => p.Timestamp)
                    };
                })
                .OrderByDescending(c => c.PacketCount)
                .ToList();

            var totalCount = allConversations.Count;
            var topConversations = allConversations.Take(30).ToList();

            return (topConversations, totalCount);
        }

        /// <summary>
        /// Calculates top ports with unique count tracking.
        /// NOTE: Keeps TCP and UDP ports separate - Port 2598/TCP and Port 2598/UDP are distinct entries.
        /// This provides accurate protocol-specific port analysis.
        /// </summary>
        public (List<PortStatistics> TopPorts, int UniqueCount) CalculateTopPortsWithCount(
            List<PacketInfo> packets,
            Dictionary<int, string> wellKnownPorts)
        {
            // Single-pass O(n) aggregation - Wireshark-compatible unique packet counting
            var portStats = new Dictionary<(int Port, Protocol Protocol), (int Count, long Bytes)>();
            var protocolOnlyStats = new Dictionary<Protocol, (int Count, long Bytes)>();

            foreach (var p in packets)
            {
                var hasPortData = false;
                var srcKey = (p.SourcePort, p.Protocol);

                if (p.SourcePort > 0)
                {
                    hasPortData = true;
                    if (portStats.TryGetValue(srcKey, out var stats))
                        portStats[srcKey] = (stats.Count + 1, stats.Bytes + p.Length);
                    else
                        portStats[srcKey] = (1, p.Length);
                }

                if (p.DestinationPort > 0)
                {
                    hasPortData = true;
                    var dstKey = (p.DestinationPort, p.Protocol);
                    // Avoid double-counting when src and dst ports are the same
                    if (p.SourcePort != p.DestinationPort)
                    {
                        if (portStats.TryGetValue(dstKey, out var stats))
                            portStats[dstKey] = (stats.Count + 1, stats.Bytes + p.Length);
                        else
                            portStats[dstKey] = (1, p.Length);
                    }
                }

                if (!hasPortData)
                {
                    if (protocolOnlyStats.TryGetValue(p.Protocol, out var stats))
                        protocolOnlyStats[p.Protocol] = (stats.Count + 1, stats.Bytes + p.Length);
                    else
                        protocolOnlyStats[p.Protocol] = (1, p.Length);
                }
            }

            int uniquePortCount = portStats.Count + protocolOnlyStats.Count;

            var topPorts = portStats
                .Select(kv => new PortStatistics
                {
                    Port = kv.Key.Port,
                    Protocol = kv.Key.Protocol.ToString(),
                    Service = wellKnownPorts.TryGetValue(kv.Key.Port, out var svc) ? svc : $"Port {kv.Key.Port}",
                    PacketCount = kv.Value.Count,
                    ByteCount = kv.Value.Bytes,
                    Percentage = packets.Count > 0 ? (double)kv.Value.Count / packets.Count * 100 : 0,
                    IsWellKnown = wellKnownPorts.ContainsKey(kv.Key.Port)
                })
                .ToList();

            topPorts.AddRange(protocolOnlyStats
                .Select(kv => new PortStatistics
                {
                    Port = 0,
                    Protocol = kv.Key.ToString(),
                    Service = kv.Key.ToString(),
                    PacketCount = kv.Value.Count,
                    ByteCount = kv.Value.Bytes,
                    Percentage = packets.Count > 0 ? (double)kv.Value.Count / packets.Count * 100 : 0,
                    IsWellKnown = true
                }));

            // Return top ports sorted by packet count, keeping TCP and UDP separate
            return (topPorts.OrderByDescending(p => p.PacketCount).Take(30).ToList(), uniquePortCount);
        }

        public Dictionary<string, ServiceStatistics> CalculateServiceStatistics(
            List<PacketInfo> packets,
            Dictionary<int, string> wellKnownPorts)
        {
            var services = new Dictionary<string, ServiceStatistics>();

            foreach (var port in wellKnownPorts)
            {
                var servicePackets = packets
                    .Where(p => p.SourcePort == port.Key || p.DestinationPort == port.Key)
                    .ToList();

                if (servicePackets.Any())
                {
                    var serviceStat = new ServiceStatistics
                    {
                        ServiceName = port.Value,
                        Port = port.Key,
                        Protocol = servicePackets.First().Protocol.ToString(),
                        PacketCount = servicePackets.Count,
                        ByteCount = servicePackets.Sum(static p => (long)p.Length),
                        UniqueHosts = servicePackets
                            .SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
                            .Distinct()
                            .ToList(),
                        IsEncrypted = port.Key == 443 || port.Key == 22 || port.Key == 8443
                    };

                    services[port.Value] = serviceStat;
                }
            }

            return services;
        }

        public bool IsInternalIP(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out var ip))
            {
                var bytes = ip.GetAddressBytes();
                if (bytes.Length == 4)
                {
                    return (bytes[0] == 10) ||
                           (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                           (bytes[0] == 192 && bytes[1] == 168);
                }
            }
            return false;
        }
    }
}
