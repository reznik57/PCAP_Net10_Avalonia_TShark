using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// Pure calculation helpers for statistics computation.
    /// Extracted from StatisticsService to reduce file size.
    /// </summary>
    internal static class StatisticsCalculators
    {
        public static Dictionary<string, ProtocolStatistics> CalculateProtocolStatistics(
            List<PacketInfo> packets,
            Dictionary<string, string> protocolColors)
        {
            try
            {
                var protocolGroups = packets
                    .GroupBy(p => p.Protocol)
                    .Select(g => new ProtocolStatistics
                    {
                        Protocol = g.Key.ToString(),
                        PacketCount = g.Count(),
                        ByteCount = g.Sum(static p => (long)p.Length),
                        Percentage = (double)g.Count() / packets.Count * 100,
                        Color = protocolColors.ContainsKey(g.Key.ToString()) ? protocolColors[g.Key.ToString()] : protocolColors["Other"]
                    })
                    .OrderByDescending(p => p.PacketCount)
                    .Take(10)
                    .ToDictionary(p => p.Protocol);

                return protocolGroups;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[StatisticsCalculators] Error calculating protocol statistics: {ex.Message}");
                return new Dictionary<string, ProtocolStatistics>();
            }
        }

        public static List<EndpointStatistics> CalculateTopEndpoints(List<PacketInfo> packets, bool isSource)
        {
            var endpoints = packets
                .GroupBy(p => isSource ? p.SourceIP : p.DestinationIP)
                .Select(g => new EndpointStatistics
                {
                    Address = g.Key,
                    PacketCount = g.Count(),
                    ByteCount = g.Sum(static p => (long)p.Length),
                    Percentage = (double)g.Count() / packets.Count * 100,
                    ProtocolBreakdown = g.GroupBy(p => p.Protocol)
                        .ToDictionary(pg => pg.Key.ToString(), pg => (long)pg.Count()),
                    IsInternal = IsInternalIP(g.Key)
                })
                .OrderByDescending(e => e.PacketCount)
                .Take(30)
                .ToList();

            return endpoints;
        }

        public static (List<ConversationStatistics> topConversations, int totalCount) CalculateTopConversations(List<PacketInfo> packets)
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
                .Select(g => new ConversationStatistics
                {
                    SourceAddress = g.Key.Source,
                    DestinationAddress = g.Key.Destination,
                    SourcePort = g.Key.SrcPort,
                    DestinationPort = g.Key.DstPort,
                    Protocol = g.Key.Protocol.ToString(),
                    PacketCount = g.Count(),
                    ByteCount = g.Sum(static p => (long)p.Length),
                    StartTime = g.Min(p => p.Timestamp),
                    EndTime = g.Max(p => p.Timestamp)
                })
                .OrderByDescending(c => c.PacketCount)
                .ToList();

            var totalCount = allConversations.Count;
            var topConversations = allConversations.Take(30).ToList();

            return (topConversations, totalCount);
        }

        public static (List<PortStatistics> topPorts, int uniqueCount) CalculateTopPortsWithCount(
            List<PacketInfo> packets,
            Dictionary<int, string> wellKnownPorts)
        {
            // Single-pass O(n) aggregation - Wireshark-compatible unique packet counting
            var portStats = new Dictionary<(int Port, Protocol Protocol), (int Count, long Bytes)>();
            var protocolOnlyStats = new Dictionary<Protocol, (int Count, long Bytes)>();

            foreach (var p in packets)
            {
                var seenInPacket = new HashSet<(int, Protocol)>();
                var hasPortData = false;

                if (p.SourcePort > 0)
                {
                    hasPortData = true;
                    var key = (p.SourcePort, p.Protocol);
                    seenInPacket.Add(key);
                    if (portStats.TryGetValue(key, out var stats))
                        portStats[key] = (stats.Count + 1, stats.Bytes + p.Length);
                    else
                        portStats[key] = (1, p.Length);
                }

                if (p.DestinationPort > 0)
                {
                    hasPortData = true;
                    var key = (p.DestinationPort, p.Protocol);
                    if (!seenInPacket.Contains(key))
                    {
                        if (portStats.TryGetValue(key, out var stats))
                            portStats[key] = (stats.Count + 1, stats.Bytes + p.Length);
                        else
                            portStats[key] = (1, p.Length);
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
                    Service = wellKnownPorts.ContainsKey(kv.Key.Port) ? wellKnownPorts[kv.Key.Port] : $"Port {kv.Key.Port}",
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

            return (topPorts.OrderByDescending(p => p.PacketCount).Take(30).ToList(), uniquePortCount);
        }

        public static Dictionary<string, ServiceStatistics> CalculateServiceStatistics(
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

        public static bool IsInternalIP(string ipAddress)
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
