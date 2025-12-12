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
            IReadOnlyDictionary<string, string> protocolColors)
        {
            try
            {
                // MEMORY FIX: Single-pass O(n) aggregation instead of GroupBy with ToList()
                var totalPackets = packets.Count;
                var protocolAgg = new Dictionary<Protocol, (int Count, long Bytes)>();

                foreach (var p in packets)
                {
                    if (protocolAgg.TryGetValue(p.Protocol, out var stats))
                        protocolAgg[p.Protocol] = (stats.Count + 1, stats.Bytes + p.Length);
                    else
                        protocolAgg[p.Protocol] = (1, p.Length);
                }

                var protocolGroups = protocolAgg
                    .OrderByDescending(kv => kv.Value.Count)
                    .Take(10)
                    .Select(kv => new ProtocolStatistics
                    {
                        Protocol = kv.Key.ToString(),
                        PacketCount = kv.Value.Count,
                        ByteCount = kv.Value.Bytes,
                        Percentage = totalPackets > 0 ? (double)kv.Value.Count / totalPackets * 100 : 0,
                        Color = protocolColors.TryGetValue(kv.Key.ToString(), out var color) ? color : protocolColors.GetValueOrDefault("Other", "#808080")
                    })
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
            // MEMORY FIX: Single-pass O(n) aggregation with protocol breakdown
            var totalPackets = packets.Count;
            var endpointAgg = new Dictionary<string, (int Count, long Bytes, Dictionary<Protocol, int> Protocols)>();

            foreach (var p in packets)
            {
                var ip = isSource ? p.SourceIP : p.DestinationIP;
                if (string.IsNullOrEmpty(ip))
                    continue;

                if (endpointAgg.TryGetValue(ip, out var stats))
                {
                    stats.Protocols.TryGetValue(p.Protocol, out var protoCount);
                    stats.Protocols[p.Protocol] = protoCount + 1;
                    endpointAgg[ip] = (stats.Count + 1, stats.Bytes + p.Length, stats.Protocols);
                }
                else
                {
                    var protocols = new Dictionary<Protocol, int> { { p.Protocol, 1 } };
                    endpointAgg[ip] = (1, p.Length, protocols);
                }
            }

            var endpoints = endpointAgg
                .OrderByDescending(kv => kv.Value.Count)
                .Take(30)
                .Select(kv => new EndpointStatistics
                {
                    Address = kv.Key,
                    PacketCount = kv.Value.Count,
                    ByteCount = kv.Value.Bytes,
                    Percentage = totalPackets > 0 ? (double)kv.Value.Count / totalPackets * 100 : 0,
                    ProtocolBreakdown = kv.Value.Protocols.ToDictionary(p => p.Key.ToString(), p => (long)p.Value),
                    IsInternal = IsInternalIP(kv.Key)
                })
                .ToList();

            return endpoints;
        }

        public (List<ConversationStatistics> TopConversations, int TotalCount) CalculateTopConversations(List<PacketInfo> packets)
        {
            // MEMORY FIX: Single-pass O(n) aggregation instead of GroupBy().Select().ToList()
            // Old code materialized ALL conversations before Take(30) - caused OOM on 5M+ packets
            var conversationStats = new Dictionary<(string Src, string Dst, int SrcPort, int DstPort, Protocol Proto), (int Count, long Bytes, DateTime Start, DateTime End)>();

            foreach (var p in packets)
            {
                if (p.SourcePort <= 0 || p.DestinationPort <= 0)
                    continue;

                // Normalize conversation key (lower IP first for bidirectional matching)
                var isSourceLower = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0;
                var key = isSourceLower
                    ? (p.SourceIP, p.DestinationIP, p.SourcePort, p.DestinationPort, p.Protocol)
                    : (p.DestinationIP, p.SourceIP, p.DestinationPort, p.SourcePort, p.Protocol);

                if (conversationStats.TryGetValue(key, out var stats))
                {
                    conversationStats[key] = (
                        stats.Count + 1,
                        stats.Bytes + p.Length,
                        p.Timestamp < stats.Start ? p.Timestamp : stats.Start,
                        p.Timestamp > stats.End ? p.Timestamp : stats.End
                    );
                }
                else
                {
                    conversationStats[key] = (1, p.Length, p.Timestamp, p.Timestamp);
                }
            }

            var totalCount = conversationStats.Count;

            // Only materialize top 30 as full ConversationStatistics objects
            var topConversations = conversationStats
                .OrderByDescending(kv => kv.Value.Count)
                .Take(30)
                .Select(kv => new ConversationStatistics
                {
                    SourceAddress = kv.Key.Src,
                    DestinationAddress = kv.Key.Dst,
                    SourcePort = kv.Key.SrcPort,
                    DestinationPort = kv.Key.DstPort,
                    Protocol = kv.Key.Proto.ToString(),
                    PacketCount = kv.Value.Count,
                    ByteCount = kv.Value.Bytes,
                    StartTime = kv.Value.Start,
                    EndTime = kv.Value.End
                })
                .ToList();

            return (topConversations, totalCount);
        }

        /// <summary>
        /// Calculates top ports with unique count tracking.
        /// NOTE: Keeps TCP and UDP ports separate - Port 2598/TCP and Port 2598/UDP are distinct entries.
        /// This provides accurate protocol-specific port analysis.
        /// </summary>
        public (List<PortStatistics> TopPorts, int UniqueCount) CalculateTopPortsWithCount(
            List<PacketInfo> packets,
            IReadOnlyDictionary<int, string> wellKnownPorts)
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
            IReadOnlyDictionary<int, string> wellKnownPorts)
        {
            // MEMORY FIX: Single-pass O(n) aggregation instead of O(ports × packets)
            // Old code scanned ALL packets for EACH well-known port - catastrophic for large files
            var serviceAgg = new Dictionary<int, (int Count, long Bytes, Protocol Proto, HashSet<string> Hosts)>();

            foreach (var p in packets)
            {
                // Check source port
                if (p.SourcePort > 0 && wellKnownPorts.ContainsKey(p.SourcePort))
                {
                    if (serviceAgg.TryGetValue(p.SourcePort, out var stats))
                    {
                        if (!string.IsNullOrEmpty(p.SourceIP)) stats.Hosts.Add(p.SourceIP);
                        if (!string.IsNullOrEmpty(p.DestinationIP)) stats.Hosts.Add(p.DestinationIP);
                        serviceAgg[p.SourcePort] = (stats.Count + 1, stats.Bytes + p.Length, stats.Proto, stats.Hosts);
                    }
                    else
                    {
                        var hosts = new HashSet<string>();
                        if (!string.IsNullOrEmpty(p.SourceIP)) hosts.Add(p.SourceIP);
                        if (!string.IsNullOrEmpty(p.DestinationIP)) hosts.Add(p.DestinationIP);
                        serviceAgg[p.SourcePort] = (1, p.Length, p.Protocol, hosts);
                    }
                }

                // Check destination port (avoid double-counting same port)
                if (p.DestinationPort > 0 && p.DestinationPort != p.SourcePort && wellKnownPorts.ContainsKey(p.DestinationPort))
                {
                    if (serviceAgg.TryGetValue(p.DestinationPort, out var stats))
                    {
                        if (!string.IsNullOrEmpty(p.SourceIP)) stats.Hosts.Add(p.SourceIP);
                        if (!string.IsNullOrEmpty(p.DestinationIP)) stats.Hosts.Add(p.DestinationIP);
                        serviceAgg[p.DestinationPort] = (stats.Count + 1, stats.Bytes + p.Length, stats.Proto, stats.Hosts);
                    }
                    else
                    {
                        var hosts = new HashSet<string>();
                        if (!string.IsNullOrEmpty(p.SourceIP)) hosts.Add(p.SourceIP);
                        if (!string.IsNullOrEmpty(p.DestinationIP)) hosts.Add(p.DestinationIP);
                        serviceAgg[p.DestinationPort] = (1, p.Length, p.Protocol, hosts);
                    }
                }
            }

            // Convert to ServiceStatistics
            var services = new Dictionary<string, ServiceStatistics>();
            foreach (var kv in serviceAgg)
            {
                var serviceName = wellKnownPorts[kv.Key];
                services[serviceName] = new ServiceStatistics
                {
                    ServiceName = serviceName,
                    Port = kv.Key,
                    Protocol = kv.Value.Proto.ToString(),
                    PacketCount = kv.Value.Count,
                    ByteCount = kv.Value.Bytes,
                    UniqueHosts = kv.Value.Hosts.ToList(),
                    IsEncrypted = kv.Key == 443 || kv.Key == 22 || kv.Key == 8443
                };
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
