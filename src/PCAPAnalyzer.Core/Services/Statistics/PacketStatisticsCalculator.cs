using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.Statistics;

/// <summary>
/// Calculates derived statistics from packet collections.
/// Thread-safe, stateless service for computing packet metrics.
/// </summary>
public class PacketStatisticsCalculator : IPacketStatisticsCalculator
{
    /// <inheritdoc />
    public int CalculateUniqueIPs(IReadOnlyList<PacketInfo> packets)
    {
        if (packets == null || packets.Count == 0)
            return 0;

        try
        {
            return packets
                .SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
                .Where(ip => !string.IsNullOrEmpty(ip))
                .Distinct()
                .Count();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PacketStatisticsCalculator] Error calculating unique IPs: {ex.Message}");
            return 0;
        }
    }

    /// <inheritdoc />
    public int CalculateUniqueDestinationPorts(IReadOnlyList<PacketInfo> packets)
    {
        if (packets == null || packets.Count == 0)
            return 0;

        try
        {
            return packets
                .Where(p => p.DestinationPort > 0)
                .Select(p => p.DestinationPort)
                .Distinct()
                .Count();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PacketStatisticsCalculator] Error calculating destination ports: {ex.Message}");
            return 0;
        }
    }

    /// <inheritdoc />
    public int CalculateTCPConversations(IReadOnlyList<PacketInfo> packets)
    {
        if (packets == null || packets.Count == 0)
            return 0;

        try
        {
            // Count ALL streams (TCP + UDP + other) - not just TCP
            // A stream is a unique 4-tuple (SrcIP, SrcPort, DstIP, DstPort)
            return packets
                .Where(p => p.SourcePort > 0 && p.DestinationPort > 0) // Must have ports
                .Select(p => (p.SourceIP, p.SourcePort, p.DestinationIP, p.DestinationPort))
                .Distinct()
                .Count();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PacketStatisticsCalculator] Error calculating streams: {ex.Message}");
            return 0;
        }
    }

    /// <inheritdoc />
    public long CalculateTotalBytes(IReadOnlyList<PacketInfo> packets)
    {
        if (packets == null || packets.Count == 0)
            return 0;

        try
        {
            return packets.Sum(p => (long)p.Length);
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PacketStatisticsCalculator] Error calculating total bytes: {ex.Message}");
            return 0;
        }
    }

    /// <inheritdoc />
    public PacketStatisticsSummary CalculateAllStatistics(IReadOnlyList<PacketInfo> packets)
    {
        if (packets == null || packets.Count == 0)
        {
            return new PacketStatisticsSummary
            {
                TotalPackets = 0,
                TotalBytes = 0,
                UniqueIPs = 0,
                UniqueDestinationPorts = 0,
                TCPConversations = 0,
                UniqueProtocols = 0
            };
        }

        try
        {
            // Single pass for efficiency with large packet collections
            var uniqueIPs = new HashSet<string>();
            var uniquePorts = new HashSet<int>();
            var tcpConversations = new HashSet<(string, int, string, int)>();
            var uniqueProtocols = new HashSet<string>();
            long totalBytes = 0;

            foreach (var packet in packets)
            {
                totalBytes += packet.Length;

                if (!string.IsNullOrEmpty(packet.SourceIP))
                    uniqueIPs.Add(packet.SourceIP);
                if (!string.IsNullOrEmpty(packet.DestinationIP))
                    uniqueIPs.Add(packet.DestinationIP);

                if (packet.DestinationPort > 0)
                    uniquePorts.Add(packet.DestinationPort);

                // Count ALL streams (not just TCP) - must have valid ports
                if (packet.SourcePort > 0 && packet.DestinationPort > 0)
                    tcpConversations.Add((packet.SourceIP ?? "", packet.SourcePort, packet.DestinationIP ?? "", packet.DestinationPort));

                if (!string.IsNullOrEmpty(packet.L7Protocol))
                    uniqueProtocols.Add(packet.L7Protocol);
                else if (packet.Protocol != Protocol.Unknown)
                    uniqueProtocols.Add(packet.Protocol.ToString());
            }

            return new PacketStatisticsSummary
            {
                TotalPackets = packets.Count,
                TotalBytes = totalBytes,
                UniqueIPs = uniqueIPs.Count,
                UniqueDestinationPorts = uniquePorts.Count,
                TCPConversations = tcpConversations.Count,
                UniqueProtocols = uniqueProtocols.Count
            };
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PacketStatisticsCalculator] Error calculating all statistics: {ex.Message}");
            return new PacketStatisticsSummary();
        }
    }
}
