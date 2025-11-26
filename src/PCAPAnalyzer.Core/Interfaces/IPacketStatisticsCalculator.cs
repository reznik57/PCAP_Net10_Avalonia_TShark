using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Calculates derived statistics from packet collections.
/// Extracted from MainWindowViewModel for testability and reuse.
/// </summary>
public interface IPacketStatisticsCalculator
{
    /// <summary>
    /// Calculate unique IP addresses (source + destination combined).
    /// </summary>
    int CalculateUniqueIPs(IReadOnlyList<PacketInfo> packets);

    /// <summary>
    /// Calculate unique destination ports.
    /// </summary>
    int CalculateUniqueDestinationPorts(IReadOnlyList<PacketInfo> packets);

    /// <summary>
    /// Calculate TCP conversation count (unique 4-tuples).
    /// </summary>
    int CalculateTCPConversations(IReadOnlyList<PacketInfo> packets);

    /// <summary>
    /// Calculate total bytes from packet collection.
    /// </summary>
    long CalculateTotalBytes(IReadOnlyList<PacketInfo> packets);

    /// <summary>
    /// Calculate all packet statistics in a single pass for efficiency.
    /// </summary>
    PacketStatisticsSummary CalculateAllStatistics(IReadOnlyList<PacketInfo> packets);
}

/// <summary>
/// Summary of packet statistics calculated in a single pass.
/// </summary>
public class PacketStatisticsSummary
{
    public int TotalPackets { get; init; }
    public long TotalBytes { get; init; }
    public int UniqueIPs { get; init; }
    public int UniqueDestinationPorts { get; init; }
    public int TCPConversations { get; init; }
    public int UniqueProtocols { get; init; }
}
