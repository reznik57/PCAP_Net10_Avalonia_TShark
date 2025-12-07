using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Indicates which PCAP file(s) contain a packet
/// </summary>
public enum PacketSource
{
    FileA,
    FileB,
    Both
}

/// <summary>
/// A packet with its comparison source information
/// </summary>
public record ComparedPacket
{
    public required PacketInfo Packet { get; init; }
    public required PacketSource Source { get; init; }
    public required string SourceFile { get; init; }
}

/// <summary>
/// Statistics from comparing two PCAP files
/// </summary>
public record ComparisonStatistics
{
    public required string FileAName { get; init; }
    public required string FileBName { get; init; }
    public required int TotalFileA { get; init; }
    public required int TotalFileB { get; init; }
    public required int CommonCount { get; init; }
    public required int UniqueToA { get; init; }
    public required int UniqueToB { get; init; }
    public double MatchPercentage => TotalFileA + TotalFileB > 0
        ? (CommonCount * 2.0) / (TotalFileA + TotalFileB) * 100
        : 0;
    public Dictionary<string, int> ProtocolDiffA { get; init; } = [];
    public Dictionary<string, int> ProtocolDiffB { get; init; } = [];
}

/// <summary>
/// Complete comparison result containing packets and statistics
/// </summary>
public record ComparisonResult
{
    public required List<ComparedPacket> AllPackets { get; init; }
    public required ComparisonStatistics Statistics { get; init; }
}
