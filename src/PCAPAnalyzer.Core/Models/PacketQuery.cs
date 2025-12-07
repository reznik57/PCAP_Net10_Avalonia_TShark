using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models;

public sealed class PacketQuery
{
    public PacketFilter? Filter { get; init; }
    public int PageNumber { get; init; } = 1;
    public int PageSize { get; init; } = 100;
    public bool SortDescending { get; init; } = true;
    public bool IncludeSummary { get; init; } = true;
    public bool IncludePackets { get; init; } = true;
}

public sealed class PacketQueryResult
{
    public IReadOnlyList<PacketInfo> Packets { get; init; } = [];
    public long TotalCount { get; init; }
    public long TotalBytes { get; init; }
    public long ThreatCount { get; init; }
    public DateTime? FirstPacketTimestamp { get; init; }
    public DateTime? LastPacketTimestamp { get; init; }
}
