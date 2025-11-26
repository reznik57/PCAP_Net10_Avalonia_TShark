using System;

namespace PCAPAnalyzer.Core.Models;

public readonly record struct FlowRecord
{
    public string SourceIP { get; init; }
    public string DestinationIP { get; init; }
    public ushort SourcePort { get; init; }
    public ushort DestinationPort { get; init; }
    public string Protocol { get; init; }
    public long PacketCount { get; init; }
    public long ByteCount { get; init; }
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; init; }
}
