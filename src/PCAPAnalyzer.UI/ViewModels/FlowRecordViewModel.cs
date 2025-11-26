using System;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

public sealed class FlowRecordViewModel
{
    public string SourceIP { get; init; } = string.Empty;
    public string DestinationIP { get; init; } = string.Empty;
    public ushort SourcePort { get; init; }
    public ushort DestinationPort { get; init; }
    public string Protocol { get; init; } = string.Empty;
    public long PacketCount { get; init; }
    public long ByteCount { get; init; }
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; init; }

    public string DisplayBytes => NumberFormatter.FormatBytes(ByteCount);

    public static FlowRecordViewModel FromRecord(FlowRecord record) => new()
    {
        SourceIP = record.SourceIP,
        DestinationIP = record.DestinationIP,
        SourcePort = record.SourcePort,
        DestinationPort = record.DestinationPort,
        Protocol = record.Protocol,
        PacketCount = record.PacketCount,
        ByteCount = record.ByteCount,
        FirstSeen = record.FirstSeen,
        LastSeen = record.LastSeen
    };
}
