namespace PCAPAnalyzer.API.DTOs;

/// <summary>
/// Statistics summary DTO
/// </summary>
public class StatisticsSummaryDto
{
    public required string PcapId { get; set; }
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public DateTime? FirstPacketTime { get; set; }
    public DateTime? LastPacketTime { get; set; }
    public TimeSpan Duration { get; set; }
    public double AveragePacketSize { get; set; }
    public double PacketsPerSecond { get; set; }
    public int UniqueSourceIPs { get; set; }
    public int UniqueDestinationIPs { get; set; }
    public Dictionary<string, long>? ProtocolDistribution { get; set; }
}

/// <summary>
/// Protocol statistics DTO
/// </summary>
public class ProtocolStatisticsDto
{
    public required string Protocol { get; set; }
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public double Percentage { get; set; }
    public double AveragePacketSize { get; set; }
}

/// <summary>
/// Conversation statistics DTO
/// </summary>
public class ConversationDto
{
    public required string SourceIP { get; set; }
    public required string DestinationIP { get; set; }
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public required string Protocol { get; set; }
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public DateTime? FirstSeen { get; set; }
    public DateTime? LastSeen { get; set; }
}

/// <summary>
/// Geographic statistics DTO
/// </summary>
public class GeographicStatisticsDto
{
    public required string Country { get; set; }
    public string? CountryCode { get; set; }
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public List<string>? IpAddresses { get; set; }
}
