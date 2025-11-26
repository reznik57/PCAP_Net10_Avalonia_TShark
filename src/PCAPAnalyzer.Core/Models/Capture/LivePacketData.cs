using System;

namespace PCAPAnalyzer.Core.Models.Capture;

/// <summary>
/// Represents a packet captured during live capture
/// </summary>
public class LivePacketData
{
    /// <summary>
    /// Packet sequence number in the capture
    /// </summary>
    public long SequenceNumber { get; set; }

    /// <summary>
    /// Timestamp when the packet was captured
    /// </summary>
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// Raw packet data
    /// </summary>
    public byte[] RawData { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Packet length in bytes
    /// </summary>
    public int Length { get; set; }

    /// <summary>
    /// Captured length (may be less than actual length if truncated)
    /// </summary>
    public int CapturedLength { get; set; }

    /// <summary>
    /// Source MAC address
    /// </summary>
    public string? SourceMac { get; set; }

    /// <summary>
    /// Destination MAC address
    /// </summary>
    public string? DestinationMac { get; set; }

    /// <summary>
    /// Source IP address
    /// </summary>
    public string? SourceIp { get; set; }

    /// <summary>
    /// Destination IP address
    /// </summary>
    public string? DestinationIp { get; set; }

    /// <summary>
    /// Source port (if applicable)
    /// </summary>
    public int? SourcePort { get; set; }

    /// <summary>
    /// Destination port (if applicable)
    /// </summary>
    public int? DestinationPort { get; set; }

    /// <summary>
    /// Protocol (TCP, UDP, ICMP, etc.)
    /// </summary>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>
    /// Additional protocol information
    /// </summary>
    public string? ProtocolInfo { get; set; }

    /// <summary>
    /// Whether this packet matches any anomaly patterns
    /// </summary>
    public bool HasAnomaly { get; set; }

    /// <summary>
    /// List of detected anomalies
    /// </summary>
    public List<string> Anomalies { get; set; } = new();

    /// <summary>
    /// Interface on which the packet was captured
    /// </summary>
    public string InterfaceId { get; set; } = string.Empty;
}
