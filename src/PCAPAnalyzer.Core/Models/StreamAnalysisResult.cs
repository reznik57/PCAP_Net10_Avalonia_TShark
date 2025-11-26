using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Complete stream analysis result containing TCP state, bandwidth, timing, and protocol detection
/// </summary>
public class StreamAnalysisResult
{
    public required TcpStateInfo TcpState { get; init; }
    public required BandwidthMetrics Bandwidth { get; init; }
    public required TimingMetrics Timing { get; init; }
    public required ApplicationProtocolInfo Protocol { get; init; }
    public required string StreamKey { get; init; }
    public required int PacketCount { get; init; }
    public SecurityIndicators? Security { get; init; }
    public DirectionalMetrics? Directional { get; init; }
}

/// <summary>
/// TCP connection state and lifecycle information
/// </summary>
public class TcpStateInfo
{
    public required string State { get; init; } // ESTABLISHED, CLOSING, CLOSED, RST, etc.
    public required HandshakeInfo? Handshake { get; init; }
    public required int RetransmissionCount { get; init; }
    public required WindowScalingInfo WindowScaling { get; init; }
    public required TcpFlagCounts Flags { get; init; }
    public required bool IsComplete { get; init; } // True if handshake completed
}

/// <summary>
/// TCP handshake detection (SYN -> SYN-ACK -> ACK)
/// </summary>
public class HandshakeInfo
{
    public required bool IsComplete { get; init; }
    public uint? SynPacketNumber { get; init; }
    public uint? SynAckPacketNumber { get; init; }
    public uint? AckPacketNumber { get; init; }
    public TimeSpan? HandshakeDuration { get; init; }

    public string GetDisplayString()
    {
        if (!IsComplete)
            return "Incomplete";

        return $"Complete (SYN #{SynPacketNumber}, SYN-ACK #{SynAckPacketNumber}, ACK #{AckPacketNumber})";
    }
}

/// <summary>
/// TCP window size tracking
/// </summary>
public class WindowScalingInfo
{
    public required ushort InitialWindow { get; init; }
    public required ushort CurrentWindow { get; init; }
    public required ushort MinWindow { get; init; }
    public required ushort MaxWindow { get; init; }

    public string GetDisplayString()
    {
        if (InitialWindow == CurrentWindow)
            return $"{CurrentWindow} bytes (stable)";

        if (CurrentWindow < InitialWindow)
            return $"{InitialWindow} → {CurrentWindow} (reduced by {InitialWindow - CurrentWindow})";

        return $"{InitialWindow} → {CurrentWindow} (increased by {CurrentWindow - InitialWindow})";
    }
}

/// <summary>
/// TCP flag occurrence counts
/// </summary>
public class TcpFlagCounts
{
    public int SYN { get; init; }
    public int FIN { get; init; }
    public int RST { get; init; }
    public int PSH { get; init; }
    public int ACK { get; init; }
    public int URG { get; init; }

    public string GetDisplayString()
    {
        return $"SYN={SYN}, FIN={FIN}, RST={RST}, PSH={PSH}, ACK={ACK}, URG={URG}";
    }
}

/// <summary>
/// Bandwidth and throughput metrics
/// </summary>
public class BandwidthMetrics
{
    public required long TotalBytes { get; init; }
    public required TimeSpan Duration { get; init; }
    public required double AverageBytesPerSecond { get; init; }
    public required double AveragePacketsPerSecond { get; init; }
    public required double AveragePacketSize { get; init; }
    public required PeakThroughput? Peak { get; init; }

    public string GetAverageThroughputDisplay()
    {
        if (AverageBytesPerSecond < 1024)
            return $"{AverageBytesPerSecond:F1} B/s";
        else if (AverageBytesPerSecond < 1024 * 1024)
            return $"{AverageBytesPerSecond / 1024:F1} KB/s";
        else
            return $"{AverageBytesPerSecond / (1024 * 1024):F1} MB/s";
    }
}

/// <summary>
/// Peak throughput in 1-second window
/// </summary>
public class PeakThroughput
{
    public required double BytesPerSecond { get; init; }
    public required DateTime Timestamp { get; init; }

    public string GetDisplayString()
    {
        if (BytesPerSecond < 1024)
            return $"{BytesPerSecond:F1} B/s";
        else if (BytesPerSecond < 1024 * 1024)
            return $"{BytesPerSecond / 1024:F1} KB/s";
        else
            return $"{BytesPerSecond / (1024 * 1024):F1} MB/s";
    }
}

/// <summary>
/// Network timing and latency metrics
/// </summary>
public class TimingMetrics
{
    public required double? AverageRttMs { get; init; }
    public required double? MinRttMs { get; init; }
    public required double? MaxRttMs { get; init; }
    public required RttSample? MinRttSample { get; init; }
    public required RttSample? MaxRttSample { get; init; }
    public required double? JitterMs { get; init; }
    public required double AverageInterPacketDelayMs { get; init; }

    public bool HasRttData => AverageRttMs.HasValue;
}

/// <summary>
/// Individual RTT measurement sample
/// </summary>
public class RttSample
{
    public required uint RequestPacket { get; init; }
    public required uint ResponsePacket { get; init; }
    public required double RttMs { get; init; }
}

/// <summary>
/// Application layer protocol detection
/// </summary>
public class ApplicationProtocolInfo
{
    public required string Name { get; init; } // HTTP, HTTPS, DNS, SSH, etc.
    public required string Description { get; init; }
    public required bool IsEncrypted { get; init; }
    public required Dictionary<string, string> Details { get; init; } // e.g., User-Agent, Content-Type

    public string GetDisplayString()
    {
        var encryption = IsEncrypted ? " (Encrypted)" : " (Unencrypted)";
        return $"{Name}{encryption}";
    }
}

/// <summary>
/// Security indicators for stream endpoints
/// </summary>
public class SecurityIndicators
{
    public required PortSecurityInfo SourcePortSecurity { get; init; }
    public required PortSecurityInfo DestinationPortSecurity { get; init; }
    public required GeoSecurityInfo? SourceGeoInfo { get; init; }
    public required GeoSecurityInfo? DestinationGeoInfo { get; init; }
    public required List<string> Warnings { get; init; }
    public required ThreatSeverity OverallRisk { get; init; }

    public bool HasWarnings => Warnings.Count > 0;
}

/// <summary>
/// Port-level security information
/// </summary>
public class PortSecurityInfo
{
    public required int Port { get; init; }
    public required bool IsKnownInsecure { get; init; }
    public required bool IsKnownMalwarePort { get; init; }
    public required string? ServiceName { get; init; }
    public required string? RiskDescription { get; init; }
    public required string? RecommendedAlternative { get; init; }
}

/// <summary>
/// Geographic security information
/// </summary>
public class GeoSecurityInfo
{
    public required string IP { get; init; }
    public required string? CountryCode { get; init; }
    public required string? CountryName { get; init; }
    public required string? City { get; init; }
    public required bool IsHighRiskCountry { get; init; }
    public required bool IsPrivateIP { get; init; }
}

/// <summary>
/// Bidirectional stream metrics (client vs server traffic)
/// </summary>
public class DirectionalMetrics
{
    public required EndpointMetrics Client { get; init; }
    public required EndpointMetrics Server { get; init; }
    public required double RequestResponseRatio { get; init; }
    public required string DominantDirection { get; init; } // "Client→Server", "Server→Client", "Balanced"
    public required int StreamPositionCurrent { get; init; } // Current packet position in stream
    public required int StreamPositionTotal { get; init; } // Total packets in stream
    public required TimeSpan ConnectionAge { get; init; } // Time from first to last packet
}

/// <summary>
/// Metrics for one endpoint in a stream
/// </summary>
public class EndpointMetrics
{
    public required string IP { get; init; }
    public required int Port { get; init; }
    public required long BytesSent { get; init; }
    public required int PacketsSent { get; init; }
    public required string BytesSentFormatted { get; init; }
}
