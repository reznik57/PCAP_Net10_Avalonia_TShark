using System;

namespace PCAPAnalyzer.UI.ViewModels;

// Note: TopPortViewModel is defined in TCPAnomalyViewModel.cs as a partial class

/// <summary>
/// ViewModel for endpoint (IP address) display.
/// </summary>
public class EndpointViewModel
{
    public int Rank { get; set; }
    public string Address { get; set; } = string.Empty;
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public string BytesFormatted { get; set; } = string.Empty;
    public double Percentage { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Country { get; set; } = "Unknown";
    public string CountryCode { get; set; } = "";
}

/// <summary>
/// ViewModel for conversation display.
/// </summary>
public class ConversationViewModel
{
    public string SourceAddress { get; set; } = string.Empty;
    public int SourcePort { get; set; }
    public string DestinationAddress { get; set; } = string.Empty;
    public int DestinationPort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public TimeSpan Duration { get; set; }
    public string SourceDisplay { get; set; } = string.Empty;
    public string DestinationDisplay { get; set; } = string.Empty;
    public string DurationFormatted { get; set; } = string.Empty;
    public double Percentage { get; set; }
    public string BytesFormatted { get; set; } = string.Empty;
}

/// <summary>
/// ViewModel for service display.
/// </summary>
public class ServiceViewModel
{
    public string ServiceName { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public int UniqueHostCount { get; set; }
    public bool IsEncrypted { get; set; }
}

/// <summary>
/// ViewModel for threat display.
/// </summary>
public class ThreatViewModel
{
    public string Type { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string SeverityColor { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; }
    public string SourceAddress { get; set; } = string.Empty;
    public string DestinationAddress { get; set; } = string.Empty;
}
