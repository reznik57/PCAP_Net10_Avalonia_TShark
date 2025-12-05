using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// QoS traffic flow item for Voice/QoS analysis tab.
/// </summary>
public class QoSTrafficItem : ObservableObject
{
    public int RowNumber { get; set; }
    public string SourceIP { get; set; } = "";
    public string DestinationIP { get; set; } = "";
    public string Protocol { get; set; } = "";
    public int PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public string QoSType { get; set; } = "";
    public string PortRange { get; set; } = "";
    public string DscpMarking { get; set; } = "";
    public int DscpValue { get; set; }
    public List<PacketInfo> Packets { get; set; } = new();

    public string BytesFormatted => NumberFormatter.FormatBytes(TotalBytes);
    public string Duration => TimeFormatter.FormatAsSeconds(LastSeen - FirstSeen);
    public string DscpDisplay => string.IsNullOrEmpty(DscpMarking) ? "N/A" : $"{DscpMarking} ({DscpValue})";
}

/// <summary>
/// High latency connection item for Voice/QoS analysis.
/// </summary>
public class LatencyConnectionItem : ObservableObject
{
    public int RowNumber { get; set; }
    public string SourceIP { get; set; } = "";
    public string DestinationIP { get; set; } = "";
    public string Protocol { get; set; } = "";
    public double AverageLatency { get; set; }
    public double MaxLatency { get; set; }
    public double MinLatency { get; set; }
    public double P5Latency { get; set; }
    public double P95Latency { get; set; }
    public int PacketCount { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public string PortRange { get; set; } = "";
    public List<PacketInfo> Packets { get; set; } = new();

    public string AverageLatencyFormatted => $"{AverageLatency:F2} ms";
    public string MaxLatencyFormatted => $"{MaxLatency:F2} ms";
    public string MinLatencyFormatted => $"{MinLatency:F2} ms";
    public string P5LatencyFormatted => $"{P5Latency:F2} ms";
    public string P95LatencyFormatted => $"{P95Latency:F2} ms";
    public string Duration => TimeFormatter.FormatAsSeconds(LastSeen - FirstSeen);
    public string LatencySeverity => AverageLatency >= 200 ? "Critical" : AverageLatency >= 100 ? "High" : "Medium";
    public string SeverityColor => ThemeColorHelper.GetQoSSeverityColorHex("latency", LatencySeverity);
}

/// <summary>
/// High jitter connection item for Voice/QoS analysis.
/// </summary>
public class JitterConnectionItem : ObservableObject
{
    public int RowNumber { get; set; }
    public string SourceIP { get; set; } = "";
    public string DestinationIP { get; set; } = "";
    public string Protocol { get; set; } = "";
    public double AverageJitter { get; set; }
    public double MaxJitter { get; set; }
    public double MinJitter { get; set; }
    public double P5Jitter { get; set; }
    public double P95Jitter { get; set; }
    public int PacketCount { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public string PortRange { get; set; } = "";
    public List<PacketInfo> Packets { get; set; } = new();

    public string AverageJitterFormatted => $"{AverageJitter:F2} ms";
    public string MaxJitterFormatted => $"{MaxJitter:F2} ms";
    public string MinJitterFormatted => $"{MinJitter:F2} ms";
    public string P5JitterFormatted => $"{P5Jitter:F2} ms";
    public string P95JitterFormatted => $"{P95Jitter:F2} ms";
    public string Duration => TimeFormatter.FormatAsSeconds(LastSeen - FirstSeen);
    public string JitterSeverity => AverageJitter >= 50 ? "Critical" : AverageJitter >= 30 ? "High" : "Medium";
    public string SeverityColor => ThemeColorHelper.GetQoSSeverityColorHex("jitter", JitterSeverity);
}

/// <summary>
/// Top endpoint summary for aggregated statistics display.
/// </summary>
public class TopEndpointItem : ObservableObject
{
    public string IPAddress { get; set; } = "";
    public int FlowCount { get; set; }
    public int PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public double AverageMetric { get; set; }
    public string MetricType { get; set; } = "";

    public string BytesFormatted => NumberFormatter.FormatBytes(TotalBytes);
    public string MetricFormatted => $"{AverageMetric:F2} ms";
}

/// <summary>
/// Extended Top Endpoint Item with Ranking and Percentage for Dashboard-style tables.
/// </summary>
public class TopEndpointItemExtended : TopEndpointItem
{
    public string Rank { get; set; } = "";
    public double Percentage { get; set; }
    public string Badge { get; set; } = "";
}
