using System;
using System.Collections.Generic;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents a legend item for interactive series toggling.
/// Supports two-line display: SourceIP on line 1, DestIP on line 2.
/// </summary>
public partial class SeriesLegendItem : ObservableObject
{
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _color = ThemeColorHelper.GetColorHex("AccentBlue", "#58A6FF");
    [ObservableProperty] private bool _isVisible = true;
    [ObservableProperty] private int _seriesIndex;

    /// <summary>Source IP for two-line display (null for "Total" series)</summary>
    [ObservableProperty] private string? _sourceIP;

    /// <summary>Destination IP for two-line display (null for "Total" series)</summary>
    [ObservableProperty] private string? _destIP;

    /// <summary>True if this is a stream (has source/dest), false for "Total"</summary>
    public bool IsStream => !string.IsNullOrEmpty(SourceIP);

    /// <summary>Returns a SolidColorBrush for the Color hex string (for XAML binding)</summary>
    public IBrush ColorBrush => new SolidColorBrush(Avalonia.Media.Color.Parse(Color));

    /// <summary>Returns a dimmed brush for secondary text</summary>
    public IBrush ColorBrushDimmed => new SolidColorBrush(Avalonia.Media.Color.Parse(Color)) { Opacity = 0.7 };

    public Action<int, bool>? OnToggle { get; set; }

    partial void OnIsVisibleChanged(bool value)
    {
        OnToggle?.Invoke(SeriesIndex, value);
    }
}

/// <summary>
/// Represents a network stream (conversation) for chart display.
/// Uses IP:Port format for detailed granularity in Packet Analysis tab.
/// </summary>
public class StreamInfo
{
    public string SourceIP { get; set; } = "";
    public int SourcePort { get; set; }
    public string DestIP { get; set; } = "";
    public int DestPort { get; set; }
    /// <summary>
    /// Canonical stream key - must match the key format used in UpdatePacketsOverTimeChart
    /// Format: "{IP1}:{Port1}↔{IP2}:{Port2}" (sorted by IP:Port string for consistency)
    /// </summary>
    public string StreamKey { get; set; } = "";
    public int TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public string DisplayName => SourcePort > 0 || DestPort > 0
        ? $"{SourceIP}:{SourcePort} → {DestIP}:{DestPort}"
        : $"{SourceIP} → {DestIP}";
}

/// <summary>
/// Represents a stream row for the Top Streams tables (IP:Port based for detailed analysis)
/// </summary>
public class TopStreamTableItem
{
    public int Rank { get; set; }
    public string SourceIP { get; set; } = "";
    public int SourcePort { get; set; }
    public string DestinationIP { get; set; } = "";
    public int DestPort { get; set; }
    public string StreamKey { get; set; } = "";
    public int PacketCount { get; set; }
    public long ByteCount { get; set; }
    public double Percentage { get; set; }
    public string DisplayName => SourcePort > 0 || DestPort > 0
        ? $"{SourceIP}:{SourcePort} ↔ {DestinationIP}:{DestPort}"
        : $"{SourceIP} ↔ {DestinationIP}";
    public string ByteCountFormatted => PCAPAnalyzer.Core.Utilities.NumberFormatter.FormatBytes(ByteCount);
    /// <summary>
    /// Service name based on well-known port (uses lower port for identification)
    /// </summary>
    public string ServiceName => PCAPAnalyzer.Core.Security.PortDatabase.GetServiceName(
        (ushort)Math.Min(SourcePort > 0 ? SourcePort : 65535, DestPort > 0 ? DestPort : 65535), true) ?? "";
}

/// <summary>
/// Data point for Packets Over Time chart with stream breakdown
/// </summary>
public class PacketsTimelineDataPoint
{
    public DateTime Time { get; set; }
    public int TotalCount { get; set; }
    public long TotalBytes { get; set; }
    public Dictionary<string, int> StreamCounts { get; set; } = new();
    public Dictionary<string, long> StreamBytes { get; set; } = new();
}
