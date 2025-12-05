using System;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Capture;

/// <summary>
/// ViewModel representing a single captured packet in the live capture view
/// Optimized for data virtualization and minimal memory footprint
/// </summary>
public partial class PacketViewModel : ObservableObject
{
    /// <summary>
    /// Packet sequence number
    /// </summary>
    [ObservableProperty]
    private long _sequenceNumber;

    /// <summary>
    /// Timestamp when packet was captured
    /// </summary>
    [ObservableProperty]
    private DateTime _timestamp;

    /// <summary>
    /// Source IP address
    /// </summary>
    [ObservableProperty]
    private string _sourceIp = string.Empty;

    /// <summary>
    /// Source port (nullable for non-TCP/UDP protocols)
    /// </summary>
    [ObservableProperty]
    private int? _sourcePort;

    /// <summary>
    /// Destination IP address
    /// </summary>
    [ObservableProperty]
    private string _destinationIp = string.Empty;

    /// <summary>
    /// Destination port (nullable for non-TCP/UDP protocols)
    /// </summary>
    [ObservableProperty]
    private int? _destinationPort;

    /// <summary>
    /// Protocol (TCP, UDP, ICMP, etc.)
    /// </summary>
    [ObservableProperty]
    private string _protocol = string.Empty;

    /// <summary>
    /// Packet length in bytes
    /// </summary>
    [ObservableProperty]
    private int _length;

    /// <summary>
    /// Additional protocol information/summary
    /// </summary>
    [ObservableProperty]
    private string _info = string.Empty;

    /// <summary>
    /// Whether this packet has detected anomalies
    /// </summary>
    [ObservableProperty]
    private bool _hasAnomaly;

    /// <summary>
    /// Color coding for protocol visualization - uses ThemeColorHelper
    /// </summary>
    public string ProtocolColor => ThemeColorHelper.GetProtocolColorHex(Protocol ?? "");

    /// <summary>
    /// Formatted timestamp for display
    /// </summary>
    public string TimestampFormatted => Timestamp.ToString("HH:mm:ss.fff");

    /// <summary>
    /// Formatted source port (displays "-" for null)
    /// </summary>
    public string SourcePortFormatted => SourcePort?.ToString() ?? "-";

    /// <summary>
    /// Formatted destination port (displays "-" for null)
    /// </summary>
    public string DestinationPortFormatted => DestinationPort?.ToString() ?? "-";

    /// <summary>
    /// Creates a PacketViewModel from LivePacketData
    /// </summary>
    public static PacketViewModel FromLivePacketData(PCAPAnalyzer.Core.Models.Capture.LivePacketData packet)
    {
        return new PacketViewModel
        {
            SequenceNumber = packet.SequenceNumber,
            Timestamp = packet.Timestamp,
            SourceIp = packet.SourceIp ?? "Unknown",
            SourcePort = packet.SourcePort,
            DestinationIp = packet.DestinationIp ?? "Unknown",
            DestinationPort = packet.DestinationPort,
            Protocol = packet.Protocol,
            Length = packet.Length,
            Info = packet.ProtocolInfo ?? string.Empty,
            HasAnomaly = packet.HasAnomaly
        };
    }
}
