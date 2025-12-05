using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// View model for a packet row in the Anomaly Packet Table.
/// Joins PacketInfo with associated NetworkAnomaly data.
/// </summary>
public class AnomalyPacketViewModel
{
    /// <summary>
    /// The underlying packet data
    /// </summary>
    public PacketInfo Packet { get; }

    /// <summary>
    /// All anomalies that reference this packet's frame number
    /// </summary>
    public List<NetworkAnomaly> Anomalies { get; }

    /// <summary>
    /// Primary anomaly (highest severity)
    /// </summary>
    public NetworkAnomaly PrimaryAnomaly { get; }

    /// <summary>
    /// Number of anomalies referencing this packet
    /// </summary>
    public int AnomalyCount => Anomalies.Count;

    /// <summary>
    /// Whether packet appears in multiple anomalies
    /// </summary>
    public bool HasMultipleAnomalies => AnomalyCount > 1;

    // Convenience properties for binding
    public uint FrameNumber => Packet.FrameNumber;
    public System.DateTime Timestamp => Packet.Timestamp;
    public string SourceIP => Packet.SourceIP;
    public int SourcePort => Packet.SourcePort;
    public string DestinationIP => Packet.DestinationIP;
    public int DestinationPort => Packet.DestinationPort;
    public Protocol Protocol => Packet.Protocol;
    public int Length => Packet.Length;
    public string Info => Packet.Info ?? string.Empty;

    // Anomaly properties
    public string AnomalyType => PrimaryAnomaly.Type;
    public AnomalySeverity Severity => PrimaryAnomaly.Severity;
    public AnomalyCategory Category => PrimaryAnomaly.Category;

    /// <summary>
    /// Display text for anomaly column (e.g., "TCP Retransmission" or "SYN Flood +2")
    /// </summary>
    public string AnomalyDisplay => HasMultipleAnomalies
        ? $"{PrimaryAnomaly.Type} +{AnomalyCount - 1}"
        : PrimaryAnomaly.Type;

    /// <summary>
    /// Tooltip showing all anomalies for this packet
    /// </summary>
    public string AnomalyTooltip => string.Join("\n", Anomalies.Select(a => $"[{a.Severity}] {a.Type}"));

    /// <summary>
    /// Severity color for UI binding - uses ThemeColorHelper
    /// </summary>
    public string SeverityColor => ThemeColorHelper.GetAnomalySeverityColorHex(Severity.ToString());

    public AnomalyPacketViewModel(PacketInfo packet, List<NetworkAnomaly> anomalies)
    {
        Packet = packet;
        Anomalies = anomalies.OrderByDescending(a => a.Severity).ToList();
        PrimaryAnomaly = Anomalies.First();
    }
}
