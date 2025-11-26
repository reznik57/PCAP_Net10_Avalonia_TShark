using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Unified anomaly model for all network anomalies.
/// Replaces SecurityAnomaly, TCPAnomaly, and SpecializedAnomaly.
/// </summary>
public class NetworkAnomaly
{
    /// <summary>
    /// Unique identifier for this anomaly
    /// </summary>
    public string Id { get; init; } = Guid.NewGuid().ToString();

    /// <summary>
    /// High-level category of the anomaly
    /// </summary>
    public AnomalyCategory Category { get; set; }

    /// <summary>
    /// Specific type within the category (e.g., "SYN Flood", "TCP Retransmission")
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Severity level of the anomaly
    /// </summary>
    public AnomalySeverity Severity { get; set; }

    /// <summary>
    /// Human-readable description of the anomaly
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Timestamp when the anomaly was detected
    /// </summary>
    public DateTime DetectedAt { get; set; }

    /// <summary>
    /// Name of the detector that identified this anomaly
    /// </summary>
    public string DetectorName { get; set; } = string.Empty;

    // Network Context

    /// <summary>
    /// Source IP address
    /// </summary>
    public string SourceIP { get; set; } = string.Empty;

    /// <summary>
    /// Destination IP address
    /// </summary>
    public string DestinationIP { get; set; } = string.Empty;

    /// <summary>
    /// Source port (0 if not applicable)
    /// </summary>
    public int SourcePort { get; set; }

    /// <summary>
    /// Destination port (0 if not applicable)
    /// </summary>
    public int DestinationPort { get; set; }

    /// <summary>
    /// Protocol name (e.g., "TCP", "UDP", "ICMP")
    /// </summary>
    public string Protocol { get; set; } = string.Empty;

    // TCP-Specific (optional)

    /// <summary>
    /// TCP stream identifier (null if not TCP)
    /// </summary>
    public string? TCPStream { get; set; }

    // Evidence

    /// <summary>
    /// List of frame numbers affected by this anomaly
    /// </summary>
    public List<long> AffectedFrames { get; set; } = new();

    /// <summary>
    /// Quantitative metrics related to the anomaly
    /// </summary>
    public Dictionary<string, object> Metrics { get; set; } = new();

    /// <summary>
    /// Additional evidence and context
    /// </summary>
    public Dictionary<string, object> Evidence { get; set; } = new();

    // Remediation

    /// <summary>
    /// Recommended action to address this anomaly
    /// </summary>
    public string Recommendation { get; set; } = string.Empty;

    /// <summary>
    /// Specific remediation action that can be taken
    /// </summary>
    public string? RemediationAction { get; set; }
}

/// <summary>
/// High-level categories of network anomalies
/// </summary>
public enum AnomalyCategory
{
    /// <summary>
    /// Network-layer anomalies (SYN floods, ARP spoofing, ICMP floods)
    /// </summary>
    Network,

    /// <summary>
    /// TCP-specific anomalies (retransmissions, duplicate ACKs, out-of-order)
    /// </summary>
    TCP,

    /// <summary>
    /// Application-layer anomalies (DNS tunneling, beaconing)
    /// </summary>
    Application,

    /// <summary>
    /// VoIP-specific anomalies (SIP flooding, RTP issues)
    /// </summary>
    VoIP,

    /// <summary>
    /// IoT protocol anomalies (MQTT, CoAP issues)
    /// </summary>
    IoT,

    /// <summary>
    /// Security-related anomalies (cryptomining, data exfiltration)
    /// </summary>
    Security,

    /// <summary>
    /// Malformed or invalid packets
    /// </summary>
    Malformed
}

/// <summary>
/// Severity levels for anomalies
/// </summary>
public enum AnomalySeverity
{
    /// <summary>
    /// Low severity - informational
    /// </summary>
    Low,

    /// <summary>
    /// Medium severity - should be investigated
    /// </summary>
    Medium,

    /// <summary>
    /// High severity - requires attention
    /// </summary>
    High,

    /// <summary>
    /// Critical severity - immediate action required
    /// </summary>
    Critical
}
