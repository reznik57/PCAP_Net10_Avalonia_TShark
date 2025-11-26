using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Legacy specialized anomaly representation used by the deprecated
/// <see cref="ISpecializedTrafficAnomalyService"/>. Maintained for consumers that
/// have not yet migrated to <see cref="NetworkAnomaly"/>.
/// </summary>
public class SpecializedAnomaly
{
    public SpecializedAnomalyType Type { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; }
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public AnomalySeverity Severity { get; set; }
    public List<long> AffectedPackets { get; set; } = new();
    public Dictionary<string, object> Metrics { get; set; } = new();
    public string Recommendation { get; set; } = string.Empty;
}

public enum SpecializedAnomalyType
{
    // VoIP
    VoIPFlooding,
    VoIPGhostCall,
    VoIPQualityIssue,
    VoIPTollFraud,

    // IoT
    IoTAnomalousActivity,
    IoTMultipleBrokers,
    IoTAmplificationAttack,
    IoTUnauthorizedAccess,

    // DNS
    DNSTunneling,
    DNSAmplification,
    DNSCachePoisoning,

    // Cryptocurrency
    Cryptomining,
    CryptojackingAttempt,

    // Data Exfiltration
    DataExfiltration,
    SlowDataExfiltration,
    EncodedDataTransfer,

    // General
    UnknownProtocolAnomaly
}
