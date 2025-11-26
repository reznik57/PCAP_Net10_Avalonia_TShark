using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Maps unified <see cref="NetworkAnomaly"/> instances back to legacy models used by
/// the deprecated anomaly services. This allows callers that still depend on
/// <see cref="SecurityAnomaly"/>, <see cref="TCPAnomaly"/>, and
/// <see cref="SpecializedAnomaly"/> to run on top of the unified detector pipeline
/// without duplicating detection logic.
/// </summary>
internal static class LegacyAnomalyMapper
{
    private static readonly Dictionary<string, TCPAnomalyType> TcpTypeMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["TCP Retransmission"] = TCPAnomalyType.Retransmission,
        ["TCP Duplicate ACK"] = TCPAnomalyType.DuplicateACK,
        ["TCP Out-of-Order"] = TCPAnomalyType.OutOfOrder,
        ["TCP Zero Window"] = TCPAnomalyType.ZeroWindow
    };

    private static readonly Dictionary<string, SpecializedAnomalyType> SpecializedTypeMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["DNS Tunneling"] = SpecializedAnomalyType.DNSTunneling,
        ["Beaconing"] = SpecializedAnomalyType.DataExfiltration,
        ["Malformed Packets"] = SpecializedAnomalyType.UnknownProtocolAnomaly,
        ["SYN Flood Attack"] = SpecializedAnomalyType.UnknownProtocolAnomaly,
        ["ICMP Flood"] = SpecializedAnomalyType.UnknownProtocolAnomaly,
        ["ARP Spoofing"] = SpecializedAnomalyType.UnknownProtocolAnomaly,
        ["Cryptomining"] = SpecializedAnomalyType.Cryptomining,
        ["Slow Data Exfiltration"] = SpecializedAnomalyType.SlowDataExfiltration,
        ["Data Exfiltration"] = SpecializedAnomalyType.DataExfiltration
    };

    public static SecurityAnomaly ToSecurityAnomaly(NetworkAnomaly anomaly)
    {
        return new SecurityAnomaly
        {
            Id = anomaly.Id,
            Type = anomaly.Type,
            Severity = anomaly.Severity,
            Description = anomaly.Description,
            DetectedAt = anomaly.DetectedAt,
            AffectedPackets = anomaly.AffectedFrames
                .Select(frame => frame > int.MaxValue ? int.MaxValue : (int)frame)
                .ToList(),
            Evidence = BuildEvidence(anomaly),
            Recommendation = anomaly.Recommendation
        };
    }

    public static TCPAnomaly? ToTcpAnomaly(NetworkAnomaly anomaly)
    {
        if (anomaly.Category != AnomalyCategory.TCP)
            return null;

        if (!TcpTypeMap.TryGetValue(anomaly.Type, out var mappedType))
            return null;

        return new TCPAnomaly
        {
            Id = anomaly.Id,
            Type = mappedType,
            Description = anomaly.Description,
            DetectedAt = anomaly.DetectedAt,
            SourceIP = anomaly.SourceIP,
            DestinationIP = anomaly.DestinationIP,
            SourcePort = anomaly.SourcePort,
            DestinationPort = anomaly.DestinationPort,
            Severity = anomaly.Severity,
            AffectedFrames = anomaly.AffectedFrames.ToList(),
            Metrics = new Dictionary<string, object>(anomaly.Metrics, StringComparer.OrdinalIgnoreCase),
            TCPStream = anomaly.TCPStream ?? string.Empty,
            Recommendation = anomaly.Recommendation
        };
    }

    public static SpecializedAnomaly? ToSpecializedAnomaly(NetworkAnomaly anomaly)
    {
        if (!TryResolveSpecializedType(anomaly, out var specializedType))
            return null;

        return new SpecializedAnomaly
        {
            Type = specializedType,
            Category = anomaly.Category.ToString(),
            Protocol = anomaly.Protocol,
            Description = anomaly.Description,
            DetectedAt = anomaly.DetectedAt,
            SourceIP = anomaly.SourceIP,
            DestinationIP = anomaly.DestinationIP,
            SourcePort = anomaly.SourcePort,
            DestinationPort = anomaly.DestinationPort,
            Severity = anomaly.Severity,
            AffectedPackets = anomaly.AffectedFrames.ToList(),
            Metrics = new Dictionary<string, object>(anomaly.Metrics, StringComparer.OrdinalIgnoreCase),
            Recommendation = anomaly.Recommendation
        };
    }

    private static Dictionary<string, object> BuildEvidence(NetworkAnomaly anomaly)
    {
        var evidence = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(anomaly.DetectorName))
            evidence["DetectorName"] = anomaly.DetectorName;
        if (!string.IsNullOrWhiteSpace(anomaly.SourceIP))
            evidence["SourceIP"] = anomaly.SourceIP;
        if (!string.IsNullOrWhiteSpace(anomaly.DestinationIP))
            evidence["DestinationIP"] = anomaly.DestinationIP;
        if (anomaly.SourcePort > 0)
            evidence["SourcePort"] = anomaly.SourcePort;
        if (anomaly.DestinationPort > 0)
            evidence["DestinationPort"] = anomaly.DestinationPort;
        if (!string.IsNullOrWhiteSpace(anomaly.Protocol))
            evidence["Protocol"] = anomaly.Protocol;
        if (!string.IsNullOrWhiteSpace(anomaly.TCPStream))
            evidence["TcpStream"] = anomaly.TCPStream;

        foreach (var kvp in anomaly.Evidence)
        {
            evidence[kvp.Key] = kvp.Value;
        }

        foreach (var kvp in anomaly.Metrics)
        {
            evidence[$"Metric.{kvp.Key}"] = kvp.Value;
        }

        return evidence;
    }

    private static bool TryResolveSpecializedType(NetworkAnomaly anomaly, out SpecializedAnomalyType specializedType)
    {
        if (SpecializedTypeMap.TryGetValue(anomaly.Type, out specializedType))
        {
            return true;
        }

        specializedType = anomaly.Category switch
        {
            AnomalyCategory.VoIP => SpecializedAnomalyType.VoIPFlooding,
            AnomalyCategory.IoT => SpecializedAnomalyType.IoTAnomalousActivity,
            AnomalyCategory.Security => SpecializedAnomalyType.DataExfiltration,
            _ => SpecializedAnomalyType.UnknownProtocolAnomaly
        };

        // If the category mapping falls back to Unknown ensure there is at least a name
        return specializedType != SpecializedAnomalyType.UnknownProtocolAnomaly
            || !string.IsNullOrWhiteSpace(anomaly.Type);
    }
}
