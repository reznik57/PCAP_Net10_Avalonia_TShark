using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Security;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Analyzes individual network streams for security risks including encryption status,
/// beaconing patterns, data exfiltration indicators, and generates risk scores.
/// </summary>
public class StreamSecurityAnalyzer
{
    // Thresholds for risk scoring
    private const double UPLOAD_DOWNLOAD_RATIO_THRESHOLD = 3.0;
    private const double BEACONING_INTERVAL_VARIANCE_THRESHOLD = 0.25; // CV threshold for regularity
    private const int MIN_PACKETS_FOR_BEACONING = 10;
    private const long LARGE_TRANSFER_THRESHOLD = 10 * 1024 * 1024; // 10MB

    // Protocol detection sets (FrozenSet for optimized static lookup)
    private static readonly FrozenSet<string> UnencryptedProtocols = FrozenSet.ToFrozenSet(
        ["HTTP", "FTP", "TELNET", "SMTP", "POP3", "IMAP", "DNS", "SNMP", "RTP", "RTCP"],
        StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenSet<int> EncryptedPorts = FrozenSet.ToFrozenSet([443, 993, 995, 465, 587, 636, 989, 990, 992, 8443]);
    private static readonly FrozenSet<int> UnencryptedPorts = FrozenSet.ToFrozenSet([80, 21, 23, 25, 110, 143, 389, 1433, 3306, 5432]);

    // SearchValues for SIMD-optimized substring matching in protocol strings
    // Covers both keyword detection (TLS, SSL, etc.) and protocol version detection (TLSV1.2, TLSV1.3)
    private static readonly SearchValues<string> EncryptionProtocolSearchValues = SearchValues.Create(
        ["TLS", "TLSV1.2", "TLSV1.3", "SSL", "HTTPS", "SRTP", "DTLS", "QUIC", "SSH", "WIREGUARD", "OPENVPN", "IPSEC", "ESP"],
        StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Performs comprehensive security analysis on a stream of packets.
    /// </summary>
    public StreamSecurityResult Analyze(IEnumerable<PacketInfo> packets, string sourceIP, int sourcePort, string destIP, int destPort)
    {
        var packetList = packets.ToList();

        if (packetList.Count == 0)
        {
            return new StreamSecurityResult
            {
                RiskScore = 0,
                RiskLevel = StreamRiskLevel.Unknown,
                EncryptionStatus = EncryptionStatus.Unknown,
                Findings = new List<StreamSecurityFinding>()
            };
        }

        var result = new StreamSecurityResult
        {
            SourceIP = sourceIP,
            SourcePort = sourcePort,
            DestinationIP = destIP,
            DestinationPort = destPort,
            PacketCount = packetList.Count,
            TotalBytes = packetList.Sum(p => (long)p.Length),
            Findings = new List<StreamSecurityFinding>()
        };

        // Analyze encryption status
        result.EncryptionStatus = AnalyzeEncryption(packetList, sourcePort, destPort);
        result.EncryptionProtocol = GetEncryptionProtocol(packetList);

        // Analyze beaconing patterns
        var beaconing = AnalyzeBeaconing(packetList);
        result.BeaconingDetected = beaconing.IsBeaconing;
        result.BeaconingInterval = beaconing.AverageInterval;
        result.BeaconingConfidence = beaconing.Confidence;

        // Analyze data exfiltration indicators
        var exfiltration = AnalyzeExfiltration(packetList, sourceIP, destIP);
        result.UploadDownloadRatio = exfiltration.Ratio;
        result.DataExfiltrationIndicator = exfiltration.IsIndicator;

        // Protocol security assessment
        var protocolAssessment = AnalyzeProtocolSecurity(packetList, sourcePort, destPort);
        result.ProtocolSecurityLevel = protocolAssessment.Level;
        result.ProtocolSecurityReason = protocolAssessment.Reason;
        result.ProtocolVulnerabilities = protocolAssessment.Vulnerabilities;
        result.ProtocolRecommendation = protocolAssessment.Recommendation;

        // Generate findings
        GenerateFindings(result, beaconing, exfiltration, protocolAssessment);

        // Calculate final risk score
        result.RiskScore = CalculateRiskScore(result, beaconing, exfiltration, protocolAssessment);
        result.RiskLevel = GetRiskLevel(result.RiskScore);

        return result;
    }

    private static EncryptionStatus AnalyzeEncryption(List<PacketInfo> packets, int sourcePort, int destPort)
    {
        // Check L7 protocol for encryption indicators
        var protocols = packets
            .Where(p => !string.IsNullOrEmpty(p.L7Protocol))
            .Select(p => p.L7Protocol!.ToUpperInvariant())
            .Distinct()
            .ToList();

        // Check for encrypted protocols (keyword match)
        if (protocols.Any(ContainsEncryptedKeyword))
            return EncryptionStatus.Encrypted;

        // Check for explicitly unencrypted protocols (exact match or PLAINTEXT keyword)
        if (protocols.Any(p => UnencryptedProtocols.Contains(p) || p.Contains("PLAINTEXT", StringComparison.Ordinal)))
            return EncryptionStatus.Unencrypted;

        // Check common encrypted ports
        if (EncryptedPorts.Contains(sourcePort) || EncryptedPorts.Contains(destPort))
            return EncryptionStatus.LikelyEncrypted;

        // Check common unencrypted ports
        if (UnencryptedPorts.Contains(sourcePort) || UnencryptedPorts.Contains(destPort))
            return EncryptionStatus.LikelyUnencrypted;

        return EncryptionStatus.Unknown;
    }

    private static bool ContainsEncryptedKeyword(string protocol)
    {
        // Use SIMD-optimized SearchValues for substring matching
        return protocol.AsSpan().ContainsAny(EncryptionProtocolSearchValues);
    }

    private static string? GetEncryptionProtocol(List<PacketInfo> packets)
    {
        foreach (var packet in packets)
        {
            if (string.IsNullOrEmpty(packet.L7Protocol)) continue;

            // Use SIMD-optimized SearchValues for substring matching
            if (packet.L7Protocol.AsSpan().ContainsAny(EncryptionProtocolSearchValues))
                return packet.L7Protocol;
        }

        return null;
    }

    private BeaconingAnalysis AnalyzeBeaconing(List<PacketInfo> packets)
    {
        var result = new BeaconingAnalysis();

        if (packets.Count < MIN_PACKETS_FOR_BEACONING)
        {
            return result;
        }

        // Sort by timestamp and calculate intervals
        var sortedPackets = packets.OrderBy(p => p.Timestamp).ToList();
        var intervals = new List<double>();

        for (int i = 1; i < sortedPackets.Count; i++)
        {
            var interval = (sortedPackets[i].Timestamp - sortedPackets[i - 1].Timestamp).TotalSeconds;
            if (interval > 0 && interval < 3600) // Ignore gaps > 1 hour
            {
                intervals.Add(interval);
            }
        }

        if (intervals.Count < MIN_PACKETS_FOR_BEACONING - 1)
        {
            return result;
        }

        result.AverageInterval = intervals.Average();
        var variance = intervals.Sum(i => Math.Pow(i - result.AverageInterval, 2)) / intervals.Count;
        var stdDev = Math.Sqrt(variance);

        // Coefficient of variation (CV) - lower = more regular
        var cv = result.AverageInterval > 0 ? stdDev / result.AverageInterval : double.MaxValue;

        // Detect beaconing: regular intervals with low variance
        result.IsBeaconing = cv < BEACONING_INTERVAL_VARIANCE_THRESHOLD && result.AverageInterval > 0.5; // > 0.5s interval
        result.Confidence = Math.Max(0, 100 - (cv * 200)); // Higher confidence for lower CV

        return result;
    }

    private ExfiltrationAnalysis AnalyzeExfiltration(List<PacketInfo> packets, string sourceIP, string destIP)
    {
        var result = new ExfiltrationAnalysis();

        // Calculate bytes in each direction
        long toDestBytes = 0, toSourceBytes = 0;

        foreach (var packet in packets)
        {
            if (packet.SourceIP == sourceIP && packet.DestinationIP == destIP)
                toDestBytes += packet.Length;
            else if (packet.SourceIP == destIP && packet.DestinationIP == sourceIP)
                toSourceBytes += packet.Length;
        }

        result.BytesToDestination = toDestBytes;
        result.BytesToSource = toSourceBytes;

        // Calculate upload/download ratio (from perspective of sourceIP)
        if (toSourceBytes > 0)
        {
            result.Ratio = (double)toDestBytes / toSourceBytes;
        }
        else if (toDestBytes > 0)
        {
            result.Ratio = double.PositiveInfinity;
        }

        // Check for exfiltration indicators
        var totalBytes = toDestBytes + toSourceBytes;
        result.IsLargeTransfer = totalBytes >= LARGE_TRANSFER_THRESHOLD;
        result.IsIndicator = result.Ratio >= UPLOAD_DOWNLOAD_RATIO_THRESHOLD && toDestBytes > 1024 * 1024; // >1MB outbound

        return result;
    }

    private ProtocolSecurityEvaluator.SecurityAssessment AnalyzeProtocolSecurity(List<PacketInfo> packets, int sourcePort, int destPort)
    {
        // Get the primary L7 protocol
        var l7Protocol = packets
            .Where(p => !string.IsNullOrEmpty(p.L7Protocol))
            .GroupBy(p => p.L7Protocol)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault();

        // Get the primary L4 protocol
        var l4Protocol = packets
            .GroupBy(p => p.Protocol)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault();

        // Use the well-known port for assessment (typically the lower port is the service)
        var servicePort = Math.Min(sourcePort, destPort);
        if (servicePort == 0) servicePort = Math.Max(sourcePort, destPort);

        if (!string.IsNullOrEmpty(l7Protocol))
        {
            return ProtocolSecurityEvaluator.EvaluateProtocol(l7Protocol, (ushort)servicePort);
        }

        // Fall back to L4 protocol
        return ProtocolSecurityEvaluator.EvaluateProtocol(l4Protocol.ToString(), (ushort)servicePort);
    }

    private void GenerateFindings(StreamSecurityResult result, BeaconingAnalysis beaconing, ExfiltrationAnalysis exfiltration, ProtocolSecurityEvaluator.SecurityAssessment protocolAssessment)
    {
        // Encryption findings
        switch (result.EncryptionStatus)
        {
            case EncryptionStatus.Unencrypted:
                result.Findings.Add(new StreamSecurityFinding
                {
                    Type = StreamFindingType.Encryption,
                    Severity = StreamFindingSeverity.High,
                    Title = "Unencrypted Communication",
                    Description = "This stream uses unencrypted protocols. Data can be intercepted by attackers.",
                    Recommendation = "Use TLS/SSL encryption for this communication."
                });
                break;
            case EncryptionStatus.LikelyUnencrypted:
                result.Findings.Add(new StreamSecurityFinding
                {
                    Type = StreamFindingType.Encryption,
                    Severity = StreamFindingSeverity.Medium,
                    Title = "Likely Unencrypted",
                    Description = "Based on port analysis, this stream is likely unencrypted.",
                    Recommendation = "Verify encryption status and consider using encrypted alternatives."
                });
                break;
            case EncryptionStatus.Encrypted:
                result.Findings.Add(new StreamSecurityFinding
                {
                    Type = StreamFindingType.Encryption,
                    Severity = StreamFindingSeverity.Info,
                    Title = "Encrypted Communication",
                    Description = $"This stream uses {result.EncryptionProtocol ?? "encryption"}.",
                    Recommendation = "Ensure encryption protocol version is up-to-date."
                });
                break;
        }

        // Beaconing findings
        if (beaconing.IsBeaconing && beaconing.Confidence > 50)
        {
            result.Findings.Add(new StreamSecurityFinding
            {
                Type = StreamFindingType.Beaconing,
                Severity = beaconing.Confidence > 80 ? StreamFindingSeverity.High : StreamFindingSeverity.Medium,
                Title = "Beaconing Pattern Detected",
                Description = $"Regular communication interval of ~{beaconing.AverageInterval:F1}s detected ({beaconing.Confidence:F0}% confidence). This may indicate C2 communication.",
                Recommendation = "Investigate source host for potential malware or verify this is expected behavior (e.g., keepalive, monitoring)."
            });
        }

        // Exfiltration findings
        if (exfiltration.IsIndicator)
        {
            result.Findings.Add(new StreamSecurityFinding
            {
                Type = StreamFindingType.DataExfiltration,
                Severity = exfiltration.IsLargeTransfer ? StreamFindingSeverity.High : StreamFindingSeverity.Medium,
                Title = "Potential Data Exfiltration",
                Description = $"Upload/Download ratio of {exfiltration.Ratio:F1}:1 with {exfiltration.BytesToDestination.ToFormattedBytes()} outbound.",
                Recommendation = "Verify if this data transfer is authorized and investigate destination."
            });
        }
        else if (exfiltration.IsLargeTransfer)
        {
            result.Findings.Add(new StreamSecurityFinding
            {
                Type = StreamFindingType.DataExfiltration,
                Severity = StreamFindingSeverity.Low,
                Title = "Large Data Transfer",
                Description = $"Total transfer of {(exfiltration.BytesToDestination + exfiltration.BytesToSource).ToFormattedBytes()}.",
                Recommendation = "Verify this transfer is expected."
            });
        }

        // Protocol security findings
        if (protocolAssessment.Level == ProtocolSecurityEvaluator.SecurityLevel.Critical ||
            protocolAssessment.Level == ProtocolSecurityEvaluator.SecurityLevel.High)
        {
            result.Findings.Add(new StreamSecurityFinding
            {
                Type = StreamFindingType.Protocol,
                Severity = protocolAssessment.Level == ProtocolSecurityEvaluator.SecurityLevel.Critical
                    ? StreamFindingSeverity.Critical
                    : StreamFindingSeverity.High,
                Title = "Insecure Protocol",
                Description = protocolAssessment.Reason,
                Recommendation = protocolAssessment.Recommendation,
                Vulnerabilities = protocolAssessment.Vulnerabilities
            });
        }
        else if (protocolAssessment.Level == ProtocolSecurityEvaluator.SecurityLevel.Medium)
        {
            result.Findings.Add(new StreamSecurityFinding
            {
                Type = StreamFindingType.Protocol,
                Severity = StreamFindingSeverity.Medium,
                Title = "Protocol Security Concern",
                Description = protocolAssessment.Reason,
                Recommendation = protocolAssessment.Recommendation
            });
        }
    }

    private int CalculateRiskScore(StreamSecurityResult result, BeaconingAnalysis beaconing, ExfiltrationAnalysis exfiltration, ProtocolSecurityEvaluator.SecurityAssessment protocolAssessment)
    {
        int score = 0;

        // Encryption (0-30 points)
        score += result.EncryptionStatus switch
        {
            EncryptionStatus.Unencrypted => 30,
            EncryptionStatus.LikelyUnencrypted => 20,
            EncryptionStatus.Unknown => 10,
            EncryptionStatus.LikelyEncrypted => 5,
            EncryptionStatus.Encrypted => 0,
            _ => 10
        };

        // Beaconing (0-25 points)
        if (beaconing.IsBeaconing)
        {
            score += (int)(beaconing.Confidence / 4); // Max 25 points
        }

        // Data exfiltration (0-25 points)
        if (exfiltration.IsIndicator)
        {
            score += exfiltration.IsLargeTransfer ? 25 : 15;
        }
        else if (exfiltration.Ratio >= 2.0)
        {
            score += 10;
        }

        // Protocol security (0-20 points)
        score += protocolAssessment.Level switch
        {
            ProtocolSecurityEvaluator.SecurityLevel.Critical => 20,
            ProtocolSecurityEvaluator.SecurityLevel.High => 15,
            ProtocolSecurityEvaluator.SecurityLevel.Medium => 10,
            ProtocolSecurityEvaluator.SecurityLevel.Low => 5,
            ProtocolSecurityEvaluator.SecurityLevel.Secure => 0,
            _ => 5
        };

        return Math.Min(100, score);
    }

    private static StreamRiskLevel GetRiskLevel(int score)
    {
        return score switch
        {
            >= 75 => StreamRiskLevel.Critical,
            >= 50 => StreamRiskLevel.High,
            >= 25 => StreamRiskLevel.Medium,
            >= 10 => StreamRiskLevel.Low,
            _ => StreamRiskLevel.Safe
        };
    }

    // Internal analysis classes
    private class BeaconingAnalysis
    {
        public bool IsBeaconing { get; set; }
        public double AverageInterval { get; set; }
        public double Confidence { get; set; }
    }

    private class ExfiltrationAnalysis
    {
        public double Ratio { get; set; }
        public bool IsIndicator { get; set; }
        public bool IsLargeTransfer { get; set; }
        public long BytesToDestination { get; set; }
        public long BytesToSource { get; set; }
    }
}

// Models for security analysis results

/// <summary>
/// Comprehensive security analysis result for a network stream.
/// </summary>
public class StreamSecurityResult
{
    // Stream identification
    public string SourceIP { get; set; } = "";
    public int SourcePort { get; set; }
    public string DestinationIP { get; set; } = "";
    public int DestinationPort { get; set; }
    public int PacketCount { get; set; }
    public long TotalBytes { get; set; }

    // Risk assessment
    public int RiskScore { get; set; }
    public StreamRiskLevel RiskLevel { get; set; }

    // Encryption analysis
    public EncryptionStatus EncryptionStatus { get; set; }
    public string? EncryptionProtocol { get; set; }

    // Beaconing analysis
    public bool BeaconingDetected { get; set; }
    public double BeaconingInterval { get; set; }
    public double BeaconingConfidence { get; set; }

    // Data exfiltration
    public double UploadDownloadRatio { get; set; }
    public bool DataExfiltrationIndicator { get; set; }

    // Protocol security
    public ProtocolSecurityEvaluator.SecurityLevel ProtocolSecurityLevel { get; set; }
    public string ProtocolSecurityReason { get; set; } = "";
    public List<string> ProtocolVulnerabilities { get; set; } = new();
    public string ProtocolRecommendation { get; set; } = "";

    // Detailed findings
    public List<StreamSecurityFinding> Findings { get; set; } = new();
}

public enum StreamRiskLevel
{
    Unknown,
    Safe,
    Low,
    Medium,
    High,
    Critical
}

public enum EncryptionStatus
{
    Unknown,
    Encrypted,
    LikelyEncrypted,
    LikelyUnencrypted,
    Unencrypted
}

/// <summary>
/// Individual security finding from stream analysis.
/// </summary>
public class StreamSecurityFinding
{
    public StreamFindingType Type { get; set; }
    public StreamFindingSeverity Severity { get; set; }
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string Recommendation { get; set; } = "";
    public List<string> Vulnerabilities { get; set; } = new();
}

public enum StreamFindingType
{
    Encryption,
    Beaconing,
    DataExfiltration,
    Protocol,
    Other
}

public enum StreamFindingSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}
