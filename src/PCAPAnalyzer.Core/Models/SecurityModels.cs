using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models
{
    public class PortRiskProfile
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string ServiceName { get; set; } = string.Empty;
        public ThreatSeverity RiskLevel { get; set; }
        public bool IsEncrypted { get; set; }
        public string[] KnownVulnerabilities { get; set; } = Array.Empty<string>();
        public string RecommendedAlternative { get; set; } = string.Empty;
        public string SecurityNotes { get; set; } = string.Empty;
        public bool RequiresImmediateAction { get; set; }
    }

    public class SecurityMetrics
    {
        public int TotalThreats { get; set; }
        public int CriticalThreats { get; set; }
        public int HighThreats { get; set; }
        public int MediumThreats { get; set; }
        public int LowThreats { get; set; }
        public int InfoThreats { get; set; }
        public double OverallRiskScore { get; set; }
        public Dictionary<string, int> ThreatsByCategory { get; set; } = new();
        public Dictionary<int, int> ThreatsByPort { get; set; } = new();
        public List<string> TopVulnerableServices { get; set; } = new();
        public DateTime AnalysisTimestamp { get; set; } = DateTime.Now;
    }

    public class EnhancedSecurityThreat
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public ThreatCategory Category { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Service { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> Vulnerabilities { get; set; } = new();
        public List<string> Mitigations { get; set; } = new();
        public string CVE { get; set; } = string.Empty;
        public double RiskScore { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public int OccurrenceCount { get; set; }
        public List<string> AffectedIPs { get; set; } = new();
        public Dictionary<string, object> Metadata { get; set; } = new();

        /// <summary>
        /// Frame numbers of packets that triggered this threat (for DrillDown investigation)
        /// </summary>
        public List<uint> FrameNumbers { get; set; } = new();

        /// <summary>
        /// Connection tuples affected by this threat (for conversation-level investigation)
        /// </summary>
        public List<ConnectionTuple> AffectedConnections { get; set; } = new();
    }

    /// <summary>
    /// Represents a network connection tuple for precise packet correlation
    /// </summary>
    public class ConnectionTuple
    {
        public string SourceIP { get; set; } = string.Empty;
        public string DestinationIP { get; set; } = string.Empty;
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = string.Empty;

        /// <summary>
        /// Creates a normalized connection key for grouping bidirectional traffic
        /// </summary>
        public string ToNormalizedKey()
        {
            // Normalize by sorting IPs so A->B and B->A produce same key
            var ips = new[] { $"{SourceIP}:{SourcePort}", $"{DestinationIP}:{DestinationPort}" };
            Array.Sort(ips);
            return $"{Protocol}|{ips[0]}|{ips[1]}";
        }

        public override string ToString() => $"{Protocol} {SourceIP}:{SourcePort} → {DestinationIP}:{DestinationPort}";

        public override bool Equals(object? obj)
        {
            if (obj is not ConnectionTuple other) return false;
            return ToNormalizedKey() == other.ToNormalizedKey();
        }

        public override int GetHashCode() => ToNormalizedKey().GetHashCode(StringComparison.Ordinal);
    }

    public enum ThreatCategory
    {
        InsecureProtocol,
        UnencryptedService,
        LegacyProtocol,
        DefaultCredentials,
        CleartextCredentials,
        KnownVulnerability,
        MaliciousActivity,
        DataExfiltration,
        CommandAndControl,
        Reconnaissance,
        DenialOfService
    }
}