using System;
using System.Collections.Generic;
using System.Linq;

namespace PCAPAnalyzer.Core.Models
{
    public enum ReportType
    {
        Executive,
        Technical,
        Compliance,
        Security,
        Performance,
        Custom
    }

    public enum SeverityLevel
    {
        Critical,
        High,
        Medium,
        Low,
        Info
    }

    public enum RemediationPriority
    {
        Immediate,
        High,
        Medium,
        Low,
        Scheduled
    }

    public class NetworkAnalysisReport
    {
        public string ReportId { get; set; } = Guid.NewGuid().ToString();
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
        public string GeneratedBy { get; set; } = "PCAP Security Analyzer";
        public string Version { get; set; } = "2.0";
        public ReportType Type { get; set; }
        public string CustomerName { get; set; } = "";
        public string NetworkSegment { get; set; } = "";
        public TimeSpan AnalysisDuration { get; set; }
        
        // Report Sections
        public ExecutiveSummary ExecutiveSummary { get; set; } = new();
        public NetworkOverview NetworkOverview { get; set; } = new();
        public List<SecurityFinding> SecurityFindings { get; set; } = new();
        public List<PerformanceIssue> PerformanceIssues { get; set; } = new();
        public List<ComplianceViolation> ComplianceViolations { get; set; } = new();
        public List<Recommendation> Recommendations { get; set; } = new();
        public RiskAssessment RiskAssessment { get; set; } = new();
        public RemediationPlan RemediationPlan { get; set; } = new();
        public TechnicalDetails TechnicalDetails { get; set; } = new();
        
        // Report Configuration
        public ReportConfiguration Configuration { get; set; } = new();
    }

    public class ReportConfiguration
    {
        public bool IncludeExecutiveSummary { get; set; } = true;
        public bool IncludeSecurityFindings { get; set; } = true;
        public bool IncludePerformanceAnalysis { get; set; } = true;
        public bool IncludeComplianceCheck { get; set; } = true;
        public bool IncludeRecommendations { get; set; } = true;
        public bool IncludeTechnicalDetails { get; set; } = true;
        public bool IncludeRawData { get; set; }
        public bool IncludePacketSamples { get; set; }
        public bool IncludeNetworkDiagrams { get; set; } = true;
        public bool IncludeRemediationTimeline { get; set; } = true;
        public bool IncludeCostEstimates { get; set; }
        public int MaxFindingsPerCategory { get; set; } = 10;
        public SeverityLevel MinimumSeverity { get; set; } = SeverityLevel.Low;
    }

    public class ExecutiveSummary
    {
        public string Overview { get; set; } = "";
        public int TotalPacketsAnalyzed { get; set; }
        public int TotalIssuesFound { get; set; }
        public int CriticalIssues { get; set; }
        public int HighPriorityIssues { get; set; }
        public string OverallRiskLevel { get; set; } = "Medium";
        public double SecurityScore { get; set; } // 0-100
        public double ComplianceScore { get; set; } // 0-100
        public double PerformanceScore { get; set; } // 0-100
        public List<string> KeyFindings { get; set; } = new();
        public List<string> ImmediateActions { get; set; } = new();
        public string BusinessImpact { get; set; } = "";
        public string EstimatedRemediationEffort { get; set; } = "";
    }

    public class NetworkOverview
    {
        public int TotalDevices { get; set; }
        public int TotalConnections { get; set; }
        public long TotalBandwidth { get; set; }
        public List<NetworkSegmentInfo> Segments { get; set; } = new();
        public List<DeviceInfo> CriticalDevices { get; set; } = new();
        public Dictionary<string, int> ProtocolDistribution { get; set; } = new();
        public Dictionary<string, int> ServiceDistribution { get; set; } = new();
        public List<TopTalker> TopTalkers { get; set; } = new();
        public List<string> ExternalConnections { get; set; } = new();
    }

    public class SecurityFinding
    {
        public string FindingId { get; set; } = Guid.NewGuid().ToString();
        public string Title { get; set; } = "";
        public string Category { get; set; } = "";
        public SeverityLevel Severity { get; set; }
        public string Description { get; set; } = "";
        public string TechnicalDetails { get; set; } = "";
        public List<AffectedSystem> AffectedSystems { get; set; } = new();
        public string PotentialImpact { get; set; } = "";
        public string RootCause { get; set; } = "";
        public RemediationStep Remediation { get; set; } = new();
        public List<string> Evidence { get; set; } = new();
        public DateTime FirstDetected { get; set; }
        public DateTime LastDetected { get; set; }
        public int OccurrenceCount { get; set; }
        public Dictionary<string, string> References { get; set; } = new();
        public string CveReference { get; set; } = "";
        public double RiskScore { get; set; }
    }

    public class AffectedSystem
    {
        public string IpAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string MacAddress { get; set; } = "";
        public string OperatingSystem { get; set; } = "";
        public List<int> AffectedPorts { get; set; } = new();
        public List<string> AffectedServices { get; set; } = new();
        public string Location { get; set; } = "";
        public string Owner { get; set; } = "";
        public string Department { get; set; } = "";
        public bool IsCriticalAsset { get; set; }
        public List<string> VulnerableComponents { get; set; } = new();
        public Dictionary<string, string> AdditionalInfo { get; set; } = new();
    }

    public class RemediationStep
    {
        public RemediationPriority Priority { get; set; }
        public string Summary { get; set; } = "";
        public List<string> DetailedSteps { get; set; } = new();
        public string EstimatedEffort { get; set; } = "";
        public string RequiredSkills { get; set; } = "";
        public List<string> Prerequisites { get; set; } = new();
        public List<string> Tools { get; set; } = new();
        public string ValidationMethod { get; set; } = "";
        public string ExpectedOutcome { get; set; } = "";
        public List<string> PotentialRisks { get; set; } = new();
        public string FallbackPlan { get; set; } = "";
        public Dictionary<string, string> ConfigurationChanges { get; set; } = new();
        public List<string> TestingSteps { get; set; } = new();
    }

    public class PerformanceIssue
    {
        public string IssueId { get; set; } = Guid.NewGuid().ToString();
        public string Title { get; set; } = "";
        public string Category { get; set; } = ""; // Latency, Bandwidth, Packet Loss, etc.
        public SeverityLevel Severity { get; set; }
        public string Description { get; set; } = "";
        public List<AffectedSystem> AffectedSystems { get; set; } = new();
        public PerformanceMetrics Metrics { get; set; } = new();
        public string Impact { get; set; } = "";
        public RemediationStep Remediation { get; set; } = new();
        public List<string> RelatedFindings { get; set; } = new();
    }

    public class PerformanceMetrics
    {
        public double AverageLatency { get; set; }
        public double MaxLatency { get; set; }
        public double PacketLossRate { get; set; }
        public double Jitter { get; set; }
        public long BandwidthUtilization { get; set; }
        public double RetransmissionRate { get; set; }
        public int ConcurrentConnections { get; set; }
        public Dictionary<string, double> CustomMetrics { get; set; } = new();
    }

    public class ComplianceViolation
    {
        public string ViolationId { get; set; } = Guid.NewGuid().ToString();
        public string Standard { get; set; } = ""; // PCI-DSS, HIPAA, GDPR, etc.
        public string Requirement { get; set; } = "";
        public string Description { get; set; } = "";
        public SeverityLevel Severity { get; set; }
        public List<AffectedSystem> AffectedSystems { get; set; } = new();
        public string Evidence { get; set; } = "";
        public RemediationStep Remediation { get; set; } = new();
        public string ComplianceImpact { get; set; } = "";
        public DateTime DueDate { get; set; }
        public string AuditorNotes { get; set; } = "";
    }

    public class Recommendation
    {
        public string RecommendationId { get; set; } = Guid.NewGuid().ToString();
        public RemediationPriority Priority { get; set; }
        public string Category { get; set; } = "";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public string Benefit { get; set; } = "";
        public string Implementation { get; set; } = "";
        public string EstimatedCost { get; set; } = "";
        public string EstimatedTimeframe { get; set; } = "";
        public List<string> Dependencies { get; set; } = new();
        public List<string> Risks { get; set; } = new();
        public double ExpectedImprovement { get; set; } // Percentage
        public List<string> RelatedFindings { get; set; } = new();
    }

    public class RiskAssessment
    {
        public double OverallRiskScore { get; set; }
        public string RiskLevel { get; set; } = "";
        public Dictionary<string, double> CategoryScores { get; set; } = new();
        public List<RiskFactor> RiskFactors { get; set; } = new();
        public string RiskTrend { get; set; } = ""; // Increasing, Stable, Decreasing
        public List<string> MitigationStrategies { get; set; } = new();
        public string BusinessImpactAnalysis { get; set; } = "";
    }

    public class RiskFactor
    {
        public string Name { get; set; } = "";
        public double Score { get; set; }
        public string Description { get; set; } = "";
        public string Mitigation { get; set; } = "";
    }

    public class RemediationPlan
    {
        public List<RemediationPhase> Phases { get; set; } = new();
        public string TotalEstimatedTime { get; set; } = "";
        public string TotalEstimatedCost { get; set; } = "";
        public List<string> RequiredResources { get; set; } = new();
        public Dictionary<string, List<RemediationTask>> TasksByPriority { get; set; } = new();
        public List<string> Dependencies { get; set; } = new();
        public string SuccessCriteria { get; set; } = "";
    }

    public class RemediationPhase
    {
        public int PhaseNumber { get; set; }
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public List<RemediationTask> Tasks { get; set; } = new();
        public List<string> Deliverables { get; set; } = new();
        public string SuccessCriteria { get; set; } = "";
    }

    public class RemediationTask
    {
        public string TaskId { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string AssignedTo { get; set; } = "";
        public RemediationPriority Priority { get; set; }
        public string EstimatedEffort { get; set; } = "";
        public List<string> Dependencies { get; set; } = new();
        public string Status { get; set; } = "Pending";
        public List<string> RelatedFindings { get; set; } = new();
    }

    public class TechnicalDetails
    {
        public Dictionary<string, List<PacketSample>> PacketSamples { get; set; } = new();
        public List<NetworkFlow> SuspiciousFlows { get; set; } = new();
        public Dictionary<string, string> ConfigurationSnapshots { get; set; } = new();
        public List<LogEntry> RelevantLogs { get; set; } = new();
        public Dictionary<string, object> RawMetrics { get; set; } = new();
    }

    public class PacketSample
    {
        public int PacketNumber { get; set; }
        public DateTime Timestamp { get; set; }
        public string Source { get; set; } = "";
        public string Destination { get; set; } = "";
        public string Protocol { get; set; } = "";
        public string Summary { get; set; } = "";
        public string HexDump { get; set; } = "";
        public Dictionary<string, string> Headers { get; set; } = new();
    }

    public class NetworkFlow
    {
        public string FlowId { get; set; } = "";
        public string SourceIP { get; set; } = "";
        public int SourcePort { get; set; }
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";
        public long BytesTransferred { get; set; }
        public int PacketCount { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public List<string> Flags { get; set; } = new();
        public string Reason { get; set; } = "";
    }

    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Source { get; set; } = "";
        public string Level { get; set; } = "";
        public string Message { get; set; } = "";
        public Dictionary<string, string> Context { get; set; } = new();
    }

    public class NetworkSegmentInfo
    {
        public string Name { get; set; } = "";
        public string Subnet { get; set; } = "";
        public int DeviceCount { get; set; }
        public List<string> Services { get; set; } = new();
        public string SecurityLevel { get; set; } = "";
    }

    public class DeviceInfo
    {
        public string IpAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string Type { get; set; } = "";
        public string Criticality { get; set; } = "";
        public List<string> Services { get; set; } = new();
    }

    public class TopTalker
    {
        public string IpAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public int ConnectionCount { get; set; }
    }
}