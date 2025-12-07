using System;
using System.Collections.Generic;
using System.Linq;

namespace PCAPAnalyzer.Core.Models
{
    public class NetworkStatistics
    {
        public long TotalPackets { get; set; }
        public long TotalBytes { get; set; }
        public DateTime FirstPacketTime { get; set; }
        public DateTime LastPacketTime { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => LastPacketTime - FirstPacketTime;
        public double PacketsPerSecond => Duration.TotalSeconds > 0 ? TotalPackets / Duration.TotalSeconds : 0;
        public double BytesPerSecond => Duration.TotalSeconds > 0 ? TotalBytes / Duration.TotalSeconds : 0;
        
        public Dictionary<string, ProtocolStatistics> ProtocolStats { get; set; } = [];
        public List<EndpointStatistics> TopSources { get; set; } = [];
        public List<EndpointStatistics> TopDestinations { get; set; } = [];
        public HashSet<string> AllUniqueIPs { get; set; } = [];
        public List<ConversationStatistics> TopConversations { get; set; } = [];
        public List<PortStatistics> TopPorts { get; set; } = [];
        public int UniquePortCount { get; set; }  // Total count of unique ports (not just top N)
        public int TotalConversationCount { get; set; }  // Total count of all unique BIDIRECTIONAL conversations (grouped by normalized IP pair + ports)
        public int TotalStreamCount { get; set; }  // Total count of all unique DIRECTIONAL streams (4-tuple: SrcIP, SrcPort, DstIP, DstPort)
        public List<ServiceStatistics> TopServices => ServiceStats?.Values.OrderByDescending(s => s.PacketCount).Take(10).ToList() ?? [];
        public List<TimeSeriesDataPoint> ThroughputTimeSeries { get; set; } = [];
        public List<TimeSeriesDataPoint> PacketsPerSecondTimeSeries { get; set; } = [];
        public List<TimeSeriesDataPoint> AnomaliesPerSecondTimeSeries { get; set; } = [];
        public List<TimeSeriesDataPoint> ThreatsPerSecondTimeSeries { get; set; } = [];
        public List<ThroughputDataPoint> ThroughputDataPoints => ThroughputTimeSeries?.Select(t => new ThroughputDataPoint { Timestamp = t.Timestamp, Value = t.Value }).ToList() ?? [];
        public List<SecurityThreat> DetectedThreats { get; set; } = [];
        public List<ThreatInfo> Threats => DetectedThreats?.Select(t => new ThreatInfo
        {
            Type = t.Type,
            Severity = t.Severity,
            Description = t.Description,
            SourceIP = t.SourceAddress,
            DestinationIP = t.DestinationAddress,
            Timestamp = t.DetectedAt,
            Confidence = 0.8
        }).ToList() ?? [];
        public Dictionary<string, ServiceStatistics> ServiceStats { get; set; } = [];

        // Country-related statistics
        public Dictionary<string, CountryTrafficStatistics> CountryStatistics { get; set; } = [];
        public List<TrafficFlowDirection> TrafficFlows { get; set; } = [];
        public List<CountryRiskProfile> HighRiskCountries { get; set; } = [];
        public int UniqueCountries => CountryStatistics?.Count ?? 0;
        public long InternationalPackets { get; set; }
        public long DomesticPackets { get; set; }
        public double InternationalPercentage => TotalPackets > 0 ? (double)InternationalPackets / TotalPackets * 100 : 0;
        public long GeolocatedPackets { get; set; }
        public long GeolocatedBytes { get; set; }

        // Packet Size Distribution
        public PacketSizeDistribution? PacketSizeDistribution { get; set; }

        // ✅ CACHE FIX: GeoIP enrichment state to prevent redundant 3× analysis
        // When true, CountryStatistics/TrafficFlows are populated and should be reused
        public bool IsGeoIPEnriched { get; set; }
        public DateTime? GeoIPEnrichmentTimestamp { get; set; }
    }

    public class ProtocolStatistics
    {
        public string Protocol { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double Percentage { get; set; }
        public string Color { get; set; } = "#808080";
    }

    public class EndpointStatistics
    {
        public string Address { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double Percentage { get; set; }
        public Dictionary<string, long> ProtocolBreakdown { get; set; } = [];
        public bool IsInternal { get; set; }
        public string Country { get; set; } = "Unknown";
        public string CountryCode { get; set; } = "";
        public string? City { get; set; }
        public string Organization { get; set; } = "Unknown";
        public bool IsHighRisk { get; set; }
    }

    public class ConversationStatistics
    {
        public string SourceAddress { get; set; } = string.Empty;
        public string DestinationAddress { get; set; } = string.Empty;
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        public double PacketsPerSecond => Duration.TotalSeconds > 0 ? PacketCount / Duration.TotalSeconds : 0;
        public string State { get; set; } = "Active";
        public string SourceCountry { get; set; } = "Unknown";
        public string DestinationCountry { get; set; } = "Unknown";
        public bool IsCrossBorder { get; set; }
        public bool IsHighRisk { get; set; }
    }

    public class PortStatistics
    {
        public int Port { get; set; }
        public string Service { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double Percentage { get; set; }
        public bool IsWellKnown { get; set; }
    }

    public class TimeSeriesDataPoint
    {
        public DateTime Timestamp { get; set; }
        public double Value { get; set; }
        public string Series { get; set; } = string.Empty;
        public Dictionary<string, double> AdditionalMetrics { get; set; } = [];
        public double PacketsPerSecond { get; set; }
        public double AnomaliesPerSecond { get; set; }
    }

    public class SecurityThreat
    {
        public string ThreatId { get; set; } = Guid.NewGuid().ToString();
        public DateTime DetectedAt { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string SourceAddress { get; set; } = string.Empty;
        public string DestinationAddress { get; set; } = string.Empty;
        public List<long> AffectedPackets { get; set; } = [];
        public Dictionary<string, object> Evidence { get; set; } = [];
        public string Recommendation { get; set; } = string.Empty;
        public bool IsFalsePositive { get; set; }
    }

    public enum ThreatSeverity
    {
        None = 0,
        Info = 1,
        Low = 2,
        Medium = 3,
        High = 4,
        Critical = 5
    }

    public class ServiceStatistics
    {
        public string ServiceName { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public List<string> UniqueHosts { get; set; } = [];
        public Dictionary<string, long> MethodBreakdown { get; set; } = [];
        public double ResponseTime { get; set; }
        public bool IsEncrypted { get; set; }
    }
    
    public class ThroughputDataPoint
    {
        public DateTime Timestamp { get; set; }
        public double Value { get; set; }
    }

    public class ExpertInsight
    {
        public string InsightId { get; set; } = Guid.NewGuid().ToString();
        public DateTime GeneratedAt { get; set; }
        public string Category { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public InsightSeverity Severity { get; set; }
        public List<string> Recommendations { get; set; } = [];
        public Dictionary<string, object> SupportingData { get; set; } = [];
    }

    public enum InsightSeverity
    {
        Info,
        Warning,
        Error,
        Critical
    }
}
