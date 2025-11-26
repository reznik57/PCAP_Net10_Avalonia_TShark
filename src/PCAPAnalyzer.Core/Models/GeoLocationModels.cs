using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models
{
    public class GeoLocation
    {
        public string IpAddress { get; set; } = string.Empty;
        public string CountryCode { get; set; } = string.Empty;
        public string CountryName { get; set; } = string.Empty;
        public string? ContinentCode { get; set; }
        public string? ContinentName { get; set; }
        public string? City { get; set; }
        public string? Region { get; set; }
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }
        public string? TimeZone { get; set; }
        public string? ISP { get; set; }
        public string? Organization { get; set; }
        public string? ASN { get; set; }
        public bool IsPublicIP { get; set; }
        public double ConfidenceScore { get; set; } = 1.0;
        public string? Source { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class CountryTrafficStatistics
    {
        public string CountryCode { get; set; } = string.Empty;
        public string CountryName { get; set; } = string.Empty;
        public long IncomingPackets { get; set; }
        public long OutgoingPackets { get; set; }
        public long TotalPackets { get; set; }
        public long IncomingBytes { get; set; }
        public long OutgoingBytes { get; set; }
        public long TotalBytes { get; set; }
        public HashSet<string> UniqueIPs { get; set; } = new();
        public HashSet<string> OutgoingIPs { get; set; } = new();
        public HashSet<string> IncomingIPs { get; set; } = new();
        public double Percentage { get; set; }
        public Dictionary<string, long> ProtocolBreakdown { get; set; } = new();
        public List<SecurityThreat> AssociatedThreats { get; set; } = new();
        public bool IsHighRisk { get; set; }
        public DateTime LatestTimestamp { get; set; }
    }

    public class GeoIPDatabase
    {
        public string Provider { get; set; } = string.Empty;
        public DateTime LastUpdate { get; set; }
        public int TotalEntries { get; set; }
        public bool IsLoaded { get; set; }
        public string FilePath { get; set; } = string.Empty;
    }

    public enum GeoIPProvider
    {
        MaxMindGeoLite2,
        IPGeolocationAPI,
        IPAPIService,
        Internal
    }

    public class IPCountryMapping
    {
        public long StartIPNumeric { get; set; }
        public long EndIPNumeric { get; set; }
        public string CountryCode { get; set; } = string.Empty;
        public string CountryName { get; set; } = string.Empty;
        public string ContinentCode { get; set; } = string.Empty;
    }

    public class CountryRiskProfile
    {
        public string CountryCode { get; set; } = string.Empty;
        public string CountryName { get; set; } = string.Empty;
        public RiskLevel Risk { get; set; }
        public string RiskLevel { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> KnownThreats { get; set; } = new();
        public List<string> ThreatTypes { get; set; } = new();
        public DateTime LastAssessment { get; set; }
    }

    public enum RiskLevel
    {
        Low,
        Medium,
        High,
        Critical,
        Unknown
    }

    public class TrafficFlowDirection
    {
        public string SourceCountry { get; set; } = string.Empty;
        public string SourceCountryName { get; set; } = string.Empty;
        public string DestinationCountry { get; set; } = string.Empty;
        public string DestinationCountryName { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public List<string> Protocols { get; set; } = new();
        public HashSet<string> UniqueConnections { get; set; } = new();
        public bool IsCrossBorder { get; set; }
        public bool IsHighRisk { get; set; }
    }
}
