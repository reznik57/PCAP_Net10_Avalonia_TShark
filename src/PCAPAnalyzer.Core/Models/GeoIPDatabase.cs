using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models
{
    /// <summary>
    /// Represents an IP range to country mapping with confidence scoring
    /// </summary>
    public class IPRangeCountryMapping
    {
        public long Id { get; set; }
        public string StartIP { get; set; } = string.Empty;
        public string EndIP { get; set; } = string.Empty;
        public long StartIPNumeric { get; set; }
        public long EndIPNumeric { get; set; }
        public string CountryCode { get; set; } = string.Empty;
        public string CountryName { get; set; } = string.Empty;
        public string? ContinentCode { get; set; }
        public string? ContinentName { get; set; }
        public string Source { get; set; } = string.Empty; // MaxMind, IP2Location, GeoLite2, etc.
        public double ConfidenceScore { get; set; } = 1.0; // 0.0 to 1.0
        public DateTime LastUpdated { get; set; }
        public DateTime LastVerified { get; set; }
        public bool IsVerified { get; set; }
        public string? ISP { get; set; }
        public string? Organization { get; set; }
        public string? ASN { get; set; }
        public string? City { get; set; }
        public string? Region { get; set; }
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }
        public string? TimeZone { get; set; }
        public bool IsProxy { get; set; }
        public bool IsVPN { get; set; }
        public bool IsTor { get; set; }
        public bool IsHosting { get; set; }
        public string? Notes { get; set; }
    }

    /// <summary>
    /// Represents aggregated country information from multiple sources
    /// </summary>
    public class CountryAggregateInfo
    {
        public string CountryCode { get; set; } = string.Empty;
        public string CountryName { get; set; } = string.Empty;
        public string? ContinentCode { get; set; }
        public string? ContinentName { get; set; }
        public List<IPRangeCountryMapping> IPRanges { get; set; } = new();
        public Dictionary<string, int> SourceCounts { get; set; } = new(); // Source -> Count of ranges
        public double AverageConfidence { get; set; }
        public int TotalIPCount { get; set; }
        public DateTime LastUpdated { get; set; }
        public bool IsHighRisk { get; set; }
        public string? RiskNotes { get; set; }
        public List<string> AlternativeNames { get; set; } = new();
        public string? ISO3Code { get; set; }
        public int? NumericCode { get; set; }
        public string? PhoneCode { get; set; }
        public string? Currency { get; set; }
        public List<string> Languages { get; set; } = new();
        public List<string> Neighbors { get; set; } = new();
    }

    /// <summary>
    /// Database statistics and health metrics
    /// </summary>
    public class GeoIPDatabaseStats
    {
        public long TotalIPRanges { get; set; }
        public int TotalCountries { get; set; }
        public Dictionary<string, long> RangesPerSource { get; set; } = new();
        public Dictionary<string, double> SourceReliability { get; set; } = new();
        public DateTime LastFullUpdate { get; set; }
        public DateTime LastIncrementalUpdate { get; set; }
        public long DatabaseSizeBytes { get; set; }
        public double AverageConfidenceScore { get; set; }
        public int ConflictingMappings { get; set; }
        public int UnverifiedMappings { get; set; }
        public Dictionary<string, int> ContinentDistribution { get; set; } = new();
        public List<string> RecentErrors { get; set; } = new();
        public bool NeedsUpdate { get; set; }
        public string DatabaseVersion { get; set; } = "1.0.0";
    }

    /// <summary>
    /// Configuration for GeoIP data sources
    /// </summary>
    public class GeoIPDataSource
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // API, File, Database
        public string ConnectionString { get; set; } = string.Empty; // URL, FilePath, etc.
        public string? ApiKey { get; set; }
        public bool IsEnabled { get; set; } = true;
        public int Priority { get; set; } = 1; // Higher priority sources are checked first
        public double ReliabilityScore { get; set; } = 0.8; // 0.0 to 1.0
        public int RateLimitPerSecond { get; set; } = 10;
        public DateTime LastSuccessfulUpdate { get; set; }
        public DateTime LastFailedUpdate { get; set; }
        public int ConsecutiveFailures { get; set; }
        public Dictionary<string, string> CustomHeaders { get; set; } = new();
        public TimeSpan UpdateInterval { get; set; } = TimeSpan.FromDays(7);
        public bool SupportsIPv6 { get; set; }
        public List<string> SupportedFields { get; set; } = new();
    }

    /// <summary>
    /// Conflict resolution when multiple sources disagree
    /// </summary>
    public class IPMappingConflict
    {
        public string IPAddress { get; set; } = string.Empty;
        public List<ConflictingMapping> ConflictingMappings { get; set; } = new();
        public IPRangeCountryMapping? ResolvedMapping { get; set; }
        public string ResolutionMethod { get; set; } = string.Empty; // Majority, HighestConfidence, Manual
        public DateTime DetectedAt { get; set; }
        public DateTime? ResolvedAt { get; set; }
        public string? Notes { get; set; }
    }

    public class ConflictingMapping
    {
        public string Source { get; set; } = string.Empty;
        public string CountryCode { get; set; } = string.Empty;
        public string CountryName { get; set; } = string.Empty;
        public double ConfidenceScore { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    /// <summary>
    /// Cache entry for fast IP lookups
    /// </summary>
    public class IPLookupCache
    {
        public string IPAddress { get; set; } = string.Empty;
        public string CountryCode { get; set; } = string.Empty;
        public string CountryName { get; set; } = string.Empty;
        public string? ContinentCode { get; set; }
        public double ConfidenceScore { get; set; }
        public DateTime CachedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public int HitCount { get; set; }
        public string? Source { get; set; }
    }

    /// <summary>
    /// Autonomous System Number (ASN) information
    /// </summary>
    public class ASNInfo
    {
        public int ASNumber { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Organization { get; set; } = string.Empty;
        public string CountryCode { get; set; } = string.Empty;
        public List<string> IPRanges { get; set; } = new();
        public bool IsISP { get; set; }
        public bool IsHostingProvider { get; set; }
        public bool IsVPNProvider { get; set; }
        public DateTime LastUpdated { get; set; }
    }
}