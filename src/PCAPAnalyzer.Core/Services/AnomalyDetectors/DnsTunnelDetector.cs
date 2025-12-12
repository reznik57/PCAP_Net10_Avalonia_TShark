using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Collections;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Advanced DNS tunnel detection using dual heuristics:
/// 1. Shannon entropy analysis on subdomain labels
/// 2. Query volume analysis per base domain
///
/// Features:
/// - Zero-allocation entropy calculation (Span-based)
/// - LRU cache to prevent memory exhaustion (10k domains max)
/// - Built-in CDN whitelist to reduce false positives
/// - Thread-safe for ParallelTSharkService
/// </summary>
public sealed class DnsTunnelDetector : IAnomalyDetector
{
    // Detection thresholds (C# 14 field keyword would be: set => field = value;)
    private double _entropyThreshold = 3.5;      // Shannon entropy threshold (bits)
    private double _volumeThreshold = 100.0;     // Queries per minute threshold
    private int _minSuspiciousQueries = 10;      // Minimum queries to flag
    private int _maxDomainsToTrack = 10_000;     // LRU cache capacity

    /// <summary>
    /// Shannon entropy threshold for suspicious subdomains.
    /// Default: 3.5 bits (typical for base64/hex encoded data)
    /// </summary>
    public double EntropyThreshold
    {
        get => _entropyThreshold;
        set => _entropyThreshold = value;
    }

    /// <summary>
    /// Query volume threshold (queries per minute) for suspicious activity.
    /// Default: 100 qpm
    /// </summary>
    public double VolumeThreshold
    {
        get => _volumeThreshold;
        set => _volumeThreshold = value;
    }

    /// <summary>
    /// Minimum suspicious queries before flagging.
    /// Default: 10
    /// </summary>
    public int MinSuspiciousQueries
    {
        get => _minSuspiciousQueries;
        set => _minSuspiciousQueries = value;
    }

    public string Name => "DNS Tunnel Detector";
    public AnomalyCategory Category => AnomalyCategory.Security;

    // Built-in whitelist for common CDN/legitimate high-entropy domains
    private static readonly HashSet<string> BuiltInWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        // CDN providers
        "cloudflare.com", "cloudflare-dns.com", "akamaihd.net", "akamai.net",
        "fastly.net", "cloudfront.net", "azureedge.net", "edgekey.net",
        "edgesuite.net", "llnwd.net", "cdninstagram.com", "fbcdn.net",

        // Cloud providers
        "amazonaws.com", "azure.com", "googleusercontent.com", "gstatic.com",
        "googleapis.com", "google.com", "microsoft.com", "apple.com",

        // Common high-entropy legitimate services
        "office365.com", "office.com", "outlook.com", "live.com",
        "windowsupdate.com", "windows.com", "digicert.com", "verisign.com",

        // DNS providers
        "opendns.com", "quad9.net", "cleanbrowsing.org",

        // Analytics/Telemetry (legitimate high-volume)
        "google-analytics.com", "doubleclick.net", "googlesyndication.com",
        "adsrvr.org", "demdex.net", "omtrdc.net"
    };

    // User-configurable whitelist (can be extended at runtime)
    private readonly HashSet<string> _userWhitelist = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Add a domain to the whitelist (e.g., "internal.corp.com")
    /// </summary>
    public void AddToWhitelist(string domain)
    {
        if (!string.IsNullOrWhiteSpace(domain))
            _userWhitelist.Add(domain.Trim().ToLowerInvariant());
    }

    /// <summary>
    /// Remove a domain from the user whitelist
    /// </summary>
    public void RemoveFromWhitelist(string domain)
    {
        if (!string.IsNullOrWhiteSpace(domain))
            _userWhitelist.Remove(domain.Trim().ToLowerInvariant());
    }

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var packetList = packets.ToList();

        if (packetList.Count == 0)
            return anomalies;

        // Filter to DNS traffic only
        var dnsPackets = packetList.Where(p => p.IsDnsTraffic()).ToList();
        if (dnsPackets.Count < _minSuspiciousQueries)
            return anomalies;

        // Track domain statistics with LRU eviction
        var domainStats = new LruCache<string, DnsDomainStats>(_maxDomainsToTrack);

        // Process each DNS packet
        foreach (var packet in dnsPackets)
        {
            var queryName = ExtractDnsQueryName(packet.Info);
            if (string.IsNullOrEmpty(queryName))
                continue;

            var baseDomain = ExtractBaseDomain(queryName);
            if (string.IsNullOrEmpty(baseDomain))
                continue;

            // Skip whitelisted domains
            if (IsWhitelisted(baseDomain))
                continue;

            // Calculate subdomain entropy (zero-allocation)
            var entropy = queryName.AsSpan().CalculateSubdomainEntropy();

            // Get or create stats for this domain
            var stats = domainStats.GetOrAdd(baseDomain, key => new DnsDomainStats(key));
            stats.RecordQuery(queryName, entropy, packet.Timestamp, packet.FrameNumber);
        }

        // Analyze collected statistics for suspicious patterns
        foreach (var stats in domainStats.GetAllValues())
        {
            var suspicionReasons = new List<string>();
            var severity = AnomalySeverity.Medium;

            // Check entropy threshold
            bool highEntropy = stats.MaxEntropy >= _entropyThreshold;
            if (highEntropy)
            {
                suspicionReasons.Add($"High subdomain entropy ({stats.MaxEntropy:F2} bits)");
                severity = AnomalySeverity.High;
            }

            // Check volume threshold
            bool highVolume = stats.QueriesPerMinute >= _volumeThreshold;
            if (highVolume)
            {
                suspicionReasons.Add($"High query volume ({stats.QueriesPerMinute:F1} qpm)");
                severity = AnomalySeverity.High;
            }

            // Both indicators = Critical (very likely tunnel)
            if (highEntropy && highVolume)
            {
                severity = AnomalySeverity.Critical;
            }

            // Only flag if we have suspicious indicators AND enough queries
            if (suspicionReasons.Count > 0 && stats.QueryCount >= _minSuspiciousQueries)
            {
                // Find most common source IP querying this domain
                var sourceIps = dnsPackets
                    .Where(p => ExtractBaseDomain(ExtractDnsQueryName(p.Info)) == stats.BaseDomain)
                    .GroupBy(p => p.SourceIP)
                    .OrderByDescending(g => g.Count())
                    .FirstOrDefault();

                var topSourceIp = sourceIps?.Key ?? "";
                var topDestIp = dnsPackets
                    .Where(p => ExtractBaseDomain(ExtractDnsQueryName(p.Info)) == stats.BaseDomain)
                    .GroupBy(p => p.DestinationIP)
                    .OrderByDescending(g => g.Count())
                    .FirstOrDefault()?.Key ?? "";

                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.Security,
                    Type = "DNS Tunnel Suspected",
                    Severity = severity,
                    Description = $"Potential DNS tunneling to {stats.BaseDomain}: {string.Join(", ", suspicionReasons)}",
                    DetectedAt = stats.FirstSeen,
                    DetectorName = Name,
                    SourceIP = topSourceIp,
                    DestinationIP = topDestIp,
                    DestinationPort = 53,
                    Protocol = "DNS",
                    AffectedFrames = stats.FrameNumbers.ToList(),
                    Metrics = new Dictionary<string, object>
                    {
                        { "BaseDomain", stats.BaseDomain },
                        { "QueryCount", stats.QueryCount },
                        { "MaxEntropy", stats.MaxEntropy },
                        { "AverageEntropy", stats.AverageEntropy },
                        { "QueriesPerMinute", stats.QueriesPerMinute },
                        { "EntropyThreshold", _entropyThreshold },
                        { "VolumeThreshold", _volumeThreshold },
                        { "Duration", (stats.LastSeen - stats.FirstSeen).TotalSeconds },
                        { "TopSourceIP", topSourceIp },
                        { "SampleQueries", stats.SampleQueries.ToList() }
                    },
                    Evidence = new Dictionary<string, object>
                    {
                        { "Indicators", suspicionReasons },
                        { "SampleQueries", stats.SampleQueries.ToList() },
                        { "TimeWindow", $"{stats.FirstSeen:HH:mm:ss} - {stats.LastSeen:HH:mm:ss}" }
                    },
                    Recommendation = severity == AnomalySeverity.Critical
                        ? "CRITICAL: Likely active DNS tunneling. Block domain immediately and investigate affected host for malware."
                        : "Investigate DNS queries to this domain. Consider blocking if queries contain encoded data or unusual patterns."
                });
            }
        }

        return anomalies
            .OrderByDescending(a => a.Severity)
            .ThenByDescending(a => (a.Metrics.TryGetValue("QueryCount", out var qc) ? (int)qc : 0))
            .ToList();
    }

    /// <summary>
    /// Extracts DNS query name from TShark info field.
    /// Example: "Standard query 0x1234 A encoded.evil.com" → "encoded.evil.com"
    /// </summary>
    private static string? ExtractDnsQueryName(string? info)
    {
        if (string.IsNullOrEmpty(info))
            return null;

        // TShark DNS info format: "Standard query 0x1234 TYPE domain.name"
        // or "Standard query response 0x1234 TYPE domain.name ..."
        var span = info.AsSpan();

        // Look for common DNS query patterns
        int queryIndex = info.IndexOf(" A ", StringComparison.Ordinal);
        if (queryIndex < 0)
            queryIndex = info.IndexOf(" AAAA ", StringComparison.Ordinal);
        if (queryIndex < 0)
            queryIndex = info.IndexOf(" TXT ", StringComparison.Ordinal);
        if (queryIndex < 0)
            queryIndex = info.IndexOf(" CNAME ", StringComparison.Ordinal);
        if (queryIndex < 0)
            queryIndex = info.IndexOf(" MX ", StringComparison.Ordinal);

        if (queryIndex >= 0)
        {
            // Skip past the record type marker
            int startIndex = queryIndex + 2;
            while (startIndex < info.Length && info[startIndex] != ' ')
                startIndex++;
            startIndex++; // Skip the space after record type

            if (startIndex < info.Length)
            {
                // Find end of domain name (space or end of string)
                int endIndex = startIndex;
                while (endIndex < info.Length && info[endIndex] != ' ')
                    endIndex++;

                if (endIndex > startIndex)
                {
                    var domain = info[startIndex..endIndex];
                    // Validate it looks like a domain (contains at least one dot)
                    if (domain.Contains('.', StringComparison.Ordinal))
                        return domain;
                }
            }
        }

        // Fallback: look for any domain-like string
        foreach (var part in info.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.Contains('.', StringComparison.Ordinal) && !part.Contains(':', StringComparison.Ordinal) && part.Length > 4)
            {
                // Looks like a domain name
                var trimmed = part.Trim('(', ')', '[', ']');
                if (trimmed.Split('.').Length >= 2)
                    return trimmed;
            }
        }

        return null;
    }

    /// <summary>
    /// Extracts base domain (TLD + 1) from full domain name.
    /// Example: "encoded.data.evil.com" → "evil.com"
    /// </summary>
    private static string? ExtractBaseDomain(string? fullDomain)
    {
        if (string.IsNullOrEmpty(fullDomain))
            return null;

        var parts = fullDomain.Split('.');
        if (parts.Length < 2)
            return fullDomain;

        // Handle common multi-part TLDs
        if (parts.Length >= 3)
        {
            var lastTwo = $"{parts[^2]}.{parts[^1]}";
            if (IsMultiPartTld(lastTwo))
            {
                // e.g., "sub.example.co.uk" → "example.co.uk"
                if (parts.Length >= 4)
                    return $"{parts[^3]}.{parts[^2]}.{parts[^1]}";
                return fullDomain;
            }
        }

        // Standard case: return last two parts
        return $"{parts[^2]}.{parts[^1]}";
    }

    /// <summary>
    /// Checks if the domain suffix is a multi-part TLD (e.g., co.uk, com.au)
    /// </summary>
    private static bool IsMultiPartTld(string suffix)
    {
        return suffix switch
        {
            "co.uk" or "co.nz" or "co.au" or "co.jp" or "co.kr" => true,
            "com.au" or "com.br" or "com.cn" or "com.mx" => true,
            "org.uk" or "org.au" or "net.au" or "gov.uk" => true,
            _ => false
        };
    }

    /// <summary>
    /// Checks if a domain is whitelisted (built-in or user-added)
    /// </summary>
    private bool IsWhitelisted(string baseDomain)
    {
        // Check built-in whitelist
        if (BuiltInWhitelist.Contains(baseDomain))
            return true;

        // Check user whitelist
        if (_userWhitelist.Contains(baseDomain))
            return true;

        // Check if domain ends with any whitelisted domain (subdomain matching)
        foreach (var whitelisted in BuiltInWhitelist)
        {
            if (baseDomain.EndsWith("." + whitelisted, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        foreach (var whitelisted in _userWhitelist)
        {
            if (baseDomain.EndsWith("." + whitelisted, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
