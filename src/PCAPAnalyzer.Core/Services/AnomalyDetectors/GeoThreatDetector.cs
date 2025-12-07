using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects geographic threat patterns including traffic to high-risk countries,
/// single-IP country anomalies (potential C2/targeted attacks), and suspicious
/// geo-based traffic patterns.
/// </summary>
public class GeoThreatDetector : ISpecializedDetector
{
    private readonly IGeoIPService? _geoIPService;

    // High-risk countries based on threat intelligence (OFAC sanctions, APT origins, cybercrime hubs)
    private static readonly FrozenSet<string> HighRiskCountryCodes = new[]
    {
        // OFAC Sanctioned
        "RU", // Russia - APT28, APT29, Sandworm
        "CN", // China - APT1, APT10, APT41
        "KP", // North Korea - Lazarus Group
        "IR", // Iran - APT33, APT34, APT35
        "SY", // Syria
        "CU", // Cuba
        "VE", // Venezuela

        // Known cybercrime/APT activity hubs
        "BY", // Belarus - GhostWriter
        "UA", // Ukraine (compromised infrastructure often used)
        "NG", // Nigeria - BEC scams
        "RO", // Romania - cybercrime
        "BR", // Brazil - banking trojans
        "VN", // Vietnam - APT32
        "PK", // Pakistan - APT36
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    // Countries requiring elevated scrutiny (not blocked but flagged)
    private static readonly FrozenSet<string> ElevatedRiskCountryCodes = new[]
    {
        "IN", // India
        "ID", // Indonesia
        "TH", // Thailand
        "PH", // Philippines
        "MY", // Malaysia
        "TR", // Turkey
        "EG", // Egypt
        "ZA", // South Africa
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private const int SINGLE_IP_PACKET_THRESHOLD = 10; // Min packets to consider significant
    private const long HIGH_RISK_BYTES_THRESHOLD = 1024 * 1024; // 1MB to high-risk = concern
    private const int HIGH_RISK_CONNECTIONS_THRESHOLD = 5; // Multiple high-risk country connections

    public string Name => "Geographic Threat Detector";
    public AnomalyCategory Category => AnomalyCategory.Security;
    public int Priority => 8; // Run after other security detectors

    public GeoThreatDetector(IGeoIPService? geoIPService = null)
    {
        _geoIPService = geoIPService;
    }

    public bool CanDetect(IEnumerable<PacketInfo> packets)
    {
        // Always run - geo analysis is always relevant for security
        return packets.Any();
    }

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var packetList = packets.ToList();

        if (!packetList.Any())
            return anomalies;

        // Build IP-to-country cache for this analysis
        var ipCountryCache = BuildIPCountryCache(packetList);

        if (ipCountryCache.Count == 0)
            return anomalies; // No geo data available

        anomalies.AddRange(DetectHighRiskCountryTraffic(packetList, ipCountryCache));
        anomalies.AddRange(DetectSingleIPCountries(packetList, ipCountryCache));
        anomalies.AddRange(DetectOutboundOnlyCountries(packetList, ipCountryCache));
        anomalies.AddRange(DetectGeoAnomalies(packetList, ipCountryCache));

        return anomalies;
    }

    /// <summary>
    /// Builds a cache of IP addresses to country codes for efficient lookup.
    /// Uses batched async lookups via Task.WhenAll for performance.
    ///
    /// NOTE: Uses GetAwaiter().GetResult() because IAnomalyDetector.Detect() is synchronous.
    /// This is intentional - batching all lookups into a single blocking wait is faster than
    /// N sequential blocking waits. Consider adding IAnomalyDetectorAsync interface if this
    /// becomes a bottleneck.
    /// </summary>
    private Dictionary<string, string> BuildIPCountryCache(List<PacketInfo> packets)
    {
        var cache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var uniqueIPs = packets
            .SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
            .Where(ip => !string.IsNullOrEmpty(ip))
            .Distinct()
            .ToList();

        // Separate private IPs (no GeoIP lookup needed)
        var externalIPs = new List<string>();
        foreach (var ip in uniqueIPs)
        {
            if (string.IsNullOrEmpty(ip)) continue;

            if (IsPrivateIP(ip))
                cache[ip] = "INTERNAL";
            else
                externalIPs.Add(ip);
        }

        // Batch lookup all external IPs in parallel (single blocking call instead of N)
        if (_geoIPService != null && externalIPs.Count > 0)
        {
            try
            {
                var lookupTasks = externalIPs
                    .Select(async ip =>
                    {
                        try
                        {
                            var location = await _geoIPService.GetLocationAsync(ip);
                            return (ip, country: location?.CountryCode ?? "UNKNOWN");
                        }
                        catch
                        {
                            return (ip, country: "UNKNOWN");
                        }
                    });

                // Single blocking wait for all lookups (much faster than N sequential waits)
                var results = System.Threading.Tasks.Task.WhenAll(lookupTasks).GetAwaiter().GetResult();

                foreach (var (ip, country) in results)
                    cache[ip] = string.IsNullOrEmpty(country) ? "UNKNOWN" : country;
            }
            catch
            {
                // If batch fails, mark all as unknown
                foreach (var ip in externalIPs)
                    cache[ip] = "UNKNOWN";
            }
        }
        else
        {
            foreach (var ip in externalIPs)
                cache[ip] = "UNKNOWN";
        }

        return cache;
    }

    /// <summary>
    /// Detects traffic to/from high-risk countries (sanctioned nations, APT origins)
    /// </summary>
    private List<NetworkAnomaly> DetectHighRiskCountryTraffic(List<PacketInfo> packets, Dictionary<string, string> ipCountryCache)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Group traffic by high-risk country
        var highRiskTraffic = new Dictionary<string, List<PacketInfo>>();

        foreach (var packet in packets)
        {
            var srcCountry = GetCountry(packet.SourceIP, ipCountryCache);
            var dstCountry = GetCountry(packet.DestinationIP, ipCountryCache);

            if (HighRiskCountryCodes.Contains(srcCountry))
            {
                if (!highRiskTraffic.ContainsKey(srcCountry))
                    highRiskTraffic[srcCountry] = new List<PacketInfo>();
                highRiskTraffic[srcCountry].Add(packet);
            }

            if (HighRiskCountryCodes.Contains(dstCountry) && srcCountry != dstCountry)
            {
                if (!highRiskTraffic.ContainsKey(dstCountry))
                    highRiskTraffic[dstCountry] = new List<PacketInfo>();
                highRiskTraffic[dstCountry].Add(packet);
            }
        }

        // Generate anomalies for each high-risk country with significant traffic
        foreach (var kvp in highRiskTraffic)
        {
            var country = kvp.Key;
            var countryPackets = kvp.Value;
            var totalBytes = countryPackets.Sum(p => (long)p.Length);
            var uniqueIPs = countryPackets
                .SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
                .Where(ip => GetCountry(ip, ipCountryCache) == country)
                .Distinct()
                .ToList();

            // Determine if traffic is inbound, outbound, or both
            var internalIPs = countryPackets
                .SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
                .Where(ip => GetCountry(ip, ipCountryCache) == "INTERNAL")
                .Distinct()
                .ToList();

            var outboundBytes = countryPackets
                .Where(p => GetCountry(p.SourceIP, ipCountryCache) == "INTERNAL" &&
                           GetCountry(p.DestinationIP, ipCountryCache) == country)
                .Sum(p => (long)p.Length);

            var inboundBytes = countryPackets
                .Where(p => GetCountry(p.SourceIP, ipCountryCache) == country &&
                           GetCountry(p.DestinationIP, ipCountryCache) == "INTERNAL")
                .Sum(p => (long)p.Length);

            // Severity based on volume and direction
            var severity = AnomalySeverity.Medium;
            if (totalBytes > HIGH_RISK_BYTES_THRESHOLD)
                severity = AnomalySeverity.High;
            if (totalBytes > 10 * HIGH_RISK_BYTES_THRESHOLD || outboundBytes > 5 * HIGH_RISK_BYTES_THRESHOLD)
                severity = AnomalySeverity.Critical;

            var direction = outboundBytes > inboundBytes ? "outbound" :
                           inboundBytes > outboundBytes ? "inbound" : "bidirectional";

            anomalies.Add(new NetworkAnomaly
            {
                Category = AnomalyCategory.Security,
                Type = "High-Risk Country Traffic",
                Severity = severity,
                Description = $"Traffic detected to/from high-risk country {country}: {totalBytes.ToFormattedBytes()} ({direction}), {uniqueIPs.Count} unique IPs",
                DetectedAt = countryPackets.First().Timestamp,
                DetectorName = Name,
                SourceIP = internalIPs.FirstOrDefault() ?? "",
                DestinationIP = uniqueIPs.FirstOrDefault() ?? "",
                Protocol = "Mixed",
                AffectedFrames = countryPackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                Metrics = new Dictionary<string, object>
                {
                    { "CountryCode", country },
                    { "TotalBytes", totalBytes },
                    { "OutboundBytes", outboundBytes },
                    { "InboundBytes", inboundBytes },
                    { "UniqueIPs", uniqueIPs.Count },
                    { "PacketCount", countryPackets.Count },
                    { "Direction", direction },
                    { "RiskLevel", "High" }
                },
                Evidence = new Dictionary<string, object>
                {
                    { "HighRiskIPs", uniqueIPs.Take(10).ToList() },
                    { "InternalIPs", internalIPs.Take(5).ToList() }
                },
                Recommendation = $"Traffic to/from {country} detected. Review if this communication is authorized. Consider blocking or monitoring this traffic closely."
            });
        }

        // Also flag if multiple high-risk countries are involved
        if (highRiskTraffic.Count >= HIGH_RISK_CONNECTIONS_THRESHOLD)
        {
            anomalies.Add(new NetworkAnomaly
            {
                Category = AnomalyCategory.Security,
                Type = "Multiple High-Risk Countries",
                Severity = AnomalySeverity.Critical,
                Description = $"Traffic detected to/from {highRiskTraffic.Count} different high-risk countries: {string.Join(", ", highRiskTraffic.Keys)}",
                DetectedAt = packets.First().Timestamp,
                DetectorName = Name,
                Protocol = "Mixed",
                AffectedFrames = highRiskTraffic.Values.SelectMany(p => p).Select(p => (long)p.FrameNumber).Take(100).ToList(),
                Metrics = new Dictionary<string, object>
                {
                    { "HighRiskCountryCount", highRiskTraffic.Count },
                    { "Countries", highRiskTraffic.Keys.ToList() }
                },
                Recommendation = "Communication with multiple high-risk countries is highly unusual and warrants immediate investigation."
            });
        }

        return anomalies;
    }

    /// <summary>
    /// Detects countries that have only a single unique IP address communicating.
    /// This pattern can indicate C2 beacons, targeted attacks, or reconnaissance.
    /// </summary>
    private List<NetworkAnomaly> DetectSingleIPCountries(List<PacketInfo> packets, Dictionary<string, string> ipCountryCache)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Group external IPs by country
        var countryToIPs = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var countryToPackets = new Dictionary<string, List<PacketInfo>>(StringComparer.OrdinalIgnoreCase);

        foreach (var packet in packets)
        {
            foreach (var ip in new[] { packet.SourceIP, packet.DestinationIP })
            {
                if (string.IsNullOrEmpty(ip)) continue;

                var country = GetCountry(ip, ipCountryCache);
                if (country == "INTERNAL" || country == "UNKNOWN") continue;

                if (!countryToIPs.ContainsKey(country))
                {
                    countryToIPs[country] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    countryToPackets[country] = new List<PacketInfo>();
                }

                countryToIPs[country].Add(ip);
                countryToPackets[country].Add(packet);
            }
        }

        // Find countries with only one IP
        foreach (var kvp in countryToIPs.Where(k => k.Value.Count == 1))
        {
            var country = kvp.Key;
            var singleIP = kvp.Value.First();
            var countryPackets = countryToPackets[country].Distinct().ToList();

            // Only flag if there's meaningful traffic
            if (countryPackets.Count < SINGLE_IP_PACKET_THRESHOLD)
                continue;

            var totalBytes = countryPackets.Sum(p => (long)p.Length);
            var timeSpan = countryPackets.Max(p => p.Timestamp) - countryPackets.Min(p => p.Timestamp);
            var uniquePorts = countryPackets.Select(p => p.DestinationPort).Distinct().Count();

            // Higher severity for high-risk countries or unusual patterns
            var severity = AnomalySeverity.Low;
            if (HighRiskCountryCodes.Contains(country))
                severity = AnomalySeverity.High;
            else if (ElevatedRiskCountryCodes.Contains(country))
                severity = AnomalySeverity.Medium;
            else if (totalBytes > HIGH_RISK_BYTES_THRESHOLD || uniquePorts == 1)
                severity = AnomalySeverity.Medium;

            anomalies.Add(new NetworkAnomaly
            {
                Category = AnomalyCategory.Security,
                Type = "Single-IP Country",
                Severity = severity,
                Description = $"Country {country} has only one communicating IP ({singleIP}): {countryPackets.Count} packets, {totalBytes.ToFormattedBytes()}",
                DetectedAt = countryPackets.First().Timestamp,
                DetectorName = Name,
                SourceIP = singleIP,
                DestinationIP = singleIP,
                Protocol = countryPackets.First().Protocol.ToString(),
                AffectedFrames = countryPackets.Select(p => (long)p.FrameNumber).Take(50).ToList(),
                Metrics = new Dictionary<string, object>
                {
                    { "CountryCode", country },
                    { "SingleIP", singleIP },
                    { "PacketCount", countryPackets.Count },
                    { "TotalBytes", totalBytes },
                    { "DurationSeconds", timeSpan.TotalSeconds },
                    { "UniquePorts", uniquePorts },
                    { "IsHighRisk", HighRiskCountryCodes.Contains(country) }
                },
                Recommendation = "Single-IP countries may indicate C2 communication, targeted attacks, or reconnaissance. Investigate the IP address and traffic pattern."
            });
        }

        return anomalies;
    }

    /// <summary>
    /// Detects countries that have only outbound traffic (data leaving but nothing coming back).
    /// This pattern can indicate data exfiltration.
    /// </summary>
    private List<NetworkAnomaly> DetectOutboundOnlyCountries(List<PacketInfo> packets, Dictionary<string, string> ipCountryCache)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Track inbound and outbound traffic per country
        var countryInbound = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var countryOutbound = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var countryPackets = new Dictionary<string, List<PacketInfo>>(StringComparer.OrdinalIgnoreCase);

        foreach (var packet in packets)
        {
            var srcCountry = GetCountry(packet.SourceIP, ipCountryCache);
            var dstCountry = GetCountry(packet.DestinationIP, ipCountryCache);

            // Outbound: Internal -> External
            if (srcCountry == "INTERNAL" && dstCountry != "INTERNAL" && dstCountry != "UNKNOWN")
            {
                if (!countryOutbound.ContainsKey(dstCountry))
                {
                    countryOutbound[dstCountry] = 0;
                    countryPackets[dstCountry] = new List<PacketInfo>();
                }
                countryOutbound[dstCountry] += packet.Length;
                countryPackets[dstCountry].Add(packet);
            }

            // Inbound: External -> Internal
            if (srcCountry != "INTERNAL" && srcCountry != "UNKNOWN" && dstCountry == "INTERNAL")
            {
                if (!countryInbound.ContainsKey(srcCountry))
                    countryInbound[srcCountry] = 0;
                countryInbound[srcCountry] += packet.Length;
            }
        }

        // Find countries with only outbound traffic (or extreme imbalance)
        foreach (var country in countryOutbound.Keys)
        {
            var outbound = countryOutbound[country];
            var inbound = countryInbound.GetValueOrDefault(country, 0);

            // Flag if outbound >> inbound (10:1 ratio or no inbound at all)
            if (outbound > HIGH_RISK_BYTES_THRESHOLD && (inbound == 0 || outbound / Math.Max(inbound, 1) > 10))
            {
                var pkts = countryPackets.GetValueOrDefault(country, new List<PacketInfo>());

                var severity = AnomalySeverity.Medium;
                if (HighRiskCountryCodes.Contains(country))
                    severity = AnomalySeverity.Critical;
                else if (outbound > 10 * HIGH_RISK_BYTES_THRESHOLD)
                    severity = AnomalySeverity.High;

                var description = inbound == 0
                    ? $"Outbound-only traffic to {country}: {outbound.ToFormattedBytes()} sent, no response traffic"
                    : $"Heavily asymmetric traffic to {country}: {outbound.ToFormattedBytes()} out vs {inbound.ToFormattedBytes()} in ({outbound / Math.Max(inbound, 1)}:1 ratio)";

                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.Security,
                    Type = "Outbound-Only Country Traffic",
                    Severity = severity,
                    Description = description,
                    DetectedAt = pkts.Any() ? pkts.First().Timestamp : DateTime.UtcNow,
                    DetectorName = Name,
                    Protocol = "Mixed",
                    AffectedFrames = pkts.Select(p => (long)p.FrameNumber).Take(50).ToList(),
                    Metrics = new Dictionary<string, object>
                    {
                        { "CountryCode", country },
                        { "OutboundBytes", outbound },
                        { "InboundBytes", inbound },
                        { "Ratio", inbound > 0 ? outbound / inbound : -1 },
                        { "IsHighRisk", HighRiskCountryCodes.Contains(country) }
                    },
                    Recommendation = "Outbound-only or heavily asymmetric traffic may indicate data exfiltration. Investigate the destination and verify authorization."
                });
            }
        }

        return anomalies;
    }

    /// <summary>
    /// Detects general geographic anomalies like unusual country diversity or patterns
    /// </summary>
    private List<NetworkAnomaly> DetectGeoAnomalies(List<PacketInfo> packets, Dictionary<string, string> ipCountryCache)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Count unique external countries
        var externalCountries = ipCountryCache.Values
            .Where(c => c != "INTERNAL" && c != "UNKNOWN")
            .Distinct()
            .ToList();

        // Flag if talking to unusually many countries (potential botnet or scanning)
        if (externalCountries.Count > 50)
        {
            anomalies.Add(new NetworkAnomaly
            {
                Category = AnomalyCategory.Security,
                Type = "Excessive Geographic Diversity",
                Severity = AnomalySeverity.Medium,
                Description = $"Traffic detected to/from {externalCountries.Count} different countries - unusually diverse geographic footprint",
                DetectedAt = packets.First().Timestamp,
                DetectorName = Name,
                Protocol = "Mixed",
                Metrics = new Dictionary<string, object>
                {
                    { "UniqueCountries", externalCountries.Count },
                    { "Countries", externalCountries.Take(20).ToList() }
                },
                Recommendation = "High geographic diversity may indicate scanning, botnet activity, or CDN usage. Review if this is expected behavior."
            });
        }

        return anomalies;
    }

    private string GetCountry(string? ip, Dictionary<string, string> cache)
    {
        if (string.IsNullOrEmpty(ip)) return "UNKNOWN";
        return cache.TryGetValue(ip, out var country) ? country : "UNKNOWN";
    }

    private static bool IsPrivateIP(string ip) => PrivateNetworkHandler.IsPrivateIP(ip);

}
