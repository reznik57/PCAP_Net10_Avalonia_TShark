using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects application-layer anomalies: DNS tunneling, beaconing, malformed packets
/// </summary>
public sealed class ApplicationAnomalyDetector : IAnomalyDetector
{
    private const int DNS_QUERY_LENGTH_THRESHOLD = 50;
    private const double BEACON_INTERVAL_TOLERANCE = 0.1; // 10% tolerance

    public string Name => "Application Anomaly Detector";
    public AnomalyCategory Category => AnomalyCategory.Application;

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var packetList = packets.ToList();

        if (!packetList.Any())
            return anomalies;

        anomalies.AddRange(DetectDNSTunneling(packetList));
        anomalies.AddRange(DetectBeaconing(packetList));
        anomalies.AddRange(DetectMalformedPackets(packetList));

        return anomalies;
    }

    private List<NetworkAnomaly> DetectDNSTunneling(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var dnsPackets = packets.Where(p => p.IsDnsTraffic()).ToList();

        if (!dnsPackets.Any())
            return anomalies;

        // Look for suspicious DNS patterns
        var suspiciousQueries = new List<PacketInfo>();

        foreach (var packet in dnsPackets)
        {
            if (packet.Info is not null)
            {
                var queryLength = EstimateDNSQueryLength(packet.Info);
                if (queryLength > DNS_QUERY_LENGTH_THRESHOLD)
                {
                    suspiciousQueries.Add(packet);
                }

                // Check for high entropy domain names
                if (HasHighEntropy(packet.Info))
                {
                    suspiciousQueries.Add(packet);
                }

                // Check for unusual TXT record queries
                if (packet.IsTxtQuery() && !packet.IsKnownTxtQuery())
                {
                    suspiciousQueries.Add(packet);
                }
            }
        }

        // Group by source to identify potential tunneling sources
        var suspiciousGroups = suspiciousQueries.GroupBy(p => p.SourceIP);

        foreach (var group in suspiciousGroups)
        {
            var groupPackets = group.ToList();
            if (groupPackets.Count >= 10) // Threshold for suspicious activity
            {
                // Get the most common DNS server destination
                var topDestination = groupPackets
                    .GroupBy(p => p.DestinationIP)
                    .OrderByDescending(g => g.Count())
                    .FirstOrDefault()?.Key ?? "";

                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.Application,
                    Type = "DNS Tunneling",
                    Severity = AnomalySeverity.High,
                    Description = $"Potential DNS tunneling detected from {group.Key}",
                    DetectedAt = groupPackets.First().Timestamp,
                    DetectorName = Name,
                    SourceIP = group.Key ?? "",
                    DestinationIP = topDestination,
                    DestinationPort = 53,
                    Protocol = "DNS",
                    AffectedFrames = groupPackets.Select(p => (long)p.FrameNumber).Take(50).ToList(),
                    Metrics = new Dictionary<string, object>
                    {
                        { "SuspiciousQueries", groupPackets.Count },
                        { "AverageQueryLength", groupPackets.Average(p => EstimateDNSQueryLength(p.Info ?? "")) },
                        { "UniqueDestinations", groupPackets.Select(p => p.DestinationIP).Distinct().Count() },
                        { "TopDNSServer", topDestination }
                    },
                    Recommendation = "Investigate DNS queries for data exfiltration. Consider blocking suspicious domains and monitoring DNS traffic patterns."
                });
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectBeaconing(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Group by source-destination pairs
        var flows = packets.GroupBy(p => new { p.SourceIP, p.DestinationIP, p.DestinationPort });

        foreach (var flow in flows)
        {
            var flowPackets = flow.OrderBy(p => p.Timestamp).ToList();

            if (flowPackets.Count < 5)
                continue;

            // Calculate intervals between packets
            var intervals = new List<double>();
            for (int i = 1; i < flowPackets.Count; i++)
            {
                var interval = (flowPackets[i].Timestamp - flowPackets[i - 1].Timestamp).TotalSeconds;
                intervals.Add(interval);
            }

            if (intervals.Count < 4)
                continue;

            // Calculate average and standard deviation
            var avgInterval = intervals.Average();
            var variance = intervals.Average(v => Math.Pow(v - avgInterval, 2));
            var stdDev = Math.Sqrt(variance);

            // Check for regular intervals (beaconing behavior)
            var coefficientOfVariation = stdDev / avgInterval;

            if (coefficientOfVariation < BEACON_INTERVAL_TOLERANCE && avgInterval > 1 && avgInterval < 300)
            {
                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.Application,
                    Type = "Beaconing",
                    Severity = AnomalySeverity.High,
                    Description = $"Potential beaconing behavior: Regular traffic every {avgInterval:F1} seconds",
                    DetectedAt = flowPackets.First().Timestamp,
                    DetectorName = Name,
                    SourceIP = flow.Key.SourceIP ?? "",
                    DestinationIP = flow.Key.DestinationIP ?? "",
                    DestinationPort = flow.Key.DestinationPort,
                    Protocol = flowPackets.First().Protocol.ToString(),
                    AffectedFrames = flowPackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                    Metrics = new Dictionary<string, object>
                    {
                        { "AverageInterval", avgInterval },
                        { "IntervalStdDev", stdDev },
                        { "CoefficientOfVariation", coefficientOfVariation },
                        { "PacketCount", flowPackets.Count }
                    },
                    Recommendation = "Beaconing patterns may indicate C&C (Command and Control) communication. Investigate the destination and block if malicious."
                });
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectMalformedPackets(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var malformed = packets.Where(p => p.IsMalformed()).ToList();

        if (malformed.Count >= 5)
        {
            var firstPacket = malformed.First();

            // Get the most common source and destination from malformed packets
            var topSource = malformed
                .Where(p => !string.IsNullOrEmpty(p.SourceIP))
                .GroupBy(p => p.SourceIP)
                .OrderByDescending(g => g.Count())
                .FirstOrDefault()?.Key ?? "";

            var topDestination = malformed
                .Where(p => !string.IsNullOrEmpty(p.DestinationIP))
                .GroupBy(p => p.DestinationIP)
                .OrderByDescending(g => g.Count())
                .FirstOrDefault()?.Key ?? "";

            anomalies.Add(new NetworkAnomaly
            {
                Category = AnomalyCategory.Malformed,
                Type = "Malformed Packets",
                Severity = malformed.Count > 20 ? AnomalySeverity.High : AnomalySeverity.Medium,
                Description = $"{malformed.Count} malformed or invalid packets detected",
                DetectedAt = firstPacket.Timestamp,
                DetectorName = Name,
                SourceIP = topSource,
                DestinationIP = topDestination,
                Protocol = "Various",
                AffectedFrames = malformed.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                Metrics = new Dictionary<string, object>
                {
                    { "MalformedCount", malformed.Count },
                    { "Protocols", malformed.Select(p => p.Protocol.ToString()).Distinct().ToList() },
                    { "TopSourceIP", topSource },
                    { "TopDestinationIP", topDestination }
                },
                Recommendation = "Malformed packets may indicate network issues, misconfigured devices, or potential attacks. Investigate packet structure."
            });
        }

        return anomalies;
    }

    private int EstimateDNSQueryLength(string info)
    {
        // Simplified DNS query length estimation
        var parts = info.Split(' ');
        foreach (var part in parts)
        {
            if (part.Contains('.', StringComparison.Ordinal) && !part.Contains(':', StringComparison.Ordinal))
            {
                return part.Length;
            }
        }
        return 0;
    }

    private bool HasHighEntropy(string text)
    {
        // Simplified entropy calculation
        if (string.IsNullOrEmpty(text) || text.Length < 10)
            return false;

        var frequencies = new Dictionary<char, int>();
        foreach (var c in text.ToLower())
        {
            if (char.IsLetterOrDigit(c))
            {
                frequencies[c] = frequencies.GetValueOrDefault(c, 0) + 1;
            }
        }

        if (frequencies.Count == 0)
            return false;

        double entropy = 0;
        int total = frequencies.Values.Sum();
        foreach (var freq in frequencies.Values)
        {
            double probability = (double)freq / total;
            entropy -= probability * Math.Log(probability, 2);
        }

        return entropy > 3.5; // High entropy threshold
    }

}
