using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects data exfiltration patterns including slow exfiltration, encoded transfers, and unusual uploads
/// </summary>
public class DataExfiltrationDetector : ISpecializedDetector
{
    private const long UPLOAD_THRESHOLD_BYTES = 10 * 1024 * 1024; // 10MB upload threshold
    private const double UPLOAD_DOWNLOAD_RATIO = 3.0; // Upload/Download ratio threshold
    private const int BASE64_PATTERN_THRESHOLD = 5; // Minimum base64-like strings to detect
    private const int SLOW_EXFIL_MIN_DURATION_HOURS = 1; // Minimum duration for slow exfiltration
    private const long SLOW_EXFIL_MIN_BYTES = 1024 * 1024; // 1MB minimum for slow exfiltration

    public string Name => "Data Exfiltration Detector";
    public AnomalyCategory Category => AnomalyCategory.Security;
    public int Priority => 7;

    public bool CanDetect(IEnumerable<PacketInfo> packets)
    {
        // Always run as data exfiltration can happen over any protocol
        var packetList = packets.ToList();
        return packetList.Any() && packetList.Count >= 50; // Need sufficient packets for analysis
    }

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var packetList = packets.ToList();

        if (!packetList.Any())
            return anomalies;

        anomalies.AddRange(DetectLargeUploads(packetList));
        anomalies.AddRange(DetectSlowExfiltration(packetList));
        anomalies.AddRange(DetectEncodedTransfers(packetList));
        anomalies.AddRange(DetectUnusualOutboundTraffic(packetList));

        return anomalies;
    }

    private List<NetworkAnomaly> DetectLargeUploads(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Group by source-destination pairs to track flows
        var flows = packets.GroupBy(p => new
        {
            SourceIP = p.SourceIP,
            DestinationIP = p.DestinationIP,
            DestinationPort = p.DestinationPort
        });

        foreach (var flow in flows)
        {
            var flowPackets = flow.OrderBy(p => p.Timestamp).ToList();

            // Separate outbound (from source) and inbound (to source) traffic
            var outboundBytes = flowPackets.Sum(p => (long)p.Length);

            // For upload detection, we're primarily interested in large outbound transfers
            if (outboundBytes >= UPLOAD_THRESHOLD_BYTES)
            {
                var timeWindow = flowPackets.Max(p => p.Timestamp) - flowPackets.Min(p => p.Timestamp);
                var throughput = outboundBytes / Math.Max(timeWindow.TotalSeconds, 1);

                // Check if this is to a non-standard port or external destination
                var isNonStandardPort = flow.Key.DestinationPort != 80 &&
                                       flow.Key.DestinationPort != 443 &&
                                       flow.Key.DestinationPort != 21 &&
                                       flow.Key.DestinationPort != 22;

                var severity = outboundBytes > 100 * 1024 * 1024
                    ? AnomalySeverity.Critical
                    : outboundBytes > 50 * 1024 * 1024
                        ? AnomalySeverity.High
                        : AnomalySeverity.Medium;

                if (isNonStandardPort)
                    severity = (AnomalySeverity)Math.Min((int)severity + 1, (int)AnomalySeverity.Critical);

                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.Security,
                    Type = "Data Exfiltration",
                    Severity = severity,
                    Description = $"Large data upload detected: {outboundBytes.ToFormattedBytes()} from {flow.Key.SourceIP} to {flow.Key.DestinationIP}:{flow.Key.DestinationPort}",
                    DetectedAt = flowPackets.First().Timestamp,
                    DetectorName = Name,
                    SourceIP = flow.Key.SourceIP ?? "",
                    DestinationIP = flow.Key.DestinationIP ?? "",
                    DestinationPort = flow.Key.DestinationPort,
                    Protocol = flowPackets.First().Protocol.ToString(),
                    AffectedFrames = flowPackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                    Metrics = new Dictionary<string, object>
                    {
                        { "TotalBytes", outboundBytes },
                        { "DurationSeconds", timeWindow.TotalSeconds },
                        { "ThroughputBytesPerSecond", throughput },
                        { "PacketCount", flowPackets.Count },
                        { "IsNonStandardPort", isNonStandardPort }
                    },
                    Recommendation = "Large data upload detected. Investigate the destination, verify if transfer is authorized, and review data loss prevention policies."
                });
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectSlowExfiltration(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Group by source and destination to track long-duration flows
        var flows = packets.GroupBy(p => new { p.SourceIP, p.DestinationIP });

        foreach (var flow in flows)
        {
            var flowPackets = flow.OrderBy(p => p.Timestamp).ToList();
            var timeWindow = flowPackets.Max(p => p.Timestamp) - flowPackets.Min(p => p.Timestamp);

            // Look for flows that are long-duration with moderate data transfer
            if (timeWindow.TotalHours >= SLOW_EXFIL_MIN_DURATION_HOURS)
            {
                var totalBytes = flowPackets.Sum(p => (long)p.Length);

                if (totalBytes >= SLOW_EXFIL_MIN_BYTES)
                {
                    var bytesPerHour = totalBytes / timeWindow.TotalHours;

                    // Slow exfiltration: low rate but sustained over time
                    if (bytesPerHour < 1024 * 1024 * 10) // Less than 10MB/hour
                    {
                        // Check for regular intervals (characteristic of automated exfiltration)
                        var intervals = new List<double>();
                        for (int i = 1; i < flowPackets.Count; i++)
                        {
                            intervals.Add((flowPackets[i].Timestamp - flowPackets[i - 1].Timestamp).TotalSeconds);
                        }

                        var avgInterval = intervals.Any() ? intervals.Average() : 0;
                        var intervalVariance = intervals.Any() ? intervals.Average(v => Math.Pow(v - avgInterval, 2)) : 0;
                        var intervalStdDev = Math.Sqrt(intervalVariance);
                        var regularPattern = avgInterval > 0 && (intervalStdDev / avgInterval) < 0.3;

                        if (regularPattern || totalBytes > 10 * 1024 * 1024)
                        {
                            anomalies.Add(new NetworkAnomaly
                            {
                                Category = AnomalyCategory.Security,
                                Type = "Slow Data Exfiltration",
                                Severity = AnomalySeverity.High,
                                Description = $"Slow data exfiltration pattern: {totalBytes.ToFormattedBytes()} over {timeWindow.TotalHours:F1} hours from {flow.Key.SourceIP}",
                                DetectedAt = flowPackets.First().Timestamp,
                                DetectorName = Name,
                                SourceIP = flow.Key.SourceIP ?? "",
                                DestinationIP = flow.Key.DestinationIP ?? "",
                                Protocol = flowPackets.First().Protocol.ToString(),
                                AffectedFrames = flowPackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                                Metrics = new Dictionary<string, object>
                                {
                                    { "TotalBytes", totalBytes },
                                    { "DurationHours", timeWindow.TotalHours },
                                    { "BytesPerHour", bytesPerHour },
                                    { "PacketCount", flowPackets.Count },
                                    { "RegularPattern", regularPattern },
                                    { "AverageInterval", avgInterval }
                                },
                                Recommendation = "Slow exfiltration detected - data being transferred slowly to avoid detection. Investigate destination and source host for compromise."
                            });
                        }
                    }
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectEncodedTransfers(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Look for patterns that suggest encoded data transfer
        var suspiciousPackets = packets.Where(p =>
            p.HasEncodingIndicators() || HasBase64Pattern(p.Info)).ToList();

        if (suspiciousPackets.Count >= BASE64_PATTERN_THRESHOLD)
        {
            // Group by source
            var sourceGroups = suspiciousPackets.GroupBy(p => p.SourceIP);

            foreach (var source in sourceGroups)
            {
                var sourcePackets = source.ToList();
                if (sourcePackets.Count >= BASE64_PATTERN_THRESHOLD)
                {
                    var totalBytes = sourcePackets.Sum(p => (long)p.Length);
                    var destinations = sourcePackets.Select(p => p.DestinationIP).Distinct().ToList();

                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.Security,
                        Type = "Encoded Data Transfer",
                        Severity = totalBytes > 1024 * 1024 ? AnomalySeverity.High : AnomalySeverity.Medium,
                        Description = $"Encoded data transfer detected from {source.Key}: {sourcePackets.Count} packets with encoding patterns",
                        DetectedAt = sourcePackets.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = source.Key ?? "",
                        Protocol = sourcePackets.First().Protocol.ToString(),
                        AffectedFrames = sourcePackets.Select(p => (long)p.FrameNumber).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "EncodedPackets", sourcePackets.Count },
                            { "TotalBytes", totalBytes },
                            { "UniqueDestinations", destinations.Count },
                            { "Destinations", destinations.Take(5).ToList() }
                        },
                        Recommendation = "Encoded data transfer may indicate data exfiltration attempt to evade detection. Investigate source host and captured traffic content."
                    });
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectUnusualOutboundTraffic(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Group by source IP to analyze traffic patterns
        var sourceGroups = packets.GroupBy(p => p.SourceIP);

        foreach (var source in sourceGroups)
        {
            var sourcePackets = source.ToList();

            // Calculate upload/download ratio
            var outboundBytes = sourcePackets.Where(p => !string.IsNullOrEmpty(p.SourceIP)).Sum(p => (long)p.Length);
            var inboundBytes = sourcePackets.Where(p => !string.IsNullOrEmpty(p.DestinationIP)).Sum(p => (long)p.Length);

            if (inboundBytes > 0)
            {
                var uploadDownloadRatio = (double)outboundBytes / inboundBytes;

                // Unusual if uploading significantly more than downloading
                if (uploadDownloadRatio >= UPLOAD_DOWNLOAD_RATIO && outboundBytes >= 5 * 1024 * 1024)
                {
                    var uniqueDestinations = sourcePackets.Select(p => p.DestinationIP).Distinct().Count();
                    var uniquePorts = sourcePackets.Select(p => p.DestinationPort).Distinct().Count();

                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.Security,
                        Type = "Unusual Outbound Traffic",
                        Severity = uploadDownloadRatio > 10 ? AnomalySeverity.High : AnomalySeverity.Medium,
                        Description = $"Unusual outbound traffic pattern from {source.Key}: Upload/Download ratio {uploadDownloadRatio:F1}:1",
                        DetectedAt = sourcePackets.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = source.Key ?? "",
                        Protocol = "Mixed",
                        AffectedFrames = sourcePackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "OutboundBytes", outboundBytes },
                            { "InboundBytes", inboundBytes },
                            { "UploadDownloadRatio", uploadDownloadRatio },
                            { "UniqueDestinations", uniqueDestinations },
                            { "UniquePorts", uniquePorts },
                            { "PacketCount", sourcePackets.Count }
                        },
                        Recommendation = "Unusual upload/download ratio detected. Verify if large uploads are authorized and investigate potential data exfiltration."
                    });
                }
            }
        }

        return anomalies;
    }

    private bool HasBase64Pattern(string? info)
    {
        if (string.IsNullOrEmpty(info) || info.Length < 20)
            return false;

        // Look for base64-like patterns: alphanumeric with + / = and proper length
        var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var consecutiveBase64 = 0;
        var maxConsecutive = 0;

        foreach (var c in info)
        {
            if (base64Chars.Contains(c, StringComparison.Ordinal))
            {
                consecutiveBase64++;
                maxConsecutive = Math.Max(maxConsecutive, consecutiveBase64);
            }
            else
            {
                consecutiveBase64 = 0;
            }
        }

        // Long sequences of base64 chars suggest encoding
        return maxConsecutive >= 40;
    }

}
