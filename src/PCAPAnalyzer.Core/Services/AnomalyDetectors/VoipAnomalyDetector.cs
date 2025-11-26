using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects VoIP-specific anomalies: SIP flooding, RTP quality issues, ghost calls, toll fraud
/// </summary>
public class VoipAnomalyDetector : ISpecializedDetector
{
    private const int SIP_FLOOD_THRESHOLD = 50; // SIP messages per second
    private const double RTP_PACKET_LOSS_THRESHOLD = 0.05; // 5% packet loss
    private const int RTP_JITTER_THRESHOLD_MS = 30; // 30ms jitter threshold
    private const int GHOST_CALL_MIN_INVITES = 10; // Minimum INVITE count for ghost call detection

    public string Name => "VoIP Anomaly Detector";
    public AnomalyCategory Category => AnomalyCategory.VoIP;
    public int Priority => 5;

    public bool CanDetect(IEnumerable<PacketInfo> packets)
    {
        // Only run if there's VoIP traffic (SIP or RTP)
        return packets.Any(p =>
            p.DestinationPort == 5060 ||
            p.SourcePort == 5060 ||
            (p.DestinationPort >= 10000 && p.DestinationPort <= 20000) || // Common RTP port range
            p.Info?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true ||
            p.Info?.Contains("RTP", StringComparison.OrdinalIgnoreCase) == true ||
            p.L7Protocol?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true);
    }

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var packetList = packets.ToList();

        if (!packetList.Any())
            return anomalies;

        anomalies.AddRange(DetectSIPFlooding(packetList));
        anomalies.AddRange(DetectGhostCalls(packetList));
        anomalies.AddRange(DetectRTPQualityIssues(packetList));
        anomalies.AddRange(DetectTollFraud(packetList));

        return anomalies;
    }

    private List<NetworkAnomaly> DetectSIPFlooding(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var sipPackets = packets.Where(p =>
            p.DestinationPort == 5060 ||
            p.SourcePort == 5060 ||
            p.Info?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true ||
            p.L7Protocol?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true).ToList();

        if (!sipPackets.Any())
            return anomalies;

        // Group by destination to detect targets
        var targetGroups = sipPackets.GroupBy(p => new { p.DestinationIP, p.DestinationPort });

        foreach (var target in targetGroups)
        {
            var targetPackets = target.ToList();
            var timeWindow = targetPackets.Max(p => p.Timestamp) - targetPackets.Min(p => p.Timestamp);

            if (timeWindow.TotalSeconds > 0)
            {
                var sipPerSecond = targetPackets.Count / timeWindow.TotalSeconds;

                if (sipPerSecond >= SIP_FLOOD_THRESHOLD)
                {
                    // Count INVITE, REGISTER, and other SIP methods
                    var invites = targetPackets.Count(p => p.Info?.Contains("INVITE", StringComparison.OrdinalIgnoreCase) == true);
                    var registers = targetPackets.Count(p => p.Info?.Contains("REGISTER", StringComparison.OrdinalIgnoreCase) == true);

                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.VoIP,
                        Type = "VoIP SIP Flooding",
                        Severity = sipPerSecond > 100 ? AnomalySeverity.Critical : AnomalySeverity.High,
                        Description = $"SIP flooding detected: {sipPerSecond:F1} messages/second to {target.Key.DestinationIP}:{target.Key.DestinationPort}",
                        DetectedAt = targetPackets.First().Timestamp,
                        DetectorName = Name,
                        DestinationIP = target.Key.DestinationIP ?? "",
                        DestinationPort = target.Key.DestinationPort,
                        Protocol = "SIP",
                        AffectedFrames = targetPackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "SIPMessagesPerSecond", sipPerSecond },
                            { "TotalSIPMessages", targetPackets.Count },
                            { "INVITECount", invites },
                            { "REGISTERCount", registers },
                            { "UniqueSources", targetPackets.Select(p => p.SourceIP).Distinct().Count() }
                        },
                        Recommendation = "SIP flooding may indicate DoS attack on VoIP infrastructure. Implement rate limiting, SIP authentication, and consider blocking suspicious sources."
                    });
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectGhostCalls(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var sipPackets = packets.Where(p =>
            p.Info?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true ||
            p.DestinationPort == 5060 ||
            p.SourcePort == 5060).ToList();

        if (!sipPackets.Any())
            return anomalies;

        // Look for INVITE without corresponding 200 OK or ACK
        var invites = sipPackets.Where(p => p.Info?.Contains("INVITE", StringComparison.OrdinalIgnoreCase) == true).ToList();
        var oks = sipPackets.Where(p => p.Info?.Contains("200 OK", StringComparison.OrdinalIgnoreCase) == true).ToList();

        // Group INVITEs by source
        var inviteGroups = invites.GroupBy(p => p.SourceIP);

        foreach (var group in inviteGroups)
        {
            var groupInvites = group.ToList();
            if (groupInvites.Count >= GHOST_CALL_MIN_INVITES)
            {
                // Check if there are corresponding responses
                var responsesForSource = oks.Count(ok =>
                    groupInvites.Any(inv => ok.DestinationIP == inv.SourceIP));

                var responseRate = groupInvites.Count > 0 ? (double)responsesForSource / groupInvites.Count : 0;

                if (responseRate < 0.2) // Less than 20% response rate
                {
                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.VoIP,
                        Type = "VoIP Ghost Call",
                        Severity = AnomalySeverity.High,
                        Description = $"Ghost call pattern detected from {group.Key}: {groupInvites.Count} unanswered INVITEs",
                        DetectedAt = groupInvites.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = group.Key ?? "",
                        Protocol = "SIP",
                        AffectedFrames = groupInvites.Select(p => (long)p.FrameNumber).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "TotalINVITEs", groupInvites.Count },
                            { "ResponseRate", responseRate },
                            { "UniqueDestinations", groupInvites.Select(p => p.DestinationIP).Distinct().Count() }
                        },
                        Recommendation = "Ghost calls may indicate scanning for vulnerable SIP endpoints. Block the source IP and enable SIP authentication."
                    });
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectRTPQualityIssues(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // RTP packets typically use UDP ports in the range 10000-20000
        var rtpPackets = packets.Where(p =>
            p.Protocol == Protocol.UDP &&
            ((p.DestinationPort >= 10000 && p.DestinationPort <= 20000) ||
             (p.SourcePort >= 10000 && p.SourcePort <= 20000)) &&
            p.Length >= 12 && p.Length <= 1500).ToList();

        if (rtpPackets.Count < 100) // Need sufficient packets for quality analysis
            return anomalies;

        // Group by RTP stream (source-destination pair)
        var rtpStreams = rtpPackets
            .GroupBy(p => $"{p.SourceIP}:{p.SourcePort}->{p.DestinationIP}:{p.DestinationPort}")
            .Where(g => g.Count() >= 50) // Analyze streams with at least 50 packets
            .ToList();

        foreach (var stream in rtpStreams)
        {
            var streamPackets = stream.OrderBy(p => p.Timestamp).ToList();

            // Calculate jitter (simplified - variation in packet arrival times)
            var intervals = new List<double>();
            for (int i = 1; i < streamPackets.Count; i++)
            {
                var interval = (streamPackets[i].Timestamp - streamPackets[i - 1].Timestamp).TotalMilliseconds;
                intervals.Add(interval);
            }

            if (intervals.Any())
            {
                var avgInterval = intervals.Average();
                var jitter = intervals.Select(i => Math.Abs(i - avgInterval)).Average();

                // Detect packet loss (gaps in sequence)
                var expectedInterval = avgInterval * 1.5; // Allow 50% tolerance
                var lostPackets = intervals.Count(i => i > expectedInterval);
                var packetLossRate = (double)lostPackets / intervals.Count;

                if (jitter > RTP_JITTER_THRESHOLD_MS || packetLossRate > RTP_PACKET_LOSS_THRESHOLD)
                {
                    var severity = (jitter > 50 || packetLossRate > 0.1)
                        ? AnomalySeverity.High
                        : AnomalySeverity.Medium;

                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.VoIP,
                        Type = "VoIP RTP Quality Issue",
                        Severity = severity,
                        Description = $"RTP quality degradation: Jitter={jitter:F1}ms, Loss={packetLossRate * 100:F2}%",
                        DetectedAt = streamPackets.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = streamPackets.First().SourceIP ?? "",
                        DestinationIP = streamPackets.First().DestinationIP ?? "",
                        SourcePort = streamPackets.First().SourcePort,
                        DestinationPort = streamPackets.First().DestinationPort,
                        Protocol = "RTP/UDP",
                        AffectedFrames = streamPackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "Jitter", jitter },
                            { "PacketLossRate", packetLossRate },
                            { "AverageInterval", avgInterval },
                            { "TotalPackets", streamPackets.Count },
                            { "EstimatedLostPackets", lostPackets }
                        },
                        Recommendation = "RTP quality issues impact call quality. Check network path for congestion, packet loss, or routing problems. Consider implementing QoS."
                    });
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectTollFraud(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var sipPackets = packets.Where(p =>
            p.Info?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true ||
            p.DestinationPort == 5060).ToList();

        if (!sipPackets.Any())
            return anomalies;

        // Look for high-volume calling patterns to international or premium numbers
        var invites = sipPackets.Where(p => p.Info?.Contains("INVITE", StringComparison.OrdinalIgnoreCase) == true).ToList();

        // Group by source to identify potential fraud sources
        var sourceGroups = invites.GroupBy(p => p.SourceIP);

        foreach (var group in sourceGroups)
        {
            var groupPackets = group.ToList();
            var timeWindow = groupPackets.Max(p => p.Timestamp) - groupPackets.Min(p => p.Timestamp);

            // Check for unusual call patterns
            if (timeWindow.TotalHours > 0 && groupPackets.Count >= 20)
            {
                var callsPerHour = groupPackets.Count / timeWindow.TotalHours;
                var uniqueDestinations = groupPackets.Select(p => p.DestinationIP).Distinct().Count();

                // Look for patterns: many calls, many destinations, short duration
                if (callsPerHour > 10 && uniqueDestinations > 5)
                {
                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.VoIP,
                        Type = "VoIP Toll Fraud",
                        Severity = AnomalySeverity.Critical,
                        Description = $"Potential toll fraud: {groupPackets.Count} calls from {group.Key} to {uniqueDestinations} destinations",
                        DetectedAt = groupPackets.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = group.Key ?? "",
                        Protocol = "SIP",
                        AffectedFrames = groupPackets.Select(p => (long)p.FrameNumber).Take(50).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "TotalCalls", groupPackets.Count },
                            { "CallsPerHour", callsPerHour },
                            { "UniqueDestinations", uniqueDestinations },
                            { "TimeWindowHours", timeWindow.TotalHours }
                        },
                        Recommendation = "Immediate action required: Potential toll fraud detected. Block source, review call logs, and enable toll fraud prevention mechanisms."
                    });
                }
            }
        }

        return anomalies;
    }
}
