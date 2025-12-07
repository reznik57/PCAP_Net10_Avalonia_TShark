using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Options;
using PCAPAnalyzer.Core.Configuration.Options;
using PCAPAnalyzer.Core.Interfaces.Statistics;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// Heuristic-based threat detection service.
    /// Implements IThreatDetector for DI injection and testability.
    /// Uses IOptions&lt;ProtocolConfiguration&gt; for configurable suspicious protocol list.
    /// </summary>
    public sealed class ThreatDetector : IThreatDetector
    {
        private readonly ITimeSeriesGenerator _timeSeriesGenerator;
        private readonly ProtocolConfiguration _protocolConfig;

        /// <summary>
        /// Creates a new ThreatDetector with configurable protocol settings.
        /// </summary>
        /// <param name="timeSeriesGenerator">Time series generator for DDoS detection.</param>
        /// <param name="protocolOptions">Protocol configuration from IOptions pattern (optional).</param>
        public ThreatDetector(ITimeSeriesGenerator timeSeriesGenerator, IOptions<ProtocolConfiguration>? protocolOptions = null)
        {
            ArgumentNullException.ThrowIfNull(timeSeriesGenerator);
            _timeSeriesGenerator = timeSeriesGenerator;
            _protocolConfig = protocolOptions?.Value ?? new ProtocolConfiguration();
        }

        public List<SecurityThreat> DetectPortScanning(List<PacketInfo> packets)
        {
            var threats = new List<SecurityThreat>();

            var portScanAnalysis = packets
                .Where(p => !string.IsNullOrEmpty(p.SourceIP) && !string.IsNullOrEmpty(p.DestinationIP))
                .GroupBy(p => new { Source = p.SourceIP, Destination = p.DestinationIP })
                .Select(g => new
                {
                    Source = g.Key.Source,
                    Destination = g.Key.Destination,
                    UniquePorts = g.Select(p => p.DestinationPort).Distinct().Count(),
                    Packets = g.OrderBy(p => p.Timestamp).ToList(),
                    TimeSpan = g.Max(p => p.Timestamp) - g.Min(p => p.Timestamp),
                    FirstPacketTime = g.Min(p => p.Timestamp),
                    PortsPerSecond = g.Select(p => p.DestinationPort).Distinct().Count() /
                                     Math.Max(1, (g.Max(p => p.Timestamp) - g.Min(p => p.Timestamp)).TotalSeconds)
                })
                .Where(x => (x.UniquePorts > 500) ||
                           (x.UniquePorts > 100 && x.PortsPerSecond > 50) ||
                           (x.UniquePorts > 50 && x.TimeSpan.TotalSeconds < 5 && x.PortsPerSecond > 20))
                .ToList();

            foreach (var scan in portScanAnalysis)
            {
                var severity = scan.UniquePorts > 1000 ? ThreatSeverity.Critical :
                              scan.UniquePorts > 500 ? ThreatSeverity.High :
                              scan.UniquePorts > 200 ? ThreatSeverity.Medium :
                              ThreatSeverity.Low;

                threats.Add(new SecurityThreat
                {
                    DetectedAt = scan.FirstPacketTime,
                    Severity = severity,
                    Type = "Port Scan",
                    Description = $"Port scanning: {scan.Source} → {scan.Destination} ({scan.UniquePorts} ports in {scan.TimeSpan.TotalSeconds:F1}s)",
                    SourceAddress = scan.Source,
                    DestinationAddress = scan.Destination,
                    AffectedPackets = scan.Packets.Select(p => (long)(int)p.FrameNumber).ToList(),
                    Recommendation = "Verify if this is authorized scanning. If unauthorized, block source IP and investigate further.",
                    Evidence = new Dictionary<string, object>
                    {
                        { "UniquePorts", scan.UniquePorts },
                        { "TotalPackets", scan.Packets.Count },
                        { "Duration", scan.TimeSpan.TotalSeconds },
                        { "PortsPerSecond", Math.Round(scan.PortsPerSecond, 2) }
                    }
                });
            }

            return threats;
        }

        public List<SecurityThreat> DetectSuspiciousProtocols(List<PacketInfo> packets)
        {
            var threats = new List<SecurityThreat>();
            // Use configurable suspicious protocols from IOptions<ProtocolConfiguration>
            var suspiciousProtocols = _protocolConfig.SuspiciousProtocols;

            var unencryptedTraffic = packets
                .Where(p => suspiciousProtocols.Contains(p.Protocol.ToString().ToUpper()))
                .GroupBy(p => p.Protocol.ToString())
                .ToList();

            foreach (var group in unencryptedTraffic)
            {
                var firstPacket = group.OrderBy(p => p.Timestamp).First();
                var threat = new SecurityThreat
                {
                    DetectedAt = firstPacket.Timestamp,
                    Severity = ThreatSeverity.Medium,
                    Type = "Unencrypted Protocol",
                    Description = $"Unencrypted {group.Key} traffic detected",
                    AffectedPackets = group.Select(p => (long)(int)p.FrameNumber).Take(100).ToList(),
                    Recommendation = $"Consider using encrypted alternatives (e.g., SSH instead of Telnet, HTTPS instead of HTTP)",
                    Evidence = new Dictionary<string, object>
                    {
                        { "Protocol", group.Key },
                        { "PacketCount", group.Count() },
                        { "FirstSeen", firstPacket.Timestamp },
                        { "SourceIP", firstPacket.SourceIP },
                        { "DestinationIP", firstPacket.DestinationIP }
                    }
                };

                threats.Add(threat);
            }

            return threats;
        }

        public List<SecurityThreat> DetectAnomalousTraffic(List<PacketInfo> packets)
        {
            var threats = new List<SecurityThreat>();

            var avgSize = packets.Any() ? packets.Average(p => p.Length) : 0;
            var stdDev = Math.Sqrt(packets.Any() ? packets.Average(p => Math.Pow(p.Length - avgSize, 2)) : 0);
            var threshold = avgSize + (3 * stdDev);

            var largePackets = packets
                .Where(p => p.Length > threshold && p.Length > 1500)
                .ToList();

            if (largePackets.Any())
            {
                var firstLargePacket = largePackets.OrderBy(p => p.Timestamp).First();
                threats.Add(new SecurityThreat
                {
                    DetectedAt = firstLargePacket.Timestamp,
                    Severity = ThreatSeverity.Low,
                    Type = "Anomalous Packet Size",
                    Description = $"Detected {largePackets.Count} packets with unusual size",
                    AffectedPackets = largePackets.Select(p => (long)(int)p.FrameNumber).Take(50).ToList(),
                    Recommendation = "Review large packets for potential data exfiltration",
                    Evidence = new Dictionary<string, object>
                    {
                        { "AverageSize", avgSize },
                        { "MaxSize", largePackets.Max(p => p.Length) },
                        { "AffectedPackets", largePackets.Count }
                    }
                });
            }

            return threats;
        }

        public List<SecurityThreat> DetectPotentialDDoS(List<PacketInfo> packets)
        {
            var threats = new List<SecurityThreat>();
            var timeWindow = TimeSpan.FromSeconds(10);
            var threshold = 1000;

            if (!packets.Any())
                return threats;

            var startTime = packets.Min(p => p.Timestamp);
            var endTime = packets.Max(p => p.Timestamp);

            var destinationGroups = packets
                .GroupBy(p => p.DestinationIP)
                .Select(g => new
                {
                    Destination = g.Key,
                    PacketsPerWindow = _timeSeriesGenerator.CalculateMaxPacketsPerWindow(g.ToList(), timeWindow, startTime, endTime),
                    FirstPacketTime = g.Min(p => p.Timestamp),
                    Packets = g.ToList()
                })
                .Where(x => x.PacketsPerWindow > threshold)
                .ToList();

            foreach (var target in destinationGroups)
            {
                threats.Add(new SecurityThreat
                {
                    DetectedAt = target.FirstPacketTime,
                    Severity = ThreatSeverity.Critical,
                    Type = "Potential DDoS",
                    Description = $"High traffic volume detected to {target.Destination} ({target.PacketsPerWindow} packets in {timeWindow.TotalSeconds}s window)",
                    DestinationAddress = target.Destination,
                    Recommendation = "Implement rate limiting and investigate traffic sources",
                    Evidence = new Dictionary<string, object>
                    {
                        { "MaxPacketsPerWindow", target.PacketsPerWindow },
                        { "TimeWindow", timeWindow.TotalSeconds }
                    }
                });
            }

            return threats;
        }
    }
}
