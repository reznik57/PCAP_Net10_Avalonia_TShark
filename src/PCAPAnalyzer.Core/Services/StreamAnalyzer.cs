using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Analyzes TCP/UDP streams for state machine, bandwidth, timing, and application protocol detection.
/// Provides comprehensive flow analysis for network troubleshooting.
/// </summary>
public class StreamAnalyzer
{
    private const ushort TCP_FLAG_SYN = 0x02;
    private const ushort TCP_FLAG_ACK = 0x10;
    private const ushort TCP_FLAG_FIN = 0x01;
    private const ushort TCP_FLAG_RST = 0x04;
    private const ushort TCP_FLAG_PSH = 0x08;
    private const ushort TCP_FLAG_URG = 0x20;

    private readonly IInsecurePortDetector? _portDetector;
    private readonly IGeoIPService? _geoIPService;

    // Known malware ports (C2, backdoors, etc.)
    private static readonly HashSet<int> MalwarePorts = new()
    {
        4444,   // Metasploit default
        5555,   // Android ADB exploitation
        6666,   // IRC backdoors
        6667,   // IRC C2
        31337,  // Back Orifice, elite
        12345,  // NetBus
        27374,  // SubSeven
        1337,   // Elite/Leet
        9001,   // Tor default
        9050    // Tor SOCKS
    };

    /// <summary>
    /// Creates StreamAnalyzer with optional security services for enhanced analysis.
    /// </summary>
    public StreamAnalyzer(
        IInsecurePortDetector? portDetector = null,
        IGeoIPService? geoIPService = null)
    {
        _portDetector = portDetector;
        _geoIPService = geoIPService;
    }

    /// <summary>
    /// Analyzes complete stream including TCP state, bandwidth, timing, and protocol detection.
    /// </summary>
    public StreamAnalysisResult AnalyzeStream(IReadOnlyList<PacketInfo> packets, string streamKey)
    {
        if (packets.Count == 0)
        {
            throw new ArgumentException("Cannot analyze empty stream", nameof(packets));
        }

        var isTcp = packets[0].Protocol == Protocol.TCP;
        var referencePacket = packets[0];

        return new StreamAnalysisResult
        {
            StreamKey = streamKey,
            PacketCount = packets.Count,
            TcpState = isTcp ? AnalyzeTcpStateMachine(packets) : CreateEmptyTcpState(),
            Bandwidth = CalculateBandwidthMetrics(packets),
            Timing = AnalyzeTimingMetrics(packets),
            Protocol = DetectApplicationProtocol(packets),
            Security = AnalyzeSecurityIndicators(referencePacket),
            Directional = AnalyzeDirectionalMetrics(packets, referencePacket)
        };
    }

    /// <summary>
    /// Analyzes complete stream with a specific current packet for positional context.
    /// </summary>
    public StreamAnalysisResult AnalyzeStream(IReadOnlyList<PacketInfo> packets, string streamKey, PacketInfo currentPacket)
    {
        if (packets.Count == 0)
        {
            throw new ArgumentException("Cannot analyze empty stream", nameof(packets));
        }

        var isTcp = packets[0].Protocol == Protocol.TCP;

        return new StreamAnalysisResult
        {
            StreamKey = streamKey,
            PacketCount = packets.Count,
            TcpState = isTcp ? AnalyzeTcpStateMachine(packets) : CreateEmptyTcpState(),
            Bandwidth = CalculateBandwidthMetrics(packets),
            Timing = AnalyzeTimingMetrics(packets),
            Protocol = DetectApplicationProtocol(packets),
            Security = AnalyzeSecurityIndicators(currentPacket),
            Directional = AnalyzeDirectionalMetrics(packets, currentPacket)
        };
    }

    /// <summary>
    /// Analyzes TCP connection lifecycle: handshake, state, retransmissions, window scaling.
    /// </summary>
    public TcpStateInfo AnalyzeTcpStateMachine(IReadOnlyList<PacketInfo> packets)
    {
        if (packets.Count == 0 || packets[0].Protocol != Protocol.TCP)
        {
            return CreateEmptyTcpState();
        }

        var handshake = DetectHandshake(packets);
        var retransmissions = DetectRetransmissions(packets);
        var windowScaling = AnalyzeWindowScaling(packets);
        var flags = CountFlags(packets);
        var state = DetermineConnectionState(packets, handshake, flags);

        return new TcpStateInfo
        {
            State = state,
            Handshake = handshake,
            RetransmissionCount = retransmissions,
            WindowScaling = windowScaling,
            Flags = flags,
            IsComplete = handshake?.IsComplete ?? false
        };
    }

    /// <summary>
    /// Calculates bandwidth and throughput metrics over stream lifetime.
    /// </summary>
    public BandwidthMetrics CalculateBandwidthMetrics(IReadOnlyList<PacketInfo> packets)
    {
        if (packets.Count == 0)
        {
            throw new ArgumentException("Cannot calculate bandwidth for empty stream", nameof(packets));
        }

        long totalBytes = packets.Sum(p => (long)p.Length);
        var duration = packets[^1].Timestamp - packets[0].Timestamp;

        // Handle single-packet or zero-duration streams
        double durationSeconds = duration.TotalSeconds > 0 ? duration.TotalSeconds : 1.0;

        double avgBytesPerSec = totalBytes / durationSeconds;
        double avgPacketsPerSec = packets.Count / durationSeconds;
        double avgPacketSize = (double)totalBytes / packets.Count;

        var peak = CalculatePeakThroughput(packets);

        return new BandwidthMetrics
        {
            TotalBytes = totalBytes,
            Duration = duration,
            AverageBytesPerSecond = avgBytesPerSec,
            AveragePacketsPerSecond = avgPacketsPerSec,
            AveragePacketSize = avgPacketSize,
            Peak = peak
        };
    }

    /// <summary>
    /// Analyzes network timing: RTT, inter-packet delay, jitter.
    /// </summary>
    public TimingMetrics AnalyzeTimingMetrics(IReadOnlyList<PacketInfo> packets)
    {
        if (packets.Count == 0)
        {
            throw new ArgumentException("Cannot analyze timing for empty stream", nameof(packets));
        }

        var rttSamples = CalculateRttSamples(packets);
        var interPacketDelays = CalculateInterPacketDelays(packets);

        double? avgRtt = null;
        double? minRtt = null;
        double? maxRtt = null;
        RttSample? minSample = null;
        RttSample? maxSample = null;
        double? jitter = null;

        if (rttSamples.Count > 0)
        {
            avgRtt = rttSamples.Average(s => s.RttMs);
            minSample = rttSamples.OrderBy(s => s.RttMs).First();
            maxSample = rttSamples.OrderBy(s => s.RttMs).Last();
            minRtt = minSample.RttMs;
            maxRtt = maxSample.RttMs;

            // Calculate jitter (variance in RTT)
            if (rttSamples.Count > 1)
            {
                var variance = rttSamples.Sum(s => Math.Pow(s.RttMs - avgRtt.Value, 2)) / rttSamples.Count;
                jitter = Math.Sqrt(variance);
            }
        }

        double avgDelay = interPacketDelays.Count > 0
            ? interPacketDelays.Average()
            : 0.0;

        return new TimingMetrics
        {
            AverageRttMs = avgRtt,
            MinRttMs = minRtt,
            MaxRttMs = maxRtt,
            MinRttSample = minSample,
            MaxRttSample = maxSample,
            JitterMs = jitter,
            AverageInterPacketDelayMs = avgDelay
        };
    }

    /// <summary>
    /// Detects application layer protocol from payload patterns and port numbers.
    /// </summary>
    public ApplicationProtocolInfo DetectApplicationProtocol(IReadOnlyList<PacketInfo> packets)
    {
        if (packets.Count == 0)
        {
            return CreateUnknownProtocol();
        }

        var firstPacket = packets[0];
        var details = new Dictionary<string, string>();

        // Check L7Protocol field first (from TShark)
        if (!string.IsNullOrWhiteSpace(firstPacket.L7Protocol))
        {
            var isEncrypted = IsEncryptedProtocol(firstPacket.L7Protocol);
            return new ApplicationProtocolInfo
            {
                Name = firstPacket.L7Protocol,
                Description = $"Detected from TShark: {firstPacket.L7Protocol}",
                IsEncrypted = isEncrypted,
                Details = details
            };
        }

        // Port-based detection
        var port = firstPacket.DestinationPort > 0 ? firstPacket.DestinationPort : firstPacket.SourcePort;

        // HTTP detection (port 80 or HTTP patterns in payload)
        if (port == 80 || DetectHttpPattern(packets, details))
        {
            return new ApplicationProtocolInfo
            {
                Name = "HTTP",
                Description = "Hypertext Transfer Protocol",
                IsEncrypted = false,
                Details = details
            };
        }

        // HTTPS/TLS detection (port 443 or TLS handshake)
        if (port == 443 || DetectTlsPattern(packets, details))
        {
            return new ApplicationProtocolInfo
            {
                Name = "HTTPS/TLS",
                Description = "Transport Layer Security",
                IsEncrypted = true,
                Details = details
            };
        }

        // DNS detection
        if (port == 53)
        {
            return new ApplicationProtocolInfo
            {
                Name = "DNS",
                Description = "Domain Name System",
                IsEncrypted = false,
                Details = details
            };
        }

        // SSH detection
        if (port == 22)
        {
            return new ApplicationProtocolInfo
            {
                Name = "SSH",
                Description = "Secure Shell",
                IsEncrypted = true,
                Details = details
            };
        }

        // Email protocols
        if (port == 25) return CreateProtocolInfo("SMTP", "Simple Mail Transfer Protocol", false, details);
        if (port == 110) return CreateProtocolInfo("POP3", "Post Office Protocol v3", false, details);
        if (port == 143) return CreateProtocolInfo("IMAP", "Internet Message Access Protocol", false, details);
        if (port == 465 || port == 587) return CreateProtocolInfo("SMTPS", "SMTP over TLS", true, details);
        if (port == 995) return CreateProtocolInfo("POP3S", "POP3 over TLS", true, details);
        if (port == 993) return CreateProtocolInfo("IMAPS", "IMAP over TLS", true, details);

        // FTP
        if (port == 20 || port == 21) return CreateProtocolInfo("FTP", "File Transfer Protocol", false, details);

        // Fallback to protocol enum
        return new ApplicationProtocolInfo
        {
            Name = firstPacket.Protocol.ToString(),
            Description = $"{firstPacket.Protocol} protocol on port {port}",
            IsEncrypted = false,
            Details = details
        };
    }

    #region Security and Directional Analysis

    /// <summary>
    /// Analyzes security indicators for stream endpoints including port and GeoIP risks.
    /// </summary>
    private SecurityIndicators? AnalyzeSecurityIndicators(PacketInfo referencePacket)
    {
        if (_portDetector == null && _geoIPService == null)
            return null;

        var warnings = new List<string>();

        // Analyze source port
        var srcPortSecurity = AnalyzePort(referencePacket.SourcePort, warnings, "Source");
        var dstPortSecurity = AnalyzePort(referencePacket.DestinationPort, warnings, "Destination");

        // Analyze GeoIP
        var srcGeo = AnalyzeGeoIP(referencePacket.SourceIP, warnings, "Source");
        var dstGeo = AnalyzeGeoIP(referencePacket.DestinationIP, warnings, "Destination");

        // Calculate overall risk
        var overallRisk = CalculateOverallRisk(srcPortSecurity, dstPortSecurity, srcGeo, dstGeo);

        return new SecurityIndicators
        {
            SourcePortSecurity = srcPortSecurity,
            DestinationPortSecurity = dstPortSecurity,
            SourceGeoInfo = srcGeo,
            DestinationGeoInfo = dstGeo,
            Warnings = warnings,
            OverallRisk = overallRisk
        };
    }

    /// <summary>
    /// Analyzes a port for security risks.
    /// </summary>
    private PortSecurityInfo AnalyzePort(int port, List<string> warnings, string direction)
    {
        var isInsecure = false;
        var isMalware = MalwarePorts.Contains(port);
        string? serviceName = null;
        string? riskDesc = null;
        string? alternative = null;

        if (_portDetector != null)
        {
            var knownPorts = _portDetector.GetKnownInsecurePorts();
            if (knownPorts.TryGetValue(port, out var profile))
            {
                isInsecure = true;
                serviceName = profile.ServiceName;
                riskDesc = profile.SecurityNotes;
                alternative = profile.RecommendedAlternative;
                warnings.Add($"{direction} port {port} ({serviceName}): {riskDesc}");
            }
        }

        if (isMalware)
        {
            warnings.Add($"[!] {direction} port {port} is associated with malware/C2 traffic");
        }

        return new PortSecurityInfo
        {
            Port = port,
            IsKnownInsecure = isInsecure,
            IsKnownMalwarePort = isMalware,
            ServiceName = serviceName,
            RiskDescription = riskDesc,
            RecommendedAlternative = alternative
        };
    }

    /// <summary>
    /// Analyzes GeoIP information for security risks.
    /// </summary>
    private GeoSecurityInfo? AnalyzeGeoIP(string ip, List<string> warnings, string direction)
    {
        if (_geoIPService == null)
            return null;

        var isPrivate = IsPrivateIP(ip);
        if (isPrivate)
        {
            return new GeoSecurityInfo
            {
                IP = ip,
                CountryCode = null,
                CountryName = "Private Network",
                City = null,
                IsHighRiskCountry = false,
                IsPrivateIP = true
            };
        }

        // Use async method with blocking wait (sync API requirement)
        GeoLocation? geoInfo = null;
        try
        {
            geoInfo = _geoIPService.GetLocationAsync(ip).GetAwaiter().GetResult();
        }
        catch
        {
            // GeoIP lookup failed - continue without geo data
        }

        var isHighRisk = _geoIPService.IsHighRiskCountry(geoInfo?.CountryCode ?? string.Empty);

        if (isHighRisk)
        {
            warnings.Add($"[GEO] {direction} IP {ip} is from high-risk country: {geoInfo?.CountryName}");
        }

        return new GeoSecurityInfo
        {
            IP = ip,
            CountryCode = geoInfo?.CountryCode,
            CountryName = geoInfo?.CountryName,
            City = geoInfo?.City,
            IsHighRiskCountry = isHighRisk,
            IsPrivateIP = false
        };
    }

    /// <summary>
    /// Checks if an IP address is in a private/reserved range.
    /// </summary>
    private static bool IsPrivateIP(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var addr))
            return false;

        var bytes = addr.GetAddressBytes();
        if (bytes.Length != 4) // IPv4 only
            return false;

        return bytes[0] == 10 ||                                          // 10.0.0.0/8
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||   // 172.16.0.0/12
               (bytes[0] == 192 && bytes[1] == 168) ||                     // 192.168.0.0/16
               (bytes[0] == 127);                                          // 127.0.0.0/8 (loopback)
    }

    /// <summary>
    /// Calculates overall risk level based on port and GeoIP security indicators.
    /// </summary>
    private static ThreatSeverity CalculateOverallRisk(
        PortSecurityInfo src, PortSecurityInfo dst,
        GeoSecurityInfo? srcGeo, GeoSecurityInfo? dstGeo)
    {
        // Critical: Known malware ports
        if (src.IsKnownMalwarePort || dst.IsKnownMalwarePort)
            return ThreatSeverity.Critical;

        // High: Known insecure services (Telnet, FTP, etc.)
        if (src.IsKnownInsecure || dst.IsKnownInsecure)
            return ThreatSeverity.High;

        // Medium: Traffic to/from high-risk countries
        if ((srcGeo?.IsHighRiskCountry ?? false) || (dstGeo?.IsHighRiskCountry ?? false))
            return ThreatSeverity.Medium;

        // Low: No identified risks
        return ThreatSeverity.Low;
    }

    /// <summary>
    /// Analyzes bidirectional traffic metrics for client/server breakdown.
    /// </summary>
    private DirectionalMetrics AnalyzeDirectionalMetrics(IReadOnlyList<PacketInfo> packets, PacketInfo currentPacket)
    {
        // Determine client (initiator) vs server based on first packet
        var firstPacket = packets.OrderBy(p => p.Timestamp).First();
        var clientIP = firstPacket.SourceIP;
        var clientPort = firstPacket.SourcePort;
        var serverIP = firstPacket.DestinationIP;
        var serverPort = firstPacket.DestinationPort;

        // Calculate bytes per direction
        long clientBytes = 0, serverBytes = 0;
        int clientPackets = 0, serverPackets = 0;

        foreach (var p in packets)
        {
            if (p.SourceIP == clientIP && p.SourcePort == clientPort)
            {
                clientBytes += p.Length;
                clientPackets++;
            }
            else
            {
                serverBytes += p.Length;
                serverPackets++;
            }
        }

        // Find current packet position
        var orderedPackets = packets.OrderBy(p => p.FrameNumber).ToList();
        var currentPosition = orderedPackets.FindIndex(p => p.FrameNumber == currentPacket.FrameNumber) + 1;
        if (currentPosition == 0) currentPosition = 1; // Default to 1 if not found

        // Calculate connection age
        var firstTime = packets.Min(p => p.Timestamp);
        var lastTime = packets.Max(p => p.Timestamp);
        var connectionAge = lastTime - firstTime;

        // Determine dominant direction
        var ratio = clientBytes > 0 ? (double)serverBytes / clientBytes : double.MaxValue;
        string direction;
        if (ratio > 2.0) direction = "Server->Client (Download)";
        else if (ratio < 0.5) direction = "Client->Server (Upload)";
        else direction = "Balanced";

        return new DirectionalMetrics
        {
            Client = new EndpointMetrics
            {
                IP = clientIP,
                Port = clientPort,
                BytesSent = clientBytes,
                PacketsSent = clientPackets,
                BytesSentFormatted = FormatBytes(clientBytes)
            },
            Server = new EndpointMetrics
            {
                IP = serverIP,
                Port = serverPort,
                BytesSent = serverBytes,
                PacketsSent = serverPackets,
                BytesSentFormatted = FormatBytes(serverBytes)
            },
            RequestResponseRatio = ratio,
            DominantDirection = direction,
            StreamPositionCurrent = currentPosition,
            StreamPositionTotal = packets.Count,
            ConnectionAge = connectionAge
        };
    }

    /// <summary>
    /// Formats byte count into human-readable string.
    /// </summary>
    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F2} MB";
        return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }

    #endregion

    #region Private Helper Methods

    private static TcpStateInfo CreateEmptyTcpState()
    {
        return new TcpStateInfo
        {
            State = "N/A (Not TCP)",
            Handshake = null,
            RetransmissionCount = 0,
            WindowScaling = new WindowScalingInfo
            {
                InitialWindow = 0,
                CurrentWindow = 0,
                MinWindow = 0,
                MaxWindow = 0
            },
            Flags = new TcpFlagCounts(),
            IsComplete = false
        };
    }

    private static HandshakeInfo? DetectHandshake(IReadOnlyList<PacketInfo> packets)
    {
        uint? synPacket = null;
        uint? synAckPacket = null;
        uint? ackPacket = null;

        // Scan for SYN -> SYN-ACK -> ACK sequence
        for (int i = 0; i < Math.Min(packets.Count, 10); i++) // Check first 10 packets
        {
            var p = packets[i];
            if (p.Protocol != Protocol.TCP) continue;

            var flags = p.TcpFlags;

            // Look for SYN (without ACK)
            if ((flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0 && !synPacket.HasValue)
            {
                synPacket = p.FrameNumber;
            }
            // Look for SYN-ACK
            else if ((flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) != 0 && synPacket.HasValue && !synAckPacket.HasValue)
            {
                synAckPacket = p.FrameNumber;
            }
            // Look for ACK (completing handshake)
            else if ((flags & TCP_FLAG_ACK) != 0 && (flags & TCP_FLAG_SYN) == 0 && synAckPacket.HasValue && !ackPacket.HasValue)
            {
                ackPacket = p.FrameNumber;
                break; // Handshake complete
            }
        }

        if (synPacket.HasValue && synAckPacket.HasValue && ackPacket.HasValue)
        {
            var synTime = packets.First(p => p.FrameNumber == synPacket.Value).Timestamp;
            var ackTime = packets.First(p => p.FrameNumber == ackPacket.Value).Timestamp;

            return new HandshakeInfo
            {
                IsComplete = true,
                SynPacketNumber = synPacket.Value,
                SynAckPacketNumber = synAckPacket.Value,
                AckPacketNumber = ackPacket.Value,
                HandshakeDuration = ackTime - synTime
            };
        }

        return new HandshakeInfo
        {
            IsComplete = false,
            SynPacketNumber = synPacket,
            SynAckPacketNumber = synAckPacket,
            AckPacketNumber = ackPacket,
            HandshakeDuration = null
        };
    }

    private static int DetectRetransmissions(IReadOnlyList<PacketInfo> packets)
    {
        var seenSequences = new HashSet<uint>();
        int retransmissions = 0;

        foreach (var packet in packets)
        {
            if (packet.Protocol != Protocol.TCP || packet.SeqNum == 0) continue;

            if (seenSequences.Contains(packet.SeqNum))
            {
                retransmissions++;
            }
            else
            {
                seenSequences.Add(packet.SeqNum);
            }
        }

        return retransmissions;
    }

    private static WindowScalingInfo AnalyzeWindowScaling(IReadOnlyList<PacketInfo> packets)
    {
        var windows = packets
            .Where(p => p.Protocol == Protocol.TCP && p.WindowSize > 0)
            .Select(p => p.WindowSize)
            .ToList();

        if (windows.Count == 0)
        {
            return new WindowScalingInfo
            {
                InitialWindow = 0,
                CurrentWindow = 0,
                MinWindow = 0,
                MaxWindow = 0
            };
        }

        return new WindowScalingInfo
        {
            InitialWindow = windows[0],
            CurrentWindow = windows[^1],
            MinWindow = windows.Min(),
            MaxWindow = windows.Max()
        };
    }

    private static TcpFlagCounts CountFlags(IReadOnlyList<PacketInfo> packets)
    {
        int syn = 0, fin = 0, rst = 0, psh = 0, ack = 0, urg = 0;

        foreach (var packet in packets)
        {
            if (packet.Protocol != Protocol.TCP) continue;

            var flags = packet.TcpFlags;
            if ((flags & TCP_FLAG_SYN) != 0) syn++;
            if ((flags & TCP_FLAG_FIN) != 0) fin++;
            if ((flags & TCP_FLAG_RST) != 0) rst++;
            if ((flags & TCP_FLAG_PSH) != 0) psh++;
            if ((flags & TCP_FLAG_ACK) != 0) ack++;
            if ((flags & TCP_FLAG_URG) != 0) urg++;
        }

        return new TcpFlagCounts
        {
            SYN = syn,
            FIN = fin,
            RST = rst,
            PSH = psh,
            ACK = ack,
            URG = urg
        };
    }

    private static string DetermineConnectionState(
        IReadOnlyList<PacketInfo> packets,
        HandshakeInfo? handshake,
        TcpFlagCounts flags)
    {
        if (flags.RST > 0)
            return "RESET";

        if (flags.FIN > 0)
            return flags.FIN >= 2 ? "CLOSED" : "CLOSING";

        if (handshake?.IsComplete == true)
            return "ESTABLISHED";

        if (flags.SYN > 0)
            return "SYN_SENT";

        return "UNKNOWN";
    }

    private static PeakThroughput? CalculatePeakThroughput(IReadOnlyList<PacketInfo> packets)
    {
        if (packets.Count < 2) return null;

        // Calculate throughput in 1-second sliding windows
        var windowSize = TimeSpan.FromSeconds(1);
        double maxThroughput = 0;
        DateTime peakTime = packets[0].Timestamp;

        for (int i = 0; i < packets.Count; i++)
        {
            var windowStart = packets[i].Timestamp;
            var windowEnd = windowStart + windowSize;

            long bytesInWindow = 0;
            for (int j = i; j < packets.Count && packets[j].Timestamp < windowEnd; j++)
            {
                bytesInWindow += packets[j].Length;
            }

            if (bytesInWindow > maxThroughput)
            {
                maxThroughput = bytesInWindow;
                peakTime = windowStart;
            }
        }

        return new PeakThroughput
        {
            BytesPerSecond = maxThroughput,
            Timestamp = peakTime
        };
    }

    private static List<RttSample> CalculateRttSamples(IReadOnlyList<PacketInfo> packets)
    {
        var samples = new List<RttSample>();

        if (packets.Count == 0 || packets[0].Protocol != Protocol.TCP)
            return samples;

        // Simple RTT estimation: time between data packet and corresponding ACK
        // Match packets by sequence/ack numbers
        var dataPackets = packets
            .Where(p => p.Protocol == Protocol.TCP && p.SeqNum > 0 && p.Length > 60)
            .ToList();

        foreach (var dataPacket in dataPackets)
        {
            // Find next ACK packet acknowledging this sequence
            var ackPacket = packets
                .Where(p => p.Protocol == Protocol.TCP &&
                           p.FrameNumber > dataPacket.FrameNumber &&
                           p.AckNum > 0 &&
                           (p.TcpFlags & TCP_FLAG_ACK) != 0 &&
                           p.AckNum >= dataPacket.SeqNum)
                .FirstOrDefault();

            if (ackPacket.FrameNumber > 0)
            {
                var rtt = (ackPacket.Timestamp - dataPacket.Timestamp).TotalMilliseconds;
                if (rtt > 0 && rtt < 10000) // Sanity check: RTT < 10 seconds
                {
                    samples.Add(new RttSample
                    {
                        RequestPacket = dataPacket.FrameNumber,
                        ResponsePacket = ackPacket.FrameNumber,
                        RttMs = rtt
                    });
                }
            }
        }

        return samples;
    }

    private static List<double> CalculateInterPacketDelays(IReadOnlyList<PacketInfo> packets)
    {
        var delays = new List<double>();

        for (int i = 1; i < packets.Count; i++)
        {
            var delay = (packets[i].Timestamp - packets[i - 1].Timestamp).TotalMilliseconds;
            delays.Add(delay);
        }

        return delays;
    }

    private static bool DetectHttpPattern(IReadOnlyList<PacketInfo> packets, Dictionary<string, string> details)
    {
        foreach (var packet in packets.Take(10))
        {
            if (packet.Payload.IsEmpty) continue;

            var payload = Encoding.ASCII.GetString(packet.Payload.Span);

            if (payload.StartsWith("GET ", StringComparison.Ordinal) ||
                payload.StartsWith("POST ", StringComparison.Ordinal) ||
                payload.StartsWith("HTTP/1.", StringComparison.Ordinal))
            {
                // Extract User-Agent or Content-Type if available
                var lines = payload.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                foreach (var line in lines)
                {
                    if (line.StartsWith("User-Agent:", StringComparison.OrdinalIgnoreCase))
                        details["User-Agent"] = line.Substring(11).Trim();
                    else if (line.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase))
                        details["Content-Type"] = line.Substring(13).Trim();
                }

                return true;
            }
        }

        return false;
    }

    private static bool DetectTlsPattern(IReadOnlyList<PacketInfo> packets, Dictionary<string, string> details)
    {
        foreach (var packet in packets.Take(10))
        {
            if (packet.Payload.Length < 2) continue;

            var span = packet.Payload.Span;
            // TLS handshake starts with 0x16 (handshake) followed by version (0x03 0x01 for TLS 1.0, 0x03 0x03 for TLS 1.2, etc.)
            if (span[0] == 0x16 && span[1] == 0x03)
            {
                details["TLS Version"] = span.Length > 2 ? $"TLS 1.{span[2] - 1}" : "TLS";
                return true;
            }
        }

        return false;
    }

    private static bool IsEncryptedProtocol(string protocolName)
    {
        return protocolName.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
               protocolName.Contains("SSL", StringComparison.OrdinalIgnoreCase) ||
               protocolName.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) ||
               protocolName.Contains("SSH", StringComparison.OrdinalIgnoreCase);
    }

    private static ApplicationProtocolInfo CreateProtocolInfo(
        string name,
        string description,
        bool encrypted,
        Dictionary<string, string> details)
    {
        return new ApplicationProtocolInfo
        {
            Name = name,
            Description = description,
            IsEncrypted = encrypted,
            Details = details
        };
    }

    private static ApplicationProtocolInfo CreateUnknownProtocol()
    {
        return new ApplicationProtocolInfo
        {
            Name = "Unknown",
            Description = "Unable to detect application protocol",
            IsEncrypted = false,
            Details = new Dictionary<string, string>()
        };
    }

    #endregion
}
