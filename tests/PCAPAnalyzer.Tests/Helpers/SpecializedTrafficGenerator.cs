using Bogus;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Generates realistic test data for specialized threat detection testing.
/// Provides traffic patterns for IoT, VoIP, Crypto Mining, and Data Exfiltration scenarios.
/// </summary>
public class SpecializedTrafficGenerator
{
    private readonly Faker _faker;
    private readonly MockDataGenerator _baseGenerator;
    private uint _frameCounter;

    public SpecializedTrafficGenerator(uint startFrame = 1)
    {
        _faker = new Faker();
        _baseGenerator = new MockDataGenerator();
        _frameCounter = startFrame;
    }

    #region IoT Traffic Generation

    /// <summary>
    /// Generates MQTT flooding traffic pattern (100+ messages/second)
    /// </summary>
    public List<PacketInfo> GenerateMqttFloodingTraffic(int messageCount, string brokerIp = "192.168.1.10")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-5);
        var timeWindowSeconds = 2.0; // Concentrate in 2 seconds for high rate

        for (int i = 0; i < messageCount; i++)
        {
            var timestamp = baseTime.AddMilliseconds(i * (timeWindowSeconds * 1000 / messageCount));
            var messageType = _faker.PickRandom(new[] { "Publish", "Subscribe", "Connect", "Disconnect" });

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp,
                FrameNumber = _frameCounter++,
                SourceIP = _faker.Internet.Ip(),
                DestinationIP = brokerIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 1883,
                Protocol = Protocol.TCP,
                Info = $"MQTT {messageType}",
                Length = 128
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates legitimate MQTT traffic (below threshold)
    /// </summary>
    public List<PacketInfo> GenerateLegitimateMqttTraffic(int messageCount, string brokerIp = "192.168.1.10")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-5);

        for (int i = 0; i < messageCount; i++)
        {
            // Spread over 30 seconds for low rate (~3 messages/second)
            var timestamp = baseTime.AddSeconds(i * 30.0 / messageCount);

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp,
                FrameNumber = _frameCounter++,
                SourceIP = "192.168.1.100",
                DestinationIP = brokerIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 1883,
                Protocol = Protocol.TCP,
                Info = "MQTT Publish",
                Length = 128
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates IoT device connecting to multiple brokers
    /// </summary>
    public List<PacketInfo> GenerateMultipleBrokerConnections(int brokerCount, string deviceIp = "192.168.1.50")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-10);

        for (int i = 0; i < brokerCount; i++)
        {
            var brokerIp = $"10.0.{_faker.Random.Int(1, 254)}.{_faker.Random.Int(1, 254)}";

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddSeconds(i * 5),
                FrameNumber = _frameCounter++,
                SourceIP = deviceIp,
                DestinationIP = brokerIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 1883,
                Protocol = Protocol.TCP,
                Info = "MQTT Connect",
                Length = 64
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates CoAP amplification attack traffic
    /// </summary>
    public List<PacketInfo> GenerateCoapAmplificationTraffic(int requestCount, double amplificationRatio = 15.0)
    {
        var packets = new List<PacketInfo>();
        var attackerIp = "10.0.0.99";
        var baseTime = DateTime.UtcNow.AddMinutes(-2);

        for (int i = 0; i < requestCount; i++)
        {
            var targetIp = $"192.168.1.{_faker.Random.Int(1, 254)}";
            var timestamp = baseTime.AddMilliseconds(i * 100);

            // Small CoAP request
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp,
                FrameNumber = _frameCounter++,
                SourceIP = attackerIp,
                DestinationIP = targetIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 5683,
                Protocol = Protocol.UDP,
                Info = "CoAP GET",
                Length = 100
            }.Build());

            // Large CoAP response (amplified)
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp.AddMilliseconds(50),
                FrameNumber = _frameCounter++,
                SourceIP = targetIp,
                DestinationIP = attackerIp,
                SourcePort = 5683,
                DestinationPort = (ushort)_faker.Random.Int(1024, 65535),
                Protocol = Protocol.UDP,
                Info = "CoAP Response",
                Length = (ushort)(100 * amplificationRatio)
            }.Build());
        }

        return packets;
    }

    #endregion

    #region VoIP Traffic Generation

    /// <summary>
    /// Generates SIP flooding attack (100+ SIP messages/second)
    /// </summary>
    public List<PacketInfo> GenerateSipFloodingTraffic(int messageCount, string targetIp = "192.168.1.20")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-3);
        var timeWindowSeconds = 1.5;

        for (int i = 0; i < messageCount; i++)
        {
            var timestamp = baseTime.AddMilliseconds(i * (timeWindowSeconds * 1000 / messageCount));
            var sipMethod = _faker.PickRandom(new[] { "INVITE", "REGISTER", "OPTIONS", "BYE" });

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp,
                FrameNumber = _frameCounter++,
                SourceIP = _faker.Internet.Ip(),
                DestinationIP = targetIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 5060,
                Protocol = Protocol.UDP,
                Info = $"SIP {sipMethod}",
                L7Protocol = "SIP",
                Length = 512
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates ghost call pattern (unanswered INVITEs)
    /// </summary>
    public List<PacketInfo> GenerateGhostCallTraffic(int inviteCount, string scannerIp = "10.0.0.50")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-5);

        for (int i = 0; i < inviteCount; i++)
        {
            var targetIp = $"192.168.1.{_faker.Random.Int(1, 254)}";

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddSeconds(i * 2),
                FrameNumber = _frameCounter++,
                SourceIP = scannerIp,
                DestinationIP = targetIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 5060,
                Protocol = Protocol.UDP,
                Info = "SIP INVITE",
                L7Protocol = "SIP",
                Length = 512
            }.Build());
            // No 200 OK response - characteristic of ghost calls
        }

        return packets;
    }

    /// <summary>
    /// Generates RTP stream with quality issues (high jitter and packet loss)
    /// </summary>
    public List<PacketInfo> GenerateRtpQualityIssues(int packetCount, double packetLossRate = 0.1)
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-3);
        var sourceIp = "192.168.1.100";
        var destIp = "192.168.1.101";
        var rtpPort = (ushort)_faker.Random.Int(10000, 20000);

        // Normal interval is 20ms for RTP packets
        const double normalInterval = 20.0;

        for (int i = 0; i < packetCount; i++)
        {
            // Introduce packet loss
            if (_faker.Random.Double() < packetLossRate)
            {
                // Skip this packet to simulate loss
                continue;
            }

            // Add jitter (variance in arrival times)
            var jitter = _faker.Random.Double(-15, 35); // -15ms to +35ms jitter
            var timestamp = baseTime.AddMilliseconds(i * normalInterval + jitter);

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp,
                FrameNumber = _frameCounter++,
                SourceIP = sourceIp,
                DestinationIP = destIp,
                SourcePort = rtpPort,
                DestinationPort = rtpPort,
                Protocol = Protocol.UDP,
                Info = "RTP",
                L7Protocol = "RTP",
                Length = 172
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates toll fraud pattern (many calls to different destinations)
    /// </summary>
    public List<PacketInfo> GenerateTollFraudTraffic(int callCount, string fraudSourceIp = "192.168.1.150")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddHours(-2);

        for (int i = 0; i < callCount; i++)
        {
            var destIp = _faker.Internet.Ip(); // Random international destination

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMinutes(i * 3),
                FrameNumber = _frameCounter++,
                SourceIP = fraudSourceIp,
                DestinationIP = destIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 5060,
                Protocol = Protocol.UDP,
                Info = $"SIP INVITE sip:+1{_faker.Phone.PhoneNumber()}@{destIp}",
                L7Protocol = "SIP",
                Length = 600
            }.Build());
        }

        return packets;
    }

    #endregion

    #region Crypto Mining Traffic Generation

    /// <summary>
    /// Generates Stratum protocol mining traffic
    /// </summary>
    public List<PacketInfo> GenerateStratumMiningTraffic(int connectionCount, string minerIp = "10.0.0.80")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-30);
        var miningPorts = new[] { 3333, 4444, 8333, 9999 };
        var miningPools = new[]
        {
            "45.76.102.45", "104.223.123.98", "167.86.102.121",
            "185.25.48.184", "198.251.89.235", "51.195.144.170"
        };

        for (int i = 0; i < connectionCount; i++)
        {
            var poolIp = _faker.PickRandom(miningPools);
            var port = _faker.PickRandom(miningPorts);
            var timestamp = baseTime.AddSeconds(i * 60);

            // mining.subscribe
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp,
                FrameNumber = _frameCounter++,
                SourceIP = minerIp,
                DestinationIP = poolIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = (ushort)port,
                Protocol = Protocol.TCP,
                Info = "{\"method\":\"mining.subscribe\"}",
                Length = 256
            }.Build());

            // mining.authorize
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp.AddSeconds(1),
                FrameNumber = _frameCounter++,
                SourceIP = minerIp,
                DestinationIP = poolIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = (ushort)port,
                Protocol = Protocol.TCP,
                Info = "{\"method\":\"mining.authorize\"}",
                Length = 256
            }.Build());

            // mining.submit
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = timestamp.AddSeconds(10),
                FrameNumber = _frameCounter++,
                SourceIP = minerIp,
                DestinationIP = poolIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = (ushort)port,
                Protocol = Protocol.TCP,
                Info = "{\"method\":\"mining.submit\"}",
                Length = 512
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates mining pool connection traffic (multiple pools)
    /// </summary>
    public List<PacketInfo> GenerateMiningPoolConnections(int poolCount, string minerIp = "10.0.0.80")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-15);
        var miningPorts = new[] { 3333, 4444, 8333 };

        for (int i = 0; i < poolCount; i++)
        {
            var poolIp = $"185.{_faker.Random.Int(1, 254)}.{_faker.Random.Int(1, 254)}.{_faker.Random.Int(1, 254)}";
            var port = _faker.PickRandom(miningPorts);

            // Generate traffic to each pool
            for (int j = 0; j < 50; j++)
            {
                packets.Add(new PacketInfoBuilder
                {
                    Timestamp = baseTime.AddSeconds(i * 60 + j * 10),
                    FrameNumber = _frameCounter++,
                    SourceIP = minerIp,
                    DestinationIP = poolIp,
                    SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                    DestinationPort = (ushort)port,
                    Protocol = Protocol.TCP,
                    Info = "Stratum mining protocol",
                    Length = 1200
                }.Build());
            }
        }

        return packets;
    }

    /// <summary>
    /// Generates legitimate cryptocurrency transaction traffic (should NOT trigger detection)
    /// </summary>
    public List<PacketInfo> GenerateLegitimateBlockchainTraffic(int transactionCount)
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-10);

        for (int i = 0; i < transactionCount; i++)
        {
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddSeconds(i * 30),
                FrameNumber = _frameCounter++,
                SourceIP = _faker.Internet.Ip(),
                DestinationIP = _faker.Internet.Ip(),
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 443, // HTTPS to exchanges
                Protocol = Protocol.TCP,
                Info = "TLSv1.3",
                L7Protocol = "TLSv1.3",
                Length = 800
            }.Build());
        }

        return packets;
    }

    #endregion

    #region Data Exfiltration Traffic Generation

    /// <summary>
    /// Generates large data upload pattern (10MB+)
    /// </summary>
    public List<PacketInfo> GenerateLargeUploadTraffic(long totalBytes, string sourceIp = "192.168.1.75")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-5);
        var destIp = _faker.Internet.Ip();
        var packetSize = 1400;
        var packetCount = (int)(totalBytes / packetSize);

        for (int i = 0; i < packetCount; i++)
        {
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * 10),
                FrameNumber = _frameCounter++,
                SourceIP = sourceIp,
                DestinationIP = destIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 8443, // Non-standard port
                Protocol = Protocol.TCP,
                Info = "Data Upload",
                Length = (ushort)packetSize
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates slow exfiltration pattern (low rate over extended time)
    /// </summary>
    public List<PacketInfo> GenerateSlowExfiltrationTraffic(long totalBytes, double durationHours, string sourceIp = "192.168.1.75")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddHours(-durationHours);
        var destIp = _faker.Internet.Ip();
        var packetSize = 1400;
        var packetCount = (int)(totalBytes / packetSize);
        var intervalMs = (durationHours * 3600 * 1000) / packetCount;

        for (int i = 0; i < packetCount; i++)
        {
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * intervalMs),
                FrameNumber = _frameCounter++,
                SourceIP = sourceIp,
                DestinationIP = destIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 443,
                Protocol = Protocol.TCP,
                Info = "TLSv1.2",
                L7Protocol = "TLSv1.2",
                Length = (ushort)packetSize
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates DNS tunneling pattern
    /// </summary>
    public List<PacketInfo> GenerateDnsTunnelingTraffic(int queryCount, string sourceIp = "192.168.1.75")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-3);

        for (int i = 0; i < queryCount; i++)
        {
            // Generate long DNS query (>50 chars)
            var subdomain = _faker.Random.String2(80, "abcdefghijklmnopqrstuvwxyz0123456789");

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddSeconds(i * 2),
                FrameNumber = _frameCounter++,
                SourceIP = sourceIp,
                DestinationIP = "8.8.8.8",
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 53,
                Protocol = Protocol.UDP,
                Info = $"Query: {subdomain}.tunnel-domain.com",
                Length = (ushort)(64 + subdomain.Length)
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates encoded data transfer pattern (base64)
    /// </summary>
    public List<PacketInfo> GenerateEncodedDataTransfer(int packetCount, string sourceIp = "192.168.1.75")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-5);

        for (int i = 0; i < packetCount; i++)
        {
            // Generate base64-like data
            var encodedData = _faker.Random.String2(100, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddSeconds(i * 5),
                FrameNumber = _frameCounter++,
                SourceIP = sourceIp,
                DestinationIP = _faker.Internet.Ip(),
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 443,
                Protocol = Protocol.TCP,
                Info = $"Data: {encodedData}",
                Length = 1200
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates unusual outbound traffic (high upload/download ratio)
    /// </summary>
    public List<PacketInfo> GenerateUnusualOutboundTraffic(int outboundPackets, int inboundPackets, string sourceIp = "192.168.1.75")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-10);
        var destIp = _faker.Internet.Ip();

        // Generate outbound traffic (large packets)
        for (int i = 0; i < outboundPackets; i++)
        {
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * 50),
                FrameNumber = _frameCounter++,
                SourceIP = sourceIp,
                DestinationIP = destIp,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = 443,
                Protocol = Protocol.TCP,
                Info = "Upload",
                Length = 1400
            }.Build());
        }

        // Generate inbound traffic (small packets)
        for (int i = 0; i < inboundPackets; i++)
        {
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * 200),
                FrameNumber = _frameCounter++,
                SourceIP = destIp,
                DestinationIP = sourceIp,
                SourcePort = 443,
                DestinationPort = (ushort)_faker.Random.Int(1024, 65535),
                Protocol = Protocol.TCP,
                Info = "ACK",
                Length = 64
            }.Build());
        }

        return packets;
    }

    #endregion

    #region Mixed Traffic Generation

    /// <summary>
    /// Generates realistic mixed normal traffic (baseline)
    /// </summary>
    public List<PacketInfo> GenerateNormalTraffic(int packetCount)
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-10);

        for (int i = 0; i < packetCount; i++)
        {
            var protocol = _faker.PickRandom(new[] { Protocol.TCP, Protocol.UDP });
            var port = _faker.PickRandom(new ushort[] { 80, 443, 53, 22, 25 });

            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * 100),
                FrameNumber = _frameCounter++,
                SourceIP = _faker.Internet.Ip(),
                DestinationIP = _faker.Internet.Ip(),
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = port,
                Protocol = protocol,
                Info = port == 80 ? "HTTP" : port == 443 ? "TLSv1.2" : port == 53 ? "DNS Query" : "Data",
                Length = (ushort)_faker.Random.Int(64, 1400)
            }.Build());
        }

        return packets;
    }

    #endregion
}
