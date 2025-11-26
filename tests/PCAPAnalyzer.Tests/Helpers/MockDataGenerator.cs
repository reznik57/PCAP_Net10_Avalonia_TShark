using Bogus;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Generates realistic test data for PCAP analysis.
/// Updated to work with readonly record struct PacketInfo.
/// </summary>
public class MockDataGenerator
{
    private readonly Faker _faker;
    private uint _frameCounter = 1;

    public MockDataGenerator()
    {
        _faker = new Faker();
    }

    /// <summary>
    /// Generates a collection of realistic packet data.
    /// </summary>
    public List<PacketInfo> GeneratePackets(int count, Action<PacketInfoBuilder>? configure = null)
    {
        var packets = new List<PacketInfo>();

        for (int i = 0; i < count; i++)
        {
            var builder = new PacketInfoBuilder
            {
                Timestamp = _faker.Date.Recent(),
                FrameNumber = _frameCounter++,
                SourceIP = _faker.Internet.Ip(),
                DestinationIP = _faker.Internet.Ip(),
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = (ushort)_faker.Random.Int(1, 65535),
                Protocol = _faker.PickRandom(Protocol.TCP, Protocol.UDP, Protocol.ICMP),
                Length = (ushort)_faker.Random.Int(40, 1500),
                Info = _faker.Lorem.Sentence()
            };

            configure?.Invoke(builder);
            packets.Add(builder.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates packets exhibiting SYN flood attack pattern.
    /// Threshold: 100 SYN packets/second to same target with less than 50% SYN-ACK ratio.
    /// </summary>
    public List<PacketInfo> GenerateSynFloodPackets(int count, string targetIp = "192.168.1.100")
    {
        var packets = new List<PacketInfo>();
        var baseTimestamp = DateTime.UtcNow.AddSeconds(-5); // Start 5 seconds ago
        var timeWindow = 3.0; // Concentrate packets in 3 second window

        for (int i = 0; i < count; i++)
        {
            // Spread packets across the time window to achieve high packets/second rate
            var timestamp = baseTimestamp.AddMilliseconds(i * (timeWindow * 1000 / count));

            var builder = new PacketInfoBuilder
            {
                Timestamp = timestamp,
                FrameNumber = _frameCounter++,
                Protocol = Protocol.TCP,
                DestinationIP = targetIp,
                DestinationPort = 80,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                SourceIP = _faker.Internet.Ip(), // Different source IPs (spoofed)
                Info = "TCP SYN", // Only SYN packets, no SYN-ACK
                Length = 64
            };

            packets.Add(builder.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates packets exhibiting DNS tunneling pattern.
    /// Threshold: 10+ suspicious queries (length > 50 chars) from same source IP.
    /// </summary>
    public List<PacketInfo> GenerateDnsTunnelingPackets(int count)
    {
        var packets = new List<PacketInfo>();
        var sourceIPs = new List<string>
        {
            "10.0.0.50", // Ensure at least one source has 10+ packets
            "10.0.0.51",
            "10.0.0.52"
        };

        for (int i = 0; i < count; i++)
        {
            // Ensure first sourceIP gets enough packets to trigger threshold
            var sourceIP = i < 15 ? sourceIPs[0] : _faker.PickRandom(sourceIPs);

            // Generate long DNS query strings (60-100 chars, above 50 threshold)
            var queryLength = _faker.Random.Int(60, 100);
            var subdomain = _faker.Random.String2(queryLength, "abcdefghijklmnopqrstuvwxyz0123456789");

            var builder = new PacketInfoBuilder
            {
                Timestamp = _faker.Date.Recent(),
                FrameNumber = _frameCounter++,
                Protocol = Protocol.UDP,
                DestinationPort = 53,
                SourceIP = sourceIP,
                DestinationIP = "8.8.8.8", // DNS server
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                Info = $"Query: {subdomain}.suspicious-tunnel.com",
                Length = (ushort)(64 + queryLength)
            };

            packets.Add(builder.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates packets for crypto mining detection.
    /// Threshold: 5+ unique mining pool connections OR 1MB+ total traffic to mining ports.
    /// </summary>
    public List<PacketInfo> GenerateCryptoMiningPackets(int count)
    {
        var packets = new List<PacketInfo>();
        var miningPorts = new ushort[] { 3333, 4444, 8888, 9999, 14444 };
        var sourceIP = "10.0.0.100"; // Single compromised machine

        // Generate at least 10 unique mining pool destinations to exceed threshold of 5
        var miningPoolIPs = new List<string>
        {
            "45.76.102.45",  // Mining pool 1
            "104.223.123.98", // Mining pool 2
            "167.86.102.121", // Mining pool 3
            "185.25.48.184",  // Mining pool 4
            "198.251.89.235", // Mining pool 5
            "51.195.144.170", // Mining pool 6
            "66.42.57.149",   // Mining pool 7
            "89.40.113.128",  // Mining pool 8
            "94.130.180.87",  // Mining pool 9
            "185.71.65.238"   // Mining pool 10
        };

        for (int i = 0; i < count; i++)
        {
            // Rotate through mining pools to ensure 5+ unique destinations
            var destinationIP = miningPoolIPs[i % miningPoolIPs.Count];
            var destinationPort = miningPorts[i % miningPorts.Length];

            var builder = new PacketInfoBuilder
            {
                Timestamp = _faker.Date.Recent(),
                FrameNumber = _frameCounter++,
                Protocol = Protocol.TCP,
                SourceIP = sourceIP,
                DestinationIP = destinationIP,
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = destinationPort,
                Info = "Stratum mining protocol",
                Length = 1200 // Larger packets to contribute to traffic volume
            };

            packets.Add(builder.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates normal HTTP/HTTPS traffic.
    /// </summary>
    public List<PacketInfo> GenerateHttpTraffic(int count)
    {
        return GeneratePackets(count, builder =>
        {
            builder.Protocol = Protocol.TCP;
            builder.DestinationPort = _faker.PickRandom<ushort>(80, 443);
            builder.Info = $"GET {_faker.Internet.UrlWithPath()}";
        });
    }

    /// <summary>
    /// Generates a realistic NetworkStatistics object for testing.
    /// </summary>
    public NetworkStatistics GenerateNetworkStatistics()
    {
        var startTime = _faker.Date.Recent(7);
        var endTime = DateTime.Now;

        return new NetworkStatistics
        {
            TotalPackets = _faker.Random.Long(1000, 1000000),
            TotalBytes = _faker.Random.Long(50000, 500000000),
            StartTime = startTime,
            EndTime = endTime,
            FirstPacketTime = startTime, // Required for ShouldBeValidStatistics
            LastPacketTime = endTime,    // Required for ShouldBeValidStatistics
            ProtocolStats = new Dictionary<string, ProtocolStatistics>
            {
                ["TCP"] = new ProtocolStatistics
                {
                    Protocol = "TCP",
                    PacketCount = _faker.Random.Long(500, 50000),
                    ByteCount = _faker.Random.Long(25000, 2500000)
                },
                ["UDP"] = new ProtocolStatistics
                {
                    Protocol = "UDP",
                    PacketCount = _faker.Random.Long(100, 10000),
                    ByteCount = _faker.Random.Long(5000, 500000)
                },
                ["ICMP"] = new ProtocolStatistics
                {
                    Protocol = "ICMP",
                    PacketCount = _faker.Random.Long(10, 1000),
                    ByteCount = _faker.Random.Long(500, 50000)
                }
            }
        };
    }

    /// <summary>
    /// Generates test IP addresses for GeoIP testing.
    /// </summary>
    public List<string> GenerateTestIPs(int count)
    {
        var ips = new List<string>();

        for (int i = 0; i < count; i++)
        {
            if (i % 3 == 0)
                ips.Add($"8.8.{_faker.Random.Int(0, 255)}.{_faker.Random.Int(0, 255)}"); // Google DNS range
            else if (i % 3 == 1)
                ips.Add($"1.1.{_faker.Random.Int(0, 255)}.{_faker.Random.Int(0, 255)}"); // Cloudflare
            else
                ips.Add(_faker.Internet.Ip()); // Random
        }

        return ips;
    }
}

/// <summary>
/// Builder pattern for creating PacketInfo readonly records.
/// </summary>
public class PacketInfoBuilder
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public uint FrameNumber { get; set; } = 1;
    public ushort Length { get; set; } = 64;
    public string SourceIP { get; set; } = "192.168.1.1";
    public string DestinationIP { get; set; } = "192.168.1.2";
    public ushort SourcePort { get; set; } = 12345;
    public ushort DestinationPort { get; set; } = 80;
    public Protocol Protocol { get; set; } = Protocol.TCP;
    public string? Info { get; set; }
    public ReadOnlyMemory<byte> Payload { get; set; } = ReadOnlyMemory<byte>.Empty;
    public string? L7Protocol { get; set; }

    public PacketInfo Build()
    {
        return new PacketInfo
        {
            Timestamp = Timestamp,
            FrameNumber = FrameNumber,
            Length = Length,
            SourceIP = SourceIP,
            DestinationIP = DestinationIP,
            SourcePort = SourcePort,
            DestinationPort = DestinationPort,
            Protocol = Protocol,
            Info = Info,
            Payload = Payload,
            L7Protocol = L7Protocol
        };
    }
}
