using Bogus;
using PCAPAnalyzer.Core.Models;
using System.Text;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Enhanced test data generator with comprehensive edge case coverage.
/// Provides realistic and malformed data for thorough testing.
/// </summary>
public class TestDataGenerator
{
    private readonly Faker _faker;
    private uint _frameCounter = 1;
    private readonly Random _random = new();

    public TestDataGenerator(int? seed = null)
    {
        if (seed.HasValue)
        {
            _faker = new Faker("en") { Random = new Randomizer(seed.Value) };
            _random = new Random(seed.Value);
        }
        else
        {
            _faker = new Faker("en");
        }
    }

    #region Packet Generation

    /// <summary>
    /// Generates realistic packet data with configurable options.
    /// </summary>
    public List<PacketInfo> GeneratePackets(int count, PacketGenerationOptions? options = null)
    {
        options ??= new PacketGenerationOptions();
        var packets = new List<PacketInfo>();
        var baseTime = options.StartTime ?? DateTime.UtcNow.AddHours(-1);

        for (int i = 0; i < count; i++)
        {
            var builder = new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * options.TimeIncrementMs),
                FrameNumber = _frameCounter++,
                SourceIP = options.FixedSourceIP ?? GenerateIP(options.IPVersion),
                DestinationIP = options.FixedDestinationIP ?? GenerateIP(options.IPVersion),
                SourcePort = options.FixedSourcePort ?? (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = options.FixedDestinationPort ?? (ushort)_faker.Random.Int(1, 65535),
                Protocol = options.Protocol ?? _faker.PickRandom<Protocol>(),
                Length = options.PacketSize ?? (ushort)_faker.Random.Int(40, 1500),
                Info = options.InfoTemplate ?? _faker.Lorem.Sentence()
            };

            options.CustomizePacket?.Invoke(builder);
            packets.Add(builder.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates large file simulation data (for performance testing).
    /// </summary>
    public IEnumerable<PacketInfo> GenerateLargeFileStream(long targetSizeGB, int batchSize = 10000)
    {
        long targetBytes = targetSizeGB * 1024L * 1024L * 1024L;
        long generatedBytes = 0;
        var baseTime = DateTime.UtcNow.AddDays(-1);

        while (generatedBytes < targetBytes)
        {
            var packets = GeneratePackets(batchSize, new PacketGenerationOptions
            {
                StartTime = baseTime.AddMilliseconds(generatedBytes / 1000)
            });

            foreach (var packet in packets)
            {
                yield return packet;
                generatedBytes += packet.Length;
            }
        }
    }

    /// <summary>
    /// Generates malformed/corrupted packets for error handling tests.
    /// </summary>
    public List<PacketInfo> GenerateMalformedPackets(int count)
    {
        var packets = new List<PacketInfo>();

        for (int i = 0; i < count; i++)
        {
            var malformationType = _random.Next(0, 7);
            var builder = new PacketInfoBuilder();

            switch (malformationType)
            {
                case 0: // Invalid IP addresses
                    builder.SourceIP = GenerateInvalidIP();
                    builder.DestinationIP = GenerateInvalidIP();
                    break;

                case 1: // Zero-length packets
                    builder.Length = 0;
                    break;

                case 2: // Oversized packets
                    builder.Length = ushort.MaxValue;
                    break;

                case 3: // Invalid port numbers
                    builder.SourcePort = 0;
                    builder.DestinationPort = 0;
                    break;

                case 4: // Invalid timestamps
                    builder.Timestamp = DateTime.MinValue;
                    break;

                case 5: // Special characters in info
                    builder.Info = GenerateSpecialCharacterString();
                    break;

                case 6: // Null/empty fields
                    builder.SourceIP = string.Empty;
                    builder.DestinationIP = string.Empty;
                    builder.Info = null;
                    break;
            }

            packets.Add(builder.Build());
        }

        return packets;
    }

    #endregion

    #region Attack Pattern Generation

    /// <summary>
    /// Generates DDoS attack pattern (SYN flood).
    /// </summary>
    public List<PacketInfo> GenerateDDoSPattern(int packetsPerSecond, int durationSeconds, string targetIP = "192.168.1.100")
    {
        var packets = new List<PacketInfo>();
        var totalPackets = packetsPerSecond * durationSeconds;
        var baseTime = DateTime.UtcNow.AddSeconds(-durationSeconds);
        var intervalMs = 1000.0 / packetsPerSecond;

        for (int i = 0; i < totalPackets; i++)
        {
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * intervalMs),
                FrameNumber = _frameCounter++,
                Protocol = Protocol.TCP,
                DestinationIP = targetIP,
                DestinationPort = 80,
                SourceIP = GenerateSpoofedIP(),
                SourcePort = (ushort)_random.Next(1024, 65535),
                Info = "SYN",
                Length = 64
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates port scanning pattern.
    /// </summary>
    public List<PacketInfo> GeneratePortScanPattern(int portCount, string sourceIP = "10.0.0.50", string targetIP = "192.168.1.100")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddSeconds(-10);

        for (ushort port = 1; port <= portCount; port++)
        {
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(port * 10),
                FrameNumber = _frameCounter++,
                Protocol = Protocol.TCP,
                SourceIP = sourceIP,
                DestinationIP = targetIP,
                SourcePort = (ushort)_random.Next(1024, 65535),
                DestinationPort = port,
                Info = "SYN",
                Length = 64
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates data exfiltration pattern (large outbound transfers).
    /// </summary>
    public List<PacketInfo> GenerateDataExfiltrationPattern(int megabytes, string sourceIP = "10.0.0.100")
    {
        var packets = new List<PacketInfo>();
        var targetBytes = megabytes * 1024 * 1024;
        var baseTime = DateTime.UtcNow.AddMinutes(-5);
        var externalIP = "203.0.113.50"; // TEST-NET-3

        while (targetBytes > 0)
        {
            var packetSize = Math.Min(1500, targetBytes);
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(packets.Count * 5),
                FrameNumber = _frameCounter++,
                Protocol = Protocol.TCP,
                SourceIP = sourceIP,
                DestinationIP = externalIP,
                SourcePort = (ushort)_random.Next(1024, 65535),
                DestinationPort = 443,
                Info = "TLS Application Data",
                Length = (ushort)packetSize
            }.Build());

            targetBytes -= packetSize;
        }

        return packets;
    }

    /// <summary>
    /// Generates DNS tunneling pattern.
    /// </summary>
    public List<PacketInfo> GenerateDNSTunnelingPattern(int queryCount, string sourceIP = "10.0.0.50")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-2);

        for (int i = 0; i < queryCount; i++)
        {
            var encodedData = GenerateBase32String(60);
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * 100),
                FrameNumber = _frameCounter++,
                Protocol = Protocol.UDP,
                SourceIP = sourceIP,
                DestinationIP = "8.8.8.8",
                SourcePort = (ushort)_random.Next(1024, 65535),
                DestinationPort = 53,
                Info = $"Query: {encodedData}.evil-c2.com",
                Length = (ushort)(64 + encodedData.Length)
            }.Build());
        }

        return packets;
    }

    /// <summary>
    /// Generates crypto mining traffic pattern.
    /// </summary>
    public List<PacketInfo> GenerateCryptoMiningPattern(int connectionCount, string sourceIP = "10.0.0.100")
    {
        var packets = new List<PacketInfo>();
        var miningPools = GenerateMiningPoolIPs(connectionCount);
        var miningPorts = new ushort[] { 3333, 4444, 8888, 9999, 14444 };
        var baseTime = DateTime.UtcNow.AddMinutes(-10);

        for (int i = 0; i < connectionCount * 20; i++) // 20 packets per connection
        {
            var poolIndex = i % miningPools.Count;
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = baseTime.AddMilliseconds(i * 500),
                FrameNumber = _frameCounter++,
                Protocol = Protocol.TCP,
                SourceIP = sourceIP,
                DestinationIP = miningPools[poolIndex],
                SourcePort = (ushort)_random.Next(1024, 65535),
                DestinationPort = miningPorts[poolIndex % miningPorts.Length],
                Info = "Stratum mining protocol",
                Length = 1200
            }.Build());
        }

        return packets;
    }

    #endregion

    #region Protocol-Specific Generation

    /// <summary>
    /// Generates HTTP/HTTPS traffic.
    /// </summary>
    public List<PacketInfo> GenerateHTTPTraffic(int count, bool useHTTPS = false)
    {
        return GeneratePackets(count, new PacketGenerationOptions
        {
            Protocol = Protocol.TCP,
            FixedDestinationPort = useHTTPS ? (ushort)443 : (ushort)80,
            InfoTemplate = useHTTPS ? "TLS Application Data" : null
        });
    }

    /// <summary>
    /// Generates VoIP traffic (SIP/RTP).
    /// </summary>
    public List<PacketInfo> GenerateVoIPTraffic(int callCount, int secondsPerCall)
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-5);

        for (int call = 0; call < callCount; call++)
        {
            var sourceIP = GeneratePrivateIP();
            var destIP = GeneratePrivateIP();
            var callStartTime = baseTime.AddSeconds(call * (secondsPerCall + 5));

            // SIP signaling
            packets.Add(new PacketInfoBuilder
            {
                Timestamp = callStartTime,
                FrameNumber = _frameCounter++,
                Protocol = Protocol.UDP,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                SourcePort = 5060,
                DestinationPort = 5060,
                Info = "INVITE sip:user@domain.com",
                Length = 512
            }.Build());

            // RTP audio packets (50 packets per second for call duration)
            var rtpPackets = secondsPerCall * 50;
            for (int i = 0; i < rtpPackets; i++)
            {
                packets.Add(new PacketInfoBuilder
                {
                    Timestamp = callStartTime.AddMilliseconds(i * 20),
                    FrameNumber = _frameCounter++,
                    Protocol = Protocol.UDP,
                    SourceIP = sourceIP,
                    DestinationIP = destIP,
                    SourcePort = (ushort)_random.Next(10000, 20000),
                    DestinationPort = (ushort)_random.Next(10000, 20000),
                    Info = "RTP audio",
                    Length = 172
                }.Build());
            }
        }

        return packets;
    }

    /// <summary>
    /// Generates IoT device traffic patterns.
    /// </summary>
    public List<PacketInfo> GenerateIoTTraffic(int deviceCount, int hoursOfActivity)
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddHours(-hoursOfActivity);
        var cloudServers = new[] { "35.164.230.1", "52.89.214.238", "54.187.205.235" };

        for (int device = 0; device < deviceCount; device++)
        {
            var deviceIP = $"192.168.1.{100 + device}";
            var beaconIntervalSeconds = _random.Next(30, 300);
            var beaconCount = (hoursOfActivity * 3600) / beaconIntervalSeconds;

            for (int beacon = 0; beacon < beaconCount; beacon++)
            {
                packets.Add(new PacketInfoBuilder
                {
                    Timestamp = baseTime.AddSeconds(beacon * beaconIntervalSeconds),
                    FrameNumber = _frameCounter++,
                    Protocol = Protocol.TCP,
                    SourceIP = deviceIP,
                    DestinationIP = cloudServers[device % cloudServers.Length],
                    SourcePort = (ushort)_random.Next(1024, 65535),
                    DestinationPort = 443,
                    Info = "TLS Application Data",
                    Length = (ushort)_random.Next(200, 500)
                }.Build());
            }
        }

        return packets;
    }

    #endregion

    #region Network Statistics Generation

    /// <summary>
    /// Generates comprehensive network statistics with realistic values.
    /// </summary>
    public NetworkStatistics GenerateNetworkStatistics(StatisticsGenerationOptions? options = null)
    {
        options ??= new StatisticsGenerationOptions();
        var startTime = options.StartTime ?? DateTime.UtcNow.AddHours(-1);
        var endTime = options.EndTime ?? DateTime.UtcNow;
        var totalPackets = options.TotalPackets ?? _faker.Random.Long(1000, 1000000);

        var serviceStats = GenerateServiceStatistics(10);
        return new NetworkStatistics
        {
            TotalPackets = totalPackets,
            TotalBytes = options.TotalBytes ?? totalPackets * _faker.Random.Long(64, 1500),
            StartTime = startTime,
            EndTime = endTime,
            FirstPacketTime = startTime,
            LastPacketTime = endTime,
            ProtocolStats = GenerateProtocolStats(totalPackets),
            TopSources = GenerateEndpointStatistics(10),
            TopDestinations = GenerateEndpointStatistics(10),
            TopConversations = GenerateConversationStatistics(10),
            TopPorts = GeneratePortStatistics(10),
            ServiceStats = serviceStats.ToDictionary(s => s.ServiceName, s => s)
        };
    }

    private Dictionary<string, ProtocolStatistics> GenerateProtocolStats(long totalPackets)
    {
        var tcpPercent = _faker.Random.Double(0.5, 0.7);
        var udpPercent = _faker.Random.Double(0.2, 0.3);
        var icmpPercent = 1.0 - tcpPercent - udpPercent;

        return new Dictionary<string, ProtocolStatistics>
        {
            ["TCP"] = new ProtocolStatistics
            {
                Protocol = "TCP",
                PacketCount = (long)(totalPackets * tcpPercent),
                ByteCount = (long)(totalPackets * tcpPercent * 800)
            },
            ["UDP"] = new ProtocolStatistics
            {
                Protocol = "UDP",
                PacketCount = (long)(totalPackets * udpPercent),
                ByteCount = (long)(totalPackets * udpPercent * 400)
            },
            ["ICMP"] = new ProtocolStatistics
            {
                Protocol = "ICMP",
                PacketCount = (long)(totalPackets * icmpPercent),
                ByteCount = (long)(totalPackets * icmpPercent * 84)
            }
        };
    }

    private List<EndpointStatistics> GenerateEndpointStatistics(int count)
    {
        var endpoints = new List<EndpointStatistics>();
        for (int i = 0; i < count; i++)
        {
            endpoints.Add(new EndpointStatistics
            {
                Address = GenerateIP(IPVersion.IPv4),
                PacketCount = _faker.Random.Long(100, 10000),
                ByteCount = _faker.Random.Long(50000, 5000000),
                Percentage = _faker.Random.Double(1.0, 15.0)
            });
        }
        return endpoints.OrderByDescending(e => e.PacketCount).ToList();
    }

    private List<ConversationStatistics> GenerateConversationStatistics(int count)
    {
        var conversations = new List<ConversationStatistics>();
        for (int i = 0; i < count; i++)
        {
            conversations.Add(new ConversationStatistics
            {
                SourceAddress = GenerateIP(IPVersion.IPv4),
                DestinationAddress = GenerateIP(IPVersion.IPv4),
                PacketCount = _faker.Random.Long(50, 5000),
                ByteCount = _faker.Random.Long(25000, 2500000),
                Protocol = "TCP",
                SourcePort = _faker.Random.Int(1024, 65535),
                DestinationPort = _faker.Random.Int(1, 1024),
                StartTime = DateTime.UtcNow.AddMinutes(-30),
                EndTime = DateTime.UtcNow
            });
        }
        return conversations.OrderByDescending(c => c.ByteCount).ToList();
    }

    private List<PortStatistics> GeneratePortStatistics(int count)
    {
        var commonPorts = new int[] { 80, 443, 22, 21, 25, 53, 3389, 3306, 5432, 8080 };
        return commonPorts.Take(count).Select(port => new PortStatistics
        {
            Port = port,
            PacketCount = _faker.Random.Long(100, 10000),
            ByteCount = _faker.Random.Long(50000, 5000000),
            Percentage = _faker.Random.Double(1.0, 20.0),
            Service = GetServiceName(port),
            Protocol = "TCP"
        }).OrderByDescending(p => p.PacketCount).ToList();
    }

    private string GetServiceName(int port)
    {
        return port switch
        {
            80 => "HTTP",
            443 => "HTTPS",
            22 => "SSH",
            21 => "FTP",
            25 => "SMTP",
            53 => "DNS",
            3389 => "RDP",
            3306 => "MySQL",
            5432 => "PostgreSQL",
            8080 => "HTTP-Alt",
            _ => "Unknown"
        };
    }

    private List<ServiceStatistics> GenerateServiceStatistics(int count)
    {
        var services = new[] { "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "DNS", "RDP", "MySQL", "PostgreSQL", "Telnet" };
        return services.Take(count).Select(service => new ServiceStatistics
        {
            ServiceName = service,
            PacketCount = _faker.Random.Long(100, 10000),
            ByteCount = _faker.Random.Long(50000, 5000000),
            UniqueHosts = Enumerable.Range(0, _faker.Random.Int(5, 50))
                .Select(_ => GenerateIP(IPVersion.IPv4)).ToList()
        }).OrderByDescending(s => s.PacketCount).ToList();
    }

    #endregion

    #region Helper Methods

    private string GenerateIP(IPVersion version)
    {
        return version switch
        {
            IPVersion.IPv4 => _faker.Internet.Ip(),
            IPVersion.IPv6 => _faker.Internet.Ipv6(),
            _ => _faker.Internet.Ip()
        };
    }

    private string GeneratePrivateIP()
    {
        var subnet = _random.Next(0, 3);
        return subnet switch
        {
            0 => $"10.{_random.Next(0, 256)}.{_random.Next(0, 256)}.{_random.Next(1, 255)}",
            1 => $"172.{_random.Next(16, 32)}.{_random.Next(0, 256)}.{_random.Next(1, 255)}",
            _ => $"192.168.{_random.Next(0, 256)}.{_random.Next(1, 255)}"
        };
    }

    private string GenerateSpoofedIP()
    {
        // Generate random public IPs for DDoS simulation
        return $"{_random.Next(1, 224)}.{_random.Next(0, 256)}.{_random.Next(0, 256)}.{_random.Next(1, 255)}";
    }

    private string GenerateInvalidIP()
    {
        var invalidTypes = new[]
        {
            "999.999.999.999",
            "invalid-ip",
            "::::",
            "256.256.256.256",
            "",
            "192.168.1",
            "192.168.1.1.1"
        };
        return _faker.PickRandom(invalidTypes);
    }

    private string GenerateSpecialCharacterString()
    {
        var specialChars = "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/`~\0\r\n\t";
        var sb = new StringBuilder();
        for (int i = 0; i < 50; i++)
        {
            sb.Append(specialChars[_random.Next(specialChars.Length)]);
        }
        return sb.ToString();
    }

    private string GenerateBase32String(int length)
    {
        const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++)
        {
            sb.Append(base32Chars[_random.Next(base32Chars.Length)]);
        }
        return sb.ToString();
    }

    private List<string> GenerateMiningPoolIPs(int count)
    {
        var knownPools = new List<string>
        {
            "45.76.102.45", "104.223.123.98", "167.86.102.121", "185.25.48.184",
            "198.251.89.235", "51.195.144.170", "66.42.57.149", "89.40.113.128",
            "94.130.180.87", "185.71.65.238"
        };

        while (knownPools.Count < count)
        {
            knownPools.Add(GenerateSpoofedIP());
        }

        return knownPools.Take(count).ToList();
    }

    #endregion
}

#region Configuration Classes

public class PacketGenerationOptions
{
    public DateTime? StartTime { get; set; }
    public double TimeIncrementMs { get; set; } = 10.0;
    public Protocol? Protocol { get; set; }
    public string? FixedSourceIP { get; set; }
    public string? FixedDestinationIP { get; set; }
    public ushort? FixedSourcePort { get; set; }
    public ushort? FixedDestinationPort { get; set; }
    public ushort? PacketSize { get; set; }
    public string? InfoTemplate { get; set; }
    public IPVersion IPVersion { get; set; } = IPVersion.IPv4;
    public Action<PacketInfoBuilder>? CustomizePacket { get; set; }
}

public class StatisticsGenerationOptions
{
    public DateTime? StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public long? TotalPackets { get; set; }
    public long? TotalBytes { get; set; }
}

public enum IPVersion
{
    IPv4,
    IPv6
}

#endregion
