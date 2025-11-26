using Bogus;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Fluent builder for creating test data using Bogus
/// </summary>
public class TestDataBuilder
{
    private readonly Faker _faker;

    public TestDataBuilder()
    {
        _faker = new Faker();
    }

    /// <summary>
    /// Build a collection of packets with customizable properties
    /// </summary>
    public PacketBuilder Packets => new PacketBuilder(_faker);

    /// <summary>
    /// Build network statistics with realistic values
    /// </summary>
    public NetworkStatisticsBuilder Statistics => new NetworkStatisticsBuilder(_faker);

    /// <summary>
    /// Build anomalies with various severity levels
    /// </summary>
    public AnomalyBuilder Anomalies => new AnomalyBuilder(_faker);
}

public class PacketBuilder
{
    private readonly Faker _faker;
    private int _count = 100;
    private DateTime? _startTime;
    private DateTime? _endTime;
    private List<string>? _protocols;
    private List<string>? _sourceIPs;
    private List<string>? _destinationIPs;

    public PacketBuilder(Faker faker)
    {
        _faker = faker;
    }

    public PacketBuilder WithCount(int count)
    {
        _count = count;
        return this;
    }

    public PacketBuilder WithTimeRange(DateTime start, DateTime end)
    {
        _startTime = start;
        _endTime = end;
        return this;
    }

    public PacketBuilder WithProtocols(params string[] protocols)
    {
        _protocols = new List<string>(protocols);
        return this;
    }

    public PacketBuilder WithSourceIPs(params string[] ips)
    {
        _sourceIPs = new List<string>(ips);
        return this;
    }

    public PacketBuilder WithDestinationIPs(params string[] ips)
    {
        _destinationIPs = new List<string>(ips);
        return this;
    }

    public List<PacketInfo> Build()
    {
        var start = _startTime ?? DateTime.UtcNow.AddMinutes(-10);
        var end = _endTime ?? DateTime.UtcNow;
        var timeSpan = (end - start).TotalSeconds;

        var packets = new List<PacketInfo>();

        for (int i = 0; i < _count; i++)
        {
            var timestamp = start.AddSeconds(_faker.Random.Double(0, timeSpan));
            var protocolStr = _protocols?.Count > 0
                ? _faker.PickRandom(_protocols)
                : _faker.PickRandom("TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS");

            var protocol = protocolStr.ToUpperInvariant() switch
            {
                "TCP" => Protocol.TCP,
                "UDP" => Protocol.UDP,
                "ICMP" => Protocol.ICMP,
                "HTTP" => Protocol.HTTP,
                "HTTPS" => Protocol.HTTPS,
                "DNS" => Protocol.DNS,
                _ => Protocol.Unknown
            };

            var sourceIP = _sourceIPs?.Count > 0
                ? _faker.PickRandom(_sourceIPs)
                : _faker.Internet.Ip();

            var destIP = _destinationIPs?.Count > 0
                ? _faker.PickRandom(_destinationIPs)
                : _faker.Internet.Ip();

            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)(i + 1),
                Timestamp = timestamp,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                Protocol = protocol,
                L7Protocol = protocolStr,
                Length = (ushort)_faker.Random.Int(64, 1500),
                SourcePort = (ushort)_faker.Random.Int(1024, 65535),
                DestinationPort = (ushort)_faker.Random.Int(1, 65535),
                Info = $"{protocolStr} packet from {sourceIP} to {destIP}"
            });
        }

        return packets.OrderBy(p => p.Timestamp).ToList();
    }
}

public class NetworkStatisticsBuilder
{
    private readonly Faker _faker;
    private int _totalPackets = 1000;
    private long _totalBytes = 1_000_000;
    private DateTime? _firstPacketTime;
    private DateTime? _lastPacketTime;
    private Dictionary<string, int>? _protocolDistribution;

    public NetworkStatisticsBuilder(Faker faker)
    {
        _faker = faker;
    }

    public NetworkStatisticsBuilder WithTotalPackets(int count)
    {
        _totalPackets = count;
        return this;
    }

    public NetworkStatisticsBuilder WithTotalBytes(long bytes)
    {
        _totalBytes = bytes;
        return this;
    }

    public NetworkStatisticsBuilder WithTimeRange(DateTime first, DateTime last)
    {
        _firstPacketTime = first;
        _lastPacketTime = last;
        return this;
    }

    public NetworkStatisticsBuilder WithProtocolDistribution(Dictionary<string, int> distribution)
    {
        _protocolDistribution = distribution;
        return this;
    }

    public NetworkStatistics Build()
    {
        var firstTime = _firstPacketTime ?? DateTime.UtcNow.AddMinutes(-30);
        var lastTime = _lastPacketTime ?? DateTime.UtcNow;
        var duration = (lastTime - firstTime).TotalSeconds;

        var protocols = _protocolDistribution ?? new Dictionary<string, int>
        {
            ["TCP"] = (int)(_totalPackets * 0.6),
            ["UDP"] = (int)(_totalPackets * 0.25),
            ["ICMP"] = (int)(_totalPackets * 0.1),
            ["Other"] = (int)(_totalPackets * 0.05)
        };

        return new NetworkStatistics
        {
            TotalPackets = _totalPackets,
            TotalBytes = _totalBytes,
            FirstPacketTime = firstTime,
            LastPacketTime = lastTime,
            StartTime = firstTime,
            EndTime = lastTime,
            ProtocolStats = protocols.ToDictionary(
                p => p.Key,
                p => new ProtocolStatistics
                {
                    Protocol = p.Key,
                    PacketCount = p.Value,
                    ByteCount = _totalBytes / protocols.Count,
                    Percentage = (double)p.Value / _totalPackets * 100
                })
        };
    }

    private Dictionary<string, int> GenerateTopIPs(int count)
    {
        var result = new Dictionary<string, int>();
        for (int i = 0; i < count; i++)
        {
            result[_faker.Internet.Ip()] = _faker.Random.Int(10, 500);
        }
        return result;
    }
}

public class AnomalyBuilder
{
    private readonly Faker _faker;
    private int _count = 5;
    private AnomalySeverity _severity = AnomalySeverity.Medium;
    private string? _type;

    public AnomalyBuilder(Faker faker)
    {
        _faker = faker;
    }

    public AnomalyBuilder WithCount(int count)
    {
        _count = count;
        return this;
    }

    public AnomalyBuilder WithSeverity(AnomalySeverity severity)
    {
        _severity = severity;
        return this;
    }

    public AnomalyBuilder WithType(string type)
    {
        _type = type;
        return this;
    }

    public List<NetworkAnomaly> Build()
    {
        var anomalies = new List<NetworkAnomaly>();
        var types = new[] { "Port Scan", "DDoS", "Unusual Traffic", "Protocol Anomaly", "Data Exfiltration" };

        for (int i = 0; i < _count; i++)
        {
            anomalies.Add(new NetworkAnomaly
            {
                Type = _type ?? _faker.PickRandom(types),
                Severity = _severity,
                Category = AnomalyCategory.Network,
                Description = _faker.Lorem.Sentence(),
                DetectedAt = DateTime.UtcNow.AddMinutes(-_faker.Random.Int(1, 60)),
                SourceIP = _faker.Internet.Ip(),
                DestinationIP = _faker.Internet.Ip(),
                DetectorName = "Test Detector",
                AffectedFrames = new List<long> { _faker.Random.Long(1, 1000), _faker.Random.Long(1, 1000) }
            });
        }

        return anomalies;
    }
}
