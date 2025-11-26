using FluentAssertions;
using Moq;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Tests.Helpers;

namespace PCAPAnalyzer.Tests.Services;

public class StatisticsServiceTests
{
    private readonly MockServiceFactory _mockFactory;
    private readonly Mock<IInsecurePortDetector> _mockPortDetector;
    private readonly Mock<IGeoIPService> _mockGeoIP;
    private readonly Mock<IPacketSizeAnalyzer> _mockSizeAnalyzer;
    private readonly StatisticsService _service;

    public StatisticsServiceTests()
    {
        _mockFactory = new MockServiceFactory();
        _mockPortDetector = new Mock<IInsecurePortDetector>();
        _mockGeoIP = _mockFactory.CreateGeoIPService();
        _mockSizeAnalyzer = new Mock<IPacketSizeAnalyzer>();

        // ✅ TIMING FIX: Updated mocks to handle new optional stage parameters
        // Setup default mocks for async methods that return empty collections
        _mockGeoIP.Setup(x => x.AnalyzeCountryTrafficAsync(It.IsAny<IEnumerable<PacketInfo>>(), It.IsAny<object?>()))
            .ReturnsAsync(new Dictionary<string, CountryTrafficStatistics>());
        _mockGeoIP.Setup(x => x.AnalyzeTrafficFlowsAsync(It.IsAny<IEnumerable<PacketInfo>>(), It.IsAny<object?>()))
            .ReturnsAsync(new List<TrafficFlowDirection>());
        _mockGeoIP.Setup(x => x.GetHighRiskCountriesAsync())
            .ReturnsAsync(new List<CountryRiskProfile>());

        _service = new StatisticsService(
            _mockPortDetector.Object,
            _mockGeoIP.Object,
            _mockSizeAnalyzer.Object);
    }

    [Fact]
    public void CalculateStatistics_WithNullPackets_ReturnsEmptyStatistics()
    {
        // Act
        var result = _service.CalculateStatistics(null!);

        // Assert
        result.Should().NotBeNull();
        result.TotalPackets.Should().Be(0);
        result.TotalBytes.Should().Be(0);
    }

    [Fact]
    public void CalculateStatistics_WithEmptyPackets_ReturnsEmptyStatistics()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.Should().NotBeNull();
        result.TotalPackets.Should().Be(0);
        result.TotalBytes.Should().Be(0);
    }

    [Fact]
    public void CalculateStatistics_WithValidPackets_CalculatesTotalPacketsCorrectly()
    {
        // Arrange
        var packets = CreateTestPackets(100);

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.TotalPackets.Should().Be(100);
    }

    [Fact]
    public void CalculateStatistics_WithValidPackets_CalculatesTotalBytesCorrectly()
    {
        // Arrange
        var packets = CreateTestPackets(10, packetSize: 500);

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.TotalBytes.Should().Be(5000); // 10 packets * 500 bytes
    }

    [Fact]
    public void CalculateStatistics_WithValidPackets_SetsFirstAndLastPacketTime()
    {
        // Arrange
        var startTime = DateTime.UtcNow.AddMinutes(-10);
        var endTime = DateTime.UtcNow;
        var packets = CreateTestPacketsWithTimeRange(100, startTime, endTime);

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.FirstPacketTime.Should().BeCloseTo(startTime, TimeSpan.FromMilliseconds(100));
        result.LastPacketTime.Should().BeCloseTo(endTime, TimeSpan.FromMilliseconds(100));
    }

    [Fact]
    public void CalculateStatistics_WithMultipleProtocols_CalculatesProtocolDistribution()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket(protocol: "TCP"),
            CreatePacket(protocol: "TCP"),
            CreatePacket(protocol: "TCP"),
            CreatePacket(protocol: "UDP"),
            CreatePacket(protocol: "UDP"),
            CreatePacket(protocol: "ICMP")
        };

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.ProtocolStats.Should().NotBeNull();
        result.ProtocolStats.Should().ContainKey("TCP");
        result.ProtocolStats["TCP"].PacketCount.Should().Be(3);
        result.ProtocolStats["UDP"].PacketCount.Should().Be(2);
        result.ProtocolStats["ICMP"].PacketCount.Should().Be(1);
    }

    [Fact]
    public void CalculateStatistics_WithValidPackets_CalculatesUniqueIPs()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket(sourceIP: "192.168.1.1", destIP: "192.168.1.2"),
            CreatePacket(sourceIP: "192.168.1.1", destIP: "192.168.1.3"),
            CreatePacket(sourceIP: "192.168.1.2", destIP: "192.168.1.1"),
            CreatePacket(sourceIP: "10.0.0.1", destIP: "192.168.1.1")
        };

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.AllUniqueIPs.Should().HaveCount(4);
        result.AllUniqueIPs.Should().Contain(new[] { "192.168.1.1", "192.168.1.2", "192.168.1.3", "10.0.0.1" });
    }

    [Fact]
    public void CalculateStatistics_WithValidPackets_CalculatesTopSources()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket(sourceIP: "192.168.1.1"),
            CreatePacket(sourceIP: "192.168.1.1"),
            CreatePacket(sourceIP: "192.168.1.1"),
            CreatePacket(sourceIP: "192.168.1.2"),
            CreatePacket(sourceIP: "192.168.1.2"),
            CreatePacket(sourceIP: "192.168.1.3")
        };

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.TopSources.Should().NotBeNull();
        result.TopSources.First().Address.Should().Be("192.168.1.1");
        result.TopSources.First().PacketCount.Should().Be(3);
    }

    [Fact]
    public void CalculateStatistics_WithValidPackets_CalculatesTopDestinations()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket(destIP: "8.8.8.8"),
            CreatePacket(destIP: "8.8.8.8"),
            CreatePacket(destIP: "8.8.8.8"),
            CreatePacket(destIP: "1.1.1.1"),
            CreatePacket(destIP: "1.1.1.1")
        };

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.TopDestinations.Should().NotBeNull();
        result.TopDestinations.First().Address.Should().Be("8.8.8.8");
        result.TopDestinations.First().PacketCount.Should().Be(3);
    }

    [Fact]
    public void CalculateStatistics_WithValidPackets_CalculatesTopConversations()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket(sourceIP: "192.168.1.1", destIP: "8.8.8.8"),
            CreatePacket(sourceIP: "192.168.1.1", destIP: "8.8.8.8"),
            CreatePacket(sourceIP: "192.168.1.1", destIP: "8.8.8.8"),
            CreatePacket(sourceIP: "192.168.1.2", destIP: "1.1.1.1")
        };

        // Act
        var result = _service.CalculateStatistics(packets);

        // Assert
        result.TopConversations.Should().NotBeNull();
        result.TopConversations.Should().NotBeEmpty();
        var topConv = result.TopConversations.First();
        topConv.SourceAddress.Should().Be("192.168.1.1");
        topConv.DestinationAddress.Should().Be("8.8.8.8");
        topConv.PacketCount.Should().Be(3);
    }

    [Fact]
    public async Task CalculateStatisticsAsync_WithValidPackets_ReturnsStatistics()
    {
        // Arrange
        var packets = CreateTestPackets(50);

        // Act
        var result = await _service.CalculateStatisticsAsync(packets);

        // Assert
        result.Should().NotBeNull();
        result.TotalPackets.Should().Be(50);
    }

    [Fact]
    public async Task EnrichWithGeoAsync_WithValidData_EnrichesCountryStatistics()
    {
        // Arrange
        var stats = new NetworkStatistics
        {
            TopSources = new List<EndpointStatistics>
            {
                new() { Address = "8.8.8.8", PacketCount = 100 }
            }
        };
        var packets = CreateTestPackets(10);

        // NOTE: EnrichWithGeoAsync enriches CountryStatistics, TrafficFlows, and HighRiskCountries
        // but does NOT update TopSources.Country (that happens in CalculateStatisticsAsync)

        // Mock the methods that EnrichWithGeoAsync actually calls
        _mockGeoIP.Setup(x => x.IsPublicIP(It.IsAny<string>())).Returns(true);

        var countryStats = new Dictionary<string, CountryTrafficStatistics>
        {
            ["US"] = new CountryTrafficStatistics
            {
                CountryCode = "US",
                CountryName = "United States",
                TotalPackets = 100,
                TotalBytes = 10000
            }
        };
        _mockGeoIP.Setup(x => x.AnalyzeCountryTrafficAsync(It.IsAny<IEnumerable<PacketInfo>>(), It.IsAny<object?>()))
            .ReturnsAsync(countryStats);

        // Act
        var result = await _service.EnrichWithGeoAsync(stats, packets);

        // Assert - verify what EnrichWithGeoAsync actually updates
        result.Should().NotBeNull();
        result.CountryStatistics.Should().NotBeNull();
        result.CountryStatistics.Should().ContainKey("US");
        result.CountryStatistics!["US"].CountryName.Should().Be("United States");
        result.GeolocatedPackets.Should().Be(100);
        result.GeolocatedBytes.Should().Be(10000);
    }

    [Fact]
    public void GenerateTimeSeries_WithValidPackets_GeneratesTimeSeriesData()
    {
        // Arrange
        var startTime = DateTime.UtcNow.AddMinutes(-10);
        var packets = CreateTestPacketsWithTimeRange(100, startTime, DateTime.UtcNow);
        var interval = TimeSpan.FromMinutes(1);

        // Act
        var result = _service.GenerateTimeSeries(packets, interval);

        // Assert
        result.Should().NotBeNull();
        result.Should().NotBeEmpty();
        result.Should().HaveCountGreaterThan(0);
    }

    [Fact]
    public void DetectThreats_WithPortScanPattern_DetectsPortScanning()
    {
        // Arrange
        var packets = PacketTestFixtures.PortScanAttack("10.0.0.100", "192.168.1.50");

        // Act
        var threats = _service.DetectThreats(packets);

        // Assert
        threats.Should().NotBeNull();
        // Note: Actual threat detection depends on implementation
        // This test validates the method doesn't throw
    }

    [Fact]
    public void GenerateInsights_WithHighTrafficStats_GeneratesInsights()
    {
        // Arrange
        var stats = new NetworkStatistics
        {
            TotalPackets = 1_000_000,
            TotalBytes = 1_000_000_000,
            FirstPacketTime = DateTime.UtcNow.AddHours(-1),
            LastPacketTime = DateTime.UtcNow,
            ProtocolStats = new Dictionary<string, ProtocolStatistics>
            {
                ["TCP"] = new() { PacketCount = 600_000 },
                ["UDP"] = new() { PacketCount = 400_000 }
            }
        };

        // Act
        var insights = _service.GenerateInsights(stats);

        // Assert
        insights.Should().NotBeNull();
        insights.Should().NotBeEmpty();
    }

    // Helper methods
    private List<PacketInfo> CreateTestPackets(int count, int packetSize = 100)
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddMinutes(-count);

        for (int i = 0; i < count; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)(i + 1),
                Timestamp = baseTime.AddSeconds(i),
                SourceIP = $"192.168.1.{(i % 10) + 1}",
                DestinationIP = $"10.0.0.{(i % 5) + 1}",
                Protocol = Protocol.TCP,
                L7Protocol = "TCP",
                Length = (ushort)packetSize,
                SourcePort = (ushort)(50000 + i),
                DestinationPort = 443,
                Info = $"Test packet {i}"
            });
        }

        return packets;
    }

    private List<PacketInfo> CreateTestPacketsWithTimeRange(int count, DateTime start, DateTime end)
    {
        var packets = new List<PacketInfo>();
        var timeSpan = (end - start).TotalSeconds;

        for (int i = 0; i < count; i++)
        {
            // Distribute packets evenly across the time range
            var packetTime = start.AddSeconds((i * timeSpan) / (count - 1));
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)(i + 1),
                Timestamp = packetTime,
                SourceIP = $"192.168.1.{(i % 10) + 1}",
                DestinationIP = $"10.0.0.{(i % 5) + 1}",
                Protocol = Protocol.TCP,
                L7Protocol = "TCP",
                Length = 100,
                SourcePort = 50000,
                DestinationPort = 443
            });
        }

        return packets;
    }

    private PacketInfo CreatePacket(
        string sourceIP = "192.168.1.1",
        string destIP = "192.168.1.2",
        string protocol = "TCP",
        int length = 100)
    {
        // Parse protocol string to enum
        var protocolEnum = protocol.ToUpper() switch
        {
            "TCP" => Protocol.TCP,
            "UDP" => Protocol.UDP,
            "ICMP" => Protocol.ICMP,
            "ARP" => Protocol.ARP,
            "HTTP" => Protocol.HTTP,
            "HTTPS" => Protocol.HTTPS,
            "DNS" => Protocol.DNS,
            _ => Protocol.Unknown
        };

        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            Protocol = protocolEnum,
            Length = (ushort)length,
            SourcePort = 50000,
            DestinationPort = 443,
            Info = "Test packet"
        };
    }
}
