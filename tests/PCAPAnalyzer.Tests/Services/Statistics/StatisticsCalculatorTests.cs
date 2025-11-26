using FluentAssertions;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.Statistics;

namespace PCAPAnalyzer.Tests.Services.Statistics;

public class StatisticsCalculatorTests
{
    private readonly StatisticsCalculator _calculator;
    private readonly Dictionary<string, string> _protocolColors;
    private readonly Dictionary<int, string> _wellKnownPorts;

    public StatisticsCalculatorTests()
    {
        _calculator = new StatisticsCalculator();
        _protocolColors = new Dictionary<string, string>
        {
            { "TCP", "#3B82F6" },
            { "UDP", "#10B981" },
            { "ICMP", "#F59E0B" },
            { "HTTP", "#8B5CF6" },
            { "HTTPS", "#EC4899" },
            { "Other", "#6B7280" }
        };

        _wellKnownPorts = new Dictionary<int, string>
        {
            { 80, "HTTP" },
            { 443, "HTTPS" },
            { 22, "SSH" },
            { 53, "DNS" },
            { 21, "FTP" },
            { 25, "SMTP" }
        };
    }

    #region CalculateProtocolStatistics Tests

    [Fact]
    public void CalculateProtocolStatistics_WithEmptyList_ReturnsEmptyDictionary()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var result = _calculator.CalculateProtocolStatistics(packets, _protocolColors);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void CalculateProtocolStatistics_WithSingleProtocol_ReturnsCorrectStats()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket(Protocol.TCP, 100),
            CreatePacket(Protocol.TCP, 200),
            CreatePacket(Protocol.TCP, 150)
        };

        // Act
        var result = _calculator.CalculateProtocolStatistics(packets, _protocolColors);

        // Assert
        result.Should().ContainKey("TCP");
        result["TCP"].PacketCount.Should().Be(3);
        result["TCP"].ByteCount.Should().Be(450);
        result["TCP"].Percentage.Should().BeApproximately(100.0, 0.01);
        result["TCP"].Color.Should().Be("#3B82F6");
    }

    [Fact]
    public void CalculateProtocolStatistics_WithMultipleProtocols_CalculatesCorrectPercentages()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket(Protocol.TCP, 100),
            CreatePacket(Protocol.TCP, 100),
            CreatePacket(Protocol.UDP, 100),
            CreatePacket(Protocol.ICMP, 100)
        };

        // Act
        var result = _calculator.CalculateProtocolStatistics(packets, _protocolColors);

        // Assert
        result["TCP"].Percentage.Should().BeApproximately(50.0, 0.01);
        result["UDP"].Percentage.Should().BeApproximately(25.0, 0.01);
        result["ICMP"].Percentage.Should().BeApproximately(25.0, 0.01);
    }

    [Fact]
    public void CalculateProtocolStatistics_WithUnknownProtocol_UsesOtherColor()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket(Protocol.Unknown, 100)
        };

        // Act
        var result = _calculator.CalculateProtocolStatistics(packets, _protocolColors);

        // Assert
        result["Unknown"].Color.Should().Be("#6B7280");
    }

    [Fact]
    public void CalculateProtocolStatistics_WithMoreThan10Protocols_LimitsTo10()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        for (int i = 0; i < 15; i++)
        {
            // Create packets with different protocols by cycling through available ones
            packets.Add(CreatePacket((Protocol)(i % 7), 100));
        }

        // Act
        var result = _calculator.CalculateProtocolStatistics(packets, _protocolColors);

        // Assert
        result.Should().HaveCountLessThanOrEqualTo(10);
    }

    #endregion

    #region CalculateTopEndpoints Tests

    [Fact]
    public void CalculateTopEndpoints_WithSources_ReturnsTopSourceIPs()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacketWithIPs("192.168.1.1", "10.0.0.1", 100),
            CreatePacketWithIPs("192.168.1.1", "10.0.0.2", 100),
            CreatePacketWithIPs("192.168.1.1", "10.0.0.3", 100),
            CreatePacketWithIPs("192.168.1.2", "10.0.0.1", 100),
            CreatePacketWithIPs("192.168.1.2", "10.0.0.2", 100)
        };

        // Act
        var result = _calculator.CalculateTopEndpoints(packets, isSource: true);

        // Assert
        result.Should().HaveCount(2);
        result[0].Address.Should().Be("192.168.1.1");
        result[0].PacketCount.Should().Be(3);
        result[0].Percentage.Should().BeApproximately(60.0, 0.01);
        result[1].Address.Should().Be("192.168.1.2");
        result[1].PacketCount.Should().Be(2);
    }

    [Fact]
    public void CalculateTopEndpoints_WithDestinations_ReturnsTopDestinationIPs()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacketWithIPs("192.168.1.1", "10.0.0.1", 100),
            CreatePacketWithIPs("192.168.1.2", "10.0.0.1", 100),
            CreatePacketWithIPs("192.168.1.3", "10.0.0.1", 100),
            CreatePacketWithIPs("192.168.1.1", "10.0.0.2", 100)
        };

        // Act
        var result = _calculator.CalculateTopEndpoints(packets, isSource: false);

        // Assert
        result.Should().HaveCount(2);
        result[0].Address.Should().Be("10.0.0.1");
        result[0].PacketCount.Should().Be(3);
    }

    [Fact]
    public void CalculateTopEndpoints_WithInternalIP_MarksAsInternal()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacketWithIPs("192.168.1.1", "10.0.0.1", 100),
            CreatePacketWithIPs("8.8.8.8", "10.0.0.2", 100)
        };

        // Act
        var result = _calculator.CalculateTopEndpoints(packets, isSource: true);

        // Assert
        result.First(e => e.Address == "192.168.1.1").IsInternal.Should().BeTrue();
        result.First(e => e.Address == "8.8.8.8").IsInternal.Should().BeFalse();
    }

    [Fact]
    public void CalculateTopEndpoints_CalculatesProtocolBreakdown()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { FrameNumber = 1, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.1", Protocol = Protocol.TCP, Length = 100, SourcePort = 50000, DestinationPort = 443 },
            new() { FrameNumber = 2, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.2", Protocol = Protocol.TCP, Length = 100, SourcePort = 50000, DestinationPort = 443 },
            new() { FrameNumber = 3, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.3", Protocol = Protocol.UDP, Length = 100, SourcePort = 50000, DestinationPort = 53 }
        };

        // Act
        var result = _calculator.CalculateTopEndpoints(packets, isSource: true);

        // Assert
        result[0].ProtocolBreakdown.Should().ContainKey("TCP");
        result[0].ProtocolBreakdown["TCP"].Should().Be(2);
        result[0].ProtocolBreakdown.Should().ContainKey("UDP");
        result[0].ProtocolBreakdown["UDP"].Should().Be(1);
    }

    [Fact]
    public void CalculateTopEndpoints_LimitsTo30Results()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        for (int i = 0; i < 100; i++)
        {
            packets.Add(CreatePacketWithIPs($"192.168.1.{i}", "10.0.0.1", 100));
        }

        // Act
        var result = _calculator.CalculateTopEndpoints(packets, isSource: true);

        // Assert
        result.Should().HaveCountLessThanOrEqualTo(30);
    }

    #endregion

    #region CalculateTopConversations Tests

    [Fact]
    public void CalculateTopConversations_WithEmptyList_ReturnsEmptyList()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var (conversations, totalCount) = _calculator.CalculateTopConversations(packets);

        // Assert
        conversations.Should().BeEmpty();
        totalCount.Should().Be(0);
    }

    [Fact]
    public void CalculateTopConversations_GroupsBidirectionalTraffic()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreateConversationPacket("192.168.1.1", "10.0.0.1", 50000, 443, Protocol.TCP),
            CreateConversationPacket("10.0.0.1", "192.168.1.1", 443, 50000, Protocol.TCP),
            CreateConversationPacket("192.168.1.1", "10.0.0.1", 50000, 443, Protocol.TCP)
        };

        // Act
        var (conversations, totalCount) = _calculator.CalculateTopConversations(packets);

        // Assert
        conversations.Should().HaveCount(1);
        conversations[0].PacketCount.Should().Be(3);
        totalCount.Should().Be(1);
    }

    [Fact]
    public void CalculateTopConversations_ExcludesPacketsWithZeroPorts()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreateConversationPacket("192.168.1.1", "10.0.0.1", 0, 0, Protocol.ICMP),
            CreateConversationPacket("192.168.1.2", "10.0.0.2", 50000, 443, Protocol.TCP)
        };

        // Act
        var (conversations, totalCount) = _calculator.CalculateTopConversations(packets);

        // Assert
        // Only packets with non-zero ports are included
        conversations.Should().HaveCount(1);
        // The conversation normalizes addresses, so just check it exists
        conversations[0].PacketCount.Should().Be(1);
    }

    [Fact]
    public void CalculateTopConversations_CalculatesStartAndEndTime()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(10);
        var packets = new List<PacketInfo>
        {
            new()
            {
                FrameNumber = 1,
                SourceIP = "192.168.1.1",
                DestinationIP = "10.0.0.1",
                SourcePort = 50000,
                DestinationPort = 443,
                Protocol = Protocol.TCP,
                Timestamp = startTime,
                Length = 100
            },
            new()
            {
                FrameNumber = 2,
                SourceIP = "192.168.1.1",
                DestinationIP = "10.0.0.1",
                SourcePort = 50000,
                DestinationPort = 443,
                Protocol = Protocol.TCP,
                Timestamp = endTime,
                Length = 100
            }
        };

        // Act
        var (conversations, _) = _calculator.CalculateTopConversations(packets);

        // Assert
        conversations[0].StartTime.Should().Be(startTime);
        conversations[0].EndTime.Should().Be(endTime);
    }

    [Fact]
    public void CalculateTopConversations_LimitsTo30Results()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        for (int i = 0; i < 100; i++)
        {
            packets.Add(CreateConversationPacket($"192.168.1.{i}", "10.0.0.1", (ushort)(50000 + i), 443, Protocol.TCP));
        }

        // Act
        var (conversations, totalCount) = _calculator.CalculateTopConversations(packets);

        // Assert
        conversations.Should().HaveCountLessThanOrEqualTo(30);
        totalCount.Should().BeGreaterThan(30);
    }

    #endregion

    #region CalculateTopPortsWithCount Tests

    [Fact]
    public void CalculateTopPortsWithCount_WithEmptyList_ReturnsEmptyList()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var (topPorts, uniqueCount) = _calculator.CalculateTopPortsWithCount(packets, _wellKnownPorts);

        // Assert
        topPorts.Should().BeEmpty();
        uniqueCount.Should().Be(0);
    }

    [Fact]
    public void CalculateTopPortsWithCount_WithWellKnownPort_IdentifiesService()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePortPacket(443, Protocol.TCP, 100),
            CreatePortPacket(443, Protocol.TCP, 100),
            CreatePortPacket(443, Protocol.TCP, 100)
        };

        // Act
        var (topPorts, uniqueCount) = _calculator.CalculateTopPortsWithCount(packets, _wellKnownPorts);

        // Assert
        // The method counts both source and destination ports, so we need to find the 443 port
        var httpsPort = topPorts.FirstOrDefault(p => p.Port == 443);
        httpsPort.Should().NotBeNull();
        httpsPort!.Service.Should().Be("HTTPS");
        httpsPort.IsWellKnown.Should().BeTrue();
        httpsPort.PacketCount.Should().Be(3);
    }

    [Fact]
    public void CalculateTopPortsWithCount_WithUnknownPort_ShowsPortNumber()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePortPacket(12345, Protocol.TCP, 100)
        };

        // Act
        var (topPorts, _) = _calculator.CalculateTopPortsWithCount(packets, _wellKnownPorts);

        // Assert
        // The method also includes source port 50000, so find the destination port
        var unknownPort = topPorts.FirstOrDefault(p => p.Port == 12345);
        unknownPort.Should().NotBeNull();
        unknownPort!.Service.Should().Be("Port 12345");
        unknownPort.IsWellKnown.Should().BeFalse();
    }

    [Fact]
    public void CalculateTopPortsWithCount_CountsUniquePortProtocolCombinations()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePortPacket(80, Protocol.TCP, 100),
            CreatePortPacket(80, Protocol.UDP, 100),
            CreatePortPacket(443, Protocol.TCP, 100)
        };

        // Act
        var (topPorts, uniqueCount) = _calculator.CalculateTopPortsWithCount(packets, _wellKnownPorts);

        // Assert
        // Each packet contributes source and destination ports
        // uniqueCount counts unique (port, protocol) combinations
        uniqueCount.Should().BeGreaterThanOrEqualTo(3); // At least Port 80/TCP, Port 80/UDP, Port 443/TCP
    }

    [Fact]
    public void CalculateTopPortsWithCount_WithNoPorts_CountsProtocolOnly()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { FrameNumber = 1, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.1", Protocol = Protocol.ICMP, SourcePort = 0, DestinationPort = 0, Length = 100 }
        };

        // Act
        var (topPorts, uniqueCount) = _calculator.CalculateTopPortsWithCount(packets, _wellKnownPorts);

        // Assert
        uniqueCount.Should().Be(1);
        topPorts[0].Port.Should().Be(0);
        topPorts[0].Protocol.Should().Be("ICMP");
    }

    [Theory]
    [InlineData("192.168.1.1", true)]
    [InlineData("192.168.255.255", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.255.255.255", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    [InlineData("172.15.0.1", false)]
    [InlineData("172.32.0.1", false)]
    public void IsInternalIP_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = _calculator.IsInternalIP(ip);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("999.999.999.999")]
    public void IsInternalIP_WithInvalidIP_ReturnsFalse(string ip)
    {
        // Act
        var result = _calculator.IsInternalIP(ip);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region CalculateServiceStatistics Tests

    [Fact]
    public void CalculateServiceStatistics_WithEmptyList_ReturnsEmptyDictionary()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var result = _calculator.CalculateServiceStatistics(packets, _wellKnownPorts);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void CalculateServiceStatistics_WithHTTPTraffic_CalculatesStats()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreateServicePacket("192.168.1.1", "10.0.0.1", 50000, 80, 100),
            CreateServicePacket("192.168.1.2", "10.0.0.1", 50001, 80, 150),
            CreateServicePacket("10.0.0.1", "192.168.1.1", 80, 50000, 200)
        };

        // Act
        var result = _calculator.CalculateServiceStatistics(packets, _wellKnownPorts);

        // Assert
        result.Should().ContainKey("HTTP");
        result["HTTP"].Port.Should().Be(80);
        result["HTTP"].PacketCount.Should().Be(3);
        result["HTTP"].ByteCount.Should().Be(450);
        result["HTTP"].UniqueHosts.Should().HaveCount(3);
        result["HTTP"].IsEncrypted.Should().BeFalse();
    }

    [Fact]
    public void CalculateServiceStatistics_WithHTTPSTraffic_MarksAsEncrypted()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreateServicePacket("192.168.1.1", "10.0.0.1", 50000, 443, 100)
        };

        // Act
        var result = _calculator.CalculateServiceStatistics(packets, _wellKnownPorts);

        // Assert
        result["HTTPS"].IsEncrypted.Should().BeTrue();
    }

    [Fact]
    public void CalculateServiceStatistics_OnlyIncludesServicesWithTraffic()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreateServicePacket("192.168.1.1", "10.0.0.1", 50000, 80, 100)
        };

        // Act
        var result = _calculator.CalculateServiceStatistics(packets, _wellKnownPorts);

        // Assert
        result.Should().ContainKey("HTTP");
        result.Should().NotContainKey("SSH"); // No SSH traffic
    }

    #endregion

    #region Helper Methods

    private PacketInfo CreatePacket(Protocol protocol, ushort length)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            Protocol = protocol,
            Length = length,
            SourceIP = "192.168.1.1",
            DestinationIP = "10.0.0.1",
            SourcePort = 50000,
            DestinationPort = 443
        };
    }

    private PacketInfo CreatePacketWithIPs(string sourceIP, string destIP, ushort length)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            Protocol = Protocol.TCP,
            Length = length,
            SourcePort = 50000,
            DestinationPort = 443
        };
    }

    private PacketInfo CreateConversationPacket(string sourceIP, string destIP, ushort srcPort, ushort dstPort, Protocol protocol)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            SourcePort = srcPort,
            DestinationPort = dstPort,
            Protocol = protocol,
            Length = 100
        };
    }

    private PacketInfo CreatePortPacket(int port, Protocol protocol, ushort length)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.1",
            DestinationIP = "10.0.0.1",
            SourcePort = 50000,
            DestinationPort = (ushort)port,
            Protocol = protocol,
            Length = length
        };
    }

    private PacketInfo CreateServicePacket(string sourceIP, string destIP, ushort srcPort, ushort dstPort, ushort length)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            SourcePort = srcPort,
            DestinationPort = dstPort,
            Protocol = Protocol.TCP,
            Length = length
        };
    }

    #endregion
}
