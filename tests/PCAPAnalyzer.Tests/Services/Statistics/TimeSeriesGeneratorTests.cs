using FluentAssertions;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.Statistics;

namespace PCAPAnalyzer.Tests.Services.Statistics;

public class TimeSeriesGeneratorTests
{
    private readonly TimeSeriesGeneratorService _generator;

    public TimeSeriesGeneratorTests()
    {
        _generator = new TimeSeriesGeneratorService();
    }

    #region GenerateTimeSeriesWithMetrics Tests

    [Fact]
    public void GenerateTimeSeriesWithMetrics_WithEmptyList_ReturnsEmptyResults()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var threats = new List<SecurityThreat>();

        // Act
        var result = _generator.GenerateTimeSeriesWithMetrics(packets, TimeSpan.FromSeconds(1), threats);

        // Assert
        result.ThroughputSeries.Should().BeEmpty();
        result.PacketsSeries.Should().BeEmpty();
        result.AnomaliesSeries.Should().BeEmpty();
    }

    [Fact]
    public void GenerateTimeSeriesWithMetrics_WithSingleInterval_GeneratesSingleDataPoint()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var packets = new List<PacketInfo>
        {
            CreatePacket(startTime, 1000),
            CreatePacket(startTime.AddMilliseconds(500), 1000)
        };
        var threats = new List<SecurityThreat>();

        // Act
        var result = _generator.GenerateTimeSeriesWithMetrics(packets, TimeSpan.FromSeconds(1), threats);

        // Assert
        result.ThroughputSeries.Should().HaveCount(1);
        result.PacketsSeries.Should().HaveCount(1);
        result.AnomaliesSeries.Should().HaveCount(1);
    }

    [Fact]
    public void GenerateTimeSeriesWithMetrics_CalculatesThroughputCorrectly()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var packets = new List<PacketInfo>
        {
            CreatePacket(startTime, 1024), // 1 KB
            CreatePacket(startTime.AddMilliseconds(100), 1024), // 1 KB
            CreatePacket(startTime.AddMilliseconds(200), 1024)  // 1 KB = 3 KB total
        };
        var threats = new List<SecurityThreat>();

        // Act
        var result = _generator.GenerateTimeSeriesWithMetrics(packets, TimeSpan.FromSeconds(1), threats);

        // Assert
        // Throughput should be 3 KB/s (3072 bytes / 1024 / 1 second)
        result.ThroughputSeries[0].Value.Should().BeApproximately(3.0, 0.1);
        result.ThroughputSeries[0].Series.Should().Be("Throughput");
    }

    [Fact]
    public void GenerateTimeSeriesWithMetrics_CalculatesPacketsPerSecond()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var packets = new List<PacketInfo>
        {
            CreatePacket(startTime, 100),
            CreatePacket(startTime.AddMilliseconds(200), 100),
            CreatePacket(startTime.AddMilliseconds(400), 100),
            CreatePacket(startTime.AddMilliseconds(600), 100)
        };
        var threats = new List<SecurityThreat>();

        // Act
        var result = _generator.GenerateTimeSeriesWithMetrics(packets, TimeSpan.FromSeconds(1), threats);

        // Assert
        // 4 packets in 1 second = 4 pps
        result.PacketsSeries[0].Value.Should().BeApproximately(4.0, 0.1);
        result.PacketsSeries[0].PacketsPerSecond.Should().BeApproximately(4.0, 0.1);
        result.PacketsSeries[0].Series.Should().Be("PacketsPerSecond");
    }

    [Fact]
    public void GenerateTimeSeriesWithMetrics_CalculatesAnomaliesPerSecond()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var packets = CreateTestPackets(10, startTime);
        var threats = new List<SecurityThreat>
        {
            new() { DetectedAt = startTime.AddMilliseconds(100) },
            new() { DetectedAt = startTime.AddMilliseconds(300) },
            new() { DetectedAt = startTime.AddMilliseconds(500) }
        };

        // Act
        var result = _generator.GenerateTimeSeriesWithMetrics(packets, TimeSpan.FromSeconds(1), threats);

        // Assert
        // 3 threats in 1 second = 3 aps
        result.AnomaliesSeries[0].Value.Should().BeApproximately(3.0, 0.1);
        result.AnomaliesSeries[0].AnomaliesPerSecond.Should().BeApproximately(3.0, 0.1);
        result.AnomaliesSeries[0].Series.Should().Be("AnomaliesPerSecond");
    }

    [Fact]
    public void GenerateTimeSeriesWithMetrics_WithMultipleIntervals_GeneratesMultipleDataPoints()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var packets = new List<PacketInfo>();
        for (int i = 0; i < 30; i++)
        {
            packets.Add(CreatePacket(startTime.AddSeconds(i), 100));
        }
        var threats = new List<SecurityThreat>();

        // Act
        var result = _generator.GenerateTimeSeriesWithMetrics(packets, TimeSpan.FromSeconds(1), threats);

        // Assert
        result.ThroughputSeries.Should().HaveCount(30);
        result.PacketsSeries.Should().HaveCount(30);
        result.AnomaliesSeries.Should().HaveCount(30);
    }

    [Fact]
    public void GenerateTimeSeriesWithMetrics_IncludesAdditionalMetrics()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var packets = new List<PacketInfo>
        {
            CreatePacket(startTime, 100),
            CreatePacket(startTime.AddMilliseconds(100), 200),
            CreatePacket(startTime.AddMilliseconds(200), 300)
        };
        var threats = new List<SecurityThreat>();

        // Act
        var result = _generator.GenerateTimeSeriesWithMetrics(packets, TimeSpan.FromSeconds(1), threats);

        // Assert
        result.ThroughputSeries[0].AdditionalMetrics.Should().ContainKey("PacketCount");
        result.ThroughputSeries[0].AdditionalMetrics.Should().ContainKey("AverageSize");
        result.ThroughputSeries[0].AdditionalMetrics!["PacketCount"].Should().Be(3);
        result.ThroughputSeries[0].AdditionalMetrics["AverageSize"].Should().BeApproximately(200, 0.1);
    }

    #endregion

    #region GenerateTrafficThreatsTimeSeries Tests

    [Fact]
    public void GenerateTrafficThreatsTimeSeries_WithNullPackets_ReturnsEmptyList()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(10);

        // Act
        var result = _generator.GenerateTrafficThreatsTimeSeries(null!, startTime, endTime, TimeSpan.FromSeconds(1));

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void GenerateTrafficThreatsTimeSeries_WithEmptyPackets_ReturnsEmptyList()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(10);

        // Act
        var result = _generator.GenerateTrafficThreatsTimeSeries(packets, startTime, endTime, TimeSpan.FromSeconds(1));

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void GenerateTrafficThreatsTimeSeries_WithInvalidTimeRange_ReturnsEmptyList()
    {
        // Arrange
        var packets = CreateTestPackets(10, DateTime.UtcNow);
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(-10); // End before start

        // Act
        var result = _generator.GenerateTrafficThreatsTimeSeries(packets, startTime, endTime, TimeSpan.FromSeconds(1));

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void GenerateTrafficThreatsTimeSeries_GeneratesCorrectNumberOfDataPoints()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(10);
        var packets = CreateTestPackets(100, startTime);

        // Act
        var result = _generator.GenerateTrafficThreatsTimeSeries(packets, startTime, endTime, TimeSpan.FromSeconds(1));

        // Assert
        result.Should().HaveCount(10);
        result[0].Series.Should().Be("ThreatsPerSecond");
    }

    [Fact]
    public void GenerateTrafficThreatsTimeSeries_CountsNetworkAnomalies()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(1);
        var packets = new List<PacketInfo>
        {
            CreatePacketWithSize(startTime, 50), // Tiny packet (anomaly)
            CreatePacketWithSize(startTime.AddMilliseconds(100), 2000), // Jumbo frame (anomaly)
            CreatePacketWithSize(startTime.AddMilliseconds(200), 500) // Normal
        };

        // Act
        var result = _generator.GenerateTrafficThreatsTimeSeries(packets, startTime, endTime, TimeSpan.FromSeconds(1));

        // Assert
        result.Should().HaveCount(1);
        result[0].Value.Should().BeGreaterThan(0); // Should detect anomalies
    }

    #endregion

    #region CountNetworkAnomalies Tests

    [Fact]
    public void CountNetworkAnomalies_WithNullPackets_ReturnsZero()
    {
        // Act
        var result = _generator.CountNetworkAnomalies(null!);

        // Assert
        result.Should().Be(0);
    }

    [Fact]
    public void CountNetworkAnomalies_WithEmptyList_ReturnsZero()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var result = _generator.CountNetworkAnomalies(packets);

        // Assert
        result.Should().Be(0);
    }

    [Fact]
    public void CountNetworkAnomalies_WithTinyPackets_CountsAsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacketWithSize(DateTime.UtcNow, 50), // Tiny
            CreatePacketWithSize(DateTime.UtcNow, 60), // Tiny
            CreatePacketWithSize(DateTime.UtcNow, 500) // Normal
        };

        // Act
        var result = _generator.CountNetworkAnomalies(packets);

        // Assert
        result.Should().Be(2); // Two tiny packets
    }

    [Fact]
    public void CountNetworkAnomalies_WithJumboFrames_CountsAsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacketWithSize(DateTime.UtcNow, 2000), // Jumbo
            CreatePacketWithSize(DateTime.UtcNow, 9000), // Jumbo
            CreatePacketWithSize(DateTime.UtcNow, 1500) // Normal (max standard)
        };

        // Act
        var result = _generator.CountNetworkAnomalies(packets);

        // Assert
        result.Should().Be(2); // Two jumbo frames
    }

    [Fact]
    public void CountNetworkAnomalies_WithICMPTraffic_CountsAsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { FrameNumber = 1, Protocol = Protocol.ICMP, Length = 100, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.1", SourcePort = 0, DestinationPort = 0 },
            new() { FrameNumber = 2, Protocol = Protocol.ICMP, Length = 100, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.1", SourcePort = 0, DestinationPort = 0 },
            new() { FrameNumber = 3, Protocol = Protocol.TCP, Length = 100, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.1", SourcePort = 50000, DestinationPort = 443 }
        };

        // Act
        var result = _generator.CountNetworkAnomalies(packets);

        // Assert
        result.Should().Be(2); // Two ICMP packets
    }

    [Fact]
    public void CountNetworkAnomalies_WithHighPortTCPNoPayload_CountsAsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new()
            {
                FrameNumber = 1,
                Protocol = Protocol.TCP,
                Length = 70, // Small payload
                SourcePort = 50000, // High port
                DestinationPort = 60000, // High port
                Timestamp = DateTime.UtcNow,
                SourceIP = "192.168.1.1",
                DestinationIP = "10.0.0.1"
            }
        };

        // Act
        var result = _generator.CountNetworkAnomalies(packets);

        // Assert
        result.Should().Be(1); // Suspicious TCP packet
    }

    [Fact]
    public void CountNetworkAnomalies_WithNormalTraffic_ReturnsZero()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { FrameNumber = 1, Protocol = Protocol.TCP, Length = 500, SourcePort = 50000, DestinationPort = 443, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.1" },
            new() { FrameNumber = 2, Protocol = Protocol.UDP, Length = 1000, SourcePort = 50001, DestinationPort = 53, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.1" },
            new() { FrameNumber = 3, Protocol = Protocol.TCP, Length = 1400, SourcePort = 50002, DestinationPort = 80, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "10.0.0.1" }
        };

        // Act
        var result = _generator.CountNetworkAnomalies(packets);

        // Assert
        result.Should().Be(0); // All normal traffic
    }

    #endregion

    #region CalculateMaxPacketsPerWindow Tests

    [Fact]
    public void CalculateMaxPacketsPerWindow_WithEmptyList_ReturnsZero()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(10);

        // Act
        var result = _generator.CalculateMaxPacketsPerWindow(packets, TimeSpan.FromSeconds(1), startTime, endTime);

        // Assert
        result.Should().Be(0);
    }

    [Fact]
    public void CalculateMaxPacketsPerWindow_WithEvenlyDistributedTraffic_ReturnsExpectedMax()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(10);
        var packets = new List<PacketInfo>();

        // 10 packets per second for 10 seconds
        for (int i = 0; i < 100; i++)
        {
            packets.Add(CreatePacket(startTime.AddMilliseconds(i * 100), 100));
        }

        // Act
        var result = _generator.CalculateMaxPacketsPerWindow(packets, TimeSpan.FromSeconds(1), startTime, endTime);

        // Assert
        result.Should().BeGreaterThanOrEqualTo(10); // At least 10 packets per second
    }

    [Fact]
    public void CalculateMaxPacketsPerWindow_WithBurstTraffic_DetectsPeak()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(10);
        var packets = new List<PacketInfo>();

        // Create burst at second 5
        for (int i = 0; i < 1000; i++)
        {
            packets.Add(CreatePacket(startTime.AddSeconds(5).AddMilliseconds(i), 100));
        }

        // Add some normal traffic elsewhere
        for (int i = 0; i < 10; i++)
        {
            packets.Add(CreatePacket(startTime.AddSeconds(i), 100));
        }

        // Act
        var result = _generator.CalculateMaxPacketsPerWindow(packets, TimeSpan.FromSeconds(1), startTime, endTime);

        // Assert
        result.Should().BeGreaterThan(100); // Should detect the burst
    }

    [Fact]
    public void CalculateMaxPacketsPerWindow_UsesOverlappingWindows()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(5);
        var packets = new List<PacketInfo>();

        // Add packets concentrated between 1-2 seconds
        for (int i = 0; i < 100; i++)
        {
            packets.Add(CreatePacket(startTime.AddSeconds(1.5).AddMilliseconds(i * 5), 100));
        }

        // Act
        var result = _generator.CalculateMaxPacketsPerWindow(packets, TimeSpan.FromSeconds(1), startTime, endTime);

        // Assert
        // With 50% overlap, should detect the concentrated traffic
        result.Should().BeGreaterThan(0);
    }

    [Fact]
    public void CalculateMaxPacketsPerWindow_WithDifferentWindowSizes_AdjustsCorrectly()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddSeconds(60);
        var packets = CreateTestPackets(600, startTime); // 10 pps steady

        // Act
        var result1s = _generator.CalculateMaxPacketsPerWindow(packets, TimeSpan.FromSeconds(1), startTime, endTime);
        var result5s = _generator.CalculateMaxPacketsPerWindow(packets, TimeSpan.FromSeconds(5), startTime, endTime);
        var result10s = _generator.CalculateMaxPacketsPerWindow(packets, TimeSpan.FromSeconds(10), startTime, endTime);

        // Assert
        result1s.Should().BeLessThanOrEqualTo(result5s);
        result5s.Should().BeLessThanOrEqualTo(result10s);
    }

    #endregion

    #region Helper Methods

    private PacketInfo CreatePacket(DateTime timestamp, ushort length)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = timestamp,
            SourceIP = "192.168.1.1",
            DestinationIP = "10.0.0.1",
            Protocol = Protocol.TCP,
            Length = length,
            SourcePort = 50000,
            DestinationPort = 443
        };
    }

    private PacketInfo CreatePacketWithSize(DateTime timestamp, ushort length)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = timestamp,
            SourceIP = "192.168.1.1",
            DestinationIP = "10.0.0.1",
            Protocol = Protocol.TCP,
            Length = length,
            SourcePort = 50000,
            DestinationPort = 443
        };
    }

    private List<PacketInfo> CreateTestPackets(int count, DateTime startTime)
    {
        var packets = new List<PacketInfo>();
        for (int i = 0; i < count; i++)
        {
            packets.Add(CreatePacket(startTime.AddMilliseconds(i * 100), 100));
        }
        return packets;
    }

    #endregion
}
