using System;
using PCAPAnalyzer.Core.Models;
using Xunit;

namespace PCAPAnalyzer.Tests.Unit;

public class PacketInfoTests
{
    [Fact]
    public void PacketInfo_Should_Initialize_With_Required_Properties()
    {
        // Arrange & Act
        var packet = new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.Now,
            Length = 100,
            SourceIP = "192.168.1.1",
            DestinationIP = "192.168.1.2",
            SourcePort = 12345,
            DestinationPort = 80,
            Protocol = Protocol.HTTP,
            Info = "GET / HTTP/1.1"
        };

        // Assert
        Assert.Equal(1u, packet.FrameNumber);
        Assert.Equal(100, packet.Length);
        Assert.Equal("192.168.1.1", packet.SourceIP);
        Assert.Equal("192.168.1.2", packet.DestinationIP);
        Assert.Equal(12345, packet.SourcePort);
        Assert.Equal(80, packet.DestinationPort);
        Assert.Equal(Protocol.HTTP, packet.Protocol);
        Assert.Equal("GET / HTTP/1.1", packet.Info);
    }

    [Theory]
    [InlineData(Protocol.TCP, "TCP")]
    [InlineData(Protocol.UDP, "UDP")]
    [InlineData(Protocol.HTTP, "HTTP")]
    [InlineData(Protocol.HTTPS, "HTTPS")]
    [InlineData(Protocol.DNS, "DNS")]
    [InlineData(Protocol.ICMP, "ICMP")]
    [InlineData(Protocol.Unknown, "Unknown")]
    public void GetProtocolDisplay_Should_Return_Correct_String(Protocol protocol, string expected)
    {
        // Arrange
        var packet = new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.Now,
            Length = 100,
            SourceIP = "127.0.0.1",
            DestinationIP = "127.0.0.1",
            SourcePort = 0,
            DestinationPort = 0,
            Protocol = protocol
        };

        // Act
        var result = packet.GetProtocolDisplay();

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void PacketStatistics_Should_Initialize_With_Empty_Collections()
    {
        // Arrange & Act
        var stats = new PacketStatistics();

        // Assert
        Assert.Equal(0, stats.TotalPackets);
        Assert.Equal(0, stats.TotalBytes);
        Assert.NotNull(stats.ProtocolCounts);
        Assert.Empty(stats.ProtocolCounts);
        Assert.NotNull(stats.TopTalkers);
        Assert.Empty(stats.TopTalkers);
        Assert.Equal(0, stats.PacketsPerSecond);
        Assert.Equal(0, stats.BytesPerSecond);
    }
}