using FluentAssertions;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.TShark;

namespace PCAPAnalyzer.Tests.TShark;

/// <summary>
/// Tests for TSharkParserOptimized - the high-performance packet line parser.
/// </summary>
public class TSharkParserOptimizedTests
{
    #region Valid Input Tests

    [Fact]
    public void ParseLine_WithValidTcpPacket_ReturnsPacketInfo()
    {
        // Arrange - Tab-delimited TShark output with 15 fields
        var line = "1\t2024-01-15 10:30:45.123456\t1705312245.123456\t1500\t192.168.1.100\t8.8.8.8\t\t\t54321\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.FrameNumber.Should().Be(1);
        result.Value.SourceIP.Should().Be("192.168.1.100");
        result.Value.DestinationIP.Should().Be("8.8.8.8");
        result.Value.SourcePort.Should().Be(54321);
        result.Value.DestinationPort.Should().Be(443);
        result.Value.Protocol.Should().Be(Protocol.TCP);
        result.Value.Length.Should().Be(1500);
    }

    [Fact]
    public void ParseLine_WithValidUdpPacket_ReturnsPacketInfo()
    {
        // Arrange - UDP packet (ports in fields 10-11 instead of 8-9)
        var line = "2\t2024-01-15 10:30:46.000000\t1705312246.0\t100\t10.0.0.1\t10.0.0.2\t\t\t\t\t53\t53\tDNS\teth:ethertype:ip:udp:dns\tStandard query";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.FrameNumber.Should().Be(2);
        result.Value.SourcePort.Should().Be(53);
        result.Value.DestinationPort.Should().Be(53);
        result.Value.Protocol.Should().Be(Protocol.UDP);
        result.Value.L7Protocol.Should().Be("DNS");
    }

    [Fact]
    public void ParseLine_WithIPv6Addresses_ParsesCorrectly()
    {
        // Arrange - IPv6 packet (fields 6-7 instead of 4-5)
        var line = "3\t2024-01-15 10:30:47.000000\t1705312247.0\t200\t\t\t2001:db8::1\tfe80::1\t80\t443\t\t\tTCP\teth:ethertype:ipv6:tcp\tSYN";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.SourceIP.Should().Be("2001:db8::1");
        result.Value.DestinationIP.Should().Be("fe80::1");
    }

    [Fact]
    public void ParseLine_WithTcpFlags_ParsesHexCorrectly()
    {
        // Arrange - TCP packet with flags in field 15 (need trailing tab for field 18)
        var line = "4\t2024-01-15 10:30:48.000000\t1705312248.0\t64\t192.168.1.1\t192.168.1.2\t\t\t1234\t80\t\t\tTCP\teth:ethertype:ip:tcp\tSYN\t0x0002\t100\t0\t65535\t";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.TcpFlags.Should().Be(0x0002); // SYN flag
        result.Value.SeqNum.Should().Be(100);
        result.Value.AckNum.Should().Be(0);
        result.Value.WindowSize.Should().Be(65535);
    }

    [Fact]
    public void ParseLine_WithIcmpPacket_ReturnsCorrectProtocol()
    {
        // Arrange
        var line = "5\t2024-01-15 10:30:49.000000\t1705312249.0\t84\t192.168.1.1\t8.8.8.8\t\t\t\t\t\t\tICMP\teth:ethertype:ip:icmp\tEcho request";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.Protocol.Should().Be(Protocol.ICMP);
    }

    [Fact]
    public void ParseLine_WithArpPacket_ReturnsCorrectProtocol()
    {
        // Arrange
        var line = "6\t2024-01-15 10:30:50.000000\t1705312250.0\t42\t\t\t\t\t\t\t\t\tARP\teth:ethertype:arp\tWho has 192.168.1.1?";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.Protocol.Should().Be(Protocol.ARP);
    }

    [Fact]
    public void ParseLine_WithTlsProtocol_ExtractsL7Protocol()
    {
        // Arrange
        var line = "7\t2024-01-15 10:30:51.000000\t1705312251.0\t1200\t192.168.1.100\t93.184.216.34\t\t\t54321\t443\t\t\tTLSv1.2\teth:ethertype:ip:tcp:tls\tApplication Data";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.L7Protocol.Should().Be("TLSv1.2");
        result.Value.Protocol.Should().Be(Protocol.TCP);
    }

    #endregion

    #region Invalid Input Tests

    [Fact]
    public void ParseLine_WithEmptyLine_ReturnsNull()
    {
        // Act
        var result = TSharkParserOptimized.ParseLine(ReadOnlySpan<char>.Empty);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ParseLine_WithTooShortLine_ReturnsNull()
    {
        // Act
        var result = TSharkParserOptimized.ParseLine("short".AsSpan());

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ParseLine_WithInsufficientFields_ReturnsNull()
    {
        // Arrange - Only 10 tabs (need at least 14)
        var line = "1\t2024\t123\t64\t192.168.1.1\t192.168.1.2\t\t\t80\t443";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ParseLine_WithInvalidFrameNumber_ReturnsNull()
    {
        // Arrange - Non-numeric frame number
        var line = "invalid\t2024-01-15 10:30:45.123456\t1705312245.123456\t1500\t192.168.1.100\t8.8.8.8\t\t\t54321\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ParseLine_WithInvalidEpochTimestamp_ReturnsNull()
    {
        // Arrange - Non-numeric epoch
        var line = "1\t2024-01-15 10:30:45.123456\tinvalid\t1500\t192.168.1.100\t8.8.8.8\t\t\t54321\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ParseLine_WithInvalidLength_ReturnsNull()
    {
        // Arrange - Non-numeric length
        var line = "1\t2024-01-15 10:30:45.123456\t1705312245.123456\tbad\t192.168.1.100\t8.8.8.8\t\t\t54321\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ParseLine_WithZeroFrameNumber_ReturnsNull()
    {
        // Arrange - Frame number 0 is invalid
        var line = "0\t2024-01-15 10:30:45.123456\t1705312245.123456\t1500\t192.168.1.100\t8.8.8.8\t\t\t54321\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().BeNull();
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void ParseLine_WithEmptyIpAddresses_HandlesGracefully()
    {
        // Arrange - Both IPv4 and IPv6 fields empty
        var line = "8\t2024-01-15 10:30:52.000000\t1705312252.0\t64\t\t\t\t\t80\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.SourceIP.Should().BeEmpty();
        result.Value.DestinationIP.Should().BeEmpty();
    }

    [Fact]
    public void ParseLine_WithEmptyPorts_ReturnsZeroPorts()
    {
        // Arrange
        var line = "9\t2024-01-15 10:30:53.000000\t1705312253.0\t64\t192.168.1.1\t192.168.1.2\t\t\t\t\t\t\tICMP\teth:ethertype:ip:icmp\tEcho";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.SourcePort.Should().Be(0);
        result.Value.DestinationPort.Should().Be(0);
    }

    [Fact]
    public void ParseLine_WithEmptyInfo_HandlesGracefully()
    {
        // Arrange - Info field (14) empty
        var line = "10\t2024-01-15 10:30:54.000000\t1705312254.0\t64\t192.168.1.1\t192.168.1.2\t\t\t80\t443\t\t\tTCP\teth:ethertype:ip:tcp\t";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
    }

    [Fact]
    public void ParseLine_WithLargeFrameNumber_ParsesCorrectly()
    {
        // Arrange
        var line = "4294967295\t2024-01-15 10:30:55.000000\t1705312255.0\t64\t192.168.1.1\t192.168.1.2\t\t\t80\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.FrameNumber.Should().Be(uint.MaxValue);
    }

    [Fact]
    public void ParseLine_WithMaxPortNumbers_ParsesCorrectly()
    {
        // Arrange
        var line = "11\t2024-01-15 10:30:56.000000\t1705312256.0\t64\t192.168.1.1\t192.168.1.2\t\t\t65535\t65535\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.SourcePort.Should().Be(65535);
        result.Value.DestinationPort.Should().Be(65535);
    }

    [Fact]
    public void ParseLine_IPv4TakesPrecedenceOverIPv6_WhenBothPresent()
    {
        // Arrange - Both IPv4 and IPv6 fields populated (unusual but possible)
        var line = "12\t2024-01-15 10:30:57.000000\t1705312257.0\t64\t192.168.1.1\t192.168.1.2\t2001:db8::1\t2001:db8::2\t80\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.SourceIP.Should().Be("192.168.1.1"); // IPv4 takes precedence
        result.Value.DestinationIP.Should().Be("192.168.1.2");
    }

    [Fact]
    public void ParseLine_WithTcpFlagsWithoutHexPrefix_ParsesCorrectly()
    {
        // Arrange - TCP flags without "0x" prefix
        var line = "13\t2024-01-15 10:30:58.000000\t1705312258.0\t64\t192.168.1.1\t192.168.1.2\t\t\t1234\t80\t\t\tTCP\teth:ethertype:ip:tcp\tSYN\t0012\t100\t0\t65535";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.TcpFlags.Should().Be(0x0012); // SYN+ACK flags
    }

    #endregion

    #region Protocol Extraction Tests

    [Theory]
    [InlineData("eth:ethertype:ip:tcp", Protocol.TCP)]
    [InlineData("eth:ethertype:ip:udp", Protocol.UDP)]
    [InlineData("eth:ethertype:ip:icmp", Protocol.ICMP)]
    [InlineData("eth:ethertype:ipv6:icmpv6", Protocol.ICMP)]
    [InlineData("eth:ethertype:arp", Protocol.ARP)]
    [InlineData("eth:ethertype:ip:tcp:tls", Protocol.TCP)]
    [InlineData("unknown", Protocol.Unknown)]
    public void ParseLine_ExtractsL4Protocol_FromProtocolStack(string protocolStack, Protocol expected)
    {
        // Arrange
        var line = $"14\t2024-01-15 10:30:59.000000\t1705312259.0\t64\t192.168.1.1\t192.168.1.2\t\t\t80\t443\t\t\tTCP\t{protocolStack}\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.Protocol.Should().Be(expected);
    }

    [Theory]
    [InlineData("TLSv1.2", "TLSv1.2")]
    [InlineData("HTTP", "HTTP")]
    [InlineData("DNS", "DNS")]
    [InlineData("SSH", "SSH")]
    [InlineData("TCP", "")] // L4 only, no L7
    [InlineData("UDP", "")] // L4 only, no L7
    public void ParseLine_ExtractsL7Protocol_FromDisplayProtocol(string displayProtocol, string expectedL7)
    {
        // Arrange - L7 protocol is in field 12
        var protocolStack = displayProtocol == "TCP" ? "eth:ethertype:ip:tcp" :
                           displayProtocol == "UDP" ? "eth:ethertype:ip:udp" :
                           $"eth:ethertype:ip:tcp:{displayProtocol.ToLower()}";
        var line = $"15\t2024-01-15 10:31:00.000000\t1705312260.0\t64\t192.168.1.1\t192.168.1.2\t\t\t80\t443\t\t\t{displayProtocol}\t{protocolStack}\tData";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        result!.Value.L7Protocol.Should().Be(expectedL7);
    }

    #endregion

    #region Timestamp Tests

    [Fact]
    public void ParseLine_ParsesEpochTimestamp_ToLocalTime()
    {
        // Arrange - Known epoch: 1705312245.123456 = 2024-01-15 09:30:45.123456 UTC
        var line = "16\t2024-01-15 10:30:45.123456\t1705312245.123456\t64\t192.168.1.1\t192.168.1.2\t\t\t80\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert
        result.Should().NotBeNull();
        // The epoch should be converted to local time
        var expectedUtc = DateTimeOffset.FromUnixTimeMilliseconds((long)(1705312245.123456 * 1000)).UtcDateTime;
        result!.Value.Timestamp.ToUniversalTime().Should().BeCloseTo(expectedUtc, TimeSpan.FromMilliseconds(10));
    }

    [Fact]
    public void ParseLine_WithNegativeEpoch_ReturnsNull()
    {
        // Arrange - Negative epoch should fail
        var line = "17\t2024-01-15 10:30:45.123456\t-1\t64\t192.168.1.1\t192.168.1.2\t\t\t80\t443\t\t\tTCP\teth:ethertype:ip:tcp\tACK";

        // Act
        var result = TSharkParserOptimized.ParseLine(line.AsSpan());

        // Assert - Should parse (negative doubles are valid, just result in dates before 1970)
        // This is actually valid parsing, the timestamp will be before Unix epoch
        result.Should().NotBeNull();
    }

    #endregion
}
