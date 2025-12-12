using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Services.Filters;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.Filters;

/// <summary>
/// Tests for QuickFilterPredicateRegistry - the single source of truth for quick filter predicates.
/// </summary>
public class QuickFilterPredicateRegistryTests
{
    #region IP Address Classification

    [Theory]
    [InlineData("192.168.1.1", "10.0.0.1", true)]   // Both RFC1918
    [InlineData("172.16.0.1", "192.168.0.1", true)] // Both RFC1918
    [InlineData("8.8.8.8", "1.1.1.1", false)]       // Both public
    public void RFC1918_FiltersCorrectly(string srcIp, string destIp, bool expected)
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("RFC1918");
        Assert.NotNull(predicate);

        var packet = CreatePacket(srcIp, destIp);
        Assert.Equal(expected, predicate(packet));
    }

    [Theory]
    [InlineData("192.168.1.1", true)]   // IPv4
    [InlineData("10.0.0.1", true)]      // IPv4
    [InlineData("8.8.8.8", true)]       // IPv4
    public void IPv4_FiltersCorrectly(string srcIp, bool expected)
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("IPv4");
        Assert.NotNull(predicate);

        var packet = CreatePacket(srcIp, "1.1.1.1");
        Assert.Equal(expected, predicate(packet));
    }

    [Theory]
    [InlineData("127.0.0.1", "192.168.1.1", true)]   // Loopback source
    [InlineData("192.168.1.1", "127.0.0.1", true)]   // Loopback dest
    [InlineData("192.168.1.1", "10.0.0.1", false)]   // No loopback
    public void Loopback_FiltersCorrectly(string srcIp, string destIp, bool expected)
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("Loopback");
        Assert.NotNull(predicate);

        var packet = CreatePacket(srcIp, destIp);
        Assert.Equal(expected, predicate(packet));
    }

    #endregion

    #region Traffic Direction

    [Fact]
    public void PrivateToPublic_MatchesOutboundTraffic()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("PrivateToPublic");
        Assert.NotNull(predicate);

        // Private to public = match
        var outbound = CreatePacket("192.168.1.1", "8.8.8.8");
        Assert.True(predicate(outbound));

        // Public to private = no match
        var inbound = CreatePacket("8.8.8.8", "192.168.1.1");
        Assert.False(predicate(inbound));

        // Private to private = no match
        var internal_ = CreatePacket("192.168.1.1", "10.0.0.1");
        Assert.False(predicate(internal_));
    }

    [Fact]
    public void PublicToPrivate_MatchesInboundTraffic()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("PublicToPrivate");
        Assert.NotNull(predicate);

        // Public to private = match
        var inbound = CreatePacket("8.8.8.8", "192.168.1.1");
        Assert.True(predicate(inbound));

        // Private to public = no match
        var outbound = CreatePacket("192.168.1.1", "8.8.8.8");
        Assert.False(predicate(outbound));
    }

    #endregion

    #region Transport Protocols

    [Fact]
    public void TCP_FiltersCorrectly()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("TCP");
        Assert.NotNull(predicate);

        var tcpPacket = CreatePacket("1.1.1.1", "2.2.2.2", Protocol.TCP);
        var udpPacket = CreatePacket("1.1.1.1", "2.2.2.2", Protocol.UDP);

        Assert.True(predicate(tcpPacket));
        Assert.False(predicate(udpPacket));
    }

    [Fact]
    public void UDP_FiltersCorrectly()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("UDP");
        Assert.NotNull(predicate);

        var udpPacket = CreatePacket("1.1.1.1", "2.2.2.2", Protocol.UDP);
        var tcpPacket = CreatePacket("1.1.1.1", "2.2.2.2", Protocol.TCP);

        Assert.True(predicate(udpPacket));
        Assert.False(predicate(tcpPacket));
    }

    [Fact]
    public void ICMP_FiltersCorrectly()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("ICMP");
        Assert.NotNull(predicate);

        var icmpPacket = CreatePacket("1.1.1.1", "2.2.2.2", Protocol.ICMP);
        var tcpPacket = CreatePacket("1.1.1.1", "2.2.2.2", Protocol.TCP);

        Assert.True(predicate(icmpPacket));
        Assert.False(predicate(tcpPacket));
    }

    #endregion

    #region TCP Flags

    [Fact]
    public void SYN_MatchesSynWithoutAck()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("SYN");
        Assert.NotNull(predicate);

        // SYN without ACK = match (connection initiation)
        var synPacket = CreateTcpPacket(0x02); // SYN only
        Assert.True(predicate(synPacket));

        // SYN-ACK = no match
        var synAckPacket = CreateTcpPacket(0x12); // SYN + ACK
        Assert.False(predicate(synAckPacket));

        // ACK only = no match
        var ackPacket = CreateTcpPacket(0x10);
        Assert.False(predicate(ackPacket));
    }

    [Fact]
    public void SYN_ACK_MatchesSynAck()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("SYN-ACK");
        Assert.NotNull(predicate);

        // SYN-ACK = match
        var synAckPacket = CreateTcpPacket(0x12);
        Assert.True(predicate(synAckPacket));

        // SYN only = no match
        var synPacket = CreateTcpPacket(0x02);
        Assert.False(predicate(synPacket));
    }

    [Fact]
    public void RST_MatchesResetFlag()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("RST");
        Assert.NotNull(predicate);

        // RST flag set = match
        var rstPacket = CreateTcpPacket(0x04);
        Assert.True(predicate(rstPacket));

        // RST + ACK = still match
        var rstAckPacket = CreateTcpPacket(0x14);
        Assert.True(predicate(rstAckPacket));

        // No RST = no match
        var synPacket = CreateTcpPacket(0x02);
        Assert.False(predicate(synPacket));
    }

    [Fact]
    public void FIN_MatchesFinFlag()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("FIN");
        Assert.NotNull(predicate);

        // FIN flag set = match
        var finPacket = CreateTcpPacket(0x01);
        Assert.True(predicate(finPacket));

        // FIN + ACK = still match
        var finAckPacket = CreateTcpPacket(0x11);
        Assert.True(predicate(finAckPacket));
    }

    #endregion

    #region Application Protocols

    [Fact]
    public void HTTP_MatchesHttpProtocol()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("HTTP");
        Assert.NotNull(predicate);

        var httpPacket = CreatePacketWithL7("HTTP");
        Assert.True(predicate(httpPacket));

        // HTTPS should not match HTTP filter
        var httpsPacket = CreatePacketWithL7("HTTPS");
        Assert.False(predicate(httpsPacket));
    }

    [Fact]
    public void DNS_MatchesDnsTraffic()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("DNS");
        Assert.NotNull(predicate);

        // DNS by protocol
        var dnsPacket = CreatePacketWithL7("DNS");
        Assert.True(predicate(dnsPacket));

        // DNS by port
        var dnsPortPacket = CreatePacket("1.1.1.1", "8.8.8.8", Protocol.UDP, 12345, 53);
        Assert.True(predicate(dnsPortPacket));
    }

    [Fact]
    public void SSH_MatchesSshPort()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("SSH");
        Assert.NotNull(predicate);

        var sshPacket = CreatePacket("1.1.1.1", "2.2.2.2", Protocol.TCP, 12345, 22);
        Assert.True(predicate(sshPacket));

        var nonSshPacket = CreatePacket("1.1.1.1", "2.2.2.2", Protocol.TCP, 12345, 80);
        Assert.False(predicate(nonSshPacket));
    }

    #endregion

    #region Registration

    [Fact]
    public void GetPredicate_ReturnsNullForUnknownFilter()
    {
        var predicate = QuickFilterPredicateRegistry.GetPredicate("UNKNOWN_FILTER_XYZ");
        Assert.Null(predicate);
    }

    [Fact]
    public void GetPredicate_ReturnsNullForNullOrEmpty()
    {
        Assert.Null(QuickFilterPredicateRegistry.GetPredicate(null));
        Assert.Null(QuickFilterPredicateRegistry.GetPredicate(""));
        Assert.Null(QuickFilterPredicateRegistry.GetPredicate("   "));
    }

    [Fact]
    public void IsRegistered_ReturnsTrueForKnownFilters()
    {
        Assert.True(QuickFilterPredicateRegistry.IsRegistered("TCP"));
        Assert.True(QuickFilterPredicateRegistry.IsRegistered("UDP"));
        Assert.True(QuickFilterPredicateRegistry.IsRegistered("SYN"));
        Assert.True(QuickFilterPredicateRegistry.IsRegistered("HTTP"));
    }

    [Fact]
    public void GetAllCodeNames_ReturnsNonEmptySet()
    {
        var codeNames = QuickFilterPredicateRegistry.GetAllCodeNames().ToList();
        Assert.NotEmpty(codeNames);
        Assert.Contains("TCP", codeNames);
        Assert.Contains("UDP", codeNames);
        Assert.Contains("SYN", codeNames);
    }

    #endregion

    #region Helper Methods

    private static PacketInfo CreatePacket(string srcIp, string destIp, Protocol protocol = Protocol.TCP,
        ushort srcPort = 12345, ushort destPort = 80)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            Length = 100,
            SourceIP = srcIp,
            DestinationIP = destIp,
            Protocol = protocol,
            SourcePort = srcPort,
            DestinationPort = destPort
        };
    }

    private static PacketInfo CreateTcpPacket(byte tcpFlags)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            Length = 100,
            SourceIP = "192.168.1.1",
            DestinationIP = "10.0.0.1",
            Protocol = Protocol.TCP,
            TcpFlags = tcpFlags,
            SourcePort = 12345,
            DestinationPort = 80
        };
    }

    private static PacketInfo CreatePacketWithL7(string l7Protocol)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            Length = 100,
            SourceIP = "192.168.1.1",
            DestinationIP = "10.0.0.1",
            Protocol = Protocol.TCP,
            L7Protocol = l7Protocol,
            SourcePort = 12345,
            DestinationPort = 80
        };
    }

    #endregion
}
