using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using Xunit;

namespace PCAPAnalyzer.Tests.Services;

/// <summary>
/// Tests for DashboardFilterService predicates, especially the new quick filters:
/// - TCP Performance (Retransmissions, ZeroWindow, KeepAlive, ConnectionRefused, WindowFull)
/// - Security Audit (CleartextAuth, ObsoleteCrypto, DnsTunneling, ScanTraffic, NonStandardPorts, SmbV1)
/// - Clean View (HideBroadcast, ApplicationDataOnly, HideTunnelOverhead)
/// - Protocol Errors (HttpErrors, DnsFailures, IcmpUnreachable)
/// </summary>
public class DashboardFilterServiceTests
{
    private readonly DashboardFilterService _service = new();
    private readonly AnomalyFrameSet _emptyAnomalyFrames = new();

    // ==================== HELPER METHODS ====================

    private static PacketInfo CreatePacket(
        Protocol protocol = Protocol.TCP,
        string? l7Protocol = null,
        ushort srcPort = 12345,
        ushort dstPort = 80,
        string srcIp = "192.168.1.100",
        string dstIp = "8.8.8.8",
        string? info = null,
        ushort length = 100,
        byte tcpFlags = 0)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            Protocol = protocol,
            L7Protocol = l7Protocol,
            SourcePort = srcPort,
            DestinationPort = dstPort,
            SourceIP = srcIp,
            DestinationIP = dstIp,
            Info = info ?? string.Empty,
            Length = length,
            TcpFlags = tcpFlags
        };
    }

    // ==================== TCP PERFORMANCE TESTS ====================

    [Theory]
    [InlineData("[TCP Retransmission]")]
    [InlineData("[TCP Fast Retransmission]")]
    [InlineData("Some prefix [TCP Retransmission] suffix")]
    public void Retransmissions_MatchesPacketsWithRetransmissionMarker(string info)
    {
        var packet = CreatePacket(info: info);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.Retransmissions, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void Retransmissions_DoesNotMatchNormalPacket()
    {
        var packet = CreatePacket(info: "Normal TCP packet");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.Retransmissions, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Theory]
    [InlineData("[TCP ZeroWindow]")]
    [InlineData("[TCP Zero Window]")]
    public void ZeroWindow_MatchesPacketsWithZeroWindowMarker(string info)
    {
        var packet = CreatePacket(info: info);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ZeroWindow, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void KeepAlive_MatchesPacketsWithKeepAliveMarker()
    {
        var packet = CreatePacket(info: "[TCP Keep-Alive]");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.KeepAlive, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void ConnectionRefused_MatchesTcpPacketWithRstFlag()
    {
        // RST flag = 0x04
        var packet = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x04);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ConnectionRefused, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void ConnectionRefused_DoesNotMatchPacketWithoutRstFlag()
    {
        // SYN flag only = 0x02
        var packet = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x02);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ConnectionRefused, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Fact]
    public void ConnectionRefused_DoesNotMatchNonTcpPacket()
    {
        var packet = CreatePacket(protocol: Protocol.UDP, tcpFlags: 0x04);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ConnectionRefused, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Fact]
    public void WindowFull_MatchesPacketsWithWindowFullMarker()
    {
        var packet = CreatePacket(info: "[TCP Window Full]");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.WindowFull, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    // ==================== SECURITY AUDIT TESTS ====================

    [Theory]
    [InlineData("HTTP", "Authorization: Basic dXNlcjpwYXNz")]
    [InlineData("HTTP", "WWW-Authenticate: Basic realm")]
    public void CleartextAuth_MatchesHttpBasicAuth(string l7Protocol, string info)
    {
        var packet = CreatePacket(l7Protocol: l7Protocol, info: info);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.CleartextAuth, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Theory]
    [InlineData("FTP", "USER anonymous")]
    [InlineData("FTP", "PASS secret123")]
    public void CleartextAuth_MatchesFtpCredentials(string l7Protocol, string info)
    {
        var packet = CreatePacket(l7Protocol: l7Protocol, info: info);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.CleartextAuth, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void CleartextAuth_MatchesTelnetOnPort23()
    {
        var packet = CreatePacket(dstPort: 23);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.CleartextAuth, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void CleartextAuth_MatchesPop3Credentials()
    {
        var packet = CreatePacket(dstPort: 110, info: "USER admin");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.CleartextAuth, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void CleartextAuth_DoesNotMatchSecureTraffic()
    {
        var packet = CreatePacket(l7Protocol: "TLS v1.3", dstPort: 443);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.CleartextAuth, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Theory]
    [InlineData("TLS v1.0")]
    [InlineData("TLS v1.1")]
    [InlineData("SSLv3")]
    public void ObsoleteCrypto_MatchesOldTlsVersions(string l7Protocol)
    {
        var packet = CreatePacket(l7Protocol: l7Protocol);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ObsoleteCrypto, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Theory]
    [InlineData("TLS v1.2")]
    [InlineData("TLS v1.3")]
    public void ObsoleteCrypto_DoesNotMatchModernTls(string l7Protocol)
    {
        var packet = CreatePacket(l7Protocol: l7Protocol);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ObsoleteCrypto, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Fact]
    public void DnsTunneling_MatchesLongDnsQuery()
    {
        // DNS packet with length > 200 (suspicious tunneling)
        var packet = CreatePacket(l7Protocol: "DNS", dstPort: 53, length: 250);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.DnsTunneling, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void DnsTunneling_MatchesTxtQuery()
    {
        var packet = CreatePacket(l7Protocol: "DNS", dstPort: 53, info: "TXT query for tunnel.example.com");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.DnsTunneling, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void DnsTunneling_DoesNotMatchNormalDns()
    {
        var packet = CreatePacket(l7Protocol: "DNS", dstPort: 53, length: 60, info: "A query");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.DnsTunneling, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Theory]
    [InlineData(0x02, true)]   // SYN only (SYN scan)
    [InlineData(0x00, true)]   // No flags (NULL scan)
    [InlineData(0x01, true)]   // FIN only (FIN scan)
    [InlineData(0x29, true)]   // FIN+PSH+URG (XMAS scan)
    [InlineData(0x12, false)]  // SYN+ACK (normal handshake)
    [InlineData(0x10, false)]  // ACK only (normal)
    public void ScanTraffic_MatchesScanPatterns(byte tcpFlags, bool shouldMatch)
    {
        var packet = CreatePacket(protocol: Protocol.TCP, tcpFlags: tcpFlags);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ScanTraffic, _emptyAnomalyFrames);

        Assert.Equal(shouldMatch, predicate(packet));
    }

    [Fact]
    public void ScanTraffic_DoesNotMatchNonTcpPacket()
    {
        var packet = CreatePacket(protocol: Protocol.UDP, tcpFlags: 0x02);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ScanTraffic, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Theory]
    [InlineData((ushort)8081, true)]   // Non-standard port
    [InlineData((ushort)9000, true)]   // Non-standard port
    [InlineData((ushort)80, false)]    // Standard port
    [InlineData((ushort)8080, false)]  // Standard port
    [InlineData((ushort)8000, false)]  // Standard port
    public void NonStandardPorts_MatchesHttpOnUnusualPorts(ushort dstPort, bool shouldMatch)
    {
        var packet = CreatePacket(l7Protocol: "HTTP", dstPort: dstPort);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.NonStandardPorts, _emptyAnomalyFrames);

        Assert.Equal(shouldMatch, predicate(packet));
    }

    [Fact]
    public void SmbV1_MatchesSmbV1Traffic()
    {
        var packet = CreatePacket(l7Protocol: "SMB", dstPort: 445, info: "SMB1 Negotiate");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.SmbV1, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void SmbV1_MatchesNtLmTraffic()
    {
        var packet = CreatePacket(l7Protocol: "SMB2", dstPort: 445, info: "NT LM 0.12");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.SmbV1, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void SmbV1_DoesNotMatchSmbV2()
    {
        var packet = CreatePacket(l7Protocol: "SMB2", dstPort: 445, info: "SMB2 Negotiate");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.SmbV1, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    // ==================== CLEAN VIEW TESTS ====================

    [Theory]
    [InlineData(Protocol.ARP, null, (ushort)0, (ushort)0, true)]           // ARP
    [InlineData(Protocol.UDP, null, (ushort)0, (ushort)1900, true)]        // SSDP
    [InlineData(Protocol.UDP, null, (ushort)0, (ushort)5353, true)]        // mDNS
    [InlineData(Protocol.UDP, null, (ushort)0, (ushort)5355, true)]        // LLMNR
    [InlineData(Protocol.UDP, null, (ushort)0, (ushort)137, true)]         // NetBIOS
    [InlineData(Protocol.TCP, null, (ushort)0, (ushort)80, false)]         // Normal HTTP
    public void HideBroadcast_MatchesBroadcastDiscoveryProtocols(
        Protocol protocol, string? l7Protocol, ushort srcPort, ushort dstPort, bool shouldMatch)
    {
        var packet = CreatePacket(protocol: protocol, l7Protocol: l7Protocol, srcPort: srcPort, dstPort: dstPort);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.HideBroadcast, _emptyAnomalyFrames);

        Assert.Equal(shouldMatch, predicate(packet));
    }

    [Fact]
    public void HideBroadcast_MatchesBroadcastDestination()
    {
        var packet = CreatePacket(dstIp: "255.255.255.255");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.HideBroadcast, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Theory]
    [InlineData((ushort)40, true)]    // Only headers (TCP/IP = ~40 bytes)
    [InlineData((ushort)66, true)]    // Minimum with no payload
    [InlineData((ushort)67, false)]   // Has some payload
    [InlineData((ushort)1500, false)] // Normal packet
    public void ApplicationDataOnly_MatchesSmallPackets(ushort length, bool shouldMatch)
    {
        var packet = CreatePacket(length: length);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.ApplicationDataOnly, _emptyAnomalyFrames);

        Assert.Equal(shouldMatch, predicate(packet));
    }

    [Theory]
    [InlineData("ESP", true)]
    [InlineData("GRE", true)]
    [InlineData("IPIP", true)]
    [InlineData("TCP", false)]
    [InlineData("HTTP", false)]
    public void HideTunnelOverhead_MatchesTunnelProtocols(string l7Protocol, bool shouldMatch)
    {
        var packet = CreatePacket(l7Protocol: l7Protocol);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.HideTunnelOverhead, _emptyAnomalyFrames);

        Assert.Equal(shouldMatch, predicate(packet));
    }

    // ==================== PROTOCOL ERROR TESTS ====================

    [Theory]
    [InlineData("HTTP/1.1 404 Not Found")]
    [InlineData("HTTP/1.1 500 Internal Server Error")]
    [InlineData("HTTP/2 403 Forbidden")]
    public void HttpErrors_MatchesErrorResponses(string info)
    {
        var packet = CreatePacket(l7Protocol: "HTTP", info: info);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.HttpErrors, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK")]
    [InlineData("HTTP/1.1 301 Moved")]
    [InlineData("GET / HTTP/1.1")]
    public void HttpErrors_DoesNotMatchSuccessResponses(string info)
    {
        var packet = CreatePacket(l7Protocol: "HTTP", info: info);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.HttpErrors, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Theory]
    [InlineData("NXDOMAIN")]
    [InlineData("SERVFAIL")]
    [InlineData("REFUSED")]
    [InlineData("No such name")]
    [InlineData("Server failure")]
    public void DnsFailures_MatchesFailureResponses(string info)
    {
        var packet = CreatePacket(l7Protocol: "DNS", dstPort: 53, info: info);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.DnsFailures, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void DnsFailures_DoesNotMatchSuccessfulQuery()
    {
        var packet = CreatePacket(l7Protocol: "DNS", dstPort: 53, info: "A record for example.com -> 93.184.216.34");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.DnsFailures, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    [Theory]
    [InlineData("Destination unreachable")]
    [InlineData("Host unreachable")]
    [InlineData("Network unreachable")]
    public void IcmpUnreachable_MatchesUnreachableMessages(string info)
    {
        var packet = CreatePacket(protocol: Protocol.ICMP, info: info);
        var predicate = _service.GetFilterPredicate(DashboardFilterType.IcmpUnreachable, _emptyAnomalyFrames);

        Assert.True(predicate(packet));
    }

    [Fact]
    public void IcmpUnreachable_DoesNotMatchEchoRequest()
    {
        var packet = CreatePacket(protocol: Protocol.ICMP, info: "Echo request");
        var predicate = _service.GetFilterPredicate(DashboardFilterType.IcmpUnreachable, _emptyAnomalyFrames);

        Assert.False(predicate(packet));
    }

    // ==================== INTEGRATION TESTS ====================

    [Fact]
    public void ApplySmartFilters_FiltersPacketsCorrectly()
    {
        var packets = new List<PacketInfo>
        {
            CreatePacket(info: "[TCP Retransmission]"),
            CreatePacket(info: "Normal packet"),
            CreatePacket(info: "[TCP Fast Retransmission]"),
            CreatePacket(info: "Another normal packet")
        };

        var filters = new DashboardSmartFilters { Retransmissions = true };
        var result = _service.ApplySmartFilters(packets, filters, _emptyAnomalyFrames).ToList();

        Assert.Equal(2, result.Count);
        Assert.All(result, p => Assert.Contains("Retransmission", p.Info));
    }

    [Fact]
    public void ApplySmartFilters_WithAndMode_RequiresAllFilters()
    {
        var packets = new List<PacketInfo>
        {
            CreatePacket(l7Protocol: "HTTP", info: "HTTP/1.1 404 Not Found"),  // HTTP + Error
            CreatePacket(l7Protocol: "HTTP", info: "HTTP/1.1 200 OK"),         // HTTP only
            CreatePacket(l7Protocol: "DNS", info: "NXDOMAIN"),                 // DNS error only
        };

        var filters = new DashboardSmartFilters
        {
            Http = true,
            HttpErrors = true
        };

        var result = _service.ApplySmartFilters(packets, filters, _emptyAnomalyFrames, useAndMode: true).ToList();

        Assert.Single(result);
        Assert.Contains("404", result[0].Info);
    }

    [Fact]
    public void ApplySmartFilters_WithOrMode_MatchesAnyFilter()
    {
        var packets = new List<PacketInfo>
        {
            CreatePacket(l7Protocol: "HTTP", info: "HTTP/1.1 404 Not Found"),
            CreatePacket(l7Protocol: "HTTP", info: "HTTP/1.1 200 OK"),
            CreatePacket(l7Protocol: "DNS", info: "NXDOMAIN"),
            CreatePacket(l7Protocol: "TCP", info: "Normal TCP"),
        };

        var filters = new DashboardSmartFilters
        {
            HttpErrors = true,
            DnsFailures = true
        };

        var result = _service.ApplySmartFilters(packets, filters, _emptyAnomalyFrames, useAndMode: false).ToList();

        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void ApplySmartFilters_WithNotMode_ExcludesMatching()
    {
        var packets = new List<PacketInfo>
        {
            CreatePacket(protocol: Protocol.ARP),       // Broadcast discovery
            CreatePacket(dstPort: 1900),                // SSDP
            CreatePacket(l7Protocol: "HTTP"),           // Normal traffic
            CreatePacket(l7Protocol: "DNS", dstPort: 53) // Normal DNS
        };

        var filters = new DashboardSmartFilters { HideBroadcast = true };
        // HideBroadcast uses inverted logic in GetActivePredicates
        var result = _service.ApplySmartFilters(packets, filters, _emptyAnomalyFrames).ToList();

        Assert.Equal(2, result.Count);
        Assert.DoesNotContain(result, p => p.Protocol == Protocol.ARP);
        Assert.DoesNotContain(result, p => p.DestinationPort == 1900);
    }
}
